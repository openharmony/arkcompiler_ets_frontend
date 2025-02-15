/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "importPathManager.h"
#include "es2panda.h"
#include <libpandabase/os/filesystem.h>
#include "util/diagnostic.h"
#include "util/diagnosticEngine.h"

#ifdef USE_UNIX_SYSCALL
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#else
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif
#endif
namespace ark::es2panda::util {

constexpr size_t SUPPORTED_INDEX_FILES_SIZE = 3;
constexpr size_t SUPPORTED_EXTENSIONS_SIZE = 6;
constexpr size_t ALLOWED_EXTENSIONS_SIZE = 8;

static bool IsCompatibleExtension(const std::string &extension)
{
    return extension == ".sts" || extension == ".ts" || extension == ".ets";
}

util::StringView ImportPathManager::ResolvePath(const StringView &currentModulePath, const StringView &importPath,
                                                const lexer::SourcePosition &srcPos) const
{
    if (importPath.Empty()) {
        diagnosticEngine_.LogFatalError(program_, "Import path cannot be empty", srcPos);
        return importPath;
    }

    if (IsRelativePath(importPath)) {
        const size_t pos = currentModulePath.Mutf8().find_last_of("/\\");
        ASSERT(pos != std::string::npos);

        auto currentDirectory = currentModulePath.Mutf8().substr(0, pos);
        auto resolvedPath = UString(currentDirectory, allocator_);
        resolvedPath.Append(pathDelimiter_);
        resolvedPath.Append(importPath.Mutf8());

        return AppendExtensionOrIndexFileIfOmitted(resolvedPath.View(), srcPos);
    }

    return ResolveAbsolutePath(importPath, srcPos);
}

util::StringView ImportPathManager::ResolveAbsolutePath(const StringView &importPath,
                                                        const lexer::SourcePosition &srcPos) const
{
    ASSERT(!IsRelativePath(importPath));

    if (importPath.Mutf8()[0] == pathDelimiter_.at(0)) {
        std::string baseUrl = arktsConfig_->BaseUrl();
        baseUrl.append(importPath.Mutf8(), 0, importPath.Mutf8().length());
        return AppendExtensionOrIndexFileIfOmitted(UString(baseUrl, allocator_).View(), srcPos);
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(importPath.Mutf8()); it != dynamicPaths.cend() && !it->second.HasDecl()) {
        return AppendExtensionOrIndexFileIfOmitted(importPath, srcPos);
    }

    const size_t pos = importPath.Mutf8().find_first_of("/\\");
    bool containsDelim = (pos != std::string::npos);
    auto rootPart = containsDelim ? importPath.Substr(0, pos) : importPath;
    if (!stdLib_.empty() &&
        (rootPart.Is("std") || rootPart.Is("escompat"))) {  // Get std or escompat path from CLI if provided
        std::string baseUrl = stdLib_ + pathDelimiter_.at(0) + rootPart.Mutf8();

        if (containsDelim) {
            baseUrl.append(1, pathDelimiter_.at(0));
            baseUrl.append(importPath.Mutf8(), rootPart.Mutf8().length() + 1, importPath.Mutf8().length());
        }
        return UString(baseUrl, allocator_).View();
    }

    ASSERT(arktsConfig_ != nullptr);
    auto resolvedPath = arktsConfig_->ResolvePath(importPath.Mutf8());
    if (!resolvedPath) {
        diagnosticEngine_.LogFatalError(program_,
                                        util::DiagnosticMessageParams {"Can't find prefix for ",
                                                                       util::StringView(importPath.Mutf8()), "' in ",
                                                                       util::StringView(arktsConfig_->ConfigPath())},
                                        srcPos);
        return "";
    }
    return AppendExtensionOrIndexFileIfOmitted(UString(resolvedPath.value(), allocator_).View(), srcPos);
}

#ifdef USE_UNIX_SYSCALL
void ImportPathManager::UnixWalkThroughDirectoryAndAddToParseList(const StringView &directoryPath,
                                                                  const ImportFlags importFlags,
                                                                  const lexer::SourcePosition &srcPos)
{
    DIR *dir = opendir(directoryPath.Mutf8().c_str());
    if (dir == nullptr) {
        diagnosticEngine_.LogFatalError(
            program_, util::DiagnosticMessageParams {"Cannot open folder: ", util::StringView(directoryPath.Mutf8())},
            srcPos);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        std::string fileName = entry->d_name;
        std::string::size_type pos = fileName.find_last_of('.');
        if (pos == std::string::npos || !IsCompatibleExtension(fileName.substr(pos))) {
            continue;
        }

        std::string filePath = directoryPath.Mutf8() + "/" + entry->d_name;
        AddToParseList(UString(filePath, allocator_).View(), importFlags, srcPos);
    }

    closedir(dir);
    return;
}
#endif

void ImportPathManager::AddToParseList(const StringView &resolvedPath, const ImportFlags importFlags,
                                       const lexer::SourcePosition &srcPos)
{
    const bool isDefaultImport = (importFlags & ImportFlags::DEFAULT_IMPORT) != 0;
    const bool isImplicitPackageImport = (importFlags & ImportFlags::IMPLICIT_PACKAGE_IMPORT) != 0;
    const auto parseInfo = ParseInfo {resolvedPath, false, isImplicitPackageImport};

    if (ark::os::file::File::IsDirectory(resolvedPath.Mutf8())) {
#ifdef USE_UNIX_SYSCALL
        UnixWalkThroughDirectoryAndAddToParseList(resolvedPath, importFlags, srcPos);
#else
        for (auto const &entry : fs::directory_iterator(resolvedPath.Mutf8())) {
            if (!fs::is_regular_file(entry) || !IsCompatibleExtension(entry.path().extension().string())) {
                continue;
            }

            AddToParseList(UString(entry.path().string(), allocator_).View(), importFlags, srcPos);
        }
        return;
#endif
    }

    // Check if file has been already added to parse list
    if (const auto &found =
            std::find_if(parseList_.begin(), parseList_.end(),
                         [&resolvedPath](const ParseInfo &info) { return (info.sourcePath == resolvedPath); });
        found != parseList_.end()) {
        // The 'parseList_' can contain at most 1 record with the same source file path (else it'll break things).
        //
        // If a file is added as implicit package imported before, then we may add it again without the implicit import
        // directive (and remove the other one), to handle when an implicitly package imported file explicitly imports
        // it. Re-parsing it is necessary, because if the implicitly package imported file contains a syntax error, then
        // it'll be ignored, but we must not ignore it if an explicitly imported file contains a parse error. Also this
        // addition can happen during parsing the files in the parse list, so re-addition is necessary in order to
        // surely re-parse it.
        //
        // If a file was already not implicitly package imported, then it's just a duplicate, return
        if (!found->isImplicitPackageImported) {
            return;
        }

        parseList_.erase(found);
    }

    if (const auto &dynamicPaths = arktsConfig_->DynamicPaths();
        dynamicPaths.find(resolvedPath.Mutf8()) != dynamicPaths.cend()) {
        parseList_.emplace(parseList_.begin(), parseInfo);
        return;
    }

    if (!ark::os::file::File::IsRegularFile(resolvedPath.Mutf8())) {
        diagnosticEngine_.LogFatalError(
            program_,
            util::DiagnosticMessageParams {"Not an available source path: ", util::StringView(resolvedPath.Mutf8())},
            srcPos);
        return;
    }

    // 'Object.sts' must be the first in the parse list
    // NOTE (mmartin): still must be the first?
    const std::size_t position = resolvedPath.Mutf8().find_last_of("/\\");
    if (isDefaultImport && resolvedPath.Substr(position + 1, resolvedPath.Length()).Is("Object.sts")) {
        parseList_.emplace(parseList_.begin(), parseInfo);
    } else {
        parseList_.emplace_back(parseInfo);
    }
}

ImportPathManager::ImportData ImportPathManager::GetImportData(const util::StringView &path,
                                                               util::gen::extension::Enum extension) const
{
    const auto &dynamicPaths = arktsConfig_->DynamicPaths();
    auto key = ark::os::NormalizePath(path.Mutf8());

    auto it = dynamicPaths.find(key);
    if (it == dynamicPaths.cend()) {
        key = ark::os::RemoveExtension(key);
    }

    while (it == dynamicPaths.cend() && !key.empty()) {
        it = dynamicPaths.find(key);
        if (it != dynamicPaths.cend()) {
            break;
        }
        key = ark::os::GetParentDir(key);
    }

    if (it != dynamicPaths.cend()) {
        return {it->second.GetLanguage(), key, it->second.HasDecl()};
    }

    return {ToLanguage(extension), path.Mutf8(), true};
}

void ImportPathManager::MarkAsParsed(const StringView &path)
{
    for (auto &parseInfo : parseList_) {
        if (parseInfo.sourcePath == path) {
            parseInfo.isParsed = true;
            return;
        }
    }
}

bool ImportPathManager::IsRelativePath(const StringView &path) const
{
    std::string currentDirReferenceLinux = "./";
    std::string parentDirReferenceLinux = "../";
    std::string currentDirReferenceWindows = ".\\";
    std::string parentDirReferenceWindows = "..\\";

    return ((path.Mutf8().find(currentDirReferenceLinux) == 0) || (path.Mutf8().find(parentDirReferenceLinux) == 0) ||
            (path.Mutf8().find(currentDirReferenceWindows) == 0) ||
            (path.Mutf8().find(parentDirReferenceWindows) == 0));
}

StringView ImportPathManager::GetRealPath(const StringView &path) const
{
    const std::string realPath = ark::os::GetAbsolutePath(path.Mutf8());
    if (realPath.empty() || realPath == path.Mutf8()) {
        return path;
    }

    return UString(realPath, allocator_).View();
}

StringView ImportPathManager::AppendExtensionOrIndexFileIfOmitted(const StringView &basePath,
                                                                  const lexer::SourcePosition &srcPos) const
{
    std::string fixedPath = std::string(basePath.Utf8());
    char delim = pathDelimiter_.at(0);
    std::replace_if(
        fixedPath.begin(), fixedPath.end(), [&](auto &c) { return ((delim != c) && ((c == '\\') || (c == '/'))); },
        delim);
    auto path = UString(fixedPath, allocator_).View();
    StringView realPath = GetRealPath(path);
    if (ark::os::file::File::IsRegularFile(realPath.Mutf8())) {
        return realPath;
    }

    if (ark::os::file::File::IsDirectory(realPath.Mutf8())) {
        // Supported index files: keep this checking order
        std::array<std::string, SUPPORTED_INDEX_FILES_SIZE> supportedIndexFiles = {"index.sts", "index.ets",
                                                                                   "index.ts"};
        for (const auto &indexFile : supportedIndexFiles) {
            std::string indexFilePath = realPath.Mutf8() + pathDelimiter_.data() + indexFile;
            if (ark::os::file::File::IsRegularFile(indexFilePath)) {
                return GetRealPath(UString(indexFilePath, allocator_).View());
            }
        }

        return realPath;
    }

    // Supported extensions: keep this checking order
    std::array<std::string, SUPPORTED_EXTENSIONS_SIZE> supportedExtensions = {".sts",   ".d.sts", ".ets",
                                                                              ".d.ets", ".ts",    ".d.ts"};
    for (const auto &extension : supportedExtensions) {
        if (ark::os::file::File::IsRegularFile(path.Mutf8() + extension)) {
            return GetRealPath(UString(path.Mutf8().append(extension), allocator_).View());
        }
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(path.Mutf8()); it != dynamicPaths.cend()) {
        return path;
    }
    diagnosticEngine_.LogFatalError(
        program_, util::DiagnosticMessageParams {"Not supported path: ", util::StringView(path.Mutf8())}, srcPos);
    return "";
}

static std::string FormUnitName(std::string name)
{
    // this policy may change
    return name;
}

// Transform /a/b/c.sts to a.b.c
static std::string FormRelativeModuleName(std::string relPath)
{
    bool isMatched = false;
    // Supported extensions: keep this checking order
    std::array<std::string, ALLOWED_EXTENSIONS_SIZE> supportedExtensionsDesc = {".d.sts", ".sts", ".d.ets", ".ets",
                                                                                ".d.ts",  ".ts",  ".js",    ".abc"};
    for (const auto &ext : supportedExtensionsDesc) {
        if (relPath.size() >= ext.size() && relPath.compare(relPath.size() - ext.size(), ext.size(), ext) == 0) {
            relPath = relPath.substr(0, relPath.size() - ext.size());
            isMatched = true;
            break;
        }
    }
    if (relPath.empty()) {
        return "";
    }

    if (!isMatched) {
        ASSERT_PRINT(false, "Invalid relative filename: " + relPath);
    }
    while (relPath[0] == util::PATH_DELIMITER) {
        relPath = relPath.substr(1);
    }
    std::replace(relPath.begin(), relPath.end(), util::PATH_DELIMITER, '.');
    return relPath;
}

util::StringView ImportPathManager::FormModuleName(const util::Path &path, const lexer::SourcePosition &srcPos)
{
    if (!absoluteEtsPath_.empty()) {
        std::string filePath(path.GetAbsolutePath());
        if (filePath.rfind(absoluteEtsPath_, 0) != 0) {
            diagnosticEngine_.LogFatalError(
                program_,
                util::DiagnosticMessageParams {"Source file ", util::StringView(filePath), " outside ets-path"},
                srcPos);
            return "";
        }
        auto name = FormRelativeModuleName(filePath.substr(absoluteEtsPath_.size()));
        return util::UString(name, allocator_).View();
    }
    if (arktsConfig_->Package().empty()) {
        return path.GetFileName();
    }

    std::string const filePath(path.GetAbsolutePath());

    // should be implemented with a stable name -> path mapping list
    auto const tryFormModuleName = [filePath](std::string const &unitName,
                                              std::string const &unitPath) -> std::optional<std::string> {
        if (filePath.rfind(unitPath, 0) != 0) {
            return std::nullopt;
        }
        auto relativePath = FormRelativeModuleName(filePath.substr(unitPath.size()));
        return FormUnitName(unitName) + (relativePath.empty() ? "" : ("." + relativePath));
    };
    if (auto res = tryFormModuleName(arktsConfig_->Package(), arktsConfig_->BaseUrl()); res) {
        return util::UString(res.value(), allocator_).View();
    }
    if (!stdLib_.empty()) {
        if (auto res = tryFormModuleName("std", stdLib_ + pathDelimiter_.at(0) + "std"); res) {
            return util::UString(res.value(), allocator_).View();
        }
        if (auto res = tryFormModuleName("escompat", stdLib_ + pathDelimiter_.at(0) + "escompat"); res) {
            return util::UString(res.value(), allocator_).View();
        }
    }
    for (auto const &[unitName, unitPath] : arktsConfig_->Paths()) {
        if (auto res = tryFormModuleName(unitName, unitPath[0]); res) {
            return util::UString(res.value(), allocator_).View();
        }
    }
    for (auto const &[unitName, unitPath] : arktsConfig_->DynamicPaths()) {
        if (auto res = tryFormModuleName(unitName, unitName); res) {
            return util::UString(res.value(), allocator_).View();
        }
    }
    diagnosticEngine_.LogFatalError(
        program_, util::DiagnosticMessageParams {"Unresolved module name", util::StringView(filePath)}, srcPos);
    return "";
}

}  // namespace ark::es2panda::util
#undef USE_UNIX_SYSCALL
