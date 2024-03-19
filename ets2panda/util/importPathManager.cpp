/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <libpandabase/os/filesystem.h>

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

constexpr size_t SUPPORTED_INDEX_FILES_SIZE = 2;
constexpr size_t SUPPORTED_EXTENSIONS_SIZE = 2;

static bool IsCompitableExtension(const std::string &extension)
{
    return extension == ".ets" || extension == ".ts";
}

StringView ImportPathManager::ResolvePath(const StringView &currentModulePath, const StringView &importPath) const
{
    if (importPath.Empty()) {
        throw Error(ErrorType::GENERIC, "", "Import path cannot be empty");
    }

    if (IsRelativePath(importPath)) {
        const size_t pos = currentModulePath.Mutf8().find_last_of(pathDelimiter_);
        ASSERT(pos != std::string::npos);

        auto currentDirectory = currentModulePath.Mutf8().substr(0, pos);
        auto resolvedPath = UString(currentDirectory, allocator_);
        resolvedPath.Append(pathDelimiter_);
        resolvedPath.Append(importPath.Mutf8());

        return AppendExtensionOrIndexFileIfOmitted(resolvedPath.View());
    }

    std::string baseUrl;
    if (importPath.Mutf8()[0] == pathDelimiter_.at(0)) {
        baseUrl = arktsConfig_->BaseUrl();
        baseUrl.append(importPath.Mutf8(), 0, importPath.Mutf8().length());
        return AppendExtensionOrIndexFileIfOmitted(UString(baseUrl, allocator_).View());
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(importPath.Mutf8()); it != dynamicPaths.cend() && !it->second.HasDecl()) {
        return AppendExtensionOrIndexFileIfOmitted(importPath);
    }

    const size_t pos = importPath.Mutf8().find(pathDelimiter_);
    bool containsDelim = (pos != std::string::npos);
    auto rootPart = containsDelim ? importPath.Substr(0, pos) : importPath;
    if (!stdLib_.empty() &&
        (rootPart.Is("std") || rootPart.Is("escompat"))) {  // Get std or escompat path from CLI if provided
        baseUrl = stdLib_ + pathDelimiter_.at(0) + rootPart.Mutf8();
    } else {
        ASSERT(arktsConfig_ != nullptr);
        auto resolvedPath = arktsConfig_->ResolvePath(importPath.Mutf8());
        if (!resolvedPath) {
            throw Error(ErrorType::GENERIC, "",
                        "Can't find prefix for '" + importPath.Mutf8() + "' in " + arktsConfig_->ConfigPath());
        }

        return AppendExtensionOrIndexFileIfOmitted(UString(resolvedPath.value(), allocator_).View());
    }

    if (containsDelim) {
        baseUrl.append(1, pathDelimiter_.at(0));
        baseUrl.append(importPath.Mutf8(), rootPart.Mutf8().length() + 1, importPath.Mutf8().length());
    }

    return UString(baseUrl, allocator_).View();
}

#ifdef USE_UNIX_SYSCALL
void ImportPathManager::UnixWalkThroughDirectoryAndAddToParseList(const StringView &directoryPath, bool isDefaultImport)
{
    DIR *dir = opendir(directoryPath.Mutf8().c_str());
    if (dir == nullptr) {
        throw Error(ErrorType::GENERIC, "", "Cannot open folder: " + directoryPath.Mutf8());
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        std::string fileName = entry->d_name;
        std::string::size_type pos = fileName.find_last_of('.');
        if (pos == std::string::npos || !IsCompitableExtension(fileName.substr(pos))) {
            continue;
        }

        std::string filePath = directoryPath.Mutf8() + "/" + entry->d_name;
        AddToParseList(UString(filePath, allocator_).View(), isDefaultImport);
    }

    closedir(dir);
    return;
}
#endif

void ImportPathManager::AddToParseList(const StringView &resolvedPath, bool isDefaultImport)
{
    if (ark::os::file::File::IsDirectory(resolvedPath.Mutf8())) {
#ifdef USE_UNIX_SYSCALL
        UnixWalkThroughDirectoryAndAddToParseList(resolvedPath, isDefaultImport);
#else
        for (auto const &entry : fs::directory_iterator(resolvedPath.Mutf8())) {
            if (!fs::is_regular_file(entry) || !IsCompitableExtension(entry.path().extension().string())) {
                continue;
            }

            AddToParseList(UString(entry.path().string(), allocator_).View(), isDefaultImport);
        }
        return;
#endif
    }

    for (const auto &parseInfo : parseList_) {
        if (parseInfo.sourcePath == resolvedPath) {
            return;
        }
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(resolvedPath.Mutf8()); it != dynamicPaths.cend()) {
        parseList_.emplace(parseList_.begin(), ParseInfo {resolvedPath, false});
        return;
    }

    if (!ark::os::file::File::IsRegularFile(resolvedPath.Mutf8())) {
        throw Error(ErrorType::GENERIC, "", "Not an available source path: " + resolvedPath.Mutf8());
    }

    if (isDefaultImport) {
        int position = resolvedPath.Mutf8().find_last_of(pathDelimiter_);
        if (resolvedPath.Substr(position + 1, resolvedPath.Length()).Is("Object.ets")) {
            parseList_.emplace(parseList_.begin(), ParseInfo {resolvedPath, false});
            return;
        }
    }

    parseList_.emplace_back(ParseInfo {resolvedPath, false});
}

const ArenaVector<ImportPathManager::ParseInfo> &ImportPathManager::ParseList()
{
    return parseList_;
}

ImportPathManager::ImportData ImportPathManager::GetImportData(const util::StringView &path,
                                                               const ScriptExtension &extension) const
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

void ImportPathManager::InsertModuleInfo(const util::StringView &path,
                                         const util::ImportPathManager::ModuleInfo &moduleInfo)
{
    moduleList_.insert({path, moduleInfo});
}

const ArenaMap<StringView, ImportPathManager::ModuleInfo> &ImportPathManager::ModuleList() const
{
    return moduleList_;
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
    std::string currentDirReference = ".";
    std::string parentDirReference = "..";

    currentDirReference.append(pathDelimiter_);
    parentDirReference.append(pathDelimiter_);

    return ((path.Mutf8().find(currentDirReference) == 0) || (path.Mutf8().find(parentDirReference) == 0));
}

StringView ImportPathManager::GetRealPath(const StringView &path) const
{
    const std::string realPath = ark::os::GetAbsolutePath(path.Mutf8());
    if (realPath.empty() || realPath == path.Mutf8()) {
        return path;
    }

    return UString(realPath, allocator_).View();
}

StringView ImportPathManager::AppendExtensionOrIndexFileIfOmitted(const StringView &path) const
{
    StringView realPath = GetRealPath(path);
    if (ark::os::file::File::IsRegularFile(realPath.Mutf8())) {
        return realPath;
    }

    if (ark::os::file::File::IsDirectory(realPath.Mutf8())) {
        // Supported index files: keep this checking order
        std::array<std::string, SUPPORTED_INDEX_FILES_SIZE> supportedIndexFiles = {"index.ets", "index.ts"};
        for (const auto &indexFile : supportedIndexFiles) {
            std::string indexFilePath = realPath.Mutf8() + pathDelimiter_.data() + indexFile;
            if (ark::os::file::File::IsRegularFile(indexFilePath)) {
                return GetRealPath(UString(indexFilePath, allocator_).View());
            }
        }

        return realPath;
    }

    // Supported extensions: keep this checking order
    std::array<std::string, SUPPORTED_EXTENSIONS_SIZE> supportedExtensions = {".ets", ".ts"};

    for (const auto &extension : supportedExtensions) {
        if (ark::os::file::File::IsRegularFile(path.Mutf8() + extension)) {
            return GetRealPath(UString(path.Mutf8().append(extension), allocator_).View());
        }
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(path.Mutf8()); it != dynamicPaths.cend()) {
        return path;
    }

    throw Error(ErrorType::GENERIC, "", "Not supported path: " + path.Mutf8());
}

}  // namespace ark::es2panda::util
#undef USE_UNIX_SYSCALL
