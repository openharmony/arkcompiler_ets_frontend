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

#include "pathHandler.h"
#include "libpandabase/os/filesystem.h"
#include <es2panda.h>

#if defined PANDA_TARGET_MOBILE
#define USE_UNIX_SYSCALL
#endif

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

static bool IsCompitableExtension(const std::string &extension)
{
    return extension == ".ets" || extension == ".ts";
}

void PathHandler::UnixWalkThroughDirectory([[maybe_unused]] const StringView &directory)
{
#ifdef USE_UNIX_SYSCALL
    DIR *dir = opendir(directory.Mutf8().c_str());
    if (dir == nullptr) {
        throw Error(ErrorType::GENERIC, "", "Cannot open folder: " + directory.Mutf8());
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

        std::string filePath = directory.Mutf8() + "/" + entry->d_name;
        StringView sourcePath = util::UString(filePath, allocator_).View();
        if (fileName == "Object.ets") {
            pathes_.insert({sourcePath, ParseInfo(allocator_, true)});
        } else {
            pathes_.insert({sourcePath, ParseInfo(allocator_)});
        }
    }

    closedir(dir);
#endif
}

StringView PathHandler::AddPath(const StringView &callerPath, const StringView &path)
{
    auto resolvedPath = ResolveSourcePath(callerPath, path);
    if (!ark::os::file::File::IsDirectory(resolvedPath.Mutf8())) {
        pathes_.insert({resolvedPath, ParseInfo(allocator_)});
        return resolvedPath;
    }

    pathes_.insert({resolvedPath, ParseInfo(allocator_)});

    bool hasIndexFile = false;
    std::string indexFile = resolvedPath.Mutf8() + pathDelimiter_.data() + "index.ets";
    if (ark::os::file::File::IsRegularFile(indexFile)) {
        hasIndexFile = true;
    } else {
        indexFile = resolvedPath.Mutf8() + pathDelimiter_.data() + "index.ts";
        if (ark::os::file::File::IsRegularFile(indexFile)) {
            hasIndexFile = true;
        }
    }

    if (hasIndexFile) {
        StringView indexFilePath = util::UString(indexFile, allocator_).View();
        pathes_.insert({indexFilePath, ParseInfo(allocator_)});
        return indexFilePath;
    }

#ifdef USE_UNIX_SYSCALL
    UnixWalkThroughDirectory(resolvedPath);
#else
    for (auto const &entry : fs::directory_iterator(resolvedPath.Mutf8())) {
        if (!fs::is_regular_file(entry) || !IsCompitableExtension(entry.path().extension().string())) {
            continue;
        }

        StringView sourcePath = util::UString(entry.path().string(), allocator_).View();
        if (entry.path().filename().string() == "Object.ets") {
            pathes_.insert({sourcePath, ParseInfo(allocator_, true)});
        } else {
            pathes_.insert({sourcePath, ParseInfo(allocator_)});
        }
    }
#endif
    return resolvedPath;
}

void PathHandler::CollectDefaultSources(const std::vector<std::string> &stdlib)
{
    for (auto const &path : stdlib) {
        StringView callerPath = util::UString(allocator_).View();
        StringView stdlibPath = ResolveSourcePath(callerPath, util::UString(path, allocator_).View());
        pathes_.insert({stdlibPath, ParseInfo(allocator_)});
#ifdef USE_UNIX_SYSCALL
        UnixWalkThroughDirectory(stdlibPath);
#else
        for (auto const &entry : fs::directory_iterator(stdlibPath.Mutf8())) {
            if (!fs::is_regular_file(entry) || !IsCompitableExtension(entry.path().extension().string())) {
                continue;
            }

            // NOTE(rsipka): seems to me a duplicated check, since it was already in pathes_
            StringView sourcePath = util::UString(entry.path().string(), allocator_).View();
            if (entry.path().filename().string() == "Object.ets") {
                pathes_.insert({sourcePath, ParseInfo(allocator_, true)});
            } else {
                pathes_.insert({sourcePath, ParseInfo(allocator_)});
            }
        }
#endif
    }
}

ArenaVector<util::StringView> PathHandler::GetParseList() const
{
    ArenaVector<util::StringView> parseableSources(allocator_->Adapter());
    for (const auto [path, info] : pathes_) {
        if (!info.IsParsed() && !ark::os::file::File::IsDirectory(path.Mutf8())) {
            // NOTE(rsipka): it should be handled in a better way
            if (info.IsObjectfile()) {
                parseableSources.emplace(parseableSources.begin(), path);
            } else {
                parseableSources.emplace_back(path);
            }
        }
    }
    return parseableSources;
}

bool PathHandler::IsRelativePath(const StringView &path) const
{
    std::string currentDirReference = ".";
    std::string parentDirReference = "..";

    currentDirReference.append(pathDelimiter_);
    parentDirReference.append(pathDelimiter_);

    return ((path.Mutf8().find(currentDirReference) == 0) || (path.Mutf8().find(parentDirReference) == 0));
}

StringView PathHandler::GetParentFolder(const StringView &path) const
{
    const size_t pos = path.Mutf8().find_last_of(pathDelimiter_);
    if (pos != std::string::npos) {
        return util::UString(path.Mutf8().substr(0, pos + 1), allocator_).View();
    }

    return util::UString(allocator_).View();
}

StringView PathHandler::AppendExtension(const StringView &path) const
{
    StringView realPath = GetRealPath(path);
    if (ark::os::file::File::IsDirectory(realPath.Mutf8()) || ark::os::file::File::IsRegularFile(realPath.Mutf8())) {
        return realPath;
    }

    std::string importExtension = ".ets";
    if (!ark::os::file::File::IsRegularFile(path.Mutf8() + importExtension)) {
        importExtension = ".ts";
        if (!ark::os::file::File::IsRegularFile(path.Mutf8() + importExtension)) {
            // NOTE(rsipka): this check should be eliminated
            auto &dynamicPaths = arktsConfig_->DynamicPaths();
            if (auto it = dynamicPaths.find(path.Mutf8()); it != dynamicPaths.cend()) {
                return path;
            }

            throw Error(ErrorType::GENERIC, "", "Not supported path: " + path.Mutf8());
        }
    }

    return GetRealPath(util::UString(path.Mutf8().append(importExtension), allocator_).View());
}

StringView PathHandler::GetRealPath(const StringView &path) const
{
    const std::string realPath = ark::os::GetAbsolutePath(path.Mutf8());
    if (realPath.empty()) {
        return path;
    }

    if (realPath == path.Mutf8()) {
        return path;
    }

    return util::UString(realPath, allocator_).View();
}

StringView PathHandler::ResolveSourcePath(const StringView &callerPath, const StringView &path) const
{
    if (IsRelativePath(path)) {
        const size_t pos = callerPath.Mutf8().find_last_of(pathDelimiter_);
        ASSERT(pos != std::string::npos);
        auto parentFolder = callerPath.Mutf8().substr(0, pos);
        auto resolvedPath = util::UString(parentFolder, allocator_);
        resolvedPath.Append(pathDelimiter_);
        resolvedPath.Append(path.Mutf8());
        return AppendExtension(resolvedPath.View());
    }

    std::string baseUrl;
    if (path.Mutf8().find('/') == 0) {
        baseUrl = arktsConfig_->BaseUrl();
        baseUrl.append(path.Mutf8(), 0, path.Mutf8().length());
        return AppendExtension(util::UString(baseUrl, allocator_).View());
    }

    auto &dynamicPaths = arktsConfig_->DynamicPaths();
    if (auto it = dynamicPaths.find(path.Mutf8()); it != dynamicPaths.cend() && !it->second.HasDecl()) {
        return AppendExtension(path);
    }

    const size_t pos = path.Mutf8().find(pathDelimiter_);
    bool containsDelim = (pos != std::string::npos);
    auto rootPart = containsDelim ? path.Substr(0, pos) : path;
    if (rootPart.Is("std") && !stdLib_.empty()) {  // Get std path from CLI if provided
        baseUrl = stdLib_ + "/std";
    } else if (rootPart.Is("escompat") && !stdLib_.empty()) {  // Get escompat path from CLI if provided
        baseUrl = stdLib_ + "/escompat";
    } else {
        ASSERT(arktsConfig_ != nullptr);
        auto resolvedPath = arktsConfig_->ResolvePath(path.Mutf8());
        if (!resolvedPath) {
            throw Error(ErrorType::GENERIC, "",
                        "Can't find prefix for '" + path.Mutf8() + "' in " + arktsConfig_->ConfigPath());
        }

        return AppendExtension(util::UString(resolvedPath.value(), allocator_).View());
    }

    if (containsDelim) {
        baseUrl.append(1, pathDelimiter_.at(0));
        baseUrl.append(path.Mutf8(), rootPart.Mutf8().length() + 1, path.Mutf8().length());
    }

    return util::UString(baseUrl, allocator_).View();
}

std::vector<std::string> &PathHandler::StdLib()
{
    static std::vector<std::string> stdlib {"std/core",       "std/math",  "std/containers",        "std/time",
                                            "std/interop/js", "std/debug", "std/debug/concurrency", "escompat"};
    return stdlib;
}

}  // namespace ark::es2panda::util
#undef USE_UNIX_SYSCALL
