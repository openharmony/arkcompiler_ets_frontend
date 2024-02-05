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

#ifndef ES2PANDA_UTIL_PATH_HANDLER_H
#define ES2PANDA_UTIL_PATH_HANDLER_H

#include "util/arktsconfig.h"
#include "util/ustring.h"
#include <string>
#include <vector>

namespace ark::es2panda::util {

class ParseInfo {
public:
    explicit ParseInfo(ark::ArenaAllocator *allocator, bool isObjectFile = false)
        : isObjectFile_(isObjectFile), isParsed_(false), moduleName_(allocator), isPackageModule_(false)
    {
    }

    ParseInfo() = delete;

    bool IsParsed() const
    {
        return isParsed_;
    }

    void MarkAsParsed()
    {
        isParsed_ = true;
    }

    StringView ModuleName() const
    {
        return moduleName_.View();
    }

    bool IsObjectfile() const
    {
        return isObjectFile_;
    }

    bool IsPackageModule() const
    {
        return isPackageModule_;
    }

    void SetModuleName(const StringView &moduleName, bool isPackageModule)
    {
        if (moduleName_.View().Empty()) {
            moduleName_.Append(moduleName);
            isPackageModule_ = isPackageModule;
        }
    }

private:
    bool isObjectFile_;
    bool isParsed_;
    util::UString moduleName_;
    bool isPackageModule_;
};

class PathHandler {
public:
    explicit PathHandler(ark::ArenaAllocator *allocator) : allocator_(allocator), pathes_(allocator->Adapter()) {}

    StringView AddPath(const StringView &callerPath, const StringView &path);
    std::vector<std::string> GetParseList() const;
    void CollectDefaultSources();

    void MarkAsParsed(const StringView &path)
    {
        auto it = pathes_.find(path);
        if (it != pathes_.end()) {
            it->second.MarkAsParsed();
        }
    }

    bool IsParsed(const std::string &path)
    {
        auto pathView = util::UString(path, allocator_).View();
        auto it = pathes_.find(pathView);
        if (it != pathes_.end()) {
            return it->second.IsParsed();
        }

        return false;
    }

    void MarkAsParsed(const std::string &path)
    {
        auto pathView = util::UString(path, allocator_).View();
        auto it = pathes_.find(pathView);
        if (it != pathes_.end()) {
            it->second.MarkAsParsed();
        }
    }

    void SetModuleName(const StringView &path, const StringView &moduleName, bool isPackageModule)
    {
        auto it = pathes_.find(path);
        if (it != pathes_.end()) {
            it->second.SetModuleName(moduleName, isPackageModule);
        }
    }

    void SetStdLib(const std::string &stdLib)
    {
        stdLib_ = stdLib;
    }

    void SetArkTsConfig(std::shared_ptr<ArkTsConfig> arktsConfig)
    {
        arktsConfig_ = std::move(arktsConfig);
    }

    ArenaUnorderedMap<StringView, ParseInfo> &GetPathes()
    {
        return pathes_;
    }

    NO_COPY_SEMANTIC(PathHandler);
    NO_MOVE_SEMANTIC(PathHandler);
    PathHandler() = delete;
    ~PathHandler() = default;

private:
    bool IsRelativePath(const StringView &path) const;
    StringView GetParentFolder(const StringView &path) const;
    StringView ResolveSourcePath(const StringView &callerPath, const StringView &path) const;
    StringView AppendExtension(const StringView &path) const;
    StringView GetRealPath(const StringView &path) const;
    void UnixWalkThroughDirectory(const StringView &directory);

    ArenaAllocator *allocator_;
    ArenaUnorderedMap<StringView, ParseInfo> pathes_;
    std::string stdLib_ = {};
    std::shared_ptr<ArkTsConfig> arktsConfig_ = {nullptr};
    std::string_view pathDelimiter_ = ark::os::file::File::GetPathDelim();
};

}  // namespace ark::es2panda::util

#endif  // ES2PANDA_UTIL_PATH_HANDLER_H
