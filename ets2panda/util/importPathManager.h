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

#ifndef ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H
#define ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H

#if defined PANDA_TARGET_MOBILE
#define USE_UNIX_SYSCALL
#endif

#include "util/arktsconfig.h"
#include "util/ustring.h"
#include "es2panda.h"

namespace ark::es2panda::util {

class ImportPathManager {
public:
    struct ImportData {
        Language lang;
        std::string module;
        bool hasDecl;
    };

    struct ParseInfo {
        StringView sourcePath;
        bool isParsed;
    };

    struct ModuleInfo {
        StringView moduleName;
        bool isPackageModule;
    };

    ImportPathManager(ark::ArenaAllocator *allocator, std::shared_ptr<ArkTsConfig> arktsConfig, std::string stdLib)
        : allocator_(allocator),
          arktsConfig_(std::move(arktsConfig)),
          stdLib_(std::move(stdLib)),
          parseList_(allocator->Adapter()),
          moduleList_(allocator->Adapter())
    {
    }

    NO_COPY_SEMANTIC(ImportPathManager);
    NO_MOVE_SEMANTIC(ImportPathManager);
    ImportPathManager() = delete;
    ~ImportPathManager() = default;

    StringView ResolvePath(const StringView &currentModulePath, const StringView &importPath) const;
    void AddToParseList(const StringView &path, bool isDefaultImport);
    const ArenaVector<ParseInfo> &ParseList();
    ImportData GetImportData(const util::StringView &path, const ScriptExtension &extension) const;
    void InsertModuleInfo(const util::StringView &path, const ModuleInfo &moduleInfo);
    const ArenaMap<StringView, ModuleInfo> &ModuleList() const;
    void MarkAsParsed(const StringView &path);

private:
    bool IsRelativePath(const StringView &path) const;
    StringView GetRealPath(const StringView &path) const;
    StringView AppendExtensionOrIndexFileIfOmitted(const StringView &path) const;
#ifdef USE_UNIX_SYSCALL
    void UnixWalkThroughDirectoryAndAddToParseList(const StringView &directoryPath, bool isDefaultImport);
#endif

    ArenaAllocator *allocator_ {nullptr};
    std::shared_ptr<ArkTsConfig> arktsConfig_ {nullptr};
    std::string stdLib_ {};
    ArenaVector<ParseInfo> parseList_;
    ArenaMap<StringView, ModuleInfo> moduleList_;
    std::string_view pathDelimiter_ {ark::os::file::File::GetPathDelim()};
};

}  // namespace ark::es2panda::util

#endif  // ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H
