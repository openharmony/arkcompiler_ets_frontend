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

#ifndef ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H
#define ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H

#if defined PANDA_TARGET_MOBILE
#define USE_UNIX_SYSCALL
#endif

#include "util/arktsconfig.h"
#include "util/ustring.h"
#include "util/enumbitops.h"
#include "util/path.h"
#include "util/options.h"

namespace ark::es2panda::util {
namespace gen::extension {
enum Enum : size_t;
}  // namespace gen::extension

using ENUMBITOPS_OPERATORS;

enum class ImportFlags {
    NONE = 0U,
    DEFAULT_IMPORT = 1U << 1U,
    IMPLICIT_PACKAGE_IMPORT = 1U << 2U,
};
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
        bool isImplicitPackageImported = false;
    };

    ImportPathManager(ark::ArenaAllocator *allocator, const util::Options &options,
                      util::DiagnosticEngine &diagnosticEngine)
        : allocator_(allocator),
          arktsConfig_(options.ArkTSConfig()),
          absoluteEtsPath_(
              options.GetEtsPath().empty() ? "" : util::Path(options.GetEtsPath(), allocator_).GetAbsolutePath()),
          stdLib_(options.GetStdlib()),
          parseList_(allocator->Adapter()),
          diagnosticEngine_ {diagnosticEngine}
    {
    }

    NO_COPY_SEMANTIC(ImportPathManager);
    NO_MOVE_SEMANTIC(ImportPathManager);
    ImportPathManager() = delete;
    ~ImportPathManager() = default;

    [[nodiscard]] const ArenaVector<ParseInfo> &ParseList() const
    {
        return parseList_;
    }

    util::StringView ResolvePath(const StringView &currentModulePath, const StringView &importPath,
                                 const lexer::SourcePosition &srcPos) const;
    void AddToParseList(const StringView &resolvedPath, ImportFlags importFlags, const lexer::SourcePosition &srcPos);
    ImportData GetImportData(const util::StringView &path, util::gen::extension::Enum extension) const;
    void MarkAsParsed(const StringView &path);

    util::StringView FormModuleNameSolelyByAbsolutePath(const util::Path &path, const lexer::SourcePosition &srcPos);
    util::StringView FormModuleName(const util::Path &path, const lexer::SourcePosition &srcPos);

private:
    bool IsRelativePath(const StringView &path) const;
    StringView ResolveAbsolutePath(const StringView &importPath, const lexer::SourcePosition &srcPos) const;
    StringView GetRealPath(const StringView &path) const;
    StringView AppendExtensionOrIndexFileIfOmitted(const StringView &basePath,
                                                   const lexer::SourcePosition &srcPos) const;
#ifdef USE_UNIX_SYSCALL
    void UnixWalkThroughDirectoryAndAddToParseList(const StringView &directoryPath, ImportFlags importFlags,
                                                   const lexer::SourcePosition &srcPos);
#endif

    ark::ArenaAllocator *const allocator_;
    std::shared_ptr<ArkTsConfig> const arktsConfig_;
    std::string absoluteEtsPath_;
    std::string stdLib_;
    ArenaVector<ParseInfo> parseList_;
    util::DiagnosticEngine &diagnosticEngine_;
    std::string_view pathDelimiter_ {ark::os::file::File::GetPathDelim()};
};

}  // namespace ark::es2panda::util

namespace enumbitops {

template <>
struct IsAllowedType<ark::es2panda::util::ImportFlags> : std::true_type {
};
}  // namespace enumbitops

#endif  // ES2PANDA_UTIL_IMPORT_PATH_MANAGER_H
