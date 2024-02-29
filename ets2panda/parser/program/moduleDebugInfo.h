/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ES2PANDA_PARSER_PROGRAM_MODULE_DEBUG_INFO_H
#define ES2PANDA_PARSER_PROGRAM_MODULE_DEBUG_INFO_H

#include "libpandabase/mem/arena_allocator.h"
#include "macros.h"

#include "util/ustring.h"

namespace ark::es2panda::ir {
class AstNode;
class ETSImportDeclaration;
class ETSReExportDeclaration;
class ExportNamedDeclaration;
class ExportSpecifier;
class Statement;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {
// Must safe all imports, even unused.
class ModuleDebugInfo {
public:
    explicit ModuleDebugInfo(ArenaAllocator *allocator);

    NO_COPY_SEMANTIC(ModuleDebugInfo);
    DEFAULT_MOVE_SEMANTIC(ModuleDebugInfo);

    virtual ~ModuleDebugInfo() noexcept = default;

    void AddImport(util::StringView modulePath, const ir::AstNode *specifier);
    void AddImports(ir::ETSImportDeclaration *importDecl);

    void AddExport(ir::Statement *stmt);
    void AddExports(const ir::ExportNamedDeclaration *exportDecl);
    void AddExports(const ir::ETSReExportDeclaration *reExportDecl);

    template <typename F>
    void EnumerateImports(F &&cb) const
    {
        for (const auto &[modulePath, alias, entity] : imports_) {
            cb(modulePath, alias, entity);
        }
    }

    template <typename F>
    void EnumerateExports(F &&cb) const
    {
        for (const auto &[modulePath, alias, entity] : exports_) {
            cb(modulePath, alias, entity);
        }
    }

private:
    void AddExport(util::StringView from, const ir::AstNode *stmt);

private:
    struct ImportInfo {
        // TODO: may require source-code-path rather than host system absolute path.
        util::StringView modulePath;
        util::StringView alias;
        util::StringView entity;

        ImportInfo(util::StringView m, util::StringView a, util::StringView e) : modulePath(m), alias(a), entity(e) {}
    };

    ArenaVector<ImportInfo> imports_;
    ArenaVector<ImportInfo> exports_;
};
}  // namespace ark::es2panda::parser

#endif /* ES2PANDA_PARSER_PROGRAM_MODULE_DEBUG_INFO_H */
