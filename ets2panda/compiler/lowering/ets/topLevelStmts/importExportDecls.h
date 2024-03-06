/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#ifndef PANDA_IMPORTEXPORTDECLS_H
#define PANDA_IMPORTEXPORTDECLS_H

#include "util/errorHandler.h"
#include <parser/ETSparser.h>
#include "varbinder/ETSBinder.h"
#include "compiler/lowering/phase.h"
#include "ir/visitor/IterateAstVisitor.h"
#include "globalClassHandler.h"

namespace ark::es2panda::compiler {

class ImportExportDecls : ir::visitor::EmptyAstVisitor {
    static constexpr std::string_view DEFAULT_IMPORT_SOURCE_FILE = "<default_import>.ets";

    static std::string CreateDefaultImportSource(const std::vector<std::string> &paths)
    {
        std::string importStdlibFile;
        for (const auto &path : paths) {
            importStdlibFile += "import * from \"" + path + "\";";
        }
        return importStdlibFile;
    }

    const std::string defaultImportSource_ = CreateDefaultImportSource(util::Helpers::StdLib());

public:
    ImportExportDecls() = default;
    ImportExportDecls(varbinder::ETSBinder *varbinder, parser::ETSParser *parser)
        : varbinder_(varbinder), parser_(parser)
    {
    }

    /**
     * Add stdlib names to default imports
     */
    void ParseDefaultSources();

    /**
     * Verifies import errors, and add Exported flag to top level variables and methods
     * @param global_stmts program global statements
     */
    void HandleGlobalStmts(const ArenaVector<parser::Program *> &programs);

    void VerifySingleExportDefault(const ArenaVector<parser::Program *> &programs);

private:
    void VisitFunctionDeclaration(ir::FunctionDeclaration *funcDecl) override;
    void VisitVariableDeclaration(ir::VariableDeclaration *varDecl) override;
    void VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl) override;

private:
    varbinder::ETSBinder *varbinder_ {nullptr};
    std::map<util::StringView, ir::AstNode *> fieldMap_;
    std::map<util::StringView, lexer::SourcePosition> exportNameMap_;
    parser::ETSParser *parser_ {nullptr};
};
}  // namespace ark::es2panda::compiler

#endif  // PANDA_IMPORTEXPORTDECLS_H
