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

#include "compiler/lowering/ets/topLevelStmts/importExportDecls.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "util/importPathManager.h"

namespace ark::es2panda::compiler {

void ImportExportDecls::ParseDefaultSources()
{
    auto imports = parser_->ParseDefaultSources(DEFAULT_IMPORT_SOURCE_FILE, defaultImportSource_);
    varbinder_->SetModuleList(parser_->ModuleList());
    varbinder_->SetDefaultImports(std::move(imports));
}

void ImportExportDecls::HandleGlobalStmts(const ArenaVector<parser::Program *> &programs)
{
    VerifySingleExportDefault(programs);
    for (const auto &program : programs) {
        auto errorHandler = util::ErrorHandler(program);
        fieldMap_.clear();
        exportNameMap_.clear();
        for (auto stmt : program->Ast()->Statements()) {
            stmt->Accept(this);
        }
        for (auto &[exportName, startLoc] : exportNameMap_) {
            if (fieldMap_.count(exportName) == 0) {
                auto errorStr = "Cannot find name '" + std::string(exportName.Utf8()) + "' to export.";
                errorHandler.ThrowSyntaxError(errorStr, startLoc);
            }
            auto field = fieldMap_[exportName];
            field->AddModifier(ir::ModifierFlags::EXPORT);
        }
    }
}

void ImportExportDecls::VisitFunctionDeclaration(ir::FunctionDeclaration *funcDecl)
{
    auto id = funcDecl->Function()->Id();
    fieldMap_.emplace(id->Name(), funcDecl->Function());
}

void ImportExportDecls::VisitVariableDeclaration(ir::VariableDeclaration *varDecl)
{
    for (const auto &decl : varDecl->Declarators()) {
        auto id = decl->Id()->AsIdentifier();
        fieldMap_.emplace(id->Name(), varDecl);
    }
}

void ImportExportDecls::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl)
{
    for (auto spec : exportDecl->Specifiers()) {
        auto local = spec->Local();
        exportNameMap_.emplace(local->Name(), local->Start());
    }
}

void ImportExportDecls::VerifySingleExportDefault(const ArenaVector<parser::Program *> &programs)
{
    bool metDefaultExport = false;
    auto verifyDefault = [&metDefaultExport](ir::Statement *stmt, parser::Program *program) {
        if ((stmt->Modifiers() & ir::ModifierFlags::DEFAULT_EXPORT) == 0) {
            return;
        }
        if (metDefaultExport) {
            util::ErrorHandler::ThrowSyntaxError(program, "Only one default export is allowed in a module",
                                                 stmt->Start());
        }
        metDefaultExport = true;
    };
    for (const auto &program : programs) {
        for (auto stmt : program->Ast()->Statements()) {
            verifyDefault(stmt, program);
        }
        metDefaultExport = false;
    }
}

}  // namespace ark::es2panda::compiler
