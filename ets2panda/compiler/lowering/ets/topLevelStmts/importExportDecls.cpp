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
    varbinder_->SetDefaultImports(std::move(imports));
}

void ImportExportDecls::HandleGlobalStmts(const ArenaVector<parser::Program *> &programs)
{
    VerifySingleExportDefault(programs);
    VerifyTypeExports(programs);
    for (const auto &program : programs) {
        auto errorHandler = util::ErrorHandler(program);
        fieldMap_.clear();
        exportNameMap_.clear();
        exportedTypes_.clear();
        for (auto stmt : program->Ast()->Statements()) {
            stmt->Accept(this);
        }
        for (auto &[exportName, startLoc] : exportNameMap_) {
            const bool isType = exportedTypes_.find(exportName) != exportedTypes_.end();
            if ((fieldMap_.count(exportName) == 0 && !isType)) {
                auto errorStr = "Cannot find name '" + std::string(exportName.Utf8()) + "' to export.";
                errorHandler.ThrowSyntaxError(errorStr, startLoc);
            }
            if (!isType) {
                auto field = fieldMap_[exportName];
                field->AddModifier(ir::ModifierFlags::EXPORT);
            }
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
        if (exportDecl->IsExportedType()) {
            exportedTypes_.insert(local->Name());
        }
        exportNameMap_.emplace(local->Name(), local->Start());
    }
}

void HandleSimpleType(std::set<util::StringView> &exportedTypes, std::set<util::StringView> &exportedStatements,
                      ir::Statement *stmt, util::StringView name, parser::Program *program, lexer::SourcePosition pos)
{
    if (stmt->IsExported()) {
        exportedStatements.insert(name);
    }

    if (!stmt->IsExportedType()) {
        return;
    }

    if (exportedStatements.find(name) != exportedStatements.end()) {
        util::ErrorHandler::ThrowSyntaxError(
            program, "Name '" + name.Mutf8() + "' cannot be exported and type exported at the same time.", pos);
    }

    if (exportedTypes.find(name) != exportedTypes.end()) {
        util::ErrorHandler::ThrowSyntaxError(program, "Cannot export the same '" + name.Mutf8() + "' type twice.", pos);
    } else {
        exportedTypes.insert(name);
    }
}

void ImportExportDecls::VerifyTypeExports(const ArenaVector<parser::Program *> &programs)
{
    std::set<util::StringView> exportedTypes;
    std::set<util::StringView> exportedStatements;
    std::map<util::StringView, ir::AstNode *> typesMap;
    auto verifyType = [&exportedTypes, &exportedStatements, &typesMap](ir::Statement *stmt, parser::Program *program) {
        if (stmt->IsClassDeclaration()) {
            typesMap.insert({stmt->AsClassDeclaration()->Definition()->Ident()->Name(), stmt});
            return HandleSimpleType(exportedTypes, exportedStatements, stmt,
                                    stmt->AsClassDeclaration()->Definition()->Ident()->Name(), program, stmt->Start());
        }

        if (stmt->IsTSInterfaceDeclaration()) {
            typesMap.insert({stmt->AsTSInterfaceDeclaration()->Id()->Name(), stmt});
            return HandleSimpleType(exportedTypes, exportedStatements, stmt,
                                    stmt->AsTSInterfaceDeclaration()->Id()->Name(), program, stmt->Start());
        }

        if (stmt->IsTSTypeAliasDeclaration()) {
            typesMap.insert({stmt->AsTSTypeAliasDeclaration()->Id()->Name(), stmt});
            return HandleSimpleType(exportedTypes, exportedStatements, stmt,
                                    stmt->AsTSTypeAliasDeclaration()->Id()->Name(), program, stmt->Start());
        }

        if (!stmt->IsExportedType()) {
            return;
        }

        if (!stmt->IsExportNamedDeclaration()) {
            util::ErrorHandler::ThrowSyntaxError(program, "Can only type export class or interface!", stmt->Start());
        }

        for (auto spec : stmt->AsExportNamedDeclaration()->Specifiers()) {
            util::StringView name = spec->Local()->Name();

            auto element = typesMap.find(name);
            if (element == typesMap.end()) {
                util::ErrorHandler::ThrowSyntaxError(program, "Can only type export class or interface!",
                                                     spec->Local()->Start());
            }
            if (!element->second->IsExportedType()) {
                element->second->AddModifier(ir::ModifierFlags::EXPORT_TYPE);
            }
            HandleSimpleType(exportedTypes, exportedStatements, stmt, name, program, spec->Local()->Start());
        }
    };

    for (const auto &program : programs) {
        for (auto stmt : program->Ast()->Statements()) {
            verifyType(stmt, program);
        }
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
