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
        fieldMap_.clear();
        exportNameMap_.clear();
        exportedTypes_.clear();
        for (auto stmt : program->Ast()->Statements()) {
            stmt->Accept(this);
            if (stmt->IsExportNamedDeclaration()) {
                PopulateAliasMap(stmt->AsExportNamedDeclaration(), program->SourceFilePath());
            }
        }
        for (auto const &[exportName, startLoc] : exportNameMap_) {
            const bool isType = exportedTypes_.find(exportName) != exportedTypes_.end();
            util::StringView originalName = varbinder_->FindNameInAliasMap(program->SourceFilePath(), exportName);

            ASSERT(!originalName.Empty());

            if (fieldMap_.find(originalName) == fieldMap_.end() && !isType) {
                util::ErrorHandler::ThrowSyntaxError(
                    varbinder_->Program(), "Cannot find name '" + originalName.Mutf8() + "' to export", startLoc);
            }
            if (!isType) {
                HandleSelectiveExportWithAlias(originalName, exportName, startLoc);
            }
        }
    }
}

void ImportExportDecls::PopulateAliasMap(const ir::ExportNamedDeclaration *decl, const util::StringView &path)
{
    for (auto spec : decl->Specifiers()) {
        if (!varbinder_->AddSelectiveExportAlias(path, spec->Local()->Name(), spec->Exported()->Name())) {
            util::ErrorHandler::ThrowSyntaxError(varbinder_->Program(),
                                                 "The given name '" + spec->Local()->Name().Mutf8() +
                                                     "' is already used in another export",
                                                 spec->Start());
        }
    }
}

void ImportExportDecls::HandleSelectiveExportWithAlias(util::StringView originalFieldName, util::StringView exportName,
                                                       lexer::SourcePosition startLoc)
{
    ir::AstNode *field = fieldMap_.find(originalFieldName)->second;
    if ((field->Modifiers() & ir::ModifierFlags::EXPORTED) != 0) {
        // Note (oeotvos) Needs to be discussed, whether we would like to allow exporting the same program
        // element using its original name and also an alias, like: export {test_func, test_func as foo}.
        util::ErrorHandler::ThrowSyntaxError(
            varbinder_->Program(), "Cannot export '" + originalFieldName.Mutf8() + "', it was already exported",
            startLoc);
    }

    field->AddModifier(ir::ModifierFlags::EXPORT);

    if (exportName != originalFieldName) {
        if (auto declItem = fieldMap_.find(exportName); declItem != fieldMap_.end()) {
            // Checking for the alias might be unnecessary, because explicit exports cannot
            // have an alias yet.
            if (((declItem->second->Modifiers() & ir::ModifierFlags::EXPORTED) != 0) &&
                !declItem->second->HasExportAlias()) {
                util::ErrorHandler::ThrowSyntaxError(
                    varbinder_->Program(),
                    "The given name '" + exportName.Mutf8() + "' is already used in another export", startLoc);
            }
        }
        field->AddAstNodeFlags(ir::AstNodeFlags::HAS_EXPORT_ALIAS);
    }
}

void ImportExportDecls::VisitFunctionDeclaration(ir::FunctionDeclaration *funcDecl)
{
    fieldMap_.emplace(funcDecl->Function()->Id()->Name(), funcDecl->Function());
}

void ImportExportDecls::VisitVariableDeclaration(ir::VariableDeclaration *varDecl)
{
    for (const auto &decl : varDecl->Declarators()) {
        fieldMap_.emplace(decl->Id()->AsIdentifier()->Name(), varDecl);
    }
}

void ImportExportDecls::VisitClassDeclaration(ir::ClassDeclaration *classDecl)
{
    fieldMap_.emplace(classDecl->Definition()->Ident()->Name(), classDecl);
}

void ImportExportDecls::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAliasDecl)
{
    fieldMap_.emplace(typeAliasDecl->Id()->Name(), typeAliasDecl);
}

void ImportExportDecls::VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interfaceDecl)
{
    fieldMap_.emplace(interfaceDecl->Id()->Name(), interfaceDecl);
}

void ImportExportDecls::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl)
{
    for (auto spec : exportDecl->Specifiers()) {
        auto local = spec->Local();
        if (exportDecl->IsExportedType()) {
            exportedTypes_.insert(local->Name());
        }
        if (!exportNameMap_.emplace(local->Name(), local->Start()).second) {
            util::ErrorHandler::ThrowSyntaxError(
                varbinder_->Program(),
                "The given name '" + local->Name().Mutf8() + "' is already used in another export", local->Start());
        }
    }
}

void ImportExportDecls::HandleSimpleType(std::set<util::StringView> &exportedTypes,
                                         std::set<util::StringView> &exportedStatements, ir::Statement *stmt,
                                         util::StringView name, parser::Program *program, lexer::SourcePosition pos)
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

    for (const auto &program : programs) {
        for (auto stmt : program->Ast()->Statements()) {
            VerifyType(stmt, program, exportedTypes, exportedStatements, typesMap);
        }
    }
}

void ImportExportDecls::VerifyType(ir::Statement *stmt, parser::Program *program,
                                   std::set<util::StringView> &exportedTypes,
                                   std::set<util::StringView> &exportedStatements,
                                   std::map<util::StringView, ir::AstNode *> &typesMap)
{
    if (stmt->IsClassDeclaration()) {
        typesMap.insert({stmt->AsClassDeclaration()->Definition()->Ident()->Name(), stmt});
        return HandleSimpleType(exportedTypes, exportedStatements, stmt,
                                stmt->AsClassDeclaration()->Definition()->Ident()->Name(), program, stmt->Start());
    }

    if (stmt->IsTSInterfaceDeclaration()) {
        typesMap.insert({stmt->AsTSInterfaceDeclaration()->Id()->Name(), stmt});
        return HandleSimpleType(exportedTypes, exportedStatements, stmt, stmt->AsTSInterfaceDeclaration()->Id()->Name(),
                                program, stmt->Start());
    }

    if (stmt->IsTSTypeAliasDeclaration()) {
        typesMap.insert({stmt->AsTSTypeAliasDeclaration()->Id()->Name(), stmt});
        return HandleSimpleType(exportedTypes, exportedStatements, stmt, stmt->AsTSTypeAliasDeclaration()->Id()->Name(),
                                program, stmt->Start());
    }

    if (!stmt->IsExportedType()) {
        return;
    }

    if (!stmt->IsExportNamedDeclaration()) {
        util::ErrorHandler::ThrowSyntaxError(program, "Can only type export class or interface!", stmt->Start());
    }

    for (auto spec : stmt->AsExportNamedDeclaration()->Specifiers()) {
        util::StringView name = spec->Local()->Name();
        util::StringView nameFind = spec->Exported()->Name();

        auto element = typesMap.find(nameFind);
        if (element == typesMap.end()) {
            util::ErrorHandler::ThrowSyntaxError(program, "Can only type export class or interface!",
                                                 spec->Local()->Start());
        }
        if (!element->second->IsExportedType()) {
            element->second->AddModifier(ir::ModifierFlags::EXPORT_TYPE);
        }
        HandleSimpleType(exportedTypes, exportedStatements, stmt, name, program, spec->Local()->Start());
        if (!name.Is(nameFind.Mutf8())) {
            element->second->AddAstNodeFlags(ir::AstNodeFlags::HAS_EXPORT_ALIAS);
            HandleSimpleType(exportedTypes, exportedStatements, stmt, nameFind, program, spec->Local()->Start());
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
