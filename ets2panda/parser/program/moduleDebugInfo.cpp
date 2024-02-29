/**
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "moduleDebugInfo.h"
#include "entityNameVisitor.h"

namespace ark::es2panda::parser {

ModuleDebugInfo::ModuleDebugInfo(ArenaAllocator *allocator)
    : imports_(allocator->Adapter()), exports_(allocator->Adapter())
{
}

void ModuleDebugInfo::AddImport(util::StringView modulePath, const ir::AstNode *specifier)
{
    ASSERT(specifier);

    util::StringView alias;
    util::StringView entity;

    if (specifier->IsImportNamespaceSpecifier()) {
        alias = specifier->AsImportNamespaceSpecifier()->Local()->Name();
        entity = "*";
    } else if (specifier->IsImportDefaultSpecifier()) {
        alias = specifier->AsImportDefaultSpecifier()->Local()->Name();
        // Empty `entity` denotes default exported declaration.
    } else {
        const auto *importSpec = specifier->AsImportSpecifier();
        alias = importSpec->Local()->Name();
        entity = importSpec->Imported()->Name();
    }

    // std::cerr << "@@@@@@@ ModuleDebugInfo::AddImport: modulePath: " << modulePath << ", alias: " << alias << ",
    // entity: " << entity << std::endl;
    imports_.emplace_back(std::move(modulePath), std::move(alias), std::move(entity));
}

void ModuleDebugInfo::AddImports(ir::ETSImportDeclaration *importDecl)
{
    ASSERT(importDecl);

    auto path = importDecl->ResolvedSource()->Str();

    for (const auto *spec : importDecl->Specifiers()) {
        AddImport(path, spec);
    }
}

void ModuleDebugInfo::AddExport(ir::Statement *stmt)
{
    ASSERT(stmt);

    EntityNameVisitor visitor;
    stmt->Accept(&visitor);
    util::StringView entity = visitor.GetName();

    util::StringView alias = stmt->IsDefaultExported() ? "" : entity;
    // std::cerr << "@@@@@@@ ModuleDebugInfo::AddExport: " << entity << std::endl;
    exports_.emplace_back("", std::move(alias), std::move(entity));
}

void ModuleDebugInfo::AddExports(const ir::ExportNamedDeclaration *exportDecl)
{
    ASSERT(exportDecl);

    // std::cerr << "@@@@@@@ ModuleDebugInfo::AddExports: specifiers: #" << exportDecl->Specifiers().size() <<
    // std::endl;
    for (const auto *spec : exportDecl->Specifiers()) {
        // Export from this module.
        AddExport("", spec);
    }
}

void ModuleDebugInfo::AddExports(const ir::ETSReExportDeclaration *reExportDecl)
{
    ASSERT(reExportDecl);

    const auto *importDecls = reExportDecl->GetETSImportDeclarations();
    auto from = importDecls->ResolvedSource()->Str();
    // std::cerr << "@@@@@@@ ModuleDebugInfo::AddExports: specifiers: #" << importDecls->Specifiers().size() << " from "
    //           << from << std::endl;
    for (const auto *spec : importDecls->Specifiers()) {
        AddExport(from, spec);
    }
}

void ModuleDebugInfo::AddExport(util::StringView from, const ir::AstNode *specifier)
{
    ASSERT(specifier);

    util::StringView alias;
    util::StringView entity;

    if (specifier->IsImportNamespaceSpecifier()) {
        alias = specifier->AsImportNamespaceSpecifier()->Local()->Name();
        entity = "*";
    } else if (specifier->IsExportDefaultDeclaration()) {
        alias = "";
        // entity = specifier->AsExportDefaultDeclaration()->Decl();
    } else if (specifier->IsImportSpecifier()) {
        const auto *importSpec = specifier->AsImportSpecifier();
        alias = importSpec->Local()->Name();
        entity = importSpec->Imported()->Name();
    } else {
        const auto *importSpec = specifier->AsExportSpecifier();
        alias = importSpec->Exported()->Name();
        entity = importSpec->Local()->Name();
    }

    // std::cerr << "@@@@@@@ ModuleDebugInfo::AddExport: from: " << from << ", alias: " << alias << ", entity: " <<
    // entity
    //           << std::endl;
    exports_.emplace_back(std::move(from), std::move(alias), std::move(entity));
}

}  // namespace ark::es2panda::parser
