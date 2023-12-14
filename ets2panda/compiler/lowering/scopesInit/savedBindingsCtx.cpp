/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "savedBindingsCtx.h"

#include <ir/module/exportDefaultDeclaration.h>
#include <ir/module/exportAllDeclaration.h>
#include <ir/statements/functionDeclaration.h>
#include <ir/base/scriptFunction.h>

namespace panda::es2panda::compiler {

void ImportDeclarationContext::BindImportDecl(ir::ImportDeclaration *import_decl)
{
    varbinder::ModuleScope::ImportDeclList decl_list(Allocator()->Adapter());

    for (const auto &[name, variable] : VarBinder()->GetScope()->Bindings()) {
        if (SavedBindings().find(name) != SavedBindings().end()) {
            continue;
        }

        decl_list.push_back(variable->Declaration()->AsImportDecl());
    }

    VarBinder()->GetScope()->AsModuleScope()->AddImportDecl(import_decl, std::move(decl_list));
}

void ExportDeclarationContext::BindExportDecl(ir::AstNode *export_decl)
{
    if (VarBinder() == nullptr) {
        return;
    }

    varbinder::ModuleScope::ExportDeclList decl_list(Allocator()->Adapter());

    if (export_decl->IsExportDefaultDeclaration()) {
        auto *decl = export_decl->AsExportDefaultDeclaration();
        auto *rhs = decl->Decl();

        if (VarBinder()->GetScope()->Bindings().size() == SavedBindings().size()) {
            if (rhs->IsFunctionDeclaration()) {
                VarBinder()->AddDecl<varbinder::FunctionDecl>(rhs->Start(), VarBinder()->Allocator(),
                                                              util::StringView(DEFAULT_EXPORT),
                                                              rhs->AsFunctionDeclaration()->Function());
            } else {
                VarBinder()->AddDecl<varbinder::ConstDecl>(rhs->Start(), util::StringView(DEFAULT_EXPORT));
            }
        }
    }

    for (const auto &[name, variable] : VarBinder()->GetScope()->Bindings()) {
        if (SavedBindings().find(name) != SavedBindings().end()) {
            continue;
        }

        util::StringView export_name(export_decl->IsExportDefaultDeclaration() ? "default" : name);

        variable->AddFlag(varbinder::VariableFlags::LOCAL_EXPORT);
        auto *decl =
            VarBinder()->AddDecl<varbinder::ExportDecl>(variable->Declaration()->Node()->Start(), export_name, name);
        decl_list.push_back(decl);
    }

    auto *module_scope = VarBinder()->GetScope()->AsModuleScope();
    module_scope->AddExportDecl(export_decl, std::move(decl_list));
}

}  // namespace panda::es2panda::compiler