/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "importNamespaceSpecifier.h"

#include "checker/ETSchecker.h"
#include "binder/ETSBinder.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/literals/stringLiteral.h"

namespace panda::es2panda::ir {
void ImportNamespaceSpecifier::Iterate(const NodeTraverser &cb) const
{
    cb(local_);
}

void ImportNamespaceSpecifier::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ImportNamespaceSpecifier"}, {"local", local_}});
}

void ImportNamespaceSpecifier::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *ImportNamespaceSpecifier::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ImportNamespaceSpecifier::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    if (Local()->Name().Empty()) {
        return nullptr;
    }

    if (Local()->AsIdentifier()->TsType() != nullptr) {
        return local_->TsType();
    }

    auto *import_decl = Parent()->AsETSImportDeclaration();
    auto import_path = import_decl->Source()->Str();

    if (import_decl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(import_decl->Language());
        checker->SetrModuleObjectTsType(local_, type);
        return type;
    }

    std::string package_name = import_path.Mutf8();
    std::replace(package_name.begin(), package_name.end(), '/', '.');
    util::UString package_path(package_name, checker->Allocator());
    std::vector<util::StringView> synthetic_names = checker->GetNameForSynteticObjectType(package_path.View());

    auto *module_object_type =
        checker->Allocator()->New<checker::ETSObjectType>(checker->Allocator(), synthetic_names[0], synthetic_names[0],
                                                          local_->AsIdentifier(), checker::ETSObjectFlags::CLASS);

    auto *root_decl = checker->Allocator()->New<binder::ClassDecl>(synthetic_names[0]);
    binder::LocalVariable *root_var =
        checker->Allocator()->New<binder::LocalVariable>(root_decl, binder::VariableFlags::NONE);
    root_var->SetTsType(module_object_type);

    synthetic_names.erase(synthetic_names.begin());
    checker::ETSObjectType *last_object_type(module_object_type);

    for (const auto &synthetic_name : synthetic_names) {
        auto *synthetic_obj_type =
            checker->Allocator()->New<checker::ETSObjectType>(checker->Allocator(), synthetic_name, synthetic_name,
                                                              local_->AsIdentifier(), checker::ETSObjectFlags::NO_OPTS);

        auto *class_decl = checker->Allocator()->New<binder::ClassDecl>(synthetic_name);
        binder::LocalVariable *var =
            checker->Allocator()->New<binder::LocalVariable>(class_decl, binder::VariableFlags::CLASS);
        var->SetTsType(synthetic_obj_type);
        last_object_type->AddProperty<checker::PropertyType::STATIC_FIELD>(var);
        synthetic_obj_type->SetEnclosingType(last_object_type);
        last_object_type = synthetic_obj_type;
    }

    checker->SetPropertiesForModuleObject(last_object_type, import_path);
    checker->SetrModuleObjectTsType(local_, last_object_type);

    return module_object_type;
}
}  // namespace panda::es2panda::ir
