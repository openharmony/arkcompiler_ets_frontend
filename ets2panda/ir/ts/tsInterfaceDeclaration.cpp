/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "tsInterfaceDeclaration.h"

#include "binder/declaration.h"
#include "binder/scope.h"
#include "binder/variable.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace panda::es2panda::ir {
void TSInterfaceDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(id_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : extends_) {
        cb(it);
    }

    cb(body_);
}

void TSInterfaceDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSInterfaceDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"body", body_},
                 {"id", id_},
                 {"extends", extends_},
                 {"typeParameters", AstDumper::Optional(type_params_)}});
}

void TSInterfaceDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void CheckInheritedPropertiesAreIdentical(checker::TSChecker *checker, checker::InterfaceType *type,
                                          const lexer::SourcePosition &loc_info)
{
    checker->GetBaseTypes(type);

    size_t constexpr BASE_SIZE_LIMIT = 2;
    if (type->Bases().size() < BASE_SIZE_LIMIT) {
        return;
    }

    checker->ResolveDeclaredMembers(type);

    checker::InterfacePropertyMap properties;

    for (auto *it : type->Properties()) {
        properties.insert({it->Name(), {it, type}});
    }

    for (auto *base : type->Bases()) {
        checker->ResolveStructuredTypeMembers(base);
        ArenaVector<binder::LocalVariable *> inherited_properties(checker->Allocator()->Adapter());
        base->AsInterfaceType()->CollectProperties(&inherited_properties);

        for (auto *inherited_prop : inherited_properties) {
            auto res = properties.find(inherited_prop->Name());
            if (res == properties.end()) {
                properties.insert({inherited_prop->Name(), {inherited_prop, base->AsInterfaceType()}});
            } else if (res->second.second != type) {
                checker::Type *source_type = checker->GetTypeOfVariable(inherited_prop);
                checker::Type *target_type = checker->GetTypeOfVariable(res->second.first);
                checker->IsTypeIdenticalTo(source_type, target_type,
                                           {"Interface '", type, "' cannot simultaneously extend types '",
                                            res->second.second, "' and '", base->AsInterfaceType(), "'."},
                                           loc_info);
            }
        }
    }
}

checker::Type *TSInterfaceDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    binder::Variable *var = id_->Variable();
    ASSERT(var->Declaration()->Node() && var->Declaration()->Node()->IsTSInterfaceDeclaration());

    if (this == var->Declaration()->Node()) {
        checker::Type *resolved_type = var->TsType();

        if (resolved_type == nullptr) {
            checker::ObjectDescriptor *desc =
                checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
            resolved_type = checker->Allocator()->New<checker::InterfaceType>(checker->Allocator(), id_->Name(), desc);
            resolved_type->SetVariable(var);
            var->SetTsType(resolved_type);
        }

        checker::InterfaceType *resolved_interface = resolved_type->AsObjectType()->AsInterfaceType();
        CheckInheritedPropertiesAreIdentical(checker, resolved_interface, id_->Start());

        for (auto *base : resolved_interface->Bases()) {
            checker->IsTypeAssignableTo(resolved_interface, base,
                                        {"Interface '", id_->Name(), "' incorrectly extends interface '", base, "'"},
                                        id_->Start());
        }

        checker->CheckIndexConstraints(resolved_interface);
    }

    body_->Check(checker);

    return nullptr;
}

checker::Type *TSInterfaceDeclaration::Check(checker::ETSChecker *checker)
{
    checker::ETSObjectType *interface_type {};

    if (TsType() == nullptr) {
        interface_type = checker->BuildInterfaceProperties(this);
        ASSERT(interface_type != nullptr);
        interface_type->SetSuperType(checker->GlobalETSObjectType());
        SetTsType(interface_type);
    }

    checker::ScopeContext scope_ctx(checker, scope_);
    auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_INTERFACE, interface_type);

    for (auto *it : body_->Body()) {
        it->Check(checker);
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
