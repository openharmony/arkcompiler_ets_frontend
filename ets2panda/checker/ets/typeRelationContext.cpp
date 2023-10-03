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

#include "typeRelationContext.h"
#include "binder/variable.h"
#include "binder/scope.h"
#include "binder/declaration.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsTypeParameter.h"

namespace panda::es2panda::checker {
void AssignmentContext::ValidateArrayTypeInitializerByElement(TypeRelation *relation, ir::ArrayExpression *node,
                                                              ETSArrayType *target)
{
    for (uint32_t index = 0; index < node->Elements().size(); index++) {
        ir::Expression *current_array_elem = node->Elements()[index];
        AssignmentContext(relation, current_array_elem,
                          current_array_elem->Check(relation->GetChecker()->AsETSChecker()), target->ElementType(),
                          current_array_elem->Start(),
                          {"Array element at index ", index, " is not compatible with the target array element type."});
    }
}

bool InstantiationContext::ValidateTypeArguments(ETSObjectType *type, ir::TSTypeParameterDeclaration *type_param_decl,
                                                 ir::TSTypeParameterInstantiation *type_args,
                                                 const lexer::SourcePosition &pos)
{
    if (type_param_decl != nullptr && type_args == nullptr) {
        checker_->ThrowTypeError({"Type '", type, "' is generic but type argument were not provided."}, pos);
    }

    if (type_param_decl == nullptr && type_args != nullptr) {
        checker_->ThrowTypeError({"Type '", type, "' is not generic."}, pos);
    }

    if (type_args == nullptr) {
        result_ = type;
        return true;
    }

    ASSERT(type_param_decl != nullptr && type_args != nullptr);
    if (type_param_decl->Params().size() != type_args->Params().size()) {
        checker_->ThrowTypeError({"Type '", type, "' has ", type_param_decl->Params().size(),
                                  " number of type parameters, but ", type_args->Params().size(),
                                  " type arguments were provided."},
                                 pos);
    }

    for (size_t type_param_iter = 0; type_param_iter < type_param_decl->Params().size(); ++type_param_iter) {
        auto *const param_type = type_args->Params().at(type_param_iter)->GetType(checker_);
        checker_->CheckValidGenericTypeParameter(param_type, pos);
        auto *const type_param_constraint =
            type_param_decl->Params().at(type_param_iter)->AsTSTypeParameter()->Constraint();
        if (type_param_constraint == nullptr) {
            continue;
        }

        bool assignable = false;
        auto *constraint_type = type_param_constraint->GetType(checker_);
        if (constraint_type->IsETSObjectType() && param_type->IsETSObjectType()) {
            assignable = ValidateTypeArg(constraint_type->AsETSObjectType(), param_type->AsETSObjectType());
        } else if (param_type->IsETSUnionType() && !constraint_type->IsETSUnionType()) {
            auto constituent_types = param_type->AsETSUnionType()->ConstituentTypes();
            assignable =
                std::all_of(constituent_types.begin(), constituent_types.end(), [this, constraint_type](Type *c_type) {
                    return c_type->IsETSObjectType() &&
                           ValidateTypeArg(constraint_type->AsETSObjectType(), c_type->AsETSObjectType());
                });
        }

        if (!assignable) {
            checker_->ThrowTypeError({"Type '", param_type->AsETSObjectType(),
                                      "' is not assignable to constraint type '", constraint_type, "'."},
                                     type_args->Params().at(type_param_iter)->Start());
        }
    }

    return false;
}

bool InstantiationContext::ValidateTypeArg(ETSObjectType *constraint_type, ETSObjectType *arg_ref_type)
{
    if (const auto *const found = checker_->AsETSChecker()->Scope()->FindLocal(
            constraint_type->Name(), binder::ResolveBindingOptions::TYPE_ALIASES);
        found != nullptr) {
        arg_ref_type = found->TsType()->AsETSObjectType();
    }

    auto assignable = checker_->Relation()->IsAssignableTo(arg_ref_type, constraint_type);
    if (constraint_type->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        for (const auto *const interface : arg_ref_type->Interfaces()) {
            // TODO(mmartin): make correct check later for multiple bounds
            assignable = (interface == constraint_type) || assignable;
        }
    }

    return assignable;
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ir::TSTypeParameterInstantiation *type_args)
{
    ArenaVector<Type *> type_arg_types(checker_->Allocator()->Adapter());
    type_arg_types.reserve(type_args->Params().size());

    auto flags = ETSObjectFlags::NO_OPTS;

    for (auto *const it : type_args->Params()) {
        auto *param_type = checker_->GetTypeFromTypeAnnotation(it);

        if (param_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
            checker_->Relation()->SetNode(it);
            auto *const boxed_type_arg = checker_->PrimitiveTypeAsETSBuiltinType(param_type);
            ASSERT(boxed_type_arg);
            param_type = boxed_type_arg->Instantiate(checker_->Allocator(), checker_->Relation(),
                                                     checker_->GetGlobalTypesHolder());
        }

        type_arg_types.push_back(param_type);
    }

    InstantiateType(type, type_arg_types, type_args->Range().start);
    result_->AddObjectFlag(flags);
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ArenaVector<Type *> &type_arg_types,
                                           const lexer::SourcePosition &pos)
{
    util::StringView hash = checker_->GetHashFromTypeArguments(type_arg_types);
    auto type_params = type->TypeArguments();
    if (type_params.size() != type_arg_types.size()) {
        checker_->ThrowTypeError({"Wrong number of type arguments"}, pos);
    }

    auto *substitution = checker_->NewSubstitution();
    for (size_t ix = 0; ix < type_params.size(); ix++) {
        auto *type_param = type_params[ix];
        bool is_compatible_type_arg;
        if (type_arg_types[ix]->IsETSUnionType()) {
            auto union_constituent_types = type_arg_types[ix]->AsETSUnionType()->ConstituentTypes();
            is_compatible_type_arg = std::all_of(union_constituent_types.begin(), union_constituent_types.end(),
                                                 [this, type_param](Type *type_arg) {
                                                     return checker_->IsCompatibleTypeArgument(type_param, type_arg);
                                                 });
        } else {
            is_compatible_type_arg = checker_->IsCompatibleTypeArgument(type_param, type_arg_types[ix]);
        }
        if (!is_compatible_type_arg) {
            checker_->ThrowTypeError(
                {"Type ", type_arg_types[ix], " is not assignable to", " type parameter ", type_params[ix]}, pos);
        }
        substitution->emplace(type_params[ix], type_arg_types[ix]);
    }
    result_ = type->Substitute(checker_->Relation(), substitution)->AsETSObjectType();

    type->GetInstantiationMap().try_emplace(hash, result_);
    result_->AddTypeFlag(TypeFlag::GENERIC);
}
}  // namespace panda::es2panda::checker
