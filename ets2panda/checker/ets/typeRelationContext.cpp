/*
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

#include "typeRelationContext.h"
#include "varbinder/scope.h"
#include "varbinder/variable.h"
#include "varbinder/declaration.h"
#include "checker/types/ets/etsUnionType.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/ts/tsTypeParameter.h"

namespace panda::es2panda::checker {
void AssignmentContext::ValidateArrayTypeInitializerByElement(TypeRelation *relation, ir::ArrayExpression *node,
                                                              ETSArrayType *target)
{
    if (target->IsETSTupleType()) {
        return;
    }

    for (uint32_t index = 0; index < node->Elements().size(); index++) {
        ir::Expression *current_array_elem = node->Elements()[index];
        AssignmentContext(relation, current_array_elem,
                          current_array_elem->Check(relation->GetChecker()->AsETSChecker()), target->ElementType(),
                          current_array_elem->Start(),
                          {"Array element at index ", index, " is not compatible with the target array element type."});
    }
}

bool InstantiationContext::ValidateTypeArguments(ETSObjectType *type, ir::TSTypeParameterInstantiation *type_args,
                                                 const lexer::SourcePosition &pos)
{
    checker_->CheckNumberOfTypeArguments(type, type_args, pos);
    if (type->TypeArguments().empty()) {
        result_ = type;
        return true;
    }

    /*
    The first loop is to create a substitution of type_params & type_args.
    so that we can replace the type_params in constaints by the right type.
    e.g:
        class X <K extends Comparable<T>,T> {}
        function main(){
            const myCharClass = new X<Char,String>();
        }
    In the case above, the constraints_substitution should store "K->Char" and "T->String".
    And in the second loop, we use this substitution to replace type_params in constraints.
    In this case, we will check "Comparable<String>" with "Char", since "Char" doesn't
    extends "Comparable<String>", we will get an error here.
    */

    auto const get_types = [this, &type_args, type](size_t idx) -> std::pair<ETSTypeParameter *, Type *> {
        auto *type_param = type->TypeArguments().at(idx)->AsETSTypeParameter();
        if (type_args != nullptr && idx < type_args->Params().size()) {
            return {type_param, type_args->Params().at(idx)->GetType(checker_)};
        }
        return {type_param, type_param->GetDefaultType()};
    };

    auto *const substitution = checker_->NewSubstitution();

    for (size_t idx = 0; idx < type->TypeArguments().size(); ++idx) {
        auto const [type_param, type_arg] = get_types(idx);
        checker_->CheckValidGenericTypeParameter(type_arg, pos);
        type_arg->Substitute(checker_->Relation(), substitution);
        ETSChecker::EmplaceSubstituted(substitution, type_param, type_arg);
    }

    for (size_t idx = 0; idx < type->TypeArguments().size(); ++idx) {
        auto const [type_param, type_arg] = get_types(idx);
        if (type_param->GetConstraintType() == nullptr) {
            continue;
        }
        auto *const constraint = type_param->GetConstraintType()->Substitute(checker_->Relation(), substitution);

        if (!ValidateTypeArg(constraint, type_arg) && type_args != nullptr &&
            !checker_->Relation()->NoThrowGenericTypeAlias()) {
            checker_->ThrowTypeError({"Type '", type_arg, "' is not assignable to constraint type '", constraint, "'."},
                                     type_args->Params().at(idx)->Start());
        }
    }

    return false;
}

bool InstantiationContext::ValidateTypeArg(Type *constraint_type, Type *type_arg)
{
    if (!ETSChecker::IsReferenceType(type_arg)) {
        return false;
    }

    if (type_arg->IsETSUnionType()) {
        auto const &constituent_types = type_arg->AsETSUnionType()->ConstituentTypes();
        return std::all_of(constituent_types.begin(), constituent_types.end(),
                           [this, constraint_type](Type *c_type) { return ValidateTypeArg(constraint_type, c_type); });
    }

    return checker_->Relation()->IsAssignableTo(type_arg, constraint_type);
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ir::TSTypeParameterInstantiation *type_args)
{
    ArenaVector<Type *> type_arg_types(checker_->Allocator()->Adapter());
    type_arg_types.reserve(type->TypeArguments().size());

    auto flags = ETSObjectFlags::NO_OPTS;

    if (type_args != nullptr) {
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
    }

    while (type_arg_types.size() < type->TypeArguments().size()) {
        type_arg_types.push_back(type->TypeArguments().at(type_arg_types.size()));
    }

    InstantiateType(type, type_arg_types, (type_args == nullptr) ? lexer::SourcePosition() : type_args->Range().start);
    result_->AddObjectFlag(flags);
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ArenaVector<Type *> &type_arg_types,
                                           const lexer::SourcePosition &pos)
{
    util::StringView hash = checker_->GetHashFromTypeArguments(type_arg_types);
    auto const &type_params = type->TypeArguments();

    while (type_arg_types.size() < type_params.size()) {
        type_arg_types.push_back(type_params.at(type_arg_types.size()));
    }

    auto *substitution = checker_->NewSubstitution();
    auto *constraints_substitution = checker_->NewSubstitution();
    for (size_t ix = 0; ix < type_params.size(); ix++) {
        if (!type_params[ix]->IsETSTypeParameter()) {
            continue;
        }
        ETSChecker::EmplaceSubstituted(constraints_substitution, type_params[ix]->AsETSTypeParameter(),
                                       type_arg_types[ix]);
    }
    for (size_t ix = 0; ix < type_params.size(); ix++) {
        auto *type_param = type_params[ix];
        if (!type_param->IsETSTypeParameter()) {
            continue;
        }
        if (!checker_->IsCompatibleTypeArgument(type_param->AsETSTypeParameter(), type_arg_types[ix],
                                                constraints_substitution) &&
            !checker_->Relation()->NoThrowGenericTypeAlias()) {
            checker_->ThrowTypeError(
                {"Type ", type_arg_types[ix], " is not assignable to", " type parameter ", type_params[ix]}, pos);
        }
        ETSChecker::EmplaceSubstituted(substitution, type_param->AsETSTypeParameter(), type_arg_types[ix]);
    }
    result_ = type->Substitute(checker_->Relation(), substitution)->AsETSObjectType();

    type->GetInstantiationMap().try_emplace(hash, result_);
    result_->AddTypeFlag(TypeFlag::GENERIC);
}
}  // namespace panda::es2panda::checker
