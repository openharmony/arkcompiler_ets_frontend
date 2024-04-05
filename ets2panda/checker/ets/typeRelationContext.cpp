/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "boxingConverter.h"
#include "varbinder/scope.h"
#include "varbinder/variable.h"
#include "varbinder/declaration.h"
#include "checker/types/ets/etsUnionType.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/ts/tsTypeParameter.h"

namespace ark::es2panda::checker {
void AssignmentContext::ValidateArrayTypeInitializerByElement(TypeRelation *relation, ir::ArrayExpression *node,
                                                              ETSArrayType *target)
{
    if (target->IsETSTupleType()) {
        return;
    }

    for (uint32_t index = 0; index < node->Elements().size(); index++) {
        ir::Expression *currentArrayElem = node->Elements()[index];
        auto *const currentArrayElementType = currentArrayElem->Check(relation->GetChecker()->AsETSChecker());

        AssignmentContext(relation, currentArrayElem, currentArrayElem->Check(relation->GetChecker()->AsETSChecker()),
                          target->ElementType(), currentArrayElem->Start(),
                          {"Array element at index ", index, " with type '", currentArrayElementType,
                           "' is not compatible with the target array element type '", target->ElementType(), "'"});
    }
}

bool InstantiationContext::ValidateTypeArguments(ETSObjectType *type, ir::TSTypeParameterInstantiation *typeArgs,
                                                 const lexer::SourcePosition &pos)
{
    if (checker_->HasStatus(CheckerStatus::IN_INSTANCEOF_CONTEXT)) {
        if (typeArgs != nullptr) {
            checker_->ReportWarning(
                {"Type parameter is erased from type '", type->Name(), "' when used in instanceof expression."}, pos);
        }

        result_ = type;
        return true;
    }

    checker_->CheckNumberOfTypeArguments(type, typeArgs, pos);
    if (type->TypeArguments().empty()) {
        result_ = type;
        return true;
    }

    /*
    The first loop is to create a substitution of typeParams & typeArgs.
    so that we can replace the typeParams in constaints by the right type.
    e.g:
        class X <K extends Comparable<T>,T> {}
        function main(){
            const myCharClass = new X<Char,String>();
        }
    In the case above, the constraintsSubstitution should store "K->Char" and "T->String".
    And in the second loop, we use this substitution to replace typeParams in constraints.
    In this case, we will check "Comparable<String>" with "Char", since "Char" doesn't
    extends "Comparable<String>", we will get an error here.
    */

    auto const isDefaulted = [typeArgs](size_t idx) { return typeArgs == nullptr || idx >= typeArgs->Params().size(); };

    auto const getTypes = [this, &typeArgs, type, isDefaulted](size_t idx) -> std::pair<ETSTypeParameter *, Type *> {
        auto *typeParam = type->TypeArguments().at(idx)->AsETSTypeParameter();
        return {typeParam, isDefaulted(idx)
                               ? typeParam->GetDefaultType()
                               : checker_->MaybePromotedBuiltinType(typeArgs->Params().at(idx)->GetType(checker_))};
    };

    auto *const substitution = checker_->NewSubstitution();

    for (size_t idx = 0; idx < type->TypeArguments().size(); ++idx) {
        auto const [typeParam, typeArg] = getTypes(idx);
        checker_->CheckValidGenericTypeParameter(typeArg, pos);
        typeArg->Substitute(checker_->Relation(), substitution);
        ETSChecker::EmplaceSubstituted(substitution, typeParam, typeArg);
    }

    for (size_t idx = 0; idx < type->TypeArguments().size(); ++idx) {
        auto const [typeParam, typeArg] = getTypes(idx);
        if (typeParam->GetConstraintType() == nullptr) {
            continue;
        }
        auto *const constraint = typeParam->GetConstraintType()->Substitute(checker_->Relation(), substitution);

        if (!ValidateTypeArg(constraint, typeArg) && typeArgs != nullptr &&
            !checker_->Relation()->NoThrowGenericTypeAlias()) {
            checker_->ThrowTypeError({"Type '", typeArg, "' is not assignable to constraint type '", constraint, "'."},
                                     isDefaulted(idx) ? pos : typeArgs->Params().at(idx)->Start());
        }
    }

    return false;
}

bool InstantiationContext::ValidateTypeArg(Type *constraintType, Type *typeArg)
{
    // NOTE: #14993 enforce IsETSReferenceType
    if (typeArg->IsWildcardType()) {
        return true;
    }

    if (typeArg->IsETSVoidType() && constraintType->IsETSUnionType()) {
        for (auto const it : constraintType->AsETSUnionType()->ConstituentTypes()) {
            if (it->IsETSUndefinedType() || it->IsETSVoidType()) {
                return true;
            }
        }
    }

    return checker_->Relation()->IsAssignableTo(typeArg, constraintType);
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ir::TSTypeParameterInstantiation *typeArgs)
{
    ArenaVector<Type *> typeArgTypes(checker_->Allocator()->Adapter());
    typeArgTypes.reserve(type->TypeArguments().size());

    auto flags = ETSObjectFlags::NO_OPTS;

    if (typeArgs != nullptr) {
        for (auto *const it : typeArgs->Params()) {
            auto *paramType = it->GetType(checker_);

            if (paramType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
                checker_->Relation()->SetNode(it);

                auto *const boxedTypeArg = checker_->PrimitiveTypeAsETSBuiltinType(paramType);
                ASSERT(boxedTypeArg);
                paramType = boxedTypeArg->Instantiate(checker_->Allocator(), checker_->Relation(),
                                                      checker_->GetGlobalTypesHolder());
            }

            if (paramType->IsETSVoidType()) {
                paramType = checker_->GlobalETSUndefinedType();
            }

            typeArgTypes.push_back(paramType);
        }
    }

    while (typeArgTypes.size() < type->TypeArguments().size()) {
        typeArgTypes.push_back(type->TypeArguments().at(typeArgTypes.size()));
    }

    InstantiateType(type, typeArgTypes, (typeArgs == nullptr) ? lexer::SourcePosition() : typeArgs->Range().start);
    result_->AddObjectFlag(flags);
}

void InstantiationContext::InstantiateType(ETSObjectType *type, ArenaVector<Type *> &typeArgTypes,
                                           const lexer::SourcePosition &pos)
{
    util::StringView hash = checker_->GetHashFromTypeArguments(typeArgTypes);
    auto const &typeParams = type->TypeArguments();

    while (typeArgTypes.size() < typeParams.size()) {
        typeArgTypes.push_back(typeParams.at(typeArgTypes.size()));
    }

    auto *substitution = checker_->NewSubstitution();
    auto *constraintsSubstitution = checker_->NewSubstitution();
    for (size_t ix = 0; ix < typeParams.size(); ix++) {
        if (!typeParams[ix]->IsETSTypeParameter()) {
            continue;
        }
        ETSChecker::EmplaceSubstituted(constraintsSubstitution, typeParams[ix]->AsETSTypeParameter(), typeArgTypes[ix]);
    }
    for (size_t ix = 0; ix < typeParams.size(); ix++) {
        auto *typeParam = typeParams[ix];
        if (!typeParam->IsETSTypeParameter()) {
            continue;
        }
        if (!checker_->IsCompatibleTypeArgument(typeParam->AsETSTypeParameter(), typeArgTypes[ix],
                                                constraintsSubstitution) &&
            !checker_->Relation()->NoThrowGenericTypeAlias()) {
            checker_->ThrowTypeError(
                {"Type ", typeArgTypes[ix], " is not assignable to", " type parameter ", typeParams[ix]}, pos);
        }
        ETSChecker::EmplaceSubstituted(substitution, typeParam->AsETSTypeParameter(), typeArgTypes[ix]);
    }
    result_ = type->Substitute(checker_->Relation(), substitution)->AsETSObjectType();

    type->GetInstantiationMap().try_emplace(hash, result_);
    result_->AddTypeFlag(TypeFlag::GENERIC);
}
}  // namespace ark::es2panda::checker
