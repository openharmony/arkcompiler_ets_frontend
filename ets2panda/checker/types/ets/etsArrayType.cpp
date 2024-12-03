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

#include "etsArrayType.h"

#include "varbinder/variable.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/types/typeRelation.h"

namespace ark::es2panda::checker {
void ETSArrayType::ToString(std::stringstream &ss, bool precise) const
{
    if (HasTypeFlag(TypeFlag::READONLY)) {
        ss << "readonly ";
    }
    bool needParens = (element_->IsETSUnionType() || element_->IsETSFunctionType());
    if (needParens) {
        ss << "(";
    }
    element_->ToString(ss, precise);
    if (needParens) {
        ss << ")";
    }
    ss << "[]";
}

void ETSArrayType::ToAssemblerType(std::stringstream &ss) const
{
    element_->ToAssemblerType(ss);
}

void ETSArrayType::ToAssemblerTypeWithRank(std::stringstream &ss) const
{
    element_->ToAssemblerType(ss);

    for (uint32_t i = Rank(); i > 0; --i) {
        ss << "[]";
    }
}

void ETSArrayType::ToDebugInfoType(std::stringstream &ss) const
{
    ss << "[";
    element_->ToDebugInfoType(ss);
}

uint32_t ETSArrayType::Rank() const
{
    uint32_t rank = 1;
    auto iter = element_;
    while (iter->IsETSArrayType() && iter->AsETSArrayType()->ElementType() != iter) {
        iter = iter->AsETSArrayType()->ElementType();
        rank++;
    }

    return rank;
}

void ETSArrayType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsETSArrayType()) {
        // will be removed, if wildcard type is assigned to array type, not element type
        if (element_->IsWildcardType() || other->AsETSArrayType()->ElementType()->IsWildcardType()) {
            relation->Result(true);
            return;
        }
        relation->IsIdenticalTo(element_, other->AsETSArrayType()->ElementType());
    }
}

void ETSArrayType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (source->HasTypeFlag(TypeFlag::READONLY)) {
        relation->Result(false);
        return;
    }
    if (source->IsETSArrayType()) {
        if (AsETSArrayType()->ElementType()->IsETSPrimitiveType() ||
            source->AsETSArrayType()->ElementType()->IsETSPrimitiveType()) {
            return;
        }
        relation->IsAssignableTo(source->AsETSArrayType()->ElementType(), element_);
    }
}

void ETSArrayType::Cast(TypeRelation *const relation, Type *const target)
{
    if (target->HasTypeFlag(TypeFlag::ETS_ARRAY)) {
        conversion::Identity(relation, this, target->AsETSArrayType());
        if (relation->IsTrue()) {
            return;
        }

        conversion::WideningReference(relation, this, target->AsETSArrayType());
        if (relation->IsTrue()) {
            return;
        }

        conversion::NarrowingReference(relation, this, target->AsETSArrayType());
        if (relation->IsTrue()) {
            return;
        }

        if (ElementType()->IsETSTypeParameter()) {
            // unchecked cast!
            relation->Result(true);
            return;
        }

        conversion::Forbidden(relation);
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        conversion::WideningReference(relation, this, target->AsETSObjectType());
        if (relation->IsTrue()) {
            return;
        }

        conversion::Forbidden(relation);
        return;
    }

    conversion::Forbidden(relation);
}

void ETSArrayType::IsSupertypeOf(TypeRelation *const relation, Type *source)
{
    relation->Result(false);
    // 3.8.3 Subtyping among Array Types
    if (source->IsETSArrayType()) {
        auto *const sourceElemType = this->AsETSArrayType()->ElementType();
        auto *const targetElemType = source->AsETSArrayType()->ElementType();
        if (targetElemType->IsETSReferenceType() && sourceElemType->IsETSReferenceType()) {
            sourceElemType->IsSupertypeOf(relation, targetElemType);
        }
    }
}

Type *ETSArrayType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    auto *elementType = element_->Instantiate(allocator, relation, globalTypes);
    bool needAllocator = HasTypeFlag(TypeFlag::READONLY);
    ETSArrayType *arrayType = needAllocator ? relation->GetChecker()->Allocator()->New<ETSArrayType>(elementType)
                                            : relation->GetChecker()->AsETSChecker()->CreateETSArrayType(elementType);
    arrayType->typeFlags_ = typeFlags_;
    return arrayType;
}

Type *ETSArrayType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }

    auto *resultElt = element_->Substitute(relation, substitution);

    if (resultElt == element_) {
        return this;
    }

    ETSArrayType *result = relation->GetChecker()->AsETSChecker()->CreateETSArrayType(resultElt);
    result->typeFlags_ = typeFlags_;
    return result;
}

}  // namespace ark::es2panda::checker
