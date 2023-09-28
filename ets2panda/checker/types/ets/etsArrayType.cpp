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

#include "etsArrayType.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/conversion.h"
#include "plugins/ecmascript/es2panda/checker/types/typeRelation.h"

namespace panda::es2panda::checker {
void ETSArrayType::ToString(std::stringstream &ss) const
{
    element_->ToString(ss);
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
    while (iter->IsETSArrayType()) {
        iter = iter->AsETSArrayType()->ElementType();
        rank++;
    }

    return rank;
}

void ETSArrayType::Identical(TypeRelation *relation, Type *other)
{
    if (IsNullableType() != other->IsNullableType()) {
        return;
    }

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
    if (source->IsETSNullType()) {
        relation->Result(IsNullableType());
        return;
    }

    if (source->IsNullableType() && !IsNullableType()) {
        return;
    }

    if (source->IsETSArrayType()) {
        if (AsETSArrayType()->ElementType()->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) ||
            source->AsETSArrayType()->ElementType()->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
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
        auto *const source_elem_type = this->AsETSArrayType()->ElementType();
        auto *const target_elem_type = source->AsETSArrayType()->ElementType();
        if (source_elem_type->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) &&
            target_elem_type->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            source_elem_type->IsSupertypeOf(relation, target_elem_type);
        }
    }
}

Type *ETSArrayType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    return relation->GetChecker()->AsETSChecker()->CreateETSArrayType(
        element_->Instantiate(allocator, relation, global_types));
}

Type *ETSArrayType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }
    if (auto found = substitution->find(this); found != substitution->end()) {
        return found->second;
    }
    auto *result_elt = element_->Substitute(relation, substitution);
    return result_elt == element_ ? this : relation->GetChecker()->AsETSChecker()->CreateETSArrayType(result_elt);
}

}  // namespace panda::es2panda::checker
