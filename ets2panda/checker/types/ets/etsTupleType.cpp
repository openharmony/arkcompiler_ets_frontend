/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "etsTupleType.h"
#include "checker/ets/conversion.h"

namespace panda::es2panda::checker {
void ETSTupleType::ToString(std::stringstream &ss) const
{
    ss << "[";
    for (const auto *const type : type_list_) {
        type->ToString(ss);
    }

    if (spread_type_ != nullptr) {
        ss << ", ...";
        spread_type_->ToString(ss);
        ss << "[]";
    }

    ss << "]";
}

Type *ETSTupleType::GetTypeAtIndex(const TupleSizeType index) const
{
    return index >= GetTupleSize() ? GetSpreadType() : GetTupleTypesList().at(static_cast<std::size_t>(index));
}

void ETSTupleType::Identical([[maybe_unused]] TypeRelation *const relation, Type *const other)
{
    if (!other->IsETSTupleType()) {
        return;
    }

    const auto *const other_tuple = other->AsETSTupleType();

    if (GetMinTupleSize() != other_tuple->GetMinTupleSize()) {
        return;
    }

    for (TupleSizeType idx = 0; idx < GetMinTupleSize(); ++idx) {
        if (!relation->IsIdenticalTo(GetTypeAtIndex(idx), other_tuple->GetTypeAtIndex(idx))) {
            relation->Result(false);
            return;
        }
    }

    if (HasSpreadType() != other_tuple->HasSpreadType()) {
        relation->Result(false);
        return;
    }

    relation->Result(true);
}

bool ETSTupleType::AssignmentSource(TypeRelation *const relation, Type *const target)
{
    if (!(target->IsETSTupleType() || target->IsETSArrayType())) {
        return false;
    }

    if (!target->IsETSTupleType()) {
        ASSERT(target->IsETSArrayType());
        auto *const array_target = target->AsETSArrayType();

        const SavedTypeRelationFlagsContext saved_flags_ctx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        relation->Result(relation->IsAssignableTo(ElementType(), array_target->ElementType()));
    }

    return relation->IsTrue();
}

void ETSTupleType::AssignmentTarget(TypeRelation *const relation, Type *const source)
{
    if (!(source->IsETSTupleType() || (source->IsETSArrayType() && HasSpreadType()))) {
        return;
    }

    if (!source->IsETSTupleType()) {
        ASSERT(source->IsETSArrayType());
        auto *const array_source = source->AsETSArrayType();

        const SavedTypeRelationFlagsContext saved_flags_ctx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        relation->Result(relation->IsAssignableTo(array_source->ElementType(), ElementType()));
        return;
    }

    const auto *const tuple_source = source->AsETSTupleType();

    if (tuple_source->GetMinTupleSize() != GetMinTupleSize()) {
        return;
    }

    for (int32_t idx = 0; idx < GetMinTupleSize(); ++idx) {
        // because an array assignment to another array simply copies it's memory address, then it's not possible to
        // make boxing/unboxing/widening for types. Only conversion allowed is reference widening, which won't generate
        // bytecode for the conversion, same as for arrays.

        const SavedTypeRelationFlagsContext saved_flags_ctx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        if (!relation->IsAssignableTo(tuple_source->GetTypeAtIndex(idx), GetTypeAtIndex(idx))) {
            relation->Result(false);
            return;
        }
    }

    if (!HasSpreadType() && tuple_source->HasSpreadType()) {
        relation->Result(false);
        return;
    }

    relation->Result(true);
}

void ETSTupleType::Cast(TypeRelation *const relation, Type *const target)
{
    // NOTE(mmartin): Might be not the correct casting rules, as these aren't defined yet

    if (!(target->IsETSTupleType() || target->IsETSArrayType())) {
        conversion::Forbidden(relation);
        return;
    }

    if (target->IsETSArrayType() && (!target->IsETSTupleType())) {
        auto *const array_target = target->AsETSArrayType();

        if (!array_target->ElementType()->IsETSObjectType()) {
            conversion::Forbidden(relation);
            return;
        }

        const SavedTypeRelationFlagsContext saved_flags_ctx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        const bool elements_assignable =
            std::all_of(GetTupleTypesList().begin(), GetTupleTypesList().end(),
                        [&relation, &array_target](auto *const tuple_type_at_idx) {
                            return relation->IsAssignableTo(tuple_type_at_idx, array_target->ElementType());
                        });

        bool spread_assignable = true;
        if (HasSpreadType()) {
            spread_assignable = relation->IsAssignableTo(GetSpreadType(), array_target->ElementType());
        }

        relation->Result(elements_assignable && spread_assignable);
        return;
    }

    const auto *const tuple_target = target->AsETSTupleType();

    if (tuple_target->GetTupleSize() != GetTupleSize()) {
        return;
    }

    for (int32_t idx = 0; idx < GetTupleSize(); ++idx) {
        const SavedTypeRelationFlagsContext saved_flags_ctx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        if (!relation->IsAssignableTo(tuple_target->GetTypeAtIndex(idx), GetTypeAtIndex(idx))) {
            return;
        }
    }

    relation->Result(true);
}

Type *ETSTupleType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                [[maybe_unused]] GlobalTypesHolder *global_types)
{
    return this;
}

}  // namespace panda::es2panda::checker
