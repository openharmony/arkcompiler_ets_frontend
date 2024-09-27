/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "ir/ets/etsTuple.h"

namespace ark::es2panda::checker {
void ETSTupleType::ToString(std::stringstream &ss, bool precise) const
{
    if (HasTypeFlag(TypeFlag::READONLY)) {
        ss << "readonly ";
    }

    ss << "[";

    for (auto it = typeList_.begin(); it != typeList_.end(); it++) {
        (*it)->ToString(ss, precise);

        if (std::next(it) != typeList_.end()) {
            ss << ", ";
        }
    }

    if (spreadType_ != nullptr) {
        ss << ", ...";
        spreadType_->ToString(ss, precise);
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

    const auto *const otherTuple = other->AsETSTupleType();

    if (GetMinTupleSize() != otherTuple->GetMinTupleSize()) {
        return;
    }

    for (TupleSizeType idx = 0; idx < GetMinTupleSize(); ++idx) {
        if (!relation->IsIdenticalTo(GetTypeAtIndex(idx), otherTuple->GetTypeAtIndex(idx))) {
            relation->Result(false);
            return;
        }
    }

    if (HasSpreadType() != otherTuple->HasSpreadType()) {
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
        auto *const arrayTarget = target->AsETSArrayType();

        const SavedTypeRelationFlagsContext savedFlagsCtx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        relation->Result(relation->IsAssignableTo(ElementType(), arrayTarget->ElementType()));
    }

    return relation->IsTrue();
}

void ETSTupleType::AssignmentTarget(TypeRelation *const relation, Type *const source)
{
    if (source->HasTypeFlag(TypeFlag::READONLY)) {
        relation->Result(false);
        return;
    }

    if (!(source->IsETSTupleType() || (source->IsETSArrayType() && HasSpreadType()))) {
        return;
    }

    if (!source->IsETSTupleType()) {
        ASSERT(source->IsETSArrayType());
        auto *const arraySource = source->AsETSArrayType();

        const SavedTypeRelationFlagsContext savedFlagsCtx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        relation->Result(relation->IsAssignableTo(arraySource->ElementType(), ElementType()));
        return;
    }

    const auto *const tupleSource = source->AsETSTupleType();

    if (tupleSource->GetMinTupleSize() != GetMinTupleSize()) {
        return;
    }

    for (int32_t idx = 0; idx < GetMinTupleSize(); ++idx) {
        // because an array assignment to another array simply copies it's memory address, then it's not possible to
        // make boxing/unboxing/widening for types. Only conversion allowed is reference widening, which won't generate
        // bytecode for the conversion, same as for arrays.

        const SavedTypeRelationFlagsContext savedFlagsCtx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        if (!relation->IsIdenticalTo(GetTypeAtIndex(idx), tupleSource->GetTypeAtIndex(idx))) {
            relation->Result(false);
            return;
        }
    }

    if (!HasSpreadType() && tupleSource->HasSpreadType()) {
        relation->Result(false);
        return;
    }

    relation->Result(true);
}

Type *ETSTupleType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    ArenaVector<Type *> newTypeList(checker->Allocator()->Adapter());

    for (auto *const tupleTypeListElement : GetTupleTypesList()) {
        newTypeList.emplace_back(tupleTypeListElement->Substitute(relation, substitution));
    }

    auto *newSpreadType = spreadType_ == nullptr ? nullptr : spreadType_->Substitute(relation, substitution);
    auto *newElementType = ir::ETSTuple::CalculateLUBForTuple(checker, newTypeList, &newSpreadType);
    return checker->Allocator()->New<ETSTupleType>(std::move(newTypeList), newElementType, newSpreadType);
}

void ETSTupleType::Cast(TypeRelation *const relation, Type *const target)
{
    // NOTE(mmartin): Might be not the correct casting rules, as these aren't defined yet

    if (!(target->IsETSTupleType() || target->IsETSArrayType())) {
        conversion::Forbidden(relation);
        return;
    }

    if (target->IsETSArrayType() && (!target->IsETSTupleType())) {
        auto *const arrayTarget = target->AsETSArrayType();

        if (!arrayTarget->ElementType()->IsETSObjectType()) {
            conversion::Forbidden(relation);
            return;
        }

        const SavedTypeRelationFlagsContext savedFlagsCtx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        const bool elementsAssignable =
            std::all_of(GetTupleTypesList().begin(), GetTupleTypesList().end(),
                        [&relation, &arrayTarget](auto *const tupleTypeAtIdx) {
                            return relation->IsAssignableTo(tupleTypeAtIdx, arrayTarget->ElementType());
                        });

        bool spreadAssignable = true;
        if (HasSpreadType()) {
            spreadAssignable = relation->IsAssignableTo(GetSpreadType(), arrayTarget->ElementType());
        }

        relation->Result(elementsAssignable && spreadAssignable);
        return;
    }

    const auto *const tupleTarget = target->AsETSTupleType();

    if (tupleTarget->GetTupleSize() != GetTupleSize()) {
        return;
    }

    for (int32_t idx = 0; idx < GetTupleSize(); ++idx) {
        const SavedTypeRelationFlagsContext savedFlagsCtx(
            relation, TypeRelationFlag::NO_BOXING | TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_WIDENING);

        if (!relation->IsAssignableTo(tupleTarget->GetTypeAtIndex(idx), GetTypeAtIndex(idx))) {
            return;
        }
    }

    relation->Result(true);
}

Type *ETSTupleType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    auto *tupleType = allocator->New<ETSTupleType>(
        GetTupleTypesList(), ElementType()->Instantiate(allocator, relation, globalTypes), GetSpreadType());
    tupleType->typeFlags_ = typeFlags_;
    return tupleType;
}

}  // namespace ark::es2panda::checker
