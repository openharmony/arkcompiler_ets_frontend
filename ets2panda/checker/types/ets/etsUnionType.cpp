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

#include <algorithm>

#include "etsUnionType.h"
#include "checker/ets/conversion.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/ETSchecker.h"
#include "ir/astNode.h"

namespace panda::es2panda::checker {
void ETSUnionType::ToString(std::stringstream &ss) const
{
    for (auto it = constituentTypes_.begin(); it != constituentTypes_.end(); it++) {
        (*it)->ToString(ss);
        if (std::next(it) != constituentTypes_.end()) {
            ss << "|";
        }
    }
}

void ETSUnionType::ToAssemblerType(std::stringstream &ss) const
{
    lubType_->ToAssemblerType(ss);
}

void ETSUnionType::ToDebugInfoType(std::stringstream &ss) const
{
    lubType_->ToDebugInfoType(ss);
}

ETSUnionType::ETSUnionType(ETSChecker *checker, ArenaVector<Type *> &&constituentTypes)
    : Type(TypeFlag::ETS_UNION), constituentTypes_(std::move(constituentTypes))
{
    ASSERT(constituentTypes_.size() > 1);
    lubType_ = ComputeLUB(checker);
}

bool ETSUnionType::EachTypeRelatedToSomeType(TypeRelation *relation, ETSUnionType *source, ETSUnionType *target)
{
    return std::all_of(source->constituentTypes_.begin(), source->constituentTypes_.end(),
                       [relation, target](auto *s) { return TypeRelatedToSomeType(relation, s, target); });
}

bool ETSUnionType::TypeRelatedToSomeType(TypeRelation *relation, Type *source, ETSUnionType *target)
{
    return std::any_of(target->constituentTypes_.begin(), target->constituentTypes_.end(),
                       [relation, source](auto *t) { return relation->IsIdenticalTo(source, t); });
}

Type *ETSUnionType::ComputeLUB(ETSChecker *checker) const
{
    auto lub = constituentTypes_.front();
    for (auto *t : constituentTypes_) {
        if (!checker->IsReferenceType(t)) {
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
        }
        if (t->IsETSObjectType() && t->AsETSObjectType()->SuperType() == nullptr) {
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
        }
        lub = checker->FindLeastUpperBound(lub, t);
    }
    return lub;
}

void ETSUnionType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsETSUnionType()) {
        if (EachTypeRelatedToSomeType(relation, this, other->AsETSUnionType()) &&
            EachTypeRelatedToSomeType(relation, other->AsETSUnionType(), this)) {
            relation->Result(true);
            return;
        }
    }

    relation->Result(false);
}

bool ETSUnionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    for (auto *it : constituentTypes_) {
        if (!relation->IsAssignableTo(it, target)) {
            return false;
        }
    }

    return relation->Result(true);
}

void ETSUnionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const refSource =
        source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) ? checker->PrimitiveTypeAsETSBuiltinType(source) : source;
    auto exactType = std::find_if(
        constituentTypes_.begin(), constituentTypes_.end(), [checker, relation, source, refSource](Type *ct) {
            if (ct == refSource && source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && ct->IsETSObjectType() &&
                ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
                relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(ct));
                return relation->IsAssignableTo(refSource, ct);
            }
            return false;
        });
    if (exactType != constituentTypes_.end()) {
        return;
    }
    size_t assignableCount = 0;
    for (auto *it : constituentTypes_) {
        if (relation->IsAssignableTo(refSource, it)) {
            if (refSource != source) {
                relation->IsAssignableTo(source, it);
                ASSERT(relation->IsTrue());
            }
            ++assignableCount;
            continue;
        }
        bool assignPrimitive = it->IsETSObjectType() &&
                               it->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE) &&
                               source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE);
        if (assignPrimitive && relation->IsAssignableTo(source, checker->ETSBuiltinTypeAsPrimitiveType(it))) {
            Type *unboxedIt = checker->ETSBuiltinTypeAsPrimitiveType(it);
            if (unboxedIt != source) {
                relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(it));
                source->Cast(relation, unboxedIt);
                ASSERT(relation->IsTrue());
            }
            ++assignableCount;
        }
    }
    if (assignableCount > 1) {
        checker->ThrowTypeError({"Ambiguous assignment: after union normalization several types are assignable."},
                                relation->GetNode()->Start());
    }
    relation->Result(assignableCount != 0U);
}

void ETSUnionType::LinearizeAndEraseIdentical(TypeRelation *relation, ArenaVector<Type *> &constituentTypes)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    // Firstly, make linearization
    ArenaVector<Type *> copiedConstituents(checker->Allocator()->Adapter());
    for (auto *ct : constituentTypes) {
        if (ct->IsETSUnionType()) {
            auto otherTypes = ct->AsETSUnionType()->ConstituentTypes();
            copiedConstituents.insert(copiedConstituents.end(), otherTypes.begin(), otherTypes.end());
        } else {
            copiedConstituents.push_back(ct);
        }
    }
    constituentTypes = copiedConstituents;
    // Secondly, remove identical types
    auto cmpIt = constituentTypes.begin();
    while (cmpIt != constituentTypes.end()) {
        auto it = std::next(cmpIt);
        while (it != constituentTypes.end()) {
            if (relation->IsIdenticalTo(*it, *cmpIt)) {
                it = constituentTypes.erase(it);
            } else {
                ++it;
            }
        }
        ++cmpIt;
    }
}

void ETSUnionType::NormalizeTypes(TypeRelation *relation, ArenaVector<Type *> &constituentTypes)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto etsObject = std::find(constituentTypes.begin(), constituentTypes.end(),
                               checker->GetGlobalTypesHolder()->GlobalETSObjectType());
    if (etsObject != constituentTypes.end()) {
        constituentTypes.clear();
        constituentTypes.push_back(checker->GetGlobalTypesHolder()->GlobalETSObjectType());
        return;
    }
    LinearizeAndEraseIdentical(relation, constituentTypes);
    // Find number type to remove other numeric types
    auto numberFound =
        std::find_if(constituentTypes.begin(), constituentTypes.end(), [](Type *const ct) {
            return ct->IsETSObjectType() && ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_DOUBLE);
        }) != constituentTypes.end();
    auto cmpIt = constituentTypes.begin();
    while (cmpIt != constituentTypes.end()) {
        auto newEnd = std::remove_if(
            constituentTypes.begin(), constituentTypes.end(), [relation, checker, cmpIt, numberFound](Type *ct) {
                relation->Result(false);
                (*cmpIt)->IsSupertypeOf(relation, ct);
                bool removeSubtype = ct != *cmpIt && relation->IsTrue();
                bool removeNumeric = numberFound && ct->IsETSObjectType() &&
                                     ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE) &&
                                     !ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_DOUBLE) &&
                                     !ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN);
                bool removeNever = ct == checker->GetGlobalTypesHolder()->GlobalBuiltinNeverType();
                return removeSubtype || removeNumeric || removeNever;
            });
        if (newEnd != constituentTypes.end()) {
            constituentTypes.erase(newEnd, constituentTypes.end());
            cmpIt = constituentTypes.begin();
            continue;
        }
        ++cmpIt;
    }
}

Type *ETSUnionType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    ArenaVector<Type *> copiedConstituents(allocator->Adapter());

    for (auto *it : constituentTypes_) {
        copiedConstituents.push_back(it->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)
                                         ? relation->GetChecker()->AsETSChecker()->PrimitiveTypeAsETSBuiltinType(it)
                                         : it->Instantiate(allocator, relation, globalTypes));
    }

    ETSUnionType::NormalizeTypes(relation, copiedConstituents);
    if (copiedConstituents.size() == 1) {
        return copiedConstituents[0];
    }

    return allocator->New<ETSUnionType>(relation->GetChecker()->AsETSChecker(), std::move(copiedConstituents));
}

Type *ETSUnionType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    ArenaVector<Type *> substitutedConstituents(checker->Allocator()->Adapter());
    for (auto *ctype : constituentTypes_) {
        substitutedConstituents.push_back(ctype->Substitute(relation, substitution));
    }
    return checker->CreateETSUnionType(std::move(substitutedConstituents));
}

void ETSUnionType::Cast(TypeRelation *relation, Type *target)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const refTarget =
        target->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) ? checker->PrimitiveTypeAsETSBuiltinType(target) : target;
    auto exactType =
        std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [this, relation, refTarget](Type *src) {
            if (src == refTarget && relation->IsCastableTo(src, refTarget)) {
                GetLeastUpperBoundType()->Cast(relation, refTarget);
                ASSERT(relation->IsTrue());
                return true;
            }
            return false;
        });
    if (exactType != constituentTypes_.end()) {
        return;
    }
    for (auto *source : constituentTypes_) {
        if (relation->IsCastableTo(source, refTarget)) {
            GetLeastUpperBoundType()->Cast(relation, refTarget);
            ASSERT(relation->IsTrue());
            if (refTarget != target) {
                source->Cast(relation, target);
                ASSERT(relation->IsTrue());
                ASSERT(relation->GetNode()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE);
            }
            return;
        }
        bool castPrimitive = source->IsETSObjectType() &&
                             source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE) &&
                             target->HasTypeFlag(TypeFlag::ETS_PRIMITIVE);
        if (castPrimitive && relation->IsCastableTo(checker->ETSBuiltinTypeAsPrimitiveType(source), target)) {
            ASSERT(relation->IsTrue());
            return;
        }
    }

    conversion::Forbidden(relation);
}

void ETSUnionType::IsSupertypeOf(TypeRelation *relation, Type *source)
{
    relation->Result(false);

    if (source->IsETSUnionType()) {
        for (auto const &sourceCtype : source->AsETSUnionType()->ConstituentTypes()) {
            if (IsSupertypeOf(relation, sourceCtype), !relation->IsTrue()) {
                return;
            }
        }
        return;
    }

    for (auto const &ctype : ConstituentTypes()) {
        if (ctype->IsSupertypeOf(relation, source), relation->IsTrue()) {
            return;
        }
    }

    if (source->IsETSTypeParameter()) {
        source->AsETSTypeParameter()->ConstraintIsSubtypeOf(relation, this);
        return;
    }
}

void ETSUnionType::CastTarget(TypeRelation *relation, Type *source)
{
    Type *targetType = FindTypeIsCastableToThis(relation->GetNode(), relation, source);
    if (targetType != nullptr) {
        source->Cast(relation, targetType);
        return;
    }

    conversion::Forbidden(relation);
}

Type *ETSUnionType::FindTypeIsCastableToThis(ir::Expression *node, TypeRelation *relation, Type *source) const
{
    ASSERT(node);
    bool nodeWasSet = false;
    if (relation->GetNode() == nullptr) {
        nodeWasSet = true;
        relation->SetNode(node);
    }
    // Prioritize object to object conversion
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [relation, source](Type *target) {
        relation->IsCastableTo(source, target);
        return relation->IsTrue() && source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) &&
               target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT);
    });
    if (it != constituentTypes_.end()) {
        if (nodeWasSet) {
            relation->SetNode(nullptr);
        }
        return *it;
    }
    it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [relation, source](Type *target) {
        relation->IsCastableTo(source, target);
        return relation->IsTrue();
    });
    if (nodeWasSet) {
        relation->SetNode(nullptr);
    }
    if (it != constituentTypes_.end()) {
        return *it;
    }
    return nullptr;
}

Type *ETSUnionType::FindTypeIsCastableToSomeType(ir::Expression *node, TypeRelation *relation, Type *target) const
{
    ASSERT(node);
    bool nodeWasSet = false;
    if (relation->GetNode() == nullptr) {
        nodeWasSet = true;
        relation->SetNode(node);
        relation->SetFlags(TypeRelationFlag::CASTING_CONTEXT);
    }
    auto isCastablePred = [](TypeRelation *r, Type *sourceType, Type *targetType) {
        if (targetType->IsETSUnionType()) {
            auto *foundTargetType = targetType->AsETSUnionType()->FindTypeIsCastableToThis(r->GetNode(), r, sourceType);
            r->Result(foundTargetType != nullptr);
        } else {
            r->IsCastableTo(sourceType, targetType);
        }
        return r->IsTrue();
    };
    // Prioritize object to object conversion
    auto it = std::find_if(
        constituentTypes_.begin(), constituentTypes_.end(), [relation, target, &isCastablePred](Type *source) {
            return isCastablePred(relation, source, target) && source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) &&
                   target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT);
        });
    if (it != constituentTypes_.end()) {
        if (nodeWasSet) {
            relation->SetNode(nullptr);
            relation->RemoveFlags(TypeRelationFlag::CASTING_CONTEXT);
        }
        return *it;
    }
    it = std::find_if(
        constituentTypes_.begin(), constituentTypes_.end(),
        [relation, target, &isCastablePred](Type *source) { return isCastablePred(relation, source, target); });
    if (nodeWasSet) {
        relation->SetNode(nullptr);
        relation->RemoveFlags(TypeRelationFlag::CASTING_CONTEXT);
    }
    if (it != constituentTypes_.end()) {
        return *it;
    }
    return nullptr;
}

Type *ETSUnionType::FindUnboxableType() const
{
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(),
                           [](Type *t) { return t->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE); });
    if (it != constituentTypes_.end()) {
        return *it;
    }
    return nullptr;
}

bool ETSUnionType::HasObjectType(ETSObjectFlags flag) const
{
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(),
                           [flag](Type *t) { return t->AsETSObjectType()->HasObjectFlag(flag); });
    return it != constituentTypes_.end();
}

Type *ETSUnionType::FindExactOrBoxedType(ETSChecker *checker, Type *const type) const
{
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [checker, type](Type *ct) {
        if (ct->IsETSObjectType() && ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
            auto *const unboxedCt = checker->ETSBuiltinTypeAsPrimitiveType(ct);
            return unboxedCt == type;
        }
        return ct == type;
    });
    if (it != constituentTypes_.end()) {
        return *it;
    }
    return nullptr;
}

}  // namespace panda::es2panda::checker
