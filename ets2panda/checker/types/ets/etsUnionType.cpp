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

#include <numeric>
#include "etsUnionType.h"

#include "checker/ets/conversion.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::checker {
void ETSUnionType::ToString(std::stringstream &ss, bool precise) const
{
    for (auto it = constituentTypes_.begin(); it != constituentTypes_.end(); it++) {
        (*it)->ToString(ss, precise);
        if (std::next(it) != constituentTypes_.end()) {
            ss << "|";
        }
    }
}

void ETSUnionType::ToAssemblerType(std::stringstream &ss) const
{
    assemblerLub_->ToAssemblerTypeWithRank(ss);
}

void ETSUnionType::ToDebugInfoType(std::stringstream &ss) const
{
    assemblerLub_->ToDebugInfoType(ss);
}

ETSUnionType::ETSUnionType(ETSChecker *checker, ArenaVector<Type *> &&constituentTypes)
    : Type(TypeFlag::ETS_UNION), constituentTypes_(std::move(constituentTypes))
{
    ASSERT(constituentTypes_.size() > 1);
    assemblerLub_ = ComputeAssemblerLUB(checker, this);
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

// This function computes effective runtime representation of union type
Type *ETSUnionType::ComputeAssemblerLUB(ETSChecker *checker, ETSUnionType *un)
{
    auto *const apparent = checker->GetApparentType(un);
    if (!apparent->IsETSUnionType()) {
        return apparent;
    }
    if (apparent != un) {
        return apparent->AsETSUnionType()->assemblerLub_;
    }
    un = apparent->AsETSUnionType();

    Type *lub = nullptr;
    for (auto *t : un->ConstituentTypes()) {
        ASSERT(t->IsETSReferenceType());
        if (t->IsETSNullType()) {
            continue;
        }
        if (t->IsETSUndefinedType()) {
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
        }
        if (lub == nullptr) {
            lub = t;
            continue;
        }
        if (t->IsETSObjectType() && lub->IsETSObjectType()) {
            lub = checker->GetClosestCommonAncestor(lub->AsETSObjectType(), t->AsETSObjectType());
        } else if (t->IsETSArrayType() && lub->IsETSArrayType()) {
            // NOTE: can compute "common(lub, t)[]"
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
        } else {
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
        }
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

static void AmbiguousUnionOperation(TypeRelation *relation)
{
    auto checker = relation->GetChecker()->AsETSChecker();
    if (!relation->NoThrow()) {
        checker->ThrowTypeError({"Ambiguous union type operation"}, relation->GetNode()->Start());
    }
    conversion::Forbidden(relation);
}

template <typename RelFN>
void ETSUnionType::RelationSource(TypeRelation *relation, Type *target, RelFN const &relFn)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const refTarget = checker->MaybePromotedBuiltinType(target);

    if (target != refTarget && !relation->ApplyUnboxing()) {
        relation->Result(false);
        return;
    }
    if (relation->IsSupertypeOf(refTarget, this)) {
        if (refTarget != target) {
            relation->GetNode()->SetBoxingUnboxingFlags(checker->GetUnboxingFlag(refTarget));
        }
        return;
    }
    if (target == refTarget) {
        relation->Result(false);
        return;
    }

    int related = 0;
    for (auto *ct : ConstituentTypes()) {  // NOTE(vpukhov): just test if union is supertype of any numeric
        if (!ct->IsETSUnboxableObject()) {
            continue;
        }
        if (!relFn(relation, checker->MaybePrimitiveBuiltinType(ct), target)) {
            continue;
        }
        relation->GetNode()->SetBoxingUnboxingFlags(checker->GetUnboxingFlag(checker->MaybePrimitiveBuiltinType(ct)));
        related++;
    }
    if (related > 1) {
        AmbiguousUnionOperation(relation);
    }
    relation->Result(related == 1);
}

template <typename RelFN>
void ETSUnionType::RelationTarget(TypeRelation *relation, Type *source, RelFN const &relFn)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const refSource = checker->MaybePromotedBuiltinType(source);

    if (source != refSource && !relation->ApplyBoxing()) {
        relation->Result(false);
        return;
    }
    if (relation->IsSupertypeOf(this, refSource)) {
        if (refSource != source) {
            relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(refSource));
        }
        return;
    }

    /* #16160: for ETSFunctionType and functional interfaces, need to check assignability apart from
       plain subtyping
    */
    int related = 0;
    for (auto *ct : ConstituentTypes()) {
        if (!relFn(relation, ct, source)) {
            continue;
        }
        related++;
    }
    if (related > 1) {
        AmbiguousUnionOperation(relation);
    }
    if (related == 1) {
        relation->Result(true);
        return;
    }

    if (source == refSource) {
        relation->Result(false);
        return;
    }

    related = 0;
    for (auto *ct : ConstituentTypes()) {  // NOTE(vpukhov): just test if union is supertype of any numeric
        if (!relFn(relation, checker->MaybePrimitiveBuiltinType(ct), source)) {
            continue;
        }
        relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(ct));
        related++;
    }
    if (related > 1) {
        AmbiguousUnionOperation(relation);
    }
    relation->Result(related == 1);
}

bool ETSUnionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    auto const relFn = []([[maybe_unused]] TypeRelation *rel, [[maybe_unused]] Type *ct, [[maybe_unused]] Type *tgt) {
        return false;
    };
    RelationSource(relation, target, relFn);
    return relation->IsTrue();
}

void ETSUnionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    auto const relFn = [](TypeRelation *rel, Type *ct, Type *src) { return rel->IsAssignableTo(src, ct); };
    RelationTarget(relation, source, relFn);
}

void ETSUnionType::Cast(TypeRelation *relation, Type *target)
{
    if (relation->InCastingContext() && target->IsETSReferenceType()) {
        relation->Result(true);  // NOTE(vpukhov): check if types intersect at least
        return;
    }
    auto const relFn = [](TypeRelation *rel, Type *ct, Type *tgt) { return rel->IsCastableTo(ct, tgt); };
    RelationSource(relation, target, relFn);
}

void ETSUnionType::CastTarget(TypeRelation *relation, Type *source)
{
    if (relation->InCastingContext() && source->IsETSReferenceType()) {
        relation->Result(true);  // NOTE(vpukhov): check if types intersect at least
        return;
    }
    auto const relFn = [](TypeRelation *rel, Type *ct, Type *src) { return rel->IsCastableTo(src, ct); };
    RelationTarget(relation, source, relFn);
}

static auto constexpr ETS_NORMALIZABLE_NUMERIC = TypeFlag(TypeFlag::ETS_NUMERIC & ~TypeFlag::CHAR);

static Type *LargestNumeric(Type *t1, Type *t2)
{
    static_assert(TypeFlag::DOUBLE > TypeFlag::FLOAT);
    static_assert(TypeFlag::FLOAT > TypeFlag::LONG);
    static_assert(TypeFlag::LONG > TypeFlag::INT);
    static_assert(TypeFlag::INT > TypeFlag::SHORT);
    static_assert(TypeFlag::SHORT > TypeFlag::BYTE);

    auto v1 = t1->TypeFlags() & ETS_NORMALIZABLE_NUMERIC;
    auto v2 = t2->TypeFlags() & ETS_NORMALIZABLE_NUMERIC;
    ASSERT(helpers::math::IsPowerOfTwo(v1));
    ASSERT(helpers::math::IsPowerOfTwo(v2));
    return v1 > v2 ? t1 : t2;
}

static std::optional<Type *> TryMergeTypes(TypeRelation *relation, Type *const t1, Type *const t2)
{
    auto checker = relation->GetChecker()->AsETSChecker();
    auto never = checker->GetGlobalTypesHolder()->GlobalBuiltinNeverType();
    if (relation->IsSupertypeOf(t1, t2) || t2 == never) {
        return t1;
    }
    if (relation->IsSupertypeOf(t2, t1) || t1 == never) {
        return t2;
    }
    // NOTE(vpukhov): numerics - clarification required
    return std::nullopt;
}

void ETSUnionType::LinearizeAndEraseIdentical(TypeRelation *relation, ArenaVector<Type *> &types)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    // Linearize
    size_t const initialSz = types.size();
    for (size_t i = 0; i < initialSz; ++i) {
        auto *const ct = types[i];
        if (ct->IsETSUnionType()) {
            auto const &otherTypes = ct->AsETSUnionType()->ConstituentTypes();
            types.insert(types.end(), otherTypes.begin(), otherTypes.end());
            types[i] = nullptr;
        } else if (ct->IsNeverType()) {
            types[i] = nullptr;
        }
    }
    size_t insPos = 0;
    for (size_t i = 0; i < types.size(); ++i) {
        auto *const ct = types[i];
        if (ct != nullptr) {
            types[insPos++] = ct;
        }
    }
    types.resize(insPos);

    // Promote primitives and literal types
    for (auto &ct : types) {
        ct = checker->MaybePromotedBuiltinType(checker->GetNonConstantTypeFromPrimitiveType(ct));
    }
    // Reduce subtypes
    for (auto cmpIt = types.begin(); cmpIt != types.end(); ++cmpIt) {
        for (auto it = std::next(cmpIt); it != types.end();) {
            if (auto merged = TryMergeTypes(relation, *cmpIt, *it); merged) {
                *cmpIt = *merged;
                it = types.erase(it);
            } else {
                it++;
            }
        }
    }
}

void ETSUnionType::NormalizeTypes(TypeRelation *relation, ArenaVector<Type *> &types)
{
    if (types.size() == 1) {
        return;
    }
    auto const isNumeric = [](auto *ct) { return ct->HasTypeFlag(ETS_NORMALIZABLE_NUMERIC); };
    if (std::all_of(types.begin(), types.end(), isNumeric)) {
        types[0] = std::accumulate(std::next(types.begin()), types.end(), types[0], LargestNumeric);
        types.resize(1);
        return;
    }
    LinearizeAndEraseIdentical(relation, types);
}

Type *ETSUnionType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    ArenaVector<Type *> copiedConstituents(allocator->Adapter());
    for (auto *it : constituentTypes_) {
        copiedConstituents.push_back(it->Instantiate(allocator, relation, globalTypes));
    }
    return checker->CreateETSUnionType(std::move(copiedConstituents));
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

void ETSUnionType::IsSupertypeOf(TypeRelation *relation, Type *source)
{
    for (auto const &ctype : ConstituentTypes()) {
        if (relation->IsSupertypeOf(ctype, source)) {
            return;
        }
    }
}

void ETSUnionType::IsSubtypeOf(TypeRelation *relation, Type *target)
{
    for (auto const &ctype : ConstituentTypes()) {
        if (!relation->IsSupertypeOf(target, ctype)) {
            return;
        }
    }
}

//  NOTE! When calling this method we assume that 'AssignmentTarget(...)' check was passes successfully,
//  thus the required assignable type always exists.
checker::Type *ETSUnionType::GetAssignableType(checker::ETSChecker *checker, checker::Type *sourceType) const noexcept
{
    if (sourceType->IsETSTypeParameter()) {
        return sourceType;
    }

    if (sourceType->IsETSUnionType() || sourceType->IsETSArrayType() || sourceType->IsETSFunctionType()) {
        return sourceType;
    }

    auto *objectType = sourceType->IsETSObjectType() ? sourceType->AsETSObjectType() : nullptr;
    if (objectType != nullptr && (!objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE) ||
                                  objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_STRING))) {
        //  NOTE: here wo don't cast the actual type to possible base type using in the union, but use it as is!
        return sourceType;
    }

    std::map<std::uint32_t, checker::Type *> numericTypes {};
    bool const isBool = objectType != nullptr ? objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)
                                              : sourceType->HasTypeFlag(TypeFlag::ETS_BOOLEAN);
    bool const isChar = objectType != nullptr ? objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)
                                              : sourceType->HasTypeFlag(TypeFlag::CHAR);
    if (checker::Type *assignableType = GetAssignableBuiltinType(checker, objectType, isBool, isChar, numericTypes);
        assignableType != nullptr) {
        return assignableType;
    }

    if (auto const sourceId =
            objectType != nullptr ? ETSObjectType::GetPrecedence(objectType) : Type::GetPrecedence(sourceType);
        sourceId > 0U) {
        for (auto const [id, type] : numericTypes) {
            if (id >= sourceId) {
                return type;
            }
        }
    }

    for (auto *constituentType : constituentTypes_) {
        if (constituentType->IsETSObjectType() && constituentType->AsETSObjectType()->IsGlobalETSObjectType()) {
            return constituentType;
        }
    }

    return nullptr;
}

checker::Type *ETSUnionType::GetAssignableBuiltinType(
    checker::ETSChecker *checker, checker::ETSObjectType *sourceType, bool const isBool, bool const isChar,
    std::map<std::uint32_t, checker::Type *> &numericTypes) const noexcept
{
    checker::Type *assignableType = nullptr;

    for (auto *constituentType : constituentTypes_) {
        if (!constituentType->IsETSObjectType()) {
            continue;
        }

        auto *const type = constituentType->AsETSObjectType();
        if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)) {
            if (isBool) {
                assignableType = constituentType;
                break;
            }
        } else if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
            if (isChar) {
                assignableType = constituentType;
                break;
            }
        } else if (auto const id = ETSObjectType::GetPrecedence(type); id > 0U) {
            numericTypes.emplace(id, constituentType);
        } else if (assignableType == nullptr && sourceType != nullptr &&
                   checker->Relation()->IsSupertypeOf(type, sourceType)) {
            assignableType = constituentType;
        }
    }

    return assignableType;
}

bool ETSUnionType::ExtractType(checker::ETSChecker *checker, checker::ETSObjectType *sourceType) noexcept
{
    std::map<std::uint32_t, ArenaVector<checker::Type *>::const_iterator> numericTypes {};
    bool const isBool = sourceType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN);
    bool const isChar = sourceType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR);

    auto it = constituentTypes_.cbegin();
    while (it != constituentTypes_.cend()) {
        auto *const constituentType = *it;

        if (checker->Relation()->IsIdenticalTo(constituentType, sourceType) ||
            //  NOTE: just a temporary solution because now Relation()->IsIdenticalTo(...) returns
            //  'false' for the types like 'ArrayLike<T>'
            constituentType->ToString() == static_cast<Type *>(sourceType)->ToString()) {
            constituentTypes_.erase(it);
            return true;
        }

        if (checker->Relation()->IsSupertypeOf(constituentType, sourceType)) {
            return true;
        }
        if (checker->Relation()->IsSupertypeOf(sourceType, constituentType)) {
            return true;
        }

        if (constituentType->IsETSObjectType()) {
            auto *const objectType = (*it)->AsETSObjectType();
            if (isBool && objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)) {
                constituentTypes_.erase(it);
                return true;
            }
            if (isChar && objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
                constituentTypes_.erase(it);
                return true;
            }
            if (auto const id = ETSObjectType::GetPrecedence(objectType); id > 0U) {
                numericTypes.emplace(id, it);
            }
        }

        ++it;
    }

    if (auto const sourceId = ETSObjectType::GetPrecedence(sourceType); sourceId > 0U) {
        for (auto const [id, it1] : numericTypes) {
            if (id >= sourceId) {
                constituentTypes_.erase(it1);
                return true;
            }
        }
    }

    return false;
}

bool ETSUnionType::ExtractType(checker::ETSChecker *checker, checker::ETSArrayType *sourceType) noexcept
{
    auto it = constituentTypes_.cbegin();
    while (it != constituentTypes_.cend()) {
        auto *const constituentType = *it;
        if (constituentType != nullptr && constituentType->IsETSArrayType()) {
            if (checker->Relation()->IsIdenticalTo(constituentType, sourceType) ||
                //  NOTE: just a temporary solution because now Relation()->IsIdenticalTo(...) returns
                //  'false' for the types like 'ArrayLike<T>'
                constituentType->ToString() == static_cast<Type *>(sourceType)->ToString()) {
                constituentTypes_.erase(it);
                return true;
            }

            if (checker->Relation()->IsSupertypeOf(constituentType, sourceType)) {
                return true;
            }
            if (checker->Relation()->IsSupertypeOf(sourceType, constituentType)) {
                return true;
            }
        }
        ++it;
    }

    for (auto const &constituentType : constituentTypes_) {
        if (constituentType != nullptr && constituentType->IsETSObjectType() &&
            constituentType->AsETSObjectType()->IsGlobalETSObjectType()) {
            return true;
        }
    }

    return false;
}

std::pair<checker::Type *, checker::Type *> ETSUnionType::GetComplimentaryType(ETSChecker *const checker,
                                                                               checker::Type *sourceType)
{
    checker::Type *clone = Clone(checker);
    bool ok = true;

    if (sourceType->IsETSUnionType()) {
        for (auto *const constituentType : sourceType->AsETSUnionType()->ConstituentTypes()) {
            if (ok = clone->AsETSUnionType()->ExtractType(checker, constituentType->AsETSObjectType()); !ok) {
                break;
            }
        }
    } else if (sourceType->IsETSArrayType()) {
        ok = clone->AsETSUnionType()->ExtractType(checker, sourceType->AsETSArrayType());
    } else {
        if (sourceType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && !sourceType->IsETSVoidType()) {
            sourceType = checker->PrimitiveTypeAsETSBuiltinType(sourceType);
        }

        if (sourceType->IsETSObjectType()) {
            ok = clone->AsETSUnionType()->ExtractType(checker, sourceType->AsETSObjectType());
        }
    }

    if (!ok) {
        return std::make_pair(checker->GetGlobalTypesHolder()->GlobalNeverType(), this);
    }

    if (clone->AsETSUnionType()->ConstituentTypes().size() == 1U) {
        clone = clone->AsETSUnionType()->ConstituentTypes().front();
    }

    return std::make_pair(sourceType, clone);
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
        return relation->IsTrue() && source->IsETSReferenceType() && target->IsETSReferenceType();
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
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(),
                           [relation, target, &isCastablePred](Type *source) {
                               return isCastablePred(relation, source, target) && source->IsETSReferenceType() &&
                                      target->IsETSReferenceType();
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

std::tuple<bool, bool> ETSUnionType::ResolveConditionExpr() const
{
    if (PossiblyETSString()) {
        return {false, false};
    }
    if (std::all_of(ConstituentTypes().begin(), ConstituentTypes().end(),
                    [](checker::Type const *ct) { return ct->DefinitelyETSNullish(); })) {
        return {true, false};
    }
    // We have to test if union can contain builtin numerics or string types to infer "true"
    return {false, false};
}

bool ETSUnionType::HasUndefinedType() const
{
    for (const auto &type : constituentTypes_) {
        if (type->IsETSUndefinedType()) {
            return true;
        }
    }
    return false;
}
}  // namespace ark::es2panda::checker
