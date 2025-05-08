/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "etsObjectType.h"
#include "etsUnionType.h"
#include "checker/ets/conversion.h"
#include "checker/types/ets/etsTupleType.h"
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
    ES2PANDA_ASSERT(constituentTypes_.size() > 1);
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
        if (t->IsTypeError()) {
            return checker->GlobalTypeError();
        }
        // NOTE(vpukhov): #19701 void refactoring
        ES2PANDA_ASSERT(t->IsETSReferenceType() || t->IsETSVoidType());
        t = t->IsETSVoidType() ? checker->GlobalETSUndefinedType() : t;

        if (lub == nullptr || lub->IsETSUndefinedType()) {
            lub = t;
            continue;
        }
        if (lub == t || t->IsETSUndefinedType()) {
            continue;
        }
        if (t->IsETSNullType()) {
            return checker->GetGlobalTypesHolder()->GlobalETSObjectType();
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
    return checker->GetNonConstantType(lub);
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
        checker->LogError(diagnostic::AMBIGUOUS_UNION_TYPE_OP, {}, relation->GetNode()->Start());
    }
    conversion::Forbidden(relation);
}

template <typename RelFN>
void ETSUnionType::RelationTarget(TypeRelation *relation, Type *source, RelFN const &relFn)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const refsource = checker->MaybeBoxType(source);

    relation->Result(false);

    if (refsource != source && !relation->ApplyBoxing()) {
        return;
    }

    if (std::any_of(constituentTypes_.begin(), constituentTypes_.end(),
                    [relation, refsource, relFn](auto *t) { return relFn(relation, refsource, t); })) {
        if (refsource != source) {
            // Some nodes can have both boxing and unboxing flags set. When applying them, first the unboxing happens
            // (then a possible primitive conversion), and boxing at last.
            // NOTE (smartin): when boxing/unboxing is moved to a lowering, review this part of the code
            const auto mergedBoxingFlags =
                relation->GetNode()->GetBoxingUnboxingFlags() | checker->GetBoxingFlag(refsource);
            relation->GetNode()->SetBoxingUnboxingFlags(mergedBoxingFlags);
        }
        relation->Result(true);
        return;
    }

    if (refsource == source) {
        relation->IsSupertypeOf(this, refsource);
        return;
    }

    bool related = false;
    for (auto *ct : ConstituentTypes()) {
        if (relFn(relation, source, checker->MaybeUnboxType(ct))) {
            if (related) {
                AmbiguousUnionOperation(relation);
            }
            relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(ct));
            related = true;
        }
    }

    relation->Result(related);
}

bool ETSUnionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    if (target->HasTypeFlag(TypeFlag::PRIMITIVE)) {
        if (!relation->ApplyUnboxing()) {
            return relation->Result(false);
        }
        relation->GetNode()->SetBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(checker->MaybeUnboxType(target)));
    }

    return relation->Result(std::all_of(constituentTypes_.begin(), constituentTypes_.end(),
                                        [relation, target](auto *t) { return relation->IsAssignableTo(t, target); }));
}

void ETSUnionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    auto const relFn = []([[maybe_unused]] TypeRelation *rel, [[maybe_unused]] Type *src, [[maybe_unused]] Type *tgt) {
        return rel->IsAssignableTo(src, tgt);
    };
    RelationTarget(relation, source, relFn);
}

void ETSUnionType::Cast(TypeRelation *relation, Type *target)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();

    if (target->HasTypeFlag(TypeFlag::PRIMITIVE)) {
        if (!relation->ApplyUnboxing()) {
            relation->Result(false);
            return;
        }

        relation->GetNode()->SetBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(checker->MaybeUnboxType(target)));
    }

    if (relation->InCastingContext()) {
        relation->Result(std::any_of(constituentTypes_.begin(), constituentTypes_.end(),
                                     [relation, target](auto *t) { return relation->IsCastableTo(t, target); }));
        return;
    }

    relation->Result(std::all_of(constituentTypes_.begin(), constituentTypes_.end(),
                                 [relation, target](auto *t) { return relation->IsCastableTo(t, target); }));
}

void ETSUnionType::CastTarget(TypeRelation *relation, Type *source)
{
    auto const relFn = []([[maybe_unused]] TypeRelation *rel, [[maybe_unused]] Type *src, [[maybe_unused]] Type *tgt) {
        return rel->IsCastableTo(src, tgt);
    };
    RelationTarget(relation, source, relFn);
}

static auto constexpr ETS_NORMALIZABLE_NUMERIC = TypeFlag(TypeFlag::ETS_NUMERIC);

static Type *LargestNumeric(Type *t1, Type *t2)
{
    static_assert(TypeFlag::DOUBLE > TypeFlag::FLOAT);
    static_assert(TypeFlag::FLOAT > TypeFlag::LONG);
    static_assert(TypeFlag::LONG > TypeFlag::INT);
    static_assert(TypeFlag::INT > TypeFlag::SHORT);
    static_assert(TypeFlag::SHORT > TypeFlag::BYTE);

    auto v1 = t1->TypeFlags() & ETS_NORMALIZABLE_NUMERIC;
    auto v2 = t2->TypeFlags() & ETS_NORMALIZABLE_NUMERIC;
    ES2PANDA_ASSERT(helpers::math::IsPowerOfTwo(v1));
    ES2PANDA_ASSERT(helpers::math::IsPowerOfTwo(v2));
    return v1 > v2 ? t1 : t2;
}

static std::optional<Type *> TryMergeTypes(TypeRelation *relation, Type *const t1, Type *const t2)
{
    auto checker = relation->GetChecker()->AsETSChecker();
    auto never = checker->GetGlobalTypesHolder()->GlobalETSNeverType();
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
        auto ct = types[i];
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

    // Promote primitives
    for (auto &ct : types) {
        ct = checker->MaybeBoxType(ct);
    }
    // Reduce subtypes
    for (auto cmpIt = types.begin(); cmpIt != types.end(); ++cmpIt) {
        for (auto it = std::next(cmpIt); it != types.end();) {
            auto merged = TryMergeTypes(relation, *cmpIt, *it);
            if (!merged) {
                ++it;
                continue;
            }

            if (merged == *cmpIt) {
                it = types.erase(it);
                continue;
            }

            cmpIt = types.erase(cmpIt);
            it = std::next(cmpIt);
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

void ETSUnionType::CheckVarianceRecursively(TypeRelation *relation, VarianceFlag varianceFlag)
{
    for (auto const &ctype : ConstituentTypes()) {
        relation->CheckVarianceRecursively(ctype, relation->TransferVariant(varianceFlag, VarianceFlag::COVARIANT));
    }
}

bool ETSUnionType::IsAssignableType(checker::Type *sourceType) const noexcept
{
    if (sourceType->IsETSTypeParameter() || sourceType->IsTypeError()) {
        return true;
    }

    if (sourceType->IsETSUnionType() || sourceType->IsETSArrayType() || sourceType->IsETSFunctionType()) {
        return true;
    }

    return false;
}

checker::Type *ETSUnionType::HandleNumericPrecedence(
    checker::ETSChecker *checker, checker::ETSObjectType *objectType, checker::Type *sourceType,
    std::map<std::uint32_t, checker::Type *> &numericTypes) const noexcept
{
    auto const sourceId =
        (objectType != nullptr) ? ETSObjectType::GetPrecedence(checker, objectType) : Type::GetPrecedence(sourceType);
    if (sourceId > 0U) {
        for (auto const [id, type] : numericTypes) {
            if (id >= sourceId) {
                return type;
            }
        }
        if (sourceType->IsConstantType() && !numericTypes.empty()) {
            return numericTypes.begin()->second;
        }
    }
    return nullptr;
}

//  NOTE! When calling this method we assume that 'AssignmentTarget(...)' check was passes successfully,
//  thus the required assignable type always exists.
checker::Type *ETSUnionType::GetAssignableType(checker::ETSChecker *checker, checker::Type *sourceType) const noexcept
{
    if (IsAssignableType(sourceType)) {
        return sourceType;
    }

    auto *objectType = sourceType->IsETSObjectType()  ? sourceType->AsETSObjectType()
                       : sourceType->IsETSTupleType() ? sourceType->AsETSTupleType()->GetWrapperType()
                                                      : nullptr;
    std::map<std::uint32_t, checker::Type *> numericTypes {};
    bool const isBool = objectType != nullptr ? objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)
                                              : sourceType->HasTypeFlag(TypeFlag::ETS_BOOLEAN);
    bool const isChar = objectType != nullptr ? objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)
                                              : sourceType->HasTypeFlag(TypeFlag::CHAR);

    if (objectType != nullptr) {
        if (objectType->IsETSResizableArrayType() || sourceType->IsETSTupleType()) {
            checker::Type *assignableType = GetAssignableBuiltinType(checker, objectType, isBool, isChar, numericTypes);
            //  NOTE: For array and tuple types, they may be readonly, so we cannot simply use the it
            if (assignableType != nullptr && assignableType->HasTypeFlag(TypeFlag::READONLY)) {
                return assignableType;
            }
        }
        if ((!objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE) ||
             objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_STRING))) {
            //  NOTE: here wo don't cast the actual type to possible base type using in the union, but use it as is!
            return sourceType;
        }
    }

    if (checker::Type *assignableType = GetAssignableBuiltinType(checker, objectType, isBool, isChar, numericTypes);
        assignableType != nullptr) {
        return assignableType;
    }

    if (auto *assignableType = HandleNumericPrecedence(checker, objectType, sourceType, numericTypes)) {
        return assignableType;
    }

    for (auto *constituentType : constituentTypes_) {
        if (constituentType->IsETSObjectType() && constituentType->AsETSObjectType()->IsGlobalETSObjectType()) {
            return constituentType;
        }
    }

    return checker->GlobalTypeError();
}

checker::Type *ETSUnionType::GetAssignableBuiltinType(
    checker::ETSChecker *checker, checker::ETSObjectType *sourceType, bool const isBool, bool const isChar,
    std::map<std::uint32_t, checker::Type *> &numericTypes) const noexcept
{
    checker::Type *assignableType = nullptr;

    for (auto *constituentType : constituentTypes_) {
        if (!constituentType->IsETSObjectType() && !constituentType->IsETSTupleType()) {
            continue;
        }

        auto *const type = constituentType->IsETSTupleType() ? constituentType->AsETSTupleType()->GetWrapperType()
                                                             : constituentType->AsETSObjectType();
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
        } else if (auto const id = ETSObjectType::GetPrecedence(checker, type); id > 0U) {
            numericTypes.emplace(id, constituentType);
        } else if (assignableType == nullptr && sourceType != nullptr &&
                   checker->Relation()->IsSupertypeOf(type, sourceType)) {
            assignableType = constituentType;
        }
    }

    return assignableType;
}

bool ETSUnionType::ExtractType(checker::ETSChecker *checker, checker::ETSObjectType *sourceType,
                               ArenaVector<Type *> &unionTypes) noexcept
{
    std::map<std::uint32_t, ArenaVector<checker::Type *>::const_iterator> numericTypes {};
    bool const isBool = sourceType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN);
    bool const isChar = sourceType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR);

    bool rc = false;
    auto it = unionTypes.cbegin();
    while (it != unionTypes.cend()) {
        auto *constituentType = *it;
        //  Because 'instanceof' expression does not check for type parameters, then for generic types we should
        //  consider that expressions like 'SomeType<U...>' and 'SomeType<T...>' are identical for smart casting.
        //  We also have to pass through all the union to process cases like 'C<T>|A|B|C<U>|undefined`
        if (constituentType->IsETSTypeParameter()) {
            constituentType = constituentType->AsETSTypeParameter()->GetConstraintType();
        } else if (constituentType->HasTypeFlag(checker::TypeFlag::GENERIC)) {
            constituentType = constituentType->Clone(checker);
            constituentType->RemoveTypeFlag(checker::TypeFlag::GENERIC);
        }

        if (checker->Relation()->IsIdenticalTo(constituentType, sourceType)) {
            rc = true;
            it = unionTypes.erase(it);
            continue;
        }

        if (checker->Relation()->IsSupertypeOf(constituentType, sourceType)) {
            rc = true;
        } else if (!rc && constituentType->IsETSObjectType()) {
            auto *const objectType = (*it)->AsETSObjectType();
            if (isBool && objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)) {
                unionTypes.erase(it);
                return true;
            }

            if (isChar && objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
                unionTypes.erase(it);
                return true;
            }

            if (auto const id = ETSObjectType::GetPrecedence(checker, objectType); id > 0U) {
                numericTypes.emplace(id, it);
            }
        }

        ++it;
    }

    if (rc) {
        return true;
    }

    if (auto const sourceId = ETSObjectType::GetPrecedence(checker, sourceType); sourceId > 0U) {
        for (auto const [id, it1] : numericTypes) {
            if (id >= sourceId) {
                unionTypes.erase(it1);
                return true;
            }
        }
    }

    return false;
}

bool ETSUnionType::ExtractType(checker::ETSChecker *checker, checker::ETSArrayType *sourceType,
                               ArenaVector<Type *> &unionTypes) noexcept
{
    auto it = unionTypes.cbegin();

    bool rc = false;
    while (it != unionTypes.cend()) {
        auto *constituentType = *it;

        if (constituentType->IsETSTypeParameter()) {
            constituentType = constituentType->AsETSTypeParameter()->GetConstraintType();
        }

        if (checker->Relation()->IsIdenticalTo(constituentType, sourceType)) {
            rc = true;
            unionTypes.erase(it);
            continue;
        }
        if (checker->Relation()->IsSupertypeOf(constituentType, sourceType)) {
            rc = true;
        }
        ++it;
    }

    return rc;
}

std::pair<checker::Type *, checker::Type *> ETSUnionType::GetComplimentaryType(ETSChecker *const checker,
                                                                               checker::Type *sourceType)
{
    ArenaVector<Type *> unionTypes(checker->Allocator()->Adapter());
    for (auto *it : constituentTypes_) {
        unionTypes.emplace_back(it);
    }
    bool ok = true;

    if (sourceType->IsETSUnionType()) {
        for (auto *const constituentType : sourceType->AsETSUnionType()->ConstituentTypes()) {
            if (ok = ExtractType(checker, constituentType->AsETSObjectType(), unionTypes); !ok) {
                break;
            }
        }
    } else if (sourceType->IsETSArrayType()) {
        ok = ExtractType(checker, sourceType->AsETSArrayType(), unionTypes);
    } else {
        // NOTE(vpukhov): #19701 void refactoring
        if (sourceType->IsETSPrimitiveType() && !sourceType->IsETSVoidType()) {
            sourceType = checker->MaybeBoxInRelation(sourceType);
        } else if (sourceType->HasTypeFlag(checker::TypeFlag::GENERIC)) {
            //  Because 'instanceof' expression does not check for type parameters, then for generic types we should
            //  consider that expressions like 'SomeType<U>' and 'SomeType<T>' are identical for smart casting.
            sourceType = sourceType->Clone(checker);
            sourceType->RemoveTypeFlag(checker::TypeFlag::GENERIC);
        }

        if (sourceType->IsETSObjectType()) {
            ok = ExtractType(checker, sourceType->AsETSObjectType(), unionTypes);
        }
    }

    if (!ok) {
        return std::make_pair(checker->GetGlobalTypesHolder()->GlobalETSNeverType(), this);
    }

    checker::Type *complimentaryType;
    if (unionTypes.size() == 1U) {
        complimentaryType = unionTypes.front();
    } else {
        complimentaryType = checker->CreateETSUnionType(std::move(unionTypes));
    }

    return std::make_pair(sourceType, complimentaryType);
}

Type *ETSUnionType::FindTypeIsCastableToThis(ir::Expression *node, TypeRelation *relation, Type *source) const
{
    ES2PANDA_ASSERT(node);
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
    ES2PANDA_ASSERT(node);
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
                           });  // CC-OFF(G.FMT.02) project code style
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
                           [](Type *t) { return t->IsETSUnboxableObject(); });
    if (it != constituentTypes_.end()) {
        return *it;
    }
    return nullptr;
}

bool ETSUnionType::HasObjectType(ETSObjectFlags flag) const
{
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [flag](Type *t) {
        return t->IsETSObjectType() && t->AsETSObjectType()->HasObjectFlag(flag);
    });
    return it != constituentTypes_.end();
}

Type *ETSUnionType::FindExactOrBoxedType(ETSChecker *checker, Type *const type) const
{
    auto it = std::find_if(constituentTypes_.begin(), constituentTypes_.end(), [checker, type](Type *ct) {
        if (ct->IsETSUnboxableObject()) {
            auto *const unboxedCt = checker->MaybeUnboxInRelation(ct);
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

bool ETSUnionType::HasType(Type *type) const
{
    for (const auto &cType : constituentTypes_) {
        if (cType == type) {
            return true;
        }
    }
    return false;
}

bool ETSUnionType::IsOverlapWith(TypeRelation *relation, Type *type)
{
    // NOTE(aakmaev): replace this func with intersection type when it will be implemented
    for (auto const &ct : ConstituentTypes()) {
        if (type->IsETSUnionType() && type->AsETSUnionType()->IsOverlapWith(relation, ct)) {
            return true;
        }
        if (relation->IsSupertypeOf(ct, type) || relation->IsSupertypeOf(type, ct)) {
            return true;
        }
    }
    return false;
}

ArenaVector<Type *> ETSUnionType::GetNonConstantTypes(ETSChecker *checker, const ArenaVector<Type *> &types)
{
    ArenaVector<Type *> nonConstTypes(checker->Allocator()->Adapter());
    for (const auto &ct : types) {
        nonConstTypes.push_back(checker->GetNonConstantType(ct));
    }
    return nonConstTypes;
}

}  // namespace ark::es2panda::checker
