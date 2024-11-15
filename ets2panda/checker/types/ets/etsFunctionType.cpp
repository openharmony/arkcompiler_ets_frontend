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

#include "etsFunctionType.h"
#include "checker/types/typeRelation.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"

namespace ark::es2panda::checker {

ETSFunctionType::ETSFunctionType(ETSChecker *checker, util::StringView name, ArenaVector<Signature *> &&signatures)
    : Type(TypeFlag::FUNCTION),
      callSignatures_(std::move(signatures)),
      name_(name),
      funcInterface_(checker->ResolveFunctionalInterfaces(callSignatures_))
{
}

Signature *ETSFunctionType::FirstAbstractSignature()
{
    for (auto *it : callSignatures_) {
        if (it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            return it;
        }
    }

    return nullptr;
}

void ETSFunctionType::ToString(std::stringstream &ss, bool precise) const
{
    callSignatures_[0]->ToString(ss, nullptr, false, precise);
}

void ETSFunctionType::Identical(TypeRelation *relation, Type *other)
{
    if (!other->IsETSFunctionType()) {
        return;
    }

    if (callSignatures_.size() == 1 && callSignatures_[0]->HasSignatureFlag(SignatureFlags::TYPE)) {
        AssignmentTarget(relation, other);
        return;
    }

    callSignatures_[0]->Compatible(relation, other->AsETSFunctionType()->CallSignatures()[0]);
}

bool ETSFunctionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (target->IsETSDynamicType()) {
        ASSERT(relation->GetNode() != nullptr);
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            ASSERT(callSignatures_.size() == 1 && callSignatures_[0]->HasSignatureFlag(SignatureFlags::CALL));
            relation->Result(true);
            return true;
        }
        relation->Result(false);
        return false;
    }

    if (target->IsETSObjectType() && target == relation->GetChecker()->AsETSChecker()->GlobalETSObjectType()) {
        relation->Result(true);
        return true;
    }

    relation->Result(false);
    return false;
}

static Signature *EnhanceSignatureSubstitution(TypeRelation *relation, Signature *super, Signature *sub)
{
    auto checker = relation->GetChecker()->AsETSChecker();
    auto *substitution = checker->NewSubstitution();

    auto const enhance = [checker, sub, substitution](Type *param, Type *arg) {
        return checker->EnhanceSubstitutionForType(sub->GetSignatureInfo()->typeParams, param, arg, substitution);
    };
    for (size_t ix = 0; ix < super->MinArgCount(); ix++) {
        if (!enhance(sub->GetSignatureInfo()->params[ix]->TsType(), super->GetSignatureInfo()->params[ix]->TsType())) {
            return nullptr;
        }
    }
    if (super->RestVar() != nullptr) {
        if (!enhance(sub->RestVar()->TsType(), super->RestVar()->TsType())) {
            return nullptr;
        }
    }
    return sub->Substitute(relation, substitution);
}

static bool IsCompatibleSignature(TypeRelation *relation, Signature *super, Signature *sub)
{
    if (super->MinArgCount() != sub->MinArgCount()) {
        return false;
    }
    if ((super->RestVar() != nullptr && sub->RestVar() == nullptr) ||
        (super->RestVar() == nullptr && sub->RestVar() != nullptr)) {
        return false;
    }
    if (!sub->GetSignatureInfo()->typeParams.empty()) {
        sub = EnhanceSignatureSubstitution(relation, super, sub);
        if (sub == nullptr) {
            return false;
        }
    }

    for (size_t idx = 0; idx != super->MinArgCount(); idx++) {
        if (!relation->IsSupertypeOf(sub->Params()[idx]->TsType(), super->Params()[idx]->TsType())) {
            return false;
        }
    }
    if (super->RestVar() != nullptr && !relation->IsSupertypeOf(sub->RestVar()->TsType(), super->RestVar()->TsType())) {
        return false;
    }
    if (!relation->IsSupertypeOf(super->ReturnType(), sub->ReturnType())) {
        return false;
    }
    return true;
}

static ETSFunctionType *CoerceToFunctionType(Type *type)
{
    if (type->IsETSFunctionType()) {
        return type->AsETSFunctionType();
    }
    if (type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        return type->AsETSObjectType()->GetFunctionalInterfaceInvokeType();
    }
    return nullptr;
}

void ETSFunctionType::IsSupertypeOf(TypeRelation *relation, Type *source)
{
    ETSFunctionType *const targetFnType = this;
    ETSFunctionType *const sourceFnType = CoerceToFunctionType(source);
    if (sourceFnType == nullptr) {
        relation->Result(false);
        return;
    }

    ASSERT(targetFnType->IsETSArrowType() && sourceFnType->IsETSArrowType());
    Signature *const targetSig = targetFnType->CallSignatures()[0];
    Signature *const sourceSig = sourceFnType->CallSignatures()[0];

    SavedTypeRelationFlagsContext savedFlagsCtx(relation, relation->GetTypeRelationFlags() |
                                                              TypeRelationFlag::ONLY_CHECK_BOXING_UNBOXING);
    if (!IsCompatibleSignature(relation, targetSig, sourceSig)) {
        relation->Result(false);
        return;
    }

    if (!(targetSig->Function()->IsThrowing() || targetSig->HasSignatureFlag(SignatureFlags::THROWS))) {
        if (sourceSig->Function()->IsThrowing() || sourceSig->Function()->IsRethrowing() ||
            sourceSig->HasSignatureFlag(SignatureFlags::THROWS) ||
            sourceSig->HasSignatureFlag(SignatureFlags::RETHROWS)) {
            relation->Result(false);
            return;
        }
    }

    ASSERT(relation->GetNode() != nullptr);
    relation->Result(true);
}

void ETSFunctionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    ETSFunctionType *const targetFnType = this;
    ETSFunctionType *const sourceFnType = CoerceToFunctionType(source);
    if (sourceFnType == nullptr) {
        relation->Result(false);
        return;
    }

    ASSERT(IsETSArrowType() && CallSignatures()[0]->HasSignatureFlag(SignatureFlags::TYPE));
    Signature *const targetSig = targetFnType->CallSignatures()[0];

    SavedTypeRelationFlagsContext savedFlagsCtx(relation, relation->GetTypeRelationFlags() |
                                                              TypeRelationFlag::ONLY_CHECK_BOXING_UNBOXING);

    // NOTE(vpukhov): #18866 optionally-typed lambda shouldnt have mulutiple signatures
    // CC-OFFNXT(G.FMT.14-CPP) project code style
    Signature *const match = [relation, targetSig, sourceFnType]() -> Signature * {
        for (auto it : sourceFnType->CallSignatures()) {
            if (IsCompatibleSignature(relation, targetSig, it)) {
                return it;
            }
        }
        return nullptr;
    }();
    if (match == nullptr) {
        relation->Result(false);
        return;
    }

    if (!(targetSig->Function()->IsThrowing() || targetSig->HasSignatureFlag(SignatureFlags::THROWS))) {
        if (match->Function()->IsThrowing() || match->Function()->IsRethrowing() ||
            match->HasSignatureFlag(SignatureFlags::THROWS) || match->HasSignatureFlag(SignatureFlags::RETHROWS)) {
            relation->GetChecker()->LogTypeError(
                "Functions that can throw exceptions cannot be assigned to non throwing functions.",
                relation->GetNode()->Start());
            relation->Result(false);
            return;
        }
    }

    ASSERT(relation->GetNode() != nullptr);
    relation->Result(true);
}

Type *ETSFunctionType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                   [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    auto *copiedType = relation->GetChecker()->AsETSChecker()->CreateETSFunctionType(name_);

    for (auto *it : callSignatures_) {
        copiedType->AddCallSignature(it->Copy(allocator, relation, globalTypes));
    }

    return copiedType;
}

ETSFunctionType *ETSFunctionType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }

    auto *checker = relation->GetChecker()->AsETSChecker();

    auto *copiedType = checker->CreateETSFunctionType(name_);
    bool anyChange = false;

    for (auto *sig : callSignatures_) {
        auto *newSig = sig->Substitute(relation, substitution);
        copiedType->AddCallSignature(newSig);
        if (newSig != sig) {
            anyChange = true;
        }
    }

    return anyChange ? copiedType : this;
}

checker::RelationResult ETSFunctionType::CastFunctionParams(TypeRelation *relation, Signature *targetInvokeSig)
{
    auto *ourSig = callSignatures_[0];
    auto &ourParams = ourSig->Params();
    auto &theirParams = targetInvokeSig->Params();
    if (ourParams.size() != theirParams.size()) {
        return RelationResult::FALSE;
    }
    for (size_t i = 0; i < theirParams.size(); i++) {
        relation->Result(RelationResult::FALSE);
        auto savedBoxFlags = relation->GetNode()->GetBoxingUnboxingFlags();
        relation->IsCastableTo(ourParams[i]->TsType(), theirParams[i]->TsType());
        relation->GetNode()->SetBoxingUnboxingFlags(savedBoxFlags);
        if (!relation->IsTrue()) {
            return RelationResult::FALSE;
        }
    }
    return RelationResult::TRUE;
}

void ETSFunctionType::Cast(TypeRelation *relation, Type *target)
{
    ASSERT(relation->GetNode()->IsArrowFunctionExpression());
    auto *savedNode = relation->GetNode();
    conversion::Forbidden(relation);
    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        auto *targetType = target->AsETSObjectType();
        if (targetType->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
            auto *targetInvokeVar = targetType->GetProperty(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME,
                                                            PropertySearchFlags::SEARCH_INSTANCE_METHOD);
            if (targetInvokeVar == nullptr || !targetInvokeVar->TsType()->IsETSFunctionType()) {
                return;
            }
            auto *targetInvokeSig = targetInvokeVar->TsType()->AsETSFunctionType()->CallSignatures()[0];
            relation->Result(CastFunctionParams(relation, targetInvokeSig));
            auto *targetReturnType = targetInvokeSig->ReturnType();
            auto savedBoxFlags = relation->GetNode()->GetBoxingUnboxingFlags();
            relation->IsCastableTo(callSignatures_[0]->ReturnType(), targetReturnType);
            relation->GetNode()->SetBoxingUnboxingFlags(savedBoxFlags);
        }
        if (relation->IsTrue()) {
            relation->SetNode(savedNode);
            return;
        }
    }
}

void ETSFunctionType::IsSubtypeOf(TypeRelation *relation, Type *target)
{
    ETSChecker *checker = relation->GetChecker()->AsETSChecker();
    auto *source = checker->FunctionTypeToFunctionalInterfaceType(callSignatures_[0]);

    if (relation->IsSupertypeOf(target, source)) {
        relation->Result(true);
        return;
    }

    relation->Result(false);
}

ETSFunctionType *ETSFunctionType::BoxPrimitives(ETSChecker *checker)
{
    auto *allocator = checker->Allocator();
    auto *ret = allocator->New<ETSFunctionType>(name_, allocator);
    for (auto *sig : callSignatures_) {
        ret->AddCallSignature(sig->BoxPrimitives(checker));
    }
    return ret;
}
}  // namespace ark::es2panda::checker
