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

#include "etsFunctionType.h"
#include "checker/types/typeRelation.h"
#include "checker/ETSchecker.h"
#include "ir/base/scriptFunction.h"

namespace ark::es2panda::checker {
//  Use this constructor in the internal class methods ONLY!
ETSFunctionType::ETSFunctionType(ETSChecker *checker, util::StringView const &name,
                                 ArenaVector<Signature *> &&signatures)
    : Type(TypeFlag::FUNCTION),
      callSignatures_(std::move(signatures)),
      name_(name),
      funcInterface_(checker->FunctionTypeToFunctionalInterfaceType(callSignatures_[0]))
{
}

ETSFunctionType::ETSFunctionType(ETSChecker *checker, util::StringView const &name, Signature *const signature)
    : Type(TypeFlag::FUNCTION),
      callSignatures_(checker->Allocator()->Adapter()),
      name_(name),
      funcInterface_(checker->FunctionTypeToFunctionalInterfaceType(signature))
{
    callSignatures_.push_back(signature);
}

ETSFunctionType::ETSFunctionType(util::StringView const &name, ArenaAllocator *allocator)
    : Type(TypeFlag::FUNCTION), callSignatures_(allocator->Adapter()), name_(name), funcInterface_(nullptr)
{
}

ETSFunctionType::ETSFunctionType(ETSChecker *checker, util::StringView const &name, Signature *signature,
                                 ETSObjectType *interface)
    : Type(TypeFlag::FUNCTION), callSignatures_(checker->Allocator()->Adapter()), name_(name), funcInterface_(interface)
{
    callSignatures_.emplace_back(signature);
}

void ETSFunctionType::AddCallSignature(Signature *signature)
{
    if (signature->Function()->IsGetter() && !signature->Function()->IsExtensionMethod()) {
        AddTypeFlag(TypeFlag::GETTER);
    } else if (signature->Function()->IsSetter() && !signature->Function()->IsExtensionMethod()) {
        AddTypeFlag(TypeFlag::SETTER);
    }
    callSignatures_.push_back(signature);
}

void ETSFunctionType::ToString(std::stringstream &ss, bool precise) const
{
    callSignatures_[0]->ToString(ss, nullptr, false, precise);
    for (std::size_t i = 1U; i < callSignatures_.size(); ++i) {
        ss << " & ";
        callSignatures_[i]->ToString(ss, nullptr, false, precise);
    }
}

void ETSFunctionType::Identical(TypeRelation *relation, Type *other)
{
    relation->Result(false);
    if (other->IsETSFunctionType()) {
        if (callSignatures_.size() == 1U && CallSignature()->IsTypeAnnotation()) {
            AssignmentTarget(relation, other);
        } else {
            CallSignature()->Compatible(relation, other->AsETSFunctionType()->CallSignature());
        }
    }
}

bool ETSFunctionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (target->IsETSDynamicType()) {
        ASSERT(relation->GetNode() != nullptr);
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            ASSERT(callSignatures_.size() == 1 && callSignatures_[0]->HasSignatureFlag(SignatureFlags::CALL));
            return relation->Result(true);
        }
        return relation->Result(false);
    }

    return relation->Result(target->IsETSObjectType() &&
                            target == relation->GetChecker()->AsETSChecker()->GlobalETSObjectType());
}

static Signature *EnhanceSignatureSubstitution(TypeRelation *relation, Signature *super, Signature *sub)
{
    auto checker = relation->GetChecker()->AsETSChecker();
    auto *substitution = checker->NewSubstitution();
    auto const &typeParameters = sub->GetSignatureInfo()->typeParams;

    auto const enhance = [checker, substitution, &typeParameters](Type *param, Type *arg) -> bool {
        return checker->EnhanceSubstitutionForType(typeParameters, param, arg, substitution);
    };

    std::size_t const paramCount =
        relation->InAssignmentContext() ? std::min(sub->Params().size(), super->Params().size()) : super->MinArgCount();

    for (std::size_t i = 0U; i < paramCount; ++i) {
        if (!enhance(sub->Params()[i]->TsType(), super->Params()[i]->TsType())) {
            return nullptr;
        }
    }

    if (super->HasRestParameter() && sub->HasRestParameter()) {
        if (!enhance(sub->RestVar()->TsType(), super->RestVar()->TsType())) {
            return nullptr;
        }
    }

    return sub->Substitute(relation, substitution);
}

static bool CheckThrowing(Signature *super, Signature *sub) noexcept
{
    if (!(super->Throws() || (super->Function() != nullptr && super->Function()->IsThrowing()))) {
        if (!(super->Rethrows() || (super->Function() != nullptr && super->Function()->IsRethrowing()))) {
            if (sub->Throwing() ||
                (sub->Function() != nullptr && (sub->Function()->IsThrowing() || sub->Function()->IsRethrowing()))) {
                return false;
            }
        } else {
            if (sub->Throws() || (sub->Function() != nullptr && sub->Function()->IsThrowing())) {
                return false;
            }
        }
    }
    return true;
}

static bool CheckGeneralProperties(TypeRelation *relation, Signature *super, Signature *sub) noexcept
{
    if (relation->InAssignmentContext()) {
        if (super->MinArgCount() < sub->MinArgCount()) {
            return false;
        }
    } else {
        if (super->MinArgCount() != sub->MinArgCount()) {
            return false;
        }
    }

    if (!CheckThrowing(super, sub)) {
        return false;
    }

    if (super->HasRestParameter() && !sub->HasRestParameter()) {
        return false;
    }

    if ((super->Flags() & SignatureFlags::GETTER_OR_SETTER) != (sub->Flags() & SignatureFlags::GETTER_OR_SETTER)) {
        return false;
    }

    return true;
}

static bool IsCompatibleSignature(TypeRelation *relation, Signature *super, Signature *sub)
{
    if (!CheckGeneralProperties(relation, super, sub)) {
        return false;
    }

    if (!sub->TypeParams().empty()) {
        sub = EnhanceSignatureSubstitution(relation, super, sub);
        if (sub == nullptr) {
            return false;
        }
    }

    std::size_t i = 0U;
    std::size_t const paramCount =
        relation->InAssignmentContext() ? std::min(sub->Params().size(), super->Params().size()) : super->MinArgCount();
    for (; i != paramCount; ++i) {
        if (!relation->IsSupertypeOf(sub->Params()[i]->TsType(), super->Params()[i]->TsType()) &&
            !relation->IsAssignableTo(super->Params()[i]->TsType(), sub->Params()[i]->TsType())) {
            return false;
        }
    }

    if (relation->InAssignmentContext() && i < super->Params().size() && sub->HasRestParameter()) {
        auto *const restType = sub->RestVar()->TsType()->AsETSArrayType()->ElementType();
        for (; i != super->Params().size(); ++i) {
            if (!relation->IsSupertypeOf(restType, super->Params()[i]->TsType()) &&
                !relation->IsAssignableTo(super->Params()[i]->TsType(), restType)) {
                return false;
            }
        }
    }

    if (super->HasRestParameter() && !relation->IsSupertypeOf(sub->RestVar()->TsType(), super->RestVar()->TsType()) &&
        !relation->IsAssignableTo(super->RestVar()->TsType(), sub->RestVar()->TsType())) {
        return false;
    }

    if (!relation->IsSupertypeOf(super->ReturnType(), sub->ReturnType()) &&
        !relation->IsAssignableTo(sub->ReturnType(), super->ReturnType())) {
        return false;
    }

    return true;
}

static ETSFunctionType *CoerceToFunctionType(Type *type) noexcept
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
    relation->Result(false);

    ETSFunctionType *const sourceFnType = CoerceToFunctionType(source);
    if (sourceFnType == nullptr) {
        return;
    }

    ASSERT(IsETSArrowType() && sourceFnType->IsETSArrowType());

    Signature *const targetSig = CallSignature();
    Signature *sourceSig = sourceFnType->CallSignature();

    SavedTypeRelationFlagsContext savedFlagsCtx(relation, relation->GetTypeRelationFlags() |
                                                              TypeRelationFlag::ONLY_CHECK_BOXING_UNBOXING);

    relation->Result(IsCompatibleSignature(relation, targetSig, sourceSig));
}

void ETSFunctionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    relation->Result(false);

    ETSFunctionType *const sourceFnType = CoerceToFunctionType(source);
    if (sourceFnType == nullptr) {
        return;
    }

    ASSERT(IsETSArrowType() && CallSignature()->IsTypeAnnotation());

    // As the source function a class method can be used which can be overloaded - loop required
    for (auto signature : sourceFnType->CallSignatures()) {
        if (IsCompatibleSignature(relation, CallSignature(), signature)) {
            relation->Result(true);
            return;
        }
    }
}

ETSFunctionType *ETSFunctionType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation,
                                              GlobalTypesHolder *globalTypes)
{
    auto signatures = ArenaVector<Signature *>(allocator->Adapter());
    for (auto *const signature : callSignatures_) {
        signatures.emplace_back(signature->Copy(allocator, relation, globalTypes));
    }

    return allocator->New<ETSFunctionType>(relation->GetChecker()->AsETSChecker(), name_, std::move(signatures));
}

ETSFunctionType *ETSFunctionType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution != nullptr && !substitution->empty()) {
        auto *const checker = relation->GetChecker()->AsETSChecker();
        auto *const allocator = checker->Allocator();

        auto signatures = ArenaVector<Signature *>(allocator->Adapter());
        bool anyChange = false;

        for (auto *const signature : callSignatures_) {
            auto *newSignature = signature->Substitute(relation, substitution);
            anyChange |= newSignature != signature;
            signatures.emplace_back(newSignature);
        }

        if (anyChange) {
            return allocator->New<ETSFunctionType>(checker, name_, std::move(signatures));
        }
    }

    return this;
}

checker::RelationResult ETSFunctionType::CastFunctionParams(TypeRelation *relation,
                                                            Signature *targetInvokeSig) const noexcept
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
    relation->Result(false);

    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        auto *targetType = target->AsETSObjectType();
        if (targetType->IsGlobalETSObjectType()) {
            relation->Result(true);
            return;
        }
        auto *savedNode = relation->GetNode();
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
    } else if (target->IsETSFunctionType()) {
        Identical(relation, target);
    }
}

void ETSFunctionType::CastTarget(TypeRelation *const relation, Type *source)
{
    Cast(relation, relation->GetChecker()->AsETSChecker()->GetNonNullishType(source));
}

ETSFunctionType *ETSFunctionType::BoxPrimitives(ETSChecker *checker) const
{
    auto *allocator = checker->Allocator();

    auto signatures = ArenaVector<Signature *>(allocator->Adapter());
    for (auto *const signature : callSignatures_) {
        signatures.emplace_back(signature->BoxPrimitives(checker));
    }

    return allocator->New<ETSFunctionType>(checker, name_, std::move(signatures));
}
}  // namespace ark::es2panda::checker
