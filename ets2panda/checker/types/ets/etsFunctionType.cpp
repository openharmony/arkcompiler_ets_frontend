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

#include "etsFunctionType.h"
#include "checker/types/typeRelation.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"

namespace panda::es2panda::checker {

Signature *ETSFunctionType::FirstAbstractSignature()
{
    for (auto *it : callSignatures_) {
        if (it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            return it;
        }
    }

    return nullptr;
}

void ETSFunctionType::ToString(std::stringstream &ss) const
{
    callSignatures_[0]->ToString(ss, nullptr);
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

    callSignatures_[0]->Identical(relation, other->AsETSFunctionType()->CallSignatures()[0]);
}

bool ETSFunctionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (target->IsETSDynamicType()) {
        ASSERT(relation->GetNode() != nullptr);
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            ASSERT(callSignatures_.size() == 1 && callSignatures_[0]->HasSignatureFlag(SignatureFlags::CALL));
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForLambdaReference(
                relation->GetNode()->AsArrowFunctionExpression(), callSignatures_[0]->Owner());
            relation->Result(true);
            return true;
        }
        relation->Result(false);
        return false;
    }

    relation->Result(false);
    return false;
}

static Signature *ProcessSignatures(TypeRelation *relation, Signature *target, ETSFunctionType *sourceFuncType)
{
    Signature *match {};
    for (auto *it : sourceFuncType->CallSignatures()) {
        if (target->MinArgCount() != it->MinArgCount()) {
            continue;
        }

        if ((target->RestVar() != nullptr && it->RestVar() == nullptr) ||
            (target->RestVar() == nullptr && it->RestVar() != nullptr)) {
            continue;
        }

        if (!it->GetSignatureInfo()->typeParams.empty()) {
            auto *substitution = relation->GetChecker()->AsETSChecker()->NewSubstitution();
            auto *instantiatedTypeParams = relation->GetChecker()->AsETSChecker()->NewInstantiatedTypeParamsSet();
            bool res = true;
            for (size_t ix = 0; ix < target->MinArgCount(); ix++) {
                res &= relation->GetChecker()->AsETSChecker()->EnhanceSubstitutionForType(
                    it->GetSignatureInfo()->typeParams, it->GetSignatureInfo()->params[ix]->TsType(),
                    target->GetSignatureInfo()->params[ix]->TsType(), substitution, instantiatedTypeParams);
            }
            if (target->RestVar() != nullptr) {
                res &= relation->GetChecker()->AsETSChecker()->EnhanceSubstitutionForType(
                    it->GetSignatureInfo()->typeParams, it->RestVar()->TsType(), target->RestVar()->TsType(),
                    substitution, instantiatedTypeParams);
            }
            if (!res) {
                continue;
            }
            it = it->Substitute(relation, substitution);
        }

        size_t idx = 0;
        for (; idx != target->MinArgCount(); idx++) {
            if (!relation->IsIdenticalTo(target->Params()[idx]->TsType(), it->Params()[idx]->TsType())) {
                break;
            }
        }

        if (idx != target->MinArgCount()) {
            continue;
        }

        if (target->RestVar() != nullptr &&
            !relation->IsIdenticalTo(target->RestVar()->TsType(), it->RestVar()->TsType())) {
            continue;
        }

        if (!relation->IsAssignableTo(target->ReturnType(), it->ReturnType())) {
            continue;
        }

        match = it;
        break;
    }
    return match;
}

void ETSFunctionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (!source->IsETSFunctionType() &&
        (!source->IsETSObjectType() || !source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
        return;
    }

    ASSERT(callSignatures_.size() == 1 && callSignatures_[0]->HasSignatureFlag(SignatureFlags::TYPE));

    Signature *target = callSignatures_[0];
    bool sourceIsFunctional = source->IsETSObjectType();
    auto *sourceFuncType = sourceIsFunctional ? source->AsETSObjectType()->GetFunctionalInterfaceInvokeType()
                                              : source->AsETSFunctionType();
    Signature *match = ProcessSignatures(relation, target, sourceFuncType);

    if (match == nullptr) {
        relation->Result(false);
        return;
    }

    if (!target->Function()->IsThrowing()) {
        if (match->Function()->IsThrowing() || match->Function()->IsRethrowing()) {
            relation->GetChecker()->ThrowTypeError(
                "Functions that can throw exceptions cannot be assigned to non throwing functions.",
                relation->GetNode()->Start());
        }
    }

    ASSERT(relation->GetNode() != nullptr);
    if (!sourceIsFunctional) {
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForLambdaReference(
                relation->GetNode()->AsArrowFunctionExpression(), callSignatures_[0]->Owner());
        } else {
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForFunctionReference(relation->GetNode(), match,
                                                                                           callSignatures_[0]->Owner());
        }
    }

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

checker::RelationResult ETSFunctionType::CastFunctionParams(TypeRelation *relation, Type *target)
{
    auto *targetType = target->AsETSObjectType();
    auto *body = targetType->GetDeclNode()->AsTSInterfaceDeclaration()->Body();
    auto targetParams = body->AsTSInterfaceBody()->Body()[0]->AsMethodDefinition()->Function()->Params();
    for (size_t i = 0; i < targetType->TypeArguments().size(); i++) {
        relation->Result(RelationResult::FALSE);
        callSignatures_[0]->Function()->Params()[i]->TsType()->Cast(
            relation, targetParams[i]->AsETSParameterExpression()->Check(relation->GetChecker()->AsETSChecker()));
        if (relation->IsTrue()) {
            continue;
        }
        return RelationResult::FALSE;
    }
    return RelationResult::TRUE;
}

void ETSFunctionType::Cast(TypeRelation *relation, Type *target)
{
    ASSERT(relation->GetNode()->IsArrowFunctionExpression());
    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        auto *targetType = target->AsETSObjectType();
        auto *body = targetType->GetDeclNode()->AsTSInterfaceDeclaration()->Body()->AsTSInterfaceBody();
        auto targetParams = body->AsTSInterfaceBody()->Body()[0]->AsMethodDefinition()->Function()->Params();
        if (targetType->HasObjectFlag(ETSObjectFlags::FUNCTIONAL_INTERFACE) &&
            targetParams.size() == callSignatures_[0]->Function()->Params().size()) {
            relation->Result(CastFunctionParams(relation, target));
        }
        relation->Result(RelationResult::FALSE);
        auto targetReturnType = body->Body()[0]->AsMethodDefinition()->Function()->ReturnTypeAnnotation();
        callSignatures_[0]->ReturnType()->Cast(relation, targetReturnType->TsType());
        if (relation->IsTrue()) {
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForLambdaReference(
                relation->GetNode()->AsArrowFunctionExpression(), targetType->AsETSObjectType());
            return;
        }
    }
    conversion::Forbidden(relation);
}
}  // namespace panda::es2panda::checker
