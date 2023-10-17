/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "ir/expressions/identifier.h"

namespace panda::es2panda::checker {

Signature *ETSFunctionType::FirstAbstractSignature()
{
    for (auto *it : call_signatures_) {
        if (it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            return it;
        }
    }

    return nullptr;
}

void ETSFunctionType::ToString(std::stringstream &ss) const
{
    call_signatures_[0]->ToString(ss, nullptr);
}

void ETSFunctionType::Identical(TypeRelation *relation, Type *other)
{
    if (!other->IsETSFunctionType()) {
        return;
    }

    if (call_signatures_.size() == 1 && call_signatures_[0]->HasSignatureFlag(SignatureFlags::TYPE)) {
        AssignmentTarget(relation, other);
        return;
    }

    call_signatures_[0]->Identical(relation, other->AsETSFunctionType()->CallSignatures()[0]);
}

bool ETSFunctionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (target->IsETSDynamicType()) {
        ASSERT(relation->GetNode() != nullptr);
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            ASSERT(call_signatures_.size() == 1 && call_signatures_[0]->HasSignatureFlag(SignatureFlags::CALL));
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForLambdaReference(
                relation->GetNode()->AsArrowFunctionExpression(), call_signatures_[0]->Owner());
            relation->Result(true);
            return true;
        }
        relation->Result(false);
        return false;
    }

    relation->Result(false);
    return false;
}

void ETSFunctionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (!source->IsETSFunctionType() &&
        (!source->IsETSObjectType() || !source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
        return;
    }

    ASSERT(call_signatures_.size() == 1 && call_signatures_[0]->HasSignatureFlag(SignatureFlags::TYPE));

    Signature *target = call_signatures_[0];
    Signature *match {};
    bool source_is_functional = source->IsETSObjectType();
    auto *source_func_type = source_is_functional ? source->AsETSObjectType()->GetFunctionalInterfaceInvokeType()
                                                  : source->AsETSFunctionType();

    for (auto *it : source_func_type->CallSignatures()) {
        if (target->MinArgCount() != it->MinArgCount()) {
            continue;
        }

        if ((target->RestVar() != nullptr && it->RestVar() == nullptr) ||
            (target->RestVar() == nullptr && it->RestVar() != nullptr)) {
            continue;
        }

        if (!it->GetSignatureInfo()->type_params.empty()) {
            auto *substitution = relation->GetChecker()->AsETSChecker()->NewSubstitution();
            for (size_t ix = 0; ix < target->MinArgCount(); ix++) {
                relation->GetChecker()->AsETSChecker()->EnhanceSubstitutionForType(
                    it->GetSignatureInfo()->type_params, it->GetSignatureInfo()->params[ix]->TsType(),
                    target->GetSignatureInfo()->params[ix]->TsType(), substitution);
            }
            if (target->RestVar() != nullptr) {
                relation->GetChecker()->AsETSChecker()->EnhanceSubstitutionForType(
                    it->GetSignatureInfo()->type_params, it->RestVar()->TsType(), target->RestVar()->TsType(),
                    substitution);
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
    if (!source_is_functional) {
        if (relation->GetNode()->IsArrowFunctionExpression()) {
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForLambdaReference(
                relation->GetNode()->AsArrowFunctionExpression(), call_signatures_[0]->Owner());
        } else {
            relation->GetChecker()->AsETSChecker()->CreateLambdaObjectForFunctionReference(
                relation->GetNode(), match, call_signatures_[0]->Owner());
        }
    }

    relation->Result(true);
}

Type *ETSFunctionType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                   [[maybe_unused]] GlobalTypesHolder *global_types)
{
    auto *copied_type = relation->GetChecker()->AsETSChecker()->CreateETSFunctionType(name_);

    for (auto *it : call_signatures_) {
        copied_type->AddCallSignature(it->Copy(allocator, relation, global_types));
    }

    return copied_type;
}

ETSFunctionType *ETSFunctionType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }

    auto *checker = relation->GetChecker()->AsETSChecker();

    auto *copied_type = checker->CreateETSFunctionType(name_);
    bool any_change = false;

    for (auto *sig : call_signatures_) {
        auto *new_sig = sig->Substitute(relation, substitution);
        copied_type->AddCallSignature(new_sig);
        if (new_sig != sig) {
            any_change = true;
        }
    }

    return any_change ? copied_type : this;
}

}  // namespace panda::es2panda::checker
