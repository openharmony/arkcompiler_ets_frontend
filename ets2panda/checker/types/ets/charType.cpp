/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "charType.h"

#include "checker/ets/conversion.h"
#include "checker/ets/narrowingWideningConverter.h"

namespace ark::es2panda::checker {
void CharType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsCharType()) {
        relation->Result(true);
    }
}

void CharType::AssignmentTarget(TypeRelation *relation, [[maybe_unused]] Type *source)
{
    if (relation->ApplyUnboxing()) {
        relation->GetChecker()->AsETSChecker()->AddUnboxingFlagToPrimitiveType(relation, source, this);
    }
    NarrowingWideningConverter(relation->GetChecker()->AsETSChecker(), relation, this, source);
}

bool CharType::AssignmentSource([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *target)
{
    if (relation->InAssignmentContext()) {
        if (target->IsETSStringType()) {
            conversion::Boxing(relation, this);
            relation->GetNode()->AddAstNodeFlags(ir::AstNodeFlags::CONVERT_TO_STRING);
            return relation->Result(true);
        }
        relation->GetChecker()->AsETSChecker()->CheckUnboxedTypeWidenable(relation, target, this);
        if (!relation->IsTrue()) {
            return false;
        }
    }

    if (relation->ApplyBoxing() && target->IsETSObjectType()) {
        relation->GetChecker()->AsETSChecker()->CheckBoxedSourceTypeAssignable(relation, this, target);
    }

    return relation->IsTrue();
}

void CharType::Cast(TypeRelation *const relation, Type *const target)
{
    if (target->HasTypeFlag(TypeFlag::CHAR)) {
        conversion::Identity(relation, this, target);
        return;
    }

    if (target->HasTypeFlag(TypeFlag::BYTE | TypeFlag::SHORT)) {
        conversion::NarrowingPrimitive(relation, this, target);
        return;
    }

    if (target->HasTypeFlag(TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
        conversion::WideningPrimitive(relation, this, target);
        return;
    }

    if (target->IsETSStringType()) {
        conversion::String(relation, this);
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        if (target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
            conversion::Boxing(relation, this);
            return;
        }

        if (target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE)) {
            auto unboxedTarget = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(target);
            if (unboxedTarget == nullptr) {
                conversion::Forbidden(relation);
                return;
            }
            Cast(relation, unboxedTarget);
            if (relation->IsTrue()) {
                conversion::Boxing(relation, unboxedTarget);
                return;
            }
            conversion::Forbidden(relation);
            return;
        }

        conversion::BoxingWideningReference(relation, this, target->AsETSObjectType());
        return;
    }

    conversion::Forbidden(relation);
}

Type *CharType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                            [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    return this;
}
}  // namespace ark::es2panda::checker
