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

#include "etsStringType.h"

#include "varbinder/ETSBinder.h"

namespace ark::es2panda::checker {
void ETSStringType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsETSStringType()) {
        relation->Result(true);
    }
}

bool ETSStringType::AssignmentSource(TypeRelation *relation, Type *target)
{
    auto node = relation->GetNode();
    if ((relation->InAssignmentContext() || relation->ApplyStringToChar()) && IsConvertibleTo(target)) {
        node->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOX_TO_CHAR);
        relation->Result(true);
    } else {
        relation->Result(target->IsETSStringType());
    }

    return relation->IsTrue();
}

void ETSStringType::AssignmentTarget([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *source)
{
    if (source->IsETSStringType()) {
        relation->Result(true);
    }
}

Type *ETSStringType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                 [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    return this;
}

bool ETSStringType::IsConvertibleTo(Type const *to) const
{
    const bool targetIsChar =
        to->IsCharType() ||
        // ETSObjectType is used in arrow function expression call.
        (to->IsETSObjectType() && to->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR));

    return targetIsChar && IsConstantType() && value_.IsConvertibleToChar();
}

}  // namespace ark::es2panda::checker
