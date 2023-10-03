/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"

namespace panda::es2panda::checker {
void ETSAsyncFuncReturnType::ToString(std::stringstream &ss) const
{
    promise_type_->ToString(ss);
    ss << " | ";
    GetPromiseTypeArg()->ToString(ss);
}

void ETSAsyncFuncReturnType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsETSAsyncFuncReturnType()) {
        auto *other_ret_type = other->AsETSAsyncFuncReturnType();
        if (relation->IsIdenticalTo(promise_type_, other_ret_type->promise_type_) &&
            relation->IsIdenticalTo(GetPromiseTypeArg(), other_ret_type->GetPromiseTypeArg())) {
            relation->Result(true);
            return;
        }
    }

    relation->Result(false);
}

bool ETSAsyncFuncReturnType::AssignmentSource([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *target)
{
    return false;
}

void ETSAsyncFuncReturnType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    relation->IsAssignableTo(source, promise_type_) || relation->IsAssignableTo(source, GetPromiseTypeArg());
    if (relation->IsTrue() && !source->IsETSObjectType() && relation->ApplyBoxing()) {
        relation->GetChecker()->AsETSChecker()->AddBoxingFlagToPrimitiveType(relation, source);
    }
}
}  // namespace panda::es2panda::checker
