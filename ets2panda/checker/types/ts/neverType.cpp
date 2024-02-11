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

#include "neverType.h"

namespace ark::es2panda::checker {
void NeverType::ToString(std::stringstream &ss) const
{
    ss << "never";
}

TypeFacts NeverType::GetTypeFacts() const
{
    return TypeFacts::NONE;
}

void NeverType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsNeverType()) {
        relation->Result(true);
    }
}

void NeverType::AssignmentTarget(TypeRelation *relation, [[maybe_unused]] Type *source)
{
    relation->Result(false);
}

bool NeverType::AssignmentSource(TypeRelation *relation, [[maybe_unused]] Type *target)
{
    relation->Result(true);
    return true;
}

Type *NeverType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                             [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    return this;
}
}  // namespace ark::es2panda::checker