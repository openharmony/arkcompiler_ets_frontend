/**
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

#include "enumType.h"

#include "varbinder/variable.h"

namespace ark::es2panda::checker {
void EnumType::ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const
{
    ss << enumLiteralVar_->Name() << "." << enumVar_->Name();
}

void EnumType::Identical([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *other)
{
    // NOTE: aszilagyi
}

void EnumType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (source->IsNumberLiteralType()) {
        relation->Result(true);
    }
}

TypeFacts EnumType::GetTypeFacts() const
{
    // NOTE: aszilagyi
    return TypeFacts::NUMBER_FACTS;
}

Type *EnumType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                            [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    // NOTE: aszilagyi
    return this;
}
}  // namespace ark::es2panda::checker
