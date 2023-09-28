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

#include "numberLiteralType.h"

#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/enumType.h"

namespace panda::es2panda::checker {
void NumberLiteralType::ToString(std::stringstream &ss) const
{
    ss << util::Helpers::ToString(value_);
}

void NumberLiteralType::ToStringAsSrc(std::stringstream &ss) const
{
    ss << "number";
}

void NumberLiteralType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsNumberLiteralType()) {
        relation->Result(value_ == other->AsNumberLiteralType()->Value());
    }
}

void NumberLiteralType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (source->IsEnumType()) {
        const EnumType *source_enum_type = source->AsEnumType();
        const binder::EnumVariable *enum_var = source_enum_type->EnumVar();

        if (std::holds_alternative<double>(enum_var->Value()) && value_ == std::get<double>(enum_var->Value())) {
            relation->Result(true);
        }
    }
}

TypeFacts NumberLiteralType::GetTypeFacts() const
{
    return value_ == 0 ? TypeFacts::ZERO_NUMBER_FACTS : TypeFacts::NON_ZERO_NUMBER_FACTS;
}

Type *NumberLiteralType::Instantiate([[maybe_unused]] ArenaAllocator *allocator,
                                     [[maybe_unused]] TypeRelation *relation,
                                     [[maybe_unused]] GlobalTypesHolder *global_types)
{
    return this;
}
}  // namespace panda::es2panda::checker
