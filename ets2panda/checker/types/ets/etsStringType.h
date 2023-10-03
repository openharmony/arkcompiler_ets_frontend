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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_STRING_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_STRING_TYPE_H

#include "checker/types/ets/etsObjectType.h"

namespace panda::es2panda::checker {
class ETSStringType : public ETSObjectType {
public:
    explicit ETSStringType(ArenaAllocator *allocator, [[maybe_unused]] ETSObjectType *super)
        : ETSObjectType(allocator, ETSObjectFlags::CLASS | ETSObjectFlags::STRING | ETSObjectFlags::RESOLVED_SUPER)
    {
        SetSuperType(super);
    }

    explicit ETSStringType(ArenaAllocator *allocator, ETSObjectType *super, util::StringView value)
        : ETSObjectType(allocator, ETSObjectFlags::CLASS | ETSObjectFlags::STRING | ETSObjectFlags::RESOLVED_SUPER),
          value_(value)
    {
        SetSuperType(super);
        AddTypeFlag(TypeFlag::CONSTANT);
        variable_ = super->Variable();
    }

    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

    void ToString(std::stringstream &ss) const override
    {
        ss << lexer::TokenToString(lexer::TokenType::KEYW_STRING);
    }

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        ss << compiler::Signatures::BUILTIN_STRING;
    }

    util::StringView GetValue() const
    {
        return value_;
    }

private:
    util::StringView value_ {};
};
}  // namespace panda::es2panda::checker

#endif
