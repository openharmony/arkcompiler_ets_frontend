/*
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_STRING_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_STRING_TYPE_H

#include "checker/types/ets/etsObjectType.h"

namespace ark::es2panda::checker {
class ETSStringType : public ETSObjectType {
public:
    explicit ETSStringType(ArenaAllocator *allocator, [[maybe_unused]] ETSObjectType *super)
        : ETSObjectType(allocator, ETSObjectFlags::CLASS | ETSObjectFlags::STRING | ETSObjectFlags::RESOLVED_SUPER)
    {
        SetSuperType(super);
        SetAssemblerName(compiler::Signatures::BUILTIN_STRING);
    }

    explicit ETSStringType(ArenaAllocator *allocator, [[maybe_unused]] ETSObjectType *super, TypeRelation *relation)
        : ETSObjectType(allocator, ETSObjectFlags::CLASS | ETSObjectFlags::STRING | ETSObjectFlags::RESOLVED_SUPER,
                        relation)
    {
        SetSuperType(super);
        SetAssemblerName(compiler::Signatures::BUILTIN_STRING);
    }

    explicit ETSStringType(ArenaAllocator *allocator, ETSObjectType *super, TypeRelation *relation,
                           util::StringView value)
        : ETSObjectType(allocator, ETSObjectFlags::CLASS | ETSObjectFlags::STRING | ETSObjectFlags::RESOLVED_SUPER,
                        relation),
          value_(value)
    {
        SetSuperType(super);
        SetAssemblerName(compiler::Signatures::BUILTIN_STRING);
        AddTypeFlag(TypeFlag::CONSTANT);
        variable_ = super->Variable();
    }

    void Identical(TypeRelation *relation, Type *other) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    void IsSubtypeOf(TypeRelation *relation, Type *source) override;

    void ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const override
    {
        if (IsConstantType()) {
            ss << "\"" << value_ << "\"";
        } else {
            ss << lexer::TokenToString(lexer::TokenType::KEYW_STRING);
        }
    }

    void ToAssemblerType(std::stringstream &ss) const override
    {
        ss << compiler::Signatures::BUILTIN_STRING;
    }

    util::StringView GetValue() const
    {
        return value_;
    }

    std::tuple<bool, bool> ResolveConditionExpr() const override
    {
        return {IsConstantType(), IsConstantType() ? (GetValue().Length() != 0) : false};
    }

    bool IsConvertibleTo(Type const *to) const;

private:
    util::StringView value_ {};
};
}  // namespace ark::es2panda::checker

#endif
