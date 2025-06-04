/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ENUM_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ENUM_TYPE_H

#include "checker/types/ets/etsObjectType.h"
#include "checker/types/ets/etsObjectTypeConstants.h"
#include "checker/types/typeFlag.h"

namespace ark::es2panda::checker {

class ETSEnumType : public ETSObjectType {
public:
    explicit ETSEnumType(ArenaAllocator *allocator, util::StringView name, util::StringView internalName,
                         ir::AstNode *declNode, TypeRelation *relation)
        : ETSObjectType(allocator, name, internalName,
                        std::make_tuple(declNode, ETSObjectFlags::CLASS | ETSObjectFlags::ENUM_OBJECT, relation))
    {
    }

    NO_COPY_SEMANTIC(ETSEnumType);
    NO_MOVE_SEMANTIC(ETSEnumType);

    ETSEnumType() = delete;
    ~ETSEnumType() override = default;

    static constexpr std::string_view const TO_STRING_METHOD_NAME {"toString"};
    static constexpr std::string_view const VALUE_OF_METHOD_NAME {"valueOf"};
    static constexpr std::string_view const GET_NAME_METHOD_NAME {"getName"};
    static constexpr std::string_view const GET_VALUE_OF_METHOD_NAME {"getValueOf"};
    static constexpr std::string_view const FROM_VALUE_METHOD_NAME {"fromValue"};
    static constexpr std::string_view const VALUES_METHOD_NAME {"values"};
    static constexpr std::string_view const GET_ORDINAL_METHOD_NAME {"getOrdinal"};
    static constexpr std::string_view const DOLLAR_GET_METHOD_NAME {"$_get"};
};

class ETSIntEnumType : public ETSEnumType {
public:
    explicit ETSIntEnumType(ArenaAllocator *allocator, util::StringView name, util::StringView internalName,
                            ir::AstNode *declNode, TypeRelation *relation)
        : ETSEnumType(allocator, name, internalName, declNode, relation)
    {
        AddTypeFlag(checker::TypeFlag::ETS_INT_ENUM);
    }

    NO_COPY_SEMANTIC(ETSIntEnumType);
    NO_MOVE_SEMANTIC(ETSIntEnumType);

    ETSIntEnumType() = delete;
    ~ETSIntEnumType() override = default;

    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;
};

class ETSStringEnumType : public ETSEnumType {
public:
    explicit ETSStringEnumType(ArenaAllocator *allocator, util::StringView name, util::StringView internalName,
                               ir::AstNode *declNode, TypeRelation *relation)
        : ETSEnumType(allocator, name, internalName, declNode, relation)
    {
        AddTypeFlag(checker::TypeFlag::ETS_STRING_ENUM);
    }

    NO_COPY_SEMANTIC(ETSStringEnumType);
    NO_MOVE_SEMANTIC(ETSStringEnumType);

    ETSStringEnumType() = delete;
    ~ETSStringEnumType() override = default;

    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;
};

}  // namespace ark::es2panda::checker

#endif