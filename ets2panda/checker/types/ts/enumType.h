
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_ENUM_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_ENUM_TYPE_H

#include "checker/types/type.h"

namespace ark::es2panda::varbinder {
class EnumVariable;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::checker {
class EnumType : public Type {
public:
    EnumType(varbinder::Variable *enumLiteralVar, varbinder::EnumVariable *enumVar)
        : Type(TypeFlag::ENUM), enumLiteralVar_(enumLiteralVar), enumVar_(enumVar)
    {
    }

    const varbinder::Variable *EnumLiteralVar() const
    {
        return enumLiteralVar_;
    }

    const varbinder::EnumVariable *EnumVar() const
    {
        return enumVar_;
    }

    void ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    TypeFacts GetTypeFacts() const override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;

private:
    varbinder::Variable *enumLiteralVar_;
    varbinder::EnumVariable *enumVar_;
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_ENUM_TYPE_H */
