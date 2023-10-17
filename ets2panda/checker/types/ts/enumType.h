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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_ENUM_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_ENUM_TYPE_H

#include "checker/types/type.h"

namespace panda::es2panda::binder {
class EnumVariable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
class EnumType : public Type {
public:
    EnumType(binder::Variable *enum_literal_var, binder::EnumVariable *enum_var)
        : Type(TypeFlag::ENUM), enum_literal_var_(enum_literal_var), enum_var_(enum_var)
    {
    }

    const binder::Variable *EnumLiteralVar() const
    {
        return enum_literal_var_;
    }

    const binder::EnumVariable *EnumVar() const
    {
        return enum_var_;
    }

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    TypeFacts GetTypeFacts() const override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

private:
    binder::Variable *enum_literal_var_;
    binder::EnumVariable *enum_var_;
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_ENUM_TYPE_H */
