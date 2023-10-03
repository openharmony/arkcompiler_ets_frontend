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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_TYPE_H

#include "checker/types/ets/etsObjectType.h"

namespace panda::es2panda::checker {
class ETSDynamicType : public ETSObjectType {
public:
    explicit ETSDynamicType(ArenaAllocator *allocator, util::StringView name, util::StringView assembler_name,
                            ir::AstNode *decl_node, ETSObjectFlags flags, Language lang)
        : ETSObjectType(allocator, name, assembler_name, decl_node, flags | ETSObjectFlags::DYNAMIC),
          properties_cache_ {allocator->Adapter()},
          lang_(lang)
    {
        AddTypeFlag(TypeFlag::ETS_DYNAMIC_TYPE);
    }

    static bool IsDynamicType(util::StringView assembler_name);

    binder::LocalVariable *GetPropertyDynamic(const util::StringView &name, const ETSChecker *checker) const;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;

    es2panda::Language Language() const
    {
        return lang_;
    }

private:
    bool IsConvertableTo(Type *target) const;

    mutable PropertyMap properties_cache_;
    es2panda::Language lang_;
};
}  // namespace panda::es2panda::checker

#endif
