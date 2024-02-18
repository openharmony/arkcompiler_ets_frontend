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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_TYPE_H

#include "checker/types/ets/etsObjectType.h"

namespace ark::es2panda::checker {
class ETSDynamicType : public ETSObjectType {
public:
    explicit ETSDynamicType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                            ir::AstNode *declNode, ETSObjectFlags flags, TypeRelation *relation, Language lang,
                            bool hasDecl)
        : ETSObjectType(allocator, name, assemblerName, declNode, flags | ETSObjectFlags::DYNAMIC, relation),
          propertiesCache_ {allocator->Adapter()},
          lang_(lang),
          hasDecl_(hasDecl)
    {
        AddTypeFlag(TypeFlag::ETS_DYNAMIC_TYPE);
    }

    varbinder::LocalVariable *GetPropertyDynamic(const util::StringView &name, const ETSChecker *checker) const;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;

    es2panda::Language Language() const
    {
        return lang_;
    }

    bool HasDecl() const
    {
        return hasDecl_;
    }

    ETSFunctionType *CreateETSFunctionType(const util::StringView &name) const override;

    void ToAssemblerType(std::stringstream &ss) const override;

    static bool IsConvertible(Type const *target);

private:
    mutable PropertyMap propertiesCache_;
    es2panda::Language lang_;
    bool hasDecl_;
};
}  // namespace ark::es2panda::checker

#endif
