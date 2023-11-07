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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TYPE_PARAMETER_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TYPE_PARAMETER_TYPE_H

#include "checker/types/type.h"
#include "ir/astNode.h"

namespace ark::es2panda::checker {
class ETSTypeParameter : public Type {
public:
    explicit ETSTypeParameter() : Type(TypeFlag::ETS_TYPE_PARAMETER) {}
    explicit ETSTypeParameter(Type *defaultType, Type *constraintType)
        : Type(TypeFlag::ETS_TYPE_PARAMETER), default_(defaultType), constraint_(constraintType)
    {
    }

    void SetDeclNode(ir::TSTypeParameter *decl)
    {
        declNode_ = decl;
    }

    ir::TSTypeParameter *GetDeclNode() const
    {
        return declNode_;
    }

    ETSTypeParameter *GetOriginal() const;

    void SetDefaultType(Type *type)
    {
        default_ = type;
    }

    Type *GetDefaultType() const
    {
        return default_;
    }

    void SetConstraintType(Type *type)
    {
        constraint_ = type;
    }

    Type *GetConstraintType() const
    {
        ASSERT(constraint_ != nullptr);
        return constraint_;
    }

    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    void IsSubtypeOf(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;

    void ToAssemblerType(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;

private:
    ir::TSTypeParameter *declNode_ {};
    Type *default_ {};
    Type *constraint_ {};
};
}  // namespace ark::es2panda::checker

#endif
