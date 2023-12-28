/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

namespace panda::es2panda::checker {
class ETSTypeParameter : public Type {
public:
    explicit ETSTypeParameter() : Type(TypeFlag::ETS_TYPE_PARAMETER) {}
    explicit ETSTypeParameter(Type *default_type, Type *constraint_type)
        : Type(TypeFlag::ETS_TYPE_PARAMETER), default_(default_type), constraint_(constraint_type)
    {
    }

    void SetDeclNode(ir::TSTypeParameter *decl)
    {
        decl_node_ = decl;
    }

    ir::TSTypeParameter *GetDeclNode() const
    {
        return decl_node_;
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
        return constraint_;
    }

    bool HasConstraint() const
    {
        return GetConstraintType() != nullptr;
    }

    Type *EffectiveConstraint(ETSChecker const *checker) const;

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;

    bool ConstraintIsSubtypeOf(TypeRelation *relation, Type *target)
    {
        if (HasConstraint()) {
            target->IsSupertypeOf(relation, GetConstraintType());
        } else {
            relation->Result(false);
        }
        return relation->IsTrue();
    }

    void ToAssemblerType(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;

private:
    ir::TSTypeParameter *decl_node_ {};
    Type *default_ {};
    Type *constraint_ {};
};
}  // namespace panda::es2panda::checker

#endif
