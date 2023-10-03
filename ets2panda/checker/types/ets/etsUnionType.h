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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_UNION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_UNION_TYPE_H

#include "checker/types/type.h"

namespace panda::es2panda::checker {
class GlobalTypesHolder;

class ETSUnionType : public Type {
public:
    explicit ETSUnionType(ArenaAllocator *allocator)
        : Type(TypeFlag::ETS_UNION), constituent_types_(allocator->Adapter())
    {
    }

    explicit ETSUnionType(ArenaVector<Type *> &&constituent_types)
        : Type(TypeFlag::ETS_UNION), constituent_types_(std::move(constituent_types))
    {
    }

    explicit ETSUnionType(ArenaVector<Type *> &constituent_types)
        : Type(TypeFlag::ETS_UNION), constituent_types_(constituent_types)
    {
    }

    const ArenaVector<Type *> &ConstituentTypes() const
    {
        return constituent_types_;
    }

    ArenaVector<Type *> &ConstituentTypes()
    {
        return constituent_types_;
    }

    void AddConstituentType(Type *type, TypeRelation *relation)
    {
        for (auto *it : constituent_types_) {
            if (relation->IsIdenticalTo(it, type)) {
                return;
            }
        }

        constituent_types_.push_back(type);
    }

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastToThis(TypeRelation *relation, Type *source);
    Type *FindTypeIsCastableToThis(ir::Expression *node, TypeRelation *relation, Type *source) const;
    Type *FindTypeIsCastableToSomeType(ir::Expression *node, TypeRelation *relation, Type *target) const;

    Type *GetLeastUpperBoundType(ETSChecker *checker);

    Type *GetLeastUpperBoundType() const
    {
        ASSERT(lub_type_ != nullptr);
        return lub_type_;
    }

    static Type *HandleUnionType(ETSUnionType *union_type);

private:
    static bool EachTypeRelatedToSomeType(TypeRelation *relation, ETSUnionType *source, ETSUnionType *target);
    static bool TypeRelatedToSomeType(TypeRelation *relation, Type *source, ETSUnionType *target);

    ArenaVector<Type *> constituent_types_;
    Type *lub_type_ {nullptr};
};
}  // namespace panda::es2panda::checker

#endif /* ETS_TYPES_ETS_UNION_TYPE_H */
