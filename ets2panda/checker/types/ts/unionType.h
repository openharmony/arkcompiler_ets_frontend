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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_UNION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_UNION_TYPE_H

#include "plugins/ecmascript/es2panda/checker/types/type.h"

namespace panda::es2panda::checker {
class GlobalTypesHolder;

class UnionType : public Type {
public:
    UnionType(ArenaAllocator *allocator, std::initializer_list<Type *> types)
        : Type(TypeFlag::UNION),
          constituent_types_(allocator->Adapter()),
          cached_synthetic_properties_(allocator->Adapter())
    {
        for (auto *it : types) {
            constituent_types_.push_back(it);
        }

        for (auto *it : constituent_types_) {
            AddConstituentFlag(it->TypeFlags());
        }
    }

    explicit UnionType(ArenaAllocator *allocator, ArenaVector<Type *> &&constituent_types)
        : Type(TypeFlag::UNION),
          constituent_types_(std::move(constituent_types)),
          cached_synthetic_properties_(allocator->Adapter())
    {
        for (auto *it : constituent_types_) {
            AddConstituentFlag(it->TypeFlags());
        }
    }

    explicit UnionType(ArenaAllocator *allocator, ArenaVector<Type *> &constituent_types)
        : Type(TypeFlag::UNION),
          constituent_types_(constituent_types),
          cached_synthetic_properties_(allocator->Adapter())
    {
        for (auto *it : constituent_types_) {
            AddConstituentFlag(it->TypeFlags());
        }
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
        if ((HasConstituentFlag(TypeFlag::NUMBER) && type->IsNumberLiteralType()) ||
            (HasConstituentFlag(TypeFlag::STRING) && type->IsStringLiteralType()) ||
            (HasConstituentFlag(TypeFlag::BIGINT) && type->IsBigintLiteralType()) ||
            (HasConstituentFlag(TypeFlag::BOOLEAN) && type->IsBooleanLiteralType())) {
            return;
        }

        for (auto *it : constituent_types_) {
            if (relation->IsIdenticalTo(it, type)) {
                return;
            }
        }

        AddConstituentFlag(type->TypeFlags());
        constituent_types_.push_back(type);
    }

    void AddConstituentFlag(TypeFlag flag)
    {
        constituent_flags_ |= flag;
    }

    void RemoveConstituentFlag(TypeFlag flag)
    {
        constituent_flags_ &= ~flag;
    }

    bool HasConstituentFlag(TypeFlag flag) const
    {
        return (constituent_flags_ & flag) != 0;
    }

    ArenaUnorderedMap<util::StringView, binder::Variable *> &CachedSyntheticProperties()
    {
        return cached_synthetic_properties_;
    }

    ObjectType *MergedObjectType()
    {
        return merged_object_type_;
    }

    void SetMergedObjectType(ObjectType *type)
    {
        merged_object_type_ = type;
    }

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    TypeFacts GetTypeFacts() const override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

    static void RemoveDuplicatedTypes(TypeRelation *relation, ArenaVector<Type *> &constituent_types);
    static Type *HandleUnionType(UnionType *union_type, GlobalTypesHolder *global_types_holder);
    static void RemoveRedundantLiteralTypesFromUnion(UnionType *type);

private:
    static bool EachTypeRelatedToSomeType(TypeRelation *relation, UnionType *source, UnionType *target);
    static bool TypeRelatedToSomeType(TypeRelation *relation, Type *source, UnionType *target);

    ArenaVector<Type *> constituent_types_;
    TypeFlag constituent_flags_ {TypeFlag::NONE};
    ArenaUnorderedMap<util::StringView, binder::Variable *> cached_synthetic_properties_;
    ObjectType *merged_object_type_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_UNION_TYPE_H */
