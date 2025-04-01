/**
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H

#include "checker/types/type.h"

namespace ark::es2panda::checker {

class ETSTupleType : public Type {
    using TupleSizeType = std::size_t;

public:
    explicit ETSTupleType(ArenaAllocator *const allocator, Type *const lubType, ETSArrayType *const holderArrayType)
        : Type(checker::TypeFlag::ETS_TUPLE),
          typeList_(allocator->Adapter()),
          lubType_(lubType),
          holderArrayType_(holderArrayType)
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }

    explicit ETSTupleType(ArenaAllocator *const allocator, const TupleSizeType size, Type *const lubType,
                          ETSArrayType *const holderArrayType)
        : Type(checker::TypeFlag::ETS_TUPLE),
          typeList_(allocator->Adapter()),
          lubType_(lubType),
          holderArrayType_(holderArrayType),
          size_(size)
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }

    explicit ETSTupleType(const ArenaVector<Type *> &typeList, Type *const lubType, ETSArrayType *const holderArrayType)
        : Type(checker::TypeFlag::ETS_TUPLE),
          typeList_(typeList),
          lubType_(lubType),
          holderArrayType_(holderArrayType),
          size_(typeList.size())
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }

    [[nodiscard]] Type *GetLubType() const
    {
        return lubType_;
    }

    [[nodiscard]] TupleSizeType GetTupleSize() const
    {
        return size_;
    }

    [[nodiscard]] ETSArrayType *GetHolderArrayType() const
    {
        return holderArrayType_;
    }

    [[nodiscard]] ArenaVector<Type *> const &GetTupleTypesList() const
    {
        return typeList_;
    }

    std::tuple<bool, bool> ResolveConditionExpr() const override
    {
        return {false, false};
    }

    [[nodiscard]] Type *GetTypeAtIndex(TupleSizeType index) const;

    void ToString(std::stringstream &ss, bool precise) const override;

    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    void IsSubtypeOf(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    void CheckVarianceRecursively(TypeRelation *relation, VarianceFlag varianceFlag) override;

    void ToAssemblerType(std::stringstream &ss) const override;
    void ToAssemblerTypeWithRank(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;
    uint32_t Rank() const override;

private:
    ArenaVector<Type *> const typeList_;
    Type *const lubType_ {};
    ETSArrayType *const holderArrayType_ {};
    TupleSizeType size_ {0};
};

}  // namespace ark::es2panda::checker

#endif /* ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H */
