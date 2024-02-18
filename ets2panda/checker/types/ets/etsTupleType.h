/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "checker/types/ets/etsArrayType.h"

namespace ark::es2panda::checker {

class ETSTupleType : public ETSArrayType {
    using TupleSizeType = int32_t;

public:
    explicit ETSTupleType(ArenaAllocator *const allocator, Type *const elementType = nullptr,
                          Type *const spreadType = nullptr)
        : ETSArrayType(elementType), typeList_(allocator->Adapter()), spreadType_(spreadType)
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }

    explicit ETSTupleType(ArenaAllocator *const allocator, const TupleSizeType size, Type *const elementType = nullptr,
                          Type *const spreadType = nullptr)
        : ETSArrayType(elementType), typeList_(allocator->Adapter()), spreadType_(spreadType), size_(size)
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }
    explicit ETSTupleType(const ArenaVector<Type *> &typeList, Type *const elementType = nullptr,
                          Type *const spreadType = nullptr)
        : ETSArrayType(elementType),
          typeList_(typeList),
          spreadType_(spreadType),
          size_(static_cast<TupleSizeType>(typeList.size()))
    {
        typeFlags_ |= TypeFlag::ETS_TUPLE;
    }

    [[nodiscard]] TupleSizeType GetTupleSize() const
    {
        return size_;
    }

    [[nodiscard]] TupleSizeType GetMinTupleSize() const
    {
        return size_ + (spreadType_ == nullptr ? 0 : 1);
    }

    [[nodiscard]] ArenaVector<Type *> const &GetTupleTypesList() const
    {
        return typeList_;
    }

    [[nodiscard]] bool HasSpreadType() const
    {
        return spreadType_ != nullptr;
    }

    [[nodiscard]] Type *GetSpreadType() const
    {
        return spreadType_;
    }

    void SetSpreadType(Type *const newSpreadType)
    {
        spreadType_ = newSpreadType;
    }

    [[nodiscard]] Type *GetTypeAtIndex(int32_t index) const;

    void ToString(std::stringstream &ss, bool precise) const override;

    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    void Cast(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;

private:
    ArenaVector<Type *> const typeList_;
    Type *spreadType_ {};
    TupleSizeType size_ {0};
};

}  // namespace ark::es2panda::checker

#endif /* ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H */
