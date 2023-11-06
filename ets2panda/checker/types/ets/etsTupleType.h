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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H

#include "checker/types/type.h"
#include "checker/types/ets/etsArrayType.h"

namespace panda::es2panda::checker {

class ETSTupleType : public ETSArrayType {
    using TupleSizeType = int32_t;

public:
    explicit ETSTupleType(ArenaAllocator *const allocator, Type *const element_type = nullptr,
                          Type *const spread_type = nullptr)
        : ETSArrayType(element_type), type_list_(allocator->Adapter()), spread_type_(spread_type)
    {
        type_flags_ |= TypeFlag::ETS_TUPLE;
    }

    explicit ETSTupleType(ArenaAllocator *const allocator, const TupleSizeType size, Type *const element_type = nullptr,
                          Type *const spread_type = nullptr)
        : ETSArrayType(element_type), type_list_(allocator->Adapter()), spread_type_(spread_type), size_(size)
    {
        type_flags_ |= TypeFlag::ETS_TUPLE;
    }
    explicit ETSTupleType(const ArenaVector<Type *> &type_list, Type *const element_type = nullptr,
                          Type *const spread_type = nullptr)
        : ETSArrayType(element_type),
          type_list_(type_list),
          spread_type_(spread_type),
          size_(static_cast<TupleSizeType>(type_list.size()))
    {
        type_flags_ |= TypeFlag::ETS_TUPLE;
    }

    [[nodiscard]] TupleSizeType GetTupleSize() const
    {
        return size_;
    }

    [[nodiscard]] TupleSizeType GetMinTupleSize() const
    {
        return size_ + (spread_type_ == nullptr ? 0 : 1);
    }

    [[nodiscard]] ArenaVector<Type *> GetTupleTypesList() const
    {
        return type_list_;
    }

    [[nodiscard]] bool HasSpreadType() const
    {
        return spread_type_ != nullptr;
    }

    [[nodiscard]] Type *GetSpreadType() const
    {
        return spread_type_;
    }

    void SetSpreadType(Type *const new_spread_type)
    {
        spread_type_ = new_spread_type;
    }

    [[nodiscard]] Type *GetTypeAtIndex(int32_t index) const;

    void ToString(std::stringstream &ss) const override;

    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void Cast(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

private:
    ArenaVector<Type *> type_list_;
    Type *spread_type_ {};
    TupleSizeType size_ {0};
};

}  // namespace panda::es2panda::checker

#endif /* ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TUPLE_TYPE_H */
