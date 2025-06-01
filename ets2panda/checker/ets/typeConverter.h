/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_TYPE_CONVERTER_H
#define ES2PANDA_COMPILER_CHECKER_ETS_TYPE_CONVERTER_H

#include "checker/types/typeFlag.h"
#include "checker/types/ets/types.h"

namespace ark::es2panda::checker {
class ETSChecker;

class TypeConverter {
public:
    TypeConverter(ETSChecker *checker, TypeRelation *relation, Type *target, Type *source);
    Type *Result() const;
    void SetResult(Type *result);
    Type *Source() const;
    Type *Target() const;
    TypeRelation *Relation() const;
    ETSChecker *Checker() const;

    //  Function should be used ONLY if all the required checks were passed and
    //  correct conversion is possible without accuracy loss!
    template <typename SourceType, typename TargetType>
    static TargetType *ConvertConstant(SourceType *source, ArenaAllocator *allocator)
    {
        if constexpr (std::is_same_v<std::decay_t<SourceType>, std::decay_t<TargetType>>) {
            return source;
        } else {
            auto target = allocator->New<TargetType>(static_cast<typename TargetType::UType>(source->GetValue()));

            if constexpr (!std::is_same_v<std::decay_t<TargetType>, DoubleType> &&
                          !std::is_same_v<std::decay_t<TargetType>, FloatType>) {
                ES2PANDA_ASSERT(source->GetValue() == static_cast<typename SourceType::UType>(target->GetValue()));
            } else if constexpr (std::is_same_v<std::decay_t<SourceType>, DoubleType>) {
                ES2PANDA_ASSERT((std::is_same_v<std::decay_t<TargetType>, FloatType>));
                ES2PANDA_ASSERT(
                    std::isnan(source->GetValue()) || std::isinf(source->GetValue()) ||
                    (std::abs(source->GetValue()) <= static_cast<double>(std::numeric_limits<float>::max()) &&
                     std::abs(source->GetValue()) >= static_cast<double>(std::numeric_limits<float>::min())));
            }

            return target;
        }
    }

    //  Function should be used ONLY if all the required checks were passed and
    //  correct conversion is possible without accuracy loss!
    template <typename TargetType>
    static Type *ConvertConstantType(Type *source, ArenaAllocator *allocator)
    {
        switch (static_cast<TypeFlag>(source->TypeFlags() & TypeFlag::ETS_TYPE)) {
            case TypeFlag::INT:
                return ConvertConstant<IntType, TargetType>(source->AsIntType(), allocator);

            case TypeFlag::LONG:
                return ConvertConstant<LongType, TargetType>(source->AsLongType(), allocator);

            case TypeFlag::DOUBLE:
                return ConvertConstant<DoubleType, TargetType>(source->AsDoubleType(), allocator);

            case TypeFlag::SHORT:
                return ConvertConstant<ShortType, TargetType>(source->AsShortType(), allocator);

            case TypeFlag::FLOAT:
                return ConvertConstant<FloatType, TargetType>(source->AsFloatType(), allocator);

            case TypeFlag::BYTE:
                return ConvertConstant<ByteType, TargetType>(source->AsByteType(), allocator);

            case TypeFlag::CHAR:
                return ConvertConstant<CharType, TargetType>(source->AsCharType(), allocator);

            default:
                ES2PANDA_UNREACHABLE();
        }
    }

    //  Function should be used ONLY if all the required checks were passed and
    //  correct conversion is possible without accuracy loss!
    static Type *ConvertConstantTypes(Type *source, Type *target, ArenaAllocator *allocator)
    {
        ES2PANDA_ASSERT(source->IsETSPrimitiveType() && target->IsETSPrimitiveType() && source->IsConstantType());

        switch (static_cast<TypeFlag>(target->TypeFlags() & TypeFlag::ETS_TYPE)) {
            case TypeFlag::INT:
                return ConvertConstantType<IntType>(source, allocator);

            case TypeFlag::LONG:
                return ConvertConstantType<LongType>(source, allocator);

            case TypeFlag::DOUBLE:
                return ConvertConstantType<DoubleType>(source, allocator);

            case TypeFlag::SHORT:
                return ConvertConstantType<ShortType>(source, allocator);

            case TypeFlag::FLOAT:
                return ConvertConstantType<FloatType>(source, allocator);

            case TypeFlag::BYTE:
                return ConvertConstantType<ByteType>(source, allocator);

            case TypeFlag::CHAR:
                return ConvertConstantType<CharType>(source, allocator);

            default:
                ES2PANDA_UNREACHABLE();
        }
    }

private:
    ETSChecker *checker_;
    TypeRelation *relation_;
    Type *target_;
    Type *source_;
    Type *result_ {};
};
}  // namespace ark::es2panda::checker

#endif
