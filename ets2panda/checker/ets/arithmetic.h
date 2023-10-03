/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_ARITHMETIC_H
#define ES2PANDA_COMPILER_CHECKER_ETS_ARITHMETIC_H

#include "checker/ETSchecker.h"
#include "checker/types/ets/etsBooleanType.h"

namespace panda::es2panda::checker {

template <typename TargetType>
typename TargetType::UType ETSChecker::GetOperand(Type *type)
{
    switch (ETSType(type)) {
        case TypeFlag::BYTE: {
            return type->AsByteType()->GetValue();
        }
        case TypeFlag::CHAR: {
            return type->AsCharType()->GetValue();
        }
        case TypeFlag::SHORT: {
            return type->AsShortType()->GetValue();
        }
        case TypeFlag::INT: {
            return type->AsIntType()->GetValue();
        }
        case TypeFlag::LONG: {
            return type->AsLongType()->GetValue();
        }
        case TypeFlag::FLOAT: {
            return type->AsFloatType()->GetValue();
        }
        case TypeFlag::DOUBLE: {
            return type->AsDoubleType()->GetValue();
        }
        default: {
            UNREACHABLE();
        }
    }
}

template <typename TargetType>
Type *ETSChecker::PerformRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type)
{
    using UType = typename TargetType::UType;

    UType left_value = GetOperand<TargetType>(left);
    UType right_value = GetOperand<TargetType>(right);

    bool result {};
    switch (operation_type) {
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            result = left_value < right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            result = left_value <= right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            result = left_value > right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            result = left_value >= right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            result = left_value == right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            result = left_value != right_value;
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    return CreateETSBooleanType(result);
}

template <typename TargetType>
Type *ETSChecker::PerformArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type)
{
    using UType = typename TargetType::UType;

    UType left_value = GetOperand<TargetType>(left);
    UType right_value = GetOperand<TargetType>(right);
    auto result = left_value;
    auto is_forbidden_zero_division = [&]() { return std::is_integral<UType>::value && right_value == 0; };

    switch (operation_type) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            result = left_value + right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL: {
            result = left_value - right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL: {
            if (is_forbidden_zero_division()) {
                return nullptr;
            }
            result = left_value / right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL: {
            result = left_value * right_value;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL: {
            if (is_forbidden_zero_division()) {
                return nullptr;
            }
            result = HandleModulo<UType>(left_value, right_value);
            break;
        }
        default: {
            result = HandleBitWiseArithmetic<UType>(left_value, right_value, operation_type);
        }
    }

    return Allocator()->New<TargetType>(result);
}

template <>
inline IntType::UType panda::es2panda::checker::ETSChecker::HandleModulo<IntType::UType>(IntType::UType left_value,
                                                                                         IntType::UType right_value)
{
    return left_value % right_value;
}

template <>
inline LongType::UType panda::es2panda::checker::ETSChecker::HandleModulo<LongType::UType>(LongType::UType left_value,
                                                                                           LongType::UType right_value)
{
    return left_value % right_value;
}

template <>
inline FloatType::UType panda::es2panda::checker::ETSChecker::HandleModulo<FloatType::UType>(
    FloatType::UType left_value, FloatType::UType right_value)
{
    return std::fmod(left_value, right_value);
}

template <>
inline DoubleType::UType panda::es2panda::checker::ETSChecker::HandleModulo<DoubleType::UType>(
    DoubleType::UType left_value, DoubleType::UType right_value)
{
    return std::fmod(left_value, right_value);
}

template <typename UType>
UType ETSChecker::HandleBitWiseArithmetic(UType left_value, UType right_value, lexer::TokenType operation_type)
{
    using UnsignedType = std::make_unsigned_t<UType>;
    auto unsigned_left_value = static_cast<UnsignedType>(left_value);
    auto unsigned_right_value = static_cast<UnsignedType>(right_value);
    size_t mask = std::numeric_limits<UnsignedType>::digits - 1U;
    size_t shift = static_cast<UnsignedType>(unsigned_right_value) & mask;

    switch (operation_type) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL: {
            return unsigned_left_value & unsigned_right_value;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL: {
            return unsigned_left_value | unsigned_right_value;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL: {
            return unsigned_left_value ^ unsigned_right_value;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL: {
            static_assert(sizeof(UType) == 4 || sizeof(UType) == 8);
            return unsigned_left_value << shift;
        }
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL: {
            static_assert(sizeof(UType) == 4 || sizeof(UType) == 8);
            return left_value >> shift;  // NOLINT(hicpp-signed-bitwise)
        }
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL: {
            static_assert(sizeof(UType) == 4 || sizeof(UType) == 8);
            return unsigned_left_value >> shift;
        }
        default: {
            UNREACHABLE();
        }
    }
}

template <>
inline FloatType::UType ETSChecker::HandleBitWiseArithmetic<FloatType::UType>(
    [[maybe_unused]] FloatType::UType left_value, [[maybe_unused]] FloatType::UType right_value,
    [[maybe_unused]] lexer::TokenType operation_type)
{
    return 0.0;
}

template <>
inline DoubleType::UType ETSChecker::HandleBitWiseArithmetic<DoubleType::UType>(
    [[maybe_unused]] DoubleType::UType left_value, [[maybe_unused]] DoubleType::UType right_value,
    [[maybe_unused]] lexer::TokenType operation_type)
{
    return 0.0;
}
}  // namespace panda::es2panda::checker

#endif
