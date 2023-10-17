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

#include "arithmetic.h"

#include "ir/expressions/identifier.h"
#include "binder/variable.h"
#include "binder/scope.h"
#include "binder/declaration.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::checker {

Type *ETSChecker::NegateNumericType(Type *type, ir::Expression *node)
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

    TypeFlag type_kind = ETSType(type);
    Type *result = nullptr;

    switch (type_kind) {
        case TypeFlag::BYTE: {
            result = CreateByteType(-(type->AsByteType()->GetValue()));
            break;
        }
        case TypeFlag::CHAR: {
            result = CreateCharType(-(type->AsCharType()->GetValue()));
            break;
        }
        case TypeFlag::SHORT: {
            result = CreateShortType(-(type->AsShortType()->GetValue()));
            break;
        }
        case TypeFlag::INT: {
            result = CreateIntType(-(type->AsIntType()->GetValue()));
            break;
        }
        case TypeFlag::LONG: {
            result = CreateLongType(-(type->AsLongType()->GetValue()));
            break;
        }
        case TypeFlag::FLOAT: {
            result = CreateFloatType(-(type->AsFloatType()->GetValue()));
            break;
        }
        case TypeFlag::DOUBLE: {
            result = CreateDoubleType(-(type->AsDoubleType()->GetValue()));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    node->SetTsType(result);
    return result;
}

Type *ETSChecker::BitwiseNegateIntegralType(Type *type, ir::Expression *node)
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_INTEGRAL));

    TypeFlag type_kind = ETSType(type);

    Type *result = nullptr;

    switch (type_kind) {
        case TypeFlag::BYTE: {
            result = CreateByteType(static_cast<int8_t>(~static_cast<uint8_t>(type->AsByteType()->GetValue())));
            break;
        }
        case TypeFlag::CHAR: {
            result = CreateCharType(~(type->AsCharType()->GetValue()));
            break;
        }
        case TypeFlag::SHORT: {
            result = CreateShortType(static_cast<int16_t>(~static_cast<uint16_t>(type->AsShortType()->GetValue())));
            break;
        }
        case TypeFlag::INT: {
            result = CreateIntType(static_cast<int32_t>(~static_cast<uint32_t>(type->AsIntType()->GetValue())));
            break;
        }
        case TypeFlag::LONG: {
            result = CreateLongType(static_cast<int64_t>(~static_cast<uint64_t>(type->AsLongType()->GetValue())));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    node->SetTsType(result);
    return result;
}

Type *ETSChecker::HandleRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

    if (left->IsDoubleType() || right->IsDoubleType()) {
        return PerformRelationOperationOnTypes<DoubleType>(left, right, operation_type);
    }

    if (left->IsFloatType() || right->IsFloatType()) {
        return PerformRelationOperationOnTypes<FloatType>(left, right, operation_type);
    }

    if (left->IsLongType() || right->IsLongType()) {
        return PerformRelationOperationOnTypes<LongType>(left, right, operation_type);
    }

    return PerformRelationOperationOnTypes<IntType>(left, right, operation_type);
}

// NOLINTNEXTLINE(readability-function-size)
std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperator(ir::Expression *left, ir::Expression *right,
                                                           lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                           bool force_promotion)
{
    checker::Type *const left_type = left->Check(this);
    checker::Type *const right_type = right->Check(this);
    Type *unboxed_l = ETSBuiltinTypeAsPrimitiveType(left_type);
    Type *unboxed_r = ETSBuiltinTypeAsPrimitiveType(right_type);
    checker::Type *ts_type {};
    bool is_equal_op = (operation_type > lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
                        operation_type < lexer::TokenType::PUNCTUATOR_ARROW) &&
                       !force_promotion;

    switch (operation_type) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL: {
            auto [promotedType, bothConst] =
                ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            if (promotedType == nullptr && !bothConst) {
                ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
            }

            if (bothConst) {
                ts_type = HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
            }

            ts_type = (ts_type != nullptr) ? ts_type : promotedType;
            break;
        }

        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL: {
            if (left_type->IsETSStringType() || right_type->IsETSStringType()) {
                ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
            }

            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            if (left_type->IsETSStringType() || right_type->IsETSStringType()) {
                ts_type = HandleStringConcatenation(left_type, right_type);
                break;
            }

            auto [promotedType, bothConst] =
                ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            if (promotedType == nullptr && !bothConst) {
                ThrowTypeError("Bad operand type, the types of the operands must be numeric type or String.", pos);
            }

            if (bothConst) {
                ts_type = HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
                break;
            }

            ts_type = promotedType;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL: {
            auto promoted_left_type = ApplyUnaryOperatorPromotion(unboxed_l, false, !is_equal_op);
            auto promoted_right_type = ApplyUnaryOperatorPromotion(unboxed_r, false, !is_equal_op);

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            if (promoted_left_type == nullptr || !promoted_left_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL) ||
                promoted_right_type == nullptr || !promoted_right_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL)) {
                ThrowTypeError("Bad operand type, the types of the operands must be integral type.", pos);
            }

            if (promoted_left_type->HasTypeFlag(TypeFlag::CONSTANT) &&
                promoted_right_type->HasTypeFlag(TypeFlag::CONSTANT)) {
                ts_type = HandleArithmeticOperationOnTypes(promoted_left_type, promoted_right_type, operation_type);
                break;
            }

            switch (ETSType(promoted_left_type)) {
                case TypeFlag::BYTE: {
                    ts_type = GlobalByteType();
                    break;
                }
                case TypeFlag::SHORT: {
                    ts_type = GlobalShortType();
                    break;
                }
                case TypeFlag::CHAR: {
                    ts_type = GlobalCharType();
                    break;
                }
                case TypeFlag::INT: {
                    ts_type = GlobalIntType();
                    break;
                }
                case TypeFlag::LONG: {
                    ts_type = GlobalLongType();
                    break;
                }
                default: {
                    UNREACHABLE();
                }
            }

            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            if (unboxed_l != nullptr && unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) &&
                unboxed_r != nullptr && unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
                FlagExpressionWithUnboxing(left_type, unboxed_l, left);
                FlagExpressionWithUnboxing(right_type, unboxed_r, right);
                ts_type = HandleBooleanLogicalOperators(unboxed_l, unboxed_r, operation_type);
                break;
            }

            auto [promotedType, bothConst] =
                ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_INTEGRAL, !is_equal_op);

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            if (promotedType == nullptr && !bothConst) {
                ThrowTypeError("Bad operand type, the types of the operands must be integral type.", pos);
            }

            if (bothConst) {
                ts_type = HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
                break;
            }

            ts_type = promotedType;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            if (unboxed_l == nullptr || !unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) ||
                unboxed_r == nullptr || !unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
                ThrowTypeError("Bad operand type, the types of the operands must be boolean type.", pos);
            }

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            ts_type = HandleBooleanLogicalOperators(unboxed_l, unboxed_r, operation_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            if (!(left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) ||
                !(right_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT))) {
                ThrowTypeError("Both operands have to be reference types", pos);
            }

            Relation()->SetNode(left);
            if (!Relation()->IsCastableTo(left_type, right_type) && !Relation()->IsCastableTo(right_type, left_type)) {
                ThrowTypeError("The operands of strict equality are not compatible with each other", pos);
            }
            ts_type = GlobalETSBooleanType();
            if (right_type->IsETSDynamicType() && left_type->IsETSDynamicType()) {
                return {ts_type, GlobalBuiltinJSValueType()};
            }
            return {ts_type, GlobalETSObjectType()};
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            if (left_type->IsETSEnumType() && right_type->IsETSEnumType()) {
                if (!left_type->AsETSEnumType()->IsSameEnumType(right_type->AsETSEnumType())) {
                    ThrowTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
                }

                ts_type = GlobalETSBooleanType();
                return {ts_type, left_type};
            }

            if (IsReferenceType(left_type) && IsReferenceType(right_type)) {
                ts_type = GlobalETSBooleanType();
                auto *op_type = GlobalETSObjectType();
                return {ts_type, op_type};
            }

            if (unboxed_l != nullptr && unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) &&
                unboxed_r != nullptr && unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
                if (unboxed_l->HasTypeFlag(checker::TypeFlag::CONSTANT) &&
                    unboxed_r->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                    bool res = unboxed_l->AsETSBooleanType()->GetValue() == unboxed_r->AsETSBooleanType()->GetValue();

                    ts_type = CreateETSBooleanType(operation_type == lexer::TokenType::PUNCTUATOR_EQUAL ? res : !res);
                    break;
                }

                FlagExpressionWithUnboxing(left_type, unboxed_l, left);
                FlagExpressionWithUnboxing(right_type, unboxed_r, right);

                ts_type = GlobalETSBooleanType();
                break;
            }

            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            auto [promotedType, bothConst] =
                ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

            FlagExpressionWithUnboxing(left_type, unboxed_l, left);
            FlagExpressionWithUnboxing(right_type, unboxed_r, right);

            if (promotedType == nullptr && !bothConst) {
                ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
            }

            if (bothConst) {
                ts_type = HandleRelationOperationOnTypes(left_type, right_type, operation_type);
                break;
            }

            ts_type = GlobalETSBooleanType();
            auto *op_type = promotedType;
            return {ts_type, op_type};
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            if (!left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) ||
                !right_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                ThrowTypeError("Bad operand type, the types of the operands must be same type.", pos);
            }

            if (right_type->IsETSDynamicType() || left_type->IsETSDynamicType()) {
                if (!(right_type->IsETSDynamicType() && left_type->IsETSDynamicType())) {
                    ThrowTypeError("Bad operand type, both types of the operands must be dynamic.", pos);
                }
            }

            ts_type = GlobalETSBooleanType();
            checker::Type *op_type =
                right_type->IsETSDynamicType() ? GlobalBuiltinJSValueType() : GlobalETSObjectType();
            return {ts_type, op_type};
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            if (!left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                ThrowTypeError("Left-hand side expression must be a reference type.", pos);
            }

            checker::Type *non_nullable_left_type = left_type;

            if (left_type->IsNullableType()) {
                non_nullable_left_type = left_type->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder());
                non_nullable_left_type->RemoveTypeFlag(TypeFlag::NULLABLE);
            }

            // TODO(user): check convertibility and use numeric promotion

            if (right_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
                Relation()->SetNode(right);
                auto boxed_right_type = PrimitiveTypeAsETSBuiltinType(right_type);
                if (boxed_right_type == nullptr) {
                    ThrowTypeError("Invalid right-hand side expression", pos);
                }
                right->AddBoxingUnboxingFlag(GetBoxingFlag(boxed_right_type));
                ts_type = FindLeastUpperBound(non_nullable_left_type, boxed_right_type);
                break;
            }

            ts_type = FindLeastUpperBound(non_nullable_left_type, right_type);
            break;
        }
        default: {
            // TODO(user):
            UNREACHABLE();
            break;
        }
    }

    return {ts_type, ts_type};
}

Type *ETSChecker::HandleArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

    if (left->IsDoubleType() || right->IsDoubleType()) {
        return PerformArithmeticOperationOnTypes<DoubleType>(left, right, operation_type);
    }

    if (left->IsFloatType() || right->IsFloatType()) {
        return PerformArithmeticOperationOnTypes<FloatType>(left, right, operation_type);
    }

    if (left->IsLongType() || right->IsLongType()) {
        return PerformArithmeticOperationOnTypes<LongType>(left, right, operation_type);
    }

    return PerformArithmeticOperationOnTypes<IntType>(left, right, operation_type);
}

void ETSChecker::FlagExpressionWithUnboxing(Type *type, Type *unboxed_type, ir::Expression *type_expression)
{
    if (type->IsETSObjectType() && (unboxed_type != nullptr)) {
        type_expression->AddBoxingUnboxingFlag(GetUnboxingFlag(unboxed_type));
    }
}

}  // namespace panda::es2panda::checker
