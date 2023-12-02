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

#include "arithmetic.h"

#include "ir/expressions/identifier.h"
#include "varbinder/variable.h"
#include "varbinder/scope.h"
#include "varbinder/declaration.h"
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

checker::Type *ETSChecker::CheckBinaryOperatorMulDivMod(ir::Expression *left, ir::Expression *right,
                                                        lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                        bool is_equal_op, checker::Type *const left_type,
                                                        checker::Type *const right_type, Type *unboxed_l,
                                                        Type *unboxed_r)
{
    checker::Type *ts_type {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

    FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    FlagExpressionWithUnboxing(right_type, unboxed_r, right);

    if (left_type->IsETSUnionType() || right_type->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
    }

    if (bothConst) {
        ts_type = HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
    }

    ts_type = (ts_type != nullptr) ? ts_type : promotedType;
    return ts_type;
}

checker::Type *ETSChecker::CheckBinaryOperatorPlus(ir::Expression *left, ir::Expression *right,
                                                   lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                   bool is_equal_op, checker::Type *const left_type,
                                                   checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    if (left_type->IsETSUnionType() || right_type->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (left_type->IsETSStringType() || right_type->IsETSStringType()) {
        return HandleStringConcatenation(left_type, right_type);
    }

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

    FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    FlagExpressionWithUnboxing(right_type, unboxed_r, right);

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type or String.", pos);
    }

    if (bothConst) {
        return HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
    }

    return promotedType;
}

checker::Type *ETSChecker::CheckBinaryOperatorShift(ir::Expression *left, ir::Expression *right,
                                                    lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                    bool is_equal_op, checker::Type *const left_type,
                                                    checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    if (left_type->IsETSUnionType() || right_type->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    auto promoted_left_type = ApplyUnaryOperatorPromotion(unboxed_l, false, !is_equal_op);
    auto promoted_right_type = ApplyUnaryOperatorPromotion(unboxed_r, false, !is_equal_op);

    FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    FlagExpressionWithUnboxing(right_type, unboxed_r, right);

    if (promoted_left_type == nullptr || !promoted_left_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL) ||
        promoted_right_type == nullptr || !promoted_right_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL)) {
        ThrowTypeError("Bad operand type, the types of the operands must be integral type.", pos);
    }

    if (promoted_left_type->HasTypeFlag(TypeFlag::CONSTANT) && promoted_right_type->HasTypeFlag(TypeFlag::CONSTANT)) {
        return HandleArithmeticOperationOnTypes(promoted_left_type, promoted_right_type, operation_type);
    }

    switch (ETSType(promoted_left_type)) {
        case TypeFlag::BYTE: {
            return GlobalByteType();
        }
        case TypeFlag::SHORT: {
            return GlobalShortType();
        }
        case TypeFlag::CHAR: {
            return GlobalCharType();
        }
        case TypeFlag::INT: {
            return GlobalIntType();
        }
        case TypeFlag::LONG: {
            return GlobalLongType();
        }
        default: {
            UNREACHABLE();
        }
    }
    return nullptr;
}

checker::Type *ETSChecker::CheckBinaryOperatorBitwise(ir::Expression *left, ir::Expression *right,
                                                      lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                      bool is_equal_op, checker::Type *const left_type,
                                                      checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    if (left_type->IsETSUnionType() || right_type->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (unboxed_l != nullptr && unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) && unboxed_r != nullptr &&
        unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
        FlagExpressionWithUnboxing(left_type, unboxed_l, left);
        FlagExpressionWithUnboxing(right_type, unboxed_r, right);
        return HandleBooleanLogicalOperators(unboxed_l, unboxed_r, operation_type);
    }

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_INTEGRAL, !is_equal_op);

    FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    FlagExpressionWithUnboxing(right_type, unboxed_r, right);

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be integral type.", pos);
    }

    if (bothConst) {
        return HandleArithmeticOperationOnTypes(left_type, right_type, operation_type);
    }

    return promotedType;
}

checker::Type *ETSChecker::CheckBinaryOperatorLogical(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                                      lexer::SourcePosition pos, checker::Type *const left_type,
                                                      checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    if (left_type->IsETSUnionType() || right_type->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (unboxed_l == nullptr || !unboxed_l->IsConditionalExprType() || unboxed_r == nullptr ||
        !unboxed_r->IsConditionalExprType()) {
        ThrowTypeError("Bad operand type, the types of the operands must be of possible condition type.", pos);
    }

    if (unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    }

    if (unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(right_type, unboxed_r, right);
    }

    if (expr->IsBinaryExpression()) {
        return HandleBooleanLogicalOperatorsExtended(unboxed_l, unboxed_r, expr->AsBinaryExpression());
    }

    UNREACHABLE();
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorStrictEqual(ir::Expression *left, lexer::SourcePosition pos,
                                                                      checker::Type *const left_type,
                                                                      checker::Type *const right_type)
{
    checker::Type *ts_type {};
    if (!(left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) || left_type->IsETSUnionType()) ||
        !(right_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) || right_type->IsETSUnionType())) {
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

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorEqual(
    ir::Expression *left, ir::Expression *right, lexer::TokenType operation_type, lexer::SourcePosition pos,
    checker::Type *const left_type, checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    checker::Type *ts_type {};
    if (left_type->IsETSEnumType() && right_type->IsETSEnumType()) {
        if (!left_type->AsETSEnumType()->IsSameEnumType(right_type->AsETSEnumType())) {
            ThrowTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
        }

        ts_type = GlobalETSBooleanType();
        return {ts_type, left_type};
    }

    if (left_type->IsETSStringEnumType() && right_type->IsETSStringEnumType()) {
        if (!left_type->AsETSStringEnumType()->IsSameEnumType(right_type->AsETSStringEnumType())) {
            ThrowTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
        }

        ts_type = GlobalETSBooleanType();
        return {ts_type, left_type};
    }

    if (left_type->IsETSDynamicType() || right_type->IsETSDynamicType()) {
        return CheckBinaryOperatorEqualDynamic(left, right, pos);
    }

    if (IsReferenceType(left_type) && IsReferenceType(right_type)) {
        ts_type = GlobalETSBooleanType();
        auto *op_type = GlobalETSObjectType();
        return {ts_type, op_type};
    }

    if (unboxed_l != nullptr && unboxed_l->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) && unboxed_r != nullptr &&
        unboxed_r->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
        if (unboxed_l->HasTypeFlag(checker::TypeFlag::CONSTANT) &&
            unboxed_r->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
            bool res = unboxed_l->AsETSBooleanType()->GetValue() == unboxed_r->AsETSBooleanType()->GetValue();

            ts_type = CreateETSBooleanType(operation_type == lexer::TokenType::PUNCTUATOR_EQUAL ? res : !res);
            return {ts_type, ts_type};
        }

        FlagExpressionWithUnboxing(left_type, unboxed_l, left);
        FlagExpressionWithUnboxing(right_type, unboxed_r, right);

        ts_type = GlobalETSBooleanType();
        return {ts_type, ts_type};
    }
    return {nullptr, nullptr};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorEqualDynamic(ir::Expression *left, ir::Expression *right,
                                                                       lexer::SourcePosition pos)
{
    // NOTE: vpukhov. enforce intrinsic call in any case?
    // canonicalize
    auto *const dyn_exp = left->TsType()->IsETSDynamicType() ? left : right;
    auto *const other_exp = dyn_exp == left ? right : left;

    if (other_exp->TsType()->IsETSDynamicType()) {
        return {GlobalETSBooleanType(), GlobalBuiltinJSValueType()};
    }
    if (dyn_exp->TsType()->AsETSDynamicType()->IsConvertibleTo(other_exp->TsType())) {
        // NOTE: vpukhov. boxing flags are not set in dynamic values
        return {GlobalETSBooleanType(), other_exp->TsType()};
    }
    if (other_exp->TsType()->IsETSObjectType()) {
        // have to prevent casting dyn_exp via ApplyCast without nullish flag
        auto *nullish_obj = CreateNullishType(GlobalETSObjectType(), checker::TypeFlag::NULLISH, Allocator(),
                                              Relation(), GetGlobalTypesHolder());
        return {GlobalETSBooleanType(), nullish_obj};
    }
    ThrowTypeError("Unimplemented case in dynamic type comparison.", pos);
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorLessGreater(
    ir::Expression *left, ir::Expression *right, lexer::TokenType operation_type, lexer::SourcePosition pos,
    bool is_equal_op, checker::Type *const left_type, checker::Type *const right_type, Type *unboxed_l, Type *unboxed_r)
{
    if ((left_type->IsETSUnionType() || right_type->IsETSUnionType()) &&
        operation_type != lexer::TokenType::PUNCTUATOR_EQUAL &&
        operation_type != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    checker::Type *ts_type {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxed_l, unboxed_r, TypeFlag::ETS_NUMERIC, !is_equal_op);

    FlagExpressionWithUnboxing(left_type, unboxed_l, left);
    FlagExpressionWithUnboxing(right_type, unboxed_r, right);

    if (left_type->IsETSUnionType()) {
        ts_type = GlobalETSBooleanType();
        return {ts_type, left_type->AsETSUnionType()};
    }

    if (right_type->IsETSUnionType()) {
        ts_type = GlobalETSBooleanType();
        return {ts_type, right_type->AsETSUnionType()};
    }

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
    }

    if (bothConst) {
        ts_type = HandleRelationOperationOnTypes(left_type, right_type, operation_type);
        return {ts_type, ts_type};
    }

    ts_type = GlobalETSBooleanType();
    auto *op_type = promotedType;
    return {ts_type, op_type};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorInstanceOf(lexer::SourcePosition pos,
                                                                     checker::Type *const left_type,
                                                                     checker::Type *const right_type)
{
    checker::Type *ts_type {};
    if (!left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT | checker::TypeFlag::ETS_UNION) ||
        !right_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT | checker::TypeFlag::ETS_UNION)) {
        ThrowTypeError("Bad operand type, the types of the operands must be same type.", pos);
    }

    if (right_type->IsETSDynamicType() || left_type->IsETSDynamicType()) {
        if (!(right_type->IsETSDynamicType() && left_type->IsETSDynamicType())) {
            ThrowTypeError("Bad operand type, both types of the operands must be dynamic.", pos);
        }
    }

    ts_type = GlobalETSBooleanType();
    checker::Type *op_type = right_type->IsETSDynamicType() ? GlobalBuiltinJSValueType() : GlobalETSObjectType();
    return {ts_type, op_type};
}

Type *ETSChecker::CheckBinaryOperatorNullishCoalescing(ir::Expression *right, lexer::SourcePosition pos,
                                                       checker::Type *const left_type, checker::Type *const right_type)
{
    if (!left_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        ThrowTypeError("Left-hand side expression must be a reference type.", pos);
    }

    checker::Type *non_nullish_left_type = left_type;

    if (left_type->IsNullish()) {
        non_nullish_left_type = GetNonNullishType(left_type);
    }

    // NOTE: vpukhov. check convertibility and use numeric promotion

    if (right_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        Relation()->SetNode(right);
        auto boxed_right_type = PrimitiveTypeAsETSBuiltinType(right_type);
        if (boxed_right_type == nullptr) {
            ThrowTypeError("Invalid right-hand side expression", pos);
        }
        right->AddBoxingUnboxingFlag(GetBoxingFlag(boxed_right_type));
        return FindLeastUpperBound(non_nullish_left_type, boxed_right_type);
    }

    return FindLeastUpperBound(non_nullish_left_type, right_type);
}

// NOLINTNEXTLINE(readability-function-size)
std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperator(ir::Expression *left, ir::Expression *right,
                                                           ir::Expression *expr, lexer::TokenType operation_type,
                                                           lexer::SourcePosition pos, bool force_promotion)
{
    checker::Type *const left_type = left->Check(this);
    checker::Type *const right_type = right->Check(this);
    const bool is_logical_extended_operator = (operation_type == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) ||
                                              (operation_type == lexer::TokenType::PUNCTUATOR_LOGICAL_OR);
    Type *unboxed_l = is_logical_extended_operator ? ETSBuiltinTypeAsConditionalType(left_type)
                                                   : ETSBuiltinTypeAsPrimitiveType(left_type);
    Type *unboxed_r = is_logical_extended_operator ? ETSBuiltinTypeAsConditionalType(right_type)
                                                   : ETSBuiltinTypeAsPrimitiveType(right_type);

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
            ts_type = CheckBinaryOperatorMulDivMod(left, right, operation_type, pos, is_equal_op, left_type, right_type,
                                                   unboxed_l, unboxed_r);
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
            ts_type = CheckBinaryOperatorPlus(left, right, operation_type, pos, is_equal_op, left_type, right_type,
                                              unboxed_l, unboxed_r);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL: {
            ts_type = CheckBinaryOperatorShift(left, right, operation_type, pos, is_equal_op, left_type, right_type,
                                               unboxed_l, unboxed_r);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            ts_type = CheckBinaryOperatorBitwise(left, right, operation_type, pos, is_equal_op, left_type, right_type,
                                                 unboxed_l, unboxed_r);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            ts_type = CheckBinaryOperatorLogical(left, right, expr, pos, left_type, right_type, unboxed_l, unboxed_r);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            return CheckBinaryOperatorStrictEqual(left, pos, left_type, right_type);
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            std::tuple<Type *, Type *> res =
                CheckBinaryOperatorEqual(left, right, operation_type, pos, left_type, right_type, unboxed_l, unboxed_r);
            if (!(std::get<0>(res) == nullptr && std::get<1>(res) == nullptr)) {
                return res;
            }
            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            return CheckBinaryOperatorLessGreater(left, right, operation_type, pos, is_equal_op, left_type, right_type,
                                                  unboxed_l, unboxed_r);
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            return CheckBinaryOperatorInstanceOf(pos, left_type, right_type);
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            ts_type = CheckBinaryOperatorNullishCoalescing(right, pos, left_type, right_type);
            break;
        }
        default: {
            // NOTE
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
