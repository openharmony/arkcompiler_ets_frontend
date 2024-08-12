/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

namespace ark::es2panda::checker {

static inline void RepairTypeErrorsInOperands(Type **left, Type **right)
{
    if (IsTypeError(*left)) {
        *left = *right;
    }
    if (IsTypeError(*right)) {
        *right = *left;
    }
}

static inline void RepairTypeErrorWithDefault(Type **type, Type *dflt)
{
    if (IsTypeError(*type)) {
        *type = dflt;
    }
}

Type *ETSChecker::NegateNumericType(Type *type, ir::Expression *node)
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC));

    TypeFlag typeKind = ETSType(type);
    Type *result = nullptr;

    switch (typeKind) {
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

Type *ETSChecker::BitwiseNegateNumericType(Type *type, ir::Expression *node)
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_INTEGRAL));

    TypeFlag typeKind = ETSType(type);

    Type *result = nullptr;

    switch (typeKind) {
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
        case TypeFlag::FLOAT: {
            result = CreateIntType(
                ~static_cast<uint32_t>(CastFloatToInt<FloatType::UType, int32_t>(type->AsFloatType()->GetValue())));
            break;
        }
        case TypeFlag::DOUBLE: {
            result = CreateLongType(
                ~static_cast<uint64_t>(CastFloatToInt<DoubleType::UType, int64_t>(type->AsDoubleType()->GetValue())));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    node->SetTsType(result);
    return result;
}

Type *ETSChecker::HandleRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC));

    if (left->IsDoubleType() || right->IsDoubleType()) {
        return PerformRelationOperationOnTypes<DoubleType>(left, right, operationType);
    }

    if (left->IsFloatType() || right->IsFloatType()) {
        return PerformRelationOperationOnTypes<FloatType>(left, right, operationType);
    }

    if (left->IsLongType() || right->IsLongType()) {
        return PerformRelationOperationOnTypes<LongType>(left, right, operationType);
    }

    return PerformRelationOperationOnTypes<IntType>(left, right, operationType);
}

bool ETSChecker::CheckBinaryOperatorForBigInt(Type *left, Type *right, lexer::TokenType op)
{
    if ((left == nullptr) || (right == nullptr)) {
        return false;
    }

    if (!left->IsETSBigIntType()) {
        return false;
    }

    if (!right->IsETSBigIntType()) {
        return false;
    }

    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL:
        case lexer::TokenType::KEYW_INSTANCEOF:
            // This is handled in the main CheckBinaryOperator function
            return false;
        default:
            break;
    }

    return true;
}

bool ETSChecker::CheckBinaryPlusMultDivOperandsForUnionType(const Type *leftType, const Type *rightType,
                                                            const ir::Expression *left, const ir::Expression *right)
{
    std::stringstream ss;
    if (leftType->IsETSUnionType()) {
        leftType->AsETSUnionType()->ToString(ss, false);
        LogTypeError("Bad operand type: multiple types left in the normalized union type (" + ss.str() +
                         "). Unions are not allowed in binary expressions except equality.",
                     left->Start());
        return false;
    }
    if (rightType->IsETSUnionType()) {
        rightType->AsETSUnionType()->ToString(ss, false);
        LogTypeError("Bad operand type: multiple types left in the normalized union type (" + ss.str() +
                         "). Unions are not allowed in binary expressions except equality.",
                     right->Start());
        return false;
    }
    return true;
}

checker::Type *ETSChecker::CheckBinaryOperatorMulDivMod(
    std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
    std::tuple<checker::Type *, checker::Type *, Type *, Type *> types)
{
    auto [left, right, operationType, pos] = op;
    auto [leftType, rightType, unboxedL, unboxedR] = types;

    // Try to handle errors on a lower level
    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return GlobalTypeError();
    }

    checker::Type *tsType {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (!CheckBinaryPlusMultDivOperandsForUnionType(leftType, rightType, left, right)) {
        return GlobalTypeError();
    }

    if (promotedType == nullptr && !bothConst) {
        LogTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
        return GlobalTypeError();
    }

    if (bothConst) {
        tsType = HandleArithmeticOperationOnTypes(leftType, rightType, operationType);
    }

    tsType = (tsType != nullptr) ? tsType : promotedType;
    return tsType;
}

checker::Type *ETSChecker::CheckBinaryOperatorPlusForEnums(const checker::Type *const leftType,
                                                           const checker::Type *const rightType)
{
    if (leftType->HasTypeFlag(TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC) &&
        rightType->HasTypeFlag(TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        if (leftType->IsETSIntEnumType() && rightType->IsETSIntEnumType()) {
            return GlobalIntType();
        }
        if (leftType->IsFloatType() || rightType->IsFloatType()) {
            return GlobalFloatType();
        }
        if (leftType->IsLongType() || rightType->IsLongType()) {
            return GlobalLongType();
        }
        return GlobalIntType();
    }
    if ((leftType->IsETSStringEnumType() && (rightType->IsETSStringType() || rightType->IsETSStringEnumType())) ||
        (rightType->IsETSStringEnumType() && (leftType->IsETSStringType() || leftType->IsETSStringEnumType()))) {
        return GlobalETSStringLiteralType();
    }
    return nullptr;
}

checker::Type *ETSChecker::CheckBinaryOperatorPlus(
    std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
    std::tuple<checker::Type *, checker::Type *, Type *, Type *> types)
{
    auto [left, right, operationType, pos] = op;
    auto [leftType, rightType, unboxedL, unboxedR] = types;

    // Try to handle errors on a lower level
    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return GlobalTypeError();
    }

    if (leftType->IsETSStringType() || rightType->IsETSStringType()) {
        if (operationType == lexer::TokenType::PUNCTUATOR_MINUS ||
            operationType == lexer::TokenType::PUNCTUATOR_MINUS_EQUAL) {
            LogTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
            return GlobalTypeError();
        }

        return HandleStringConcatenation(leftType, rightType);
    }

    if (!CheckBinaryPlusMultDivOperandsForUnionType(leftType, rightType, left, right)) {
        return GlobalTypeError();
    }

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedType == nullptr && !bothConst) {
        auto type = CheckBinaryOperatorPlusForEnums(leftType, rightType);
        if (type != nullptr) {
            return type;
        }
        LogTypeError("Bad operand type, the types of the operands must be numeric type, enum or String.", pos);
        return GlobalTypeError();
    }

    if (bothConst) {
        return HandleArithmeticOperationOnTypes(leftType, rightType, operationType);
    }

    return promotedType;
}

checker::Type *ETSChecker::CheckBinaryOperatorShift(
    std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
    std::tuple<checker::Type *, checker::Type *, Type *, Type *> types)
{
    auto [left, right, operationType, pos] = op;
    auto [leftType, rightType, unboxedL, unboxedR] = types;

    RepairTypeErrorWithDefault(&leftType, GlobalIntType());
    RepairTypeErrorWithDefault(&rightType, GlobalIntType());
    RepairTypeErrorWithDefault(&unboxedL, GlobalIntType());
    RepairTypeErrorWithDefault(&unboxedR, GlobalIntType());

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        LogTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
        return GlobalTypeError();
    }

    auto promotedLeftType = ApplyUnaryOperatorPromotion(unboxedL, false, !isEqualOp);
    auto promotedRightType = ApplyUnaryOperatorPromotion(unboxedR, false, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedLeftType == nullptr || !promotedLeftType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC) ||
        promotedRightType == nullptr ||
        !promotedRightType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        LogTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
        return GlobalTypeError();
    }

    if (promotedLeftType->HasTypeFlag(TypeFlag::CONSTANT) && promotedRightType->HasTypeFlag(TypeFlag::CONSTANT)) {
        return HandleBitwiseOperationOnTypes(promotedLeftType, promotedRightType, operationType);
    }

    switch (ETSType(promotedLeftType)) {
        case TypeFlag::BYTE: {
            return GlobalByteType();
        }
        case TypeFlag::SHORT: {
            return GlobalShortType();
        }
        case TypeFlag::CHAR: {
            return GlobalCharType();
        }
        case TypeFlag::INT:
        case TypeFlag::FLOAT: {
            return GlobalIntType();
        }
        case TypeFlag::LONG:
        case TypeFlag::DOUBLE: {
            return GlobalLongType();
        }
        default: {
            UNREACHABLE();
        }
    }
    return nullptr;
}

checker::Type *ETSChecker::CheckBinaryOperatorBitwise(
    std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
    std::tuple<checker::Type *, checker::Type *, Type *, Type *> types)
{
    auto [left, right, operationType, pos] = op;
    auto [leftType, rightType, unboxedL, unboxedR] = types;

    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return GlobalTypeError();
    }

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        LogTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
        return GlobalTypeError();
    }

    if (unboxedL != nullptr && unboxedL->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) && unboxedR != nullptr &&
        unboxedR->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
        FlagExpressionWithUnboxing(leftType, unboxedL, left);
        FlagExpressionWithUnboxing(rightType, unboxedR, right);
        return HandleBooleanLogicalOperators(unboxedL, unboxedR, operationType);
    }

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedType == nullptr && !bothConst) {
        LogTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
        return GlobalTypeError();
    }

    if (bothConst) {
        return HandleBitwiseOperationOnTypes(leftType, rightType, operationType);
    }

    return SelectGlobalIntegerTypeForNumeric(promotedType);
}

checker::Type *ETSChecker::CheckBinaryOperatorLogical(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                                      lexer::SourcePosition pos, checker::Type *leftType,
                                                      checker::Type *rightType, Type *unboxedL, Type *unboxedR)
{
    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return GlobalTypeError();
    }

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        LogTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
        return GlobalTypeError();
    }

    if (unboxedL == nullptr || !unboxedL->IsConditionalExprType() || unboxedR == nullptr ||
        !unboxedR->IsConditionalExprType()) {
        LogTypeError("Bad operand type, the types of the operands must be of possible condition type.", pos);
        return GlobalTypeError();
    }

    if (unboxedL->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(leftType, unboxedL, left);
    }

    if (unboxedR->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(rightType, unboxedR, right);
    }

    if (expr->IsBinaryExpression()) {
        return HandleBooleanLogicalOperatorsExtended(unboxedL, unboxedR, expr->AsBinaryExpression());
    }

    UNREACHABLE();
}

void ETSChecker::LogOperatorCannotBeApplied(lexer::TokenType operationType, checker::Type *const leftType,
                                            checker::Type *const rightType, lexer::SourcePosition pos)
{
    LogTypeError({"Operator '", operationType, "' cannot be applied to types '", leftType, "' and '", rightType, "'."},
                 pos);
}

bool ETSChecker::CheckValidEqualReferenceType(checker::Type *const leftType, checker::Type *const rightType)
{
    auto isGlobalObjectType {[](checker::Type *const type) -> bool {
        return type->IsETSObjectType() && type->AsETSObjectType()->IsGlobalETSObjectType();
    }};

    // Equality expression is always allowed for Object, undefined and null
    if (isGlobalObjectType(leftType) || isGlobalObjectType(rightType) || leftType->IsETSUndefinedType() ||
        rightType->IsETSUndefinedType() || leftType->IsETSNullType() || rightType->IsETSNullType()) {
        return true;
    }

    // NOTE (mxlgv): Skip for unions. Required implementation of the specification section:
    // 7.25.6 Reference Equality Based on Actual Type (Union Equality Operators)
    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        return true;
    }

    // NOTE (mxlgv): Skip for generic. Required implementation of the specification section:
    // 7.25.6 Reference Equality Based on Actual Type (Type Parameter Equality Operators)
    if (leftType->HasTypeFlag(TypeFlag::GENERIC) || rightType->HasTypeFlag(TypeFlag::GENERIC)) {
        return true;
    }

    // Equality expression can only be applied to String and String, and BigInt and BigInt
    if (leftType->IsETSStringType() || rightType->IsETSStringType() || leftType->IsETSBigIntType() ||
        rightType->IsETSBigIntType()) {
        if (!Relation()->IsIdenticalTo(leftType, rightType) && !Relation()->IsIdenticalTo(rightType, leftType)) {
            return false;
        }
    }

    return true;
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorStrictEqual(ir::Expression *left,
                                                                      lexer::TokenType operationType,
                                                                      lexer::SourcePosition pos,
                                                                      checker::Type *leftType, checker::Type *rightType)
{
    RepairTypeErrorsInOperands(&leftType, &rightType);
    if (leftType->IsTypeError()) {  // both are errors
        // We still know that operation result should be boolean, so recover.
        return {GlobalETSBooleanType(), GlobalETSObjectType()};
    }

    checker::Type *tsType {};
    if (!IsReferenceType(leftType) || !IsReferenceType(rightType)) {
        LogTypeError("Both operands have to be reference types", pos);
        return {GlobalETSBooleanType(), GlobalETSObjectType()};
    }

    Relation()->SetNode(left);
    if (!CheckValidEqualReferenceType(leftType, rightType)) {
        LogOperatorCannotBeApplied(operationType, leftType, rightType, pos);
        return {GlobalETSBooleanType(), GlobalETSObjectType()};
    }

    if (!Relation()->IsCastableTo(leftType, rightType) && !Relation()->IsCastableTo(rightType, leftType)) {
        LogOperatorCannotBeApplied(operationType, leftType, rightType, pos);
        return {GlobalETSBooleanType(), GlobalETSObjectType()};
    }

    tsType = GlobalETSBooleanType();
    if (rightType->IsETSDynamicType() && leftType->IsETSDynamicType()) {
        return {tsType, GlobalBuiltinJSValueType()};
    }

    return {tsType, GlobalETSObjectType()};
}

std::optional<std::tuple<Type *, Type *>> ETSChecker::CheckBinaryOperatorEqualError(checker::Type *const leftType,
                                                                                    checker::Type *const rightType,
                                                                                    checker::Type *tsType,
                                                                                    lexer::SourcePosition pos)
{
    if (leftType->IsETSIntEnumType() && rightType->IsETSIntEnumType()) {
        if (!leftType->AsETSIntEnumType()->IsSameEnumType(rightType->AsETSIntEnumType())) {
            // We still know that operation result should be boolean, so recover.
            LogTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
            return {{GlobalETSBooleanType(), leftType}};
        }

        tsType = GlobalETSBooleanType();
        return std::make_tuple(tsType, leftType);
    }

    if (leftType->IsETSStringEnumType() && rightType->IsETSStringEnumType()) {
        if (!leftType->AsETSStringEnumType()->IsSameEnumType(rightType->AsETSStringEnumType())) {
            LogTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
            return {{GlobalETSBooleanType(), leftType}};
        }

        tsType = GlobalETSBooleanType();
        return std::make_tuple(tsType, leftType);
    }
    return std::nullopt;
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorEqual(ir::Expression *left, ir::Expression *right,
                                                                lexer::TokenType operationType,
                                                                lexer::SourcePosition pos, checker::Type *leftType,
                                                                checker::Type *rightType, Type *unboxedL,
                                                                Type *unboxedR)
{
    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return {GlobalETSBooleanType(), GlobalTypeError()};
    }

    checker::Type *tsType {};

    auto checkError = CheckBinaryOperatorEqualError(leftType, rightType, tsType, pos);
    if (checkError.has_value()) {
        return checkError.value();
    }
    if (leftType->IsETSDynamicType() || rightType->IsETSDynamicType()) {
        return CheckBinaryOperatorEqualDynamic(left, right, pos);
    }

    if (IsReferenceType(leftType) && IsReferenceType(rightType)) {
        Relation()->SetNode(left);
        if (!CheckValidEqualReferenceType(leftType, rightType)) {
            LogOperatorCannotBeApplied(operationType, leftType, rightType, pos);
            return {GlobalETSBooleanType(), leftType};
        }

        tsType = GlobalETSBooleanType();
        return {tsType, CreateETSUnionType({leftType, rightType})};
    }

    if (unboxedL != nullptr && unboxedL->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) && unboxedR != nullptr &&
        unboxedR->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
        if (unboxedL->HasTypeFlag(checker::TypeFlag::CONSTANT) && unboxedR->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
            bool res = unboxedL->AsETSBooleanType()->GetValue() == unboxedR->AsETSBooleanType()->GetValue();

            tsType = CreateETSBooleanType(operationType == lexer::TokenType::PUNCTUATOR_EQUAL ? res : !res);
            return {tsType, tsType};
        }

        FlagExpressionWithUnboxing(leftType, unboxedL, left);
        FlagExpressionWithUnboxing(rightType, unboxedR, right);

        tsType = GlobalETSBooleanType();
        return {tsType, tsType};
    }

    // Temporary workaround before == and === refactoring
    if ((rightType->IsETSNullType() && leftType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) ||
        (leftType->IsETSNullType() && rightType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE))) {
        return {GlobalETSBooleanType(), CreateETSUnionType({leftType, rightType})};
    }

    return {nullptr, nullptr};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorEqualDynamic(ir::Expression *left, ir::Expression *right,
                                                                       lexer::SourcePosition pos)
{
    // NOTE: vpukhov. enforce intrinsic call in any case?
    // canonicalize
    auto *const dynExp = left->TsType()->IsETSDynamicType() ? left : right;
    auto *const otherExp = dynExp == left ? right : left;

    if (otherExp->TsType()->IsETSDynamicType()) {
        return {GlobalETSBooleanType(), GlobalBuiltinJSValueType()};
    }
    if (dynExp->TsType()->AsETSDynamicType()->IsConvertible(otherExp->TsType())) {
        // NOTE: vpukhov. boxing flags are not set in dynamic values
        return {GlobalETSBooleanType(), otherExp->TsType()};
    }
    if (IsReferenceType(otherExp->TsType())) {
        // have to prevent casting dyn_exp via ApplyCast without nullish flag
        return {GlobalETSBooleanType(), GlobalETSNullishObjectType()};
    }
    LogTypeError("Unimplemented case in dynamic type comparison.", pos);
    return {GlobalETSBooleanType(), GlobalETSNullishObjectType()};
}

// Satisfying the Chinese checker
static bool NonNumericTypesAreAppropriateForComparison(Type *leftType, Type *rightType)
{
    return (rightType->IsETSStringType() && leftType->IsETSStringType()) ||
           (((leftType->IsETSIntEnumType() && rightType->IsETSIntEnumType()) ||
             (leftType->IsETSStringEnumType() && rightType->IsETSStringEnumType())) &&
            leftType->AsETSEnumType()->IsSameEnumType(rightType->AsETSEnumType()));
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorLessGreater(ir::Expression *left, ir::Expression *right,
                                                                      lexer::TokenType operationType,
                                                                      lexer::SourcePosition pos, bool isEqualOp,
                                                                      checker::Type *leftType, checker::Type *rightType,
                                                                      Type *unboxedL, Type *unboxedR)
{
    RepairTypeErrorsInOperands(&leftType, &rightType);
    RepairTypeErrorsInOperands(&unboxedL, &unboxedR);
    if (leftType->IsTypeError()) {  // both are errors
        return {GlobalETSBooleanType(), GlobalTypeError()};
    }

    if ((leftType->IsETSUnionType() || rightType->IsETSUnionType()) &&
        operationType != lexer::TokenType::PUNCTUATOR_EQUAL &&
        operationType != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        LogTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
        return {GlobalETSBooleanType(), leftType};
    }

    checker::Type *tsType {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_PRIMITIVE, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        return {GlobalETSBooleanType(), CreateETSUnionType({MaybeBoxExpression(left), MaybeBoxExpression(right)})};
    }

    if ((unboxedL != nullptr) && (unboxedR != nullptr) &&
        (unboxedL->IsETSBooleanType() != unboxedR->IsETSBooleanType())) {
        LogOperatorCannotBeApplied(operationType, leftType, rightType, pos);
        return {GlobalETSBooleanType(), leftType};
    }

    if (promotedType == nullptr && !bothConst) {
        if (NonNumericTypesAreAppropriateForComparison(leftType, rightType)) {
            return {GlobalETSBooleanType(), GlobalETSBooleanType()};
        }
        if (((leftType->IsETSIntEnumType() && rightType->IsETSIntEnumType()) ||
             (leftType->IsETSStringEnumType() && rightType->IsETSStringEnumType())) &&
            leftType->AsETSEnumType()->IsSameEnumType(rightType->AsETSEnumType())) {
            return {GlobalETSBooleanType(), GlobalETSBooleanType()};
        }

        LogTypeError("Bad operand type, the types of the operands must be numeric, same enumeration, or boolean type.",
                     pos);
        return {GlobalETSBooleanType(), GlobalETSBooleanType()};
    }

    if (bothConst) {
        tsType = HandleRelationOperationOnTypes(leftType, rightType, operationType);
        return {tsType, tsType};
    }

    tsType = GlobalETSBooleanType();
    auto *opType = promotedType;
    return {tsType, opType};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorInstanceOf(lexer::SourcePosition pos, checker::Type *leftType,
                                                                     checker::Type *rightType)
{
    RepairTypeErrorsInOperands(&leftType, &rightType);
    if (leftType->IsTypeError()) {  // both are errors
        return {GlobalETSBooleanType(), GlobalTypeError()};
    }

    checker::Type *tsType {};
    if (!IsReferenceType(leftType) || (!IsReferenceType(rightType) && !rightType->IsETSEnumType())) {
        LogTypeError("Bad operand type, the types of the operands must be same type.", pos);
        return {GlobalETSBooleanType(), leftType};
    }

    if (rightType->IsETSDynamicType() && !rightType->AsETSDynamicType()->HasDecl()) {
        LogTypeError("Right-hand side of instanceof expression must represent a type.", pos);
        return {GlobalETSBooleanType(), leftType};
    }

    tsType = GlobalETSBooleanType();
    checker::Type *opType = rightType->IsETSDynamicType() ? GlobalBuiltinJSValueType() : GlobalETSObjectType();
    ComputeApparentType(rightType);
    RemoveStatus(checker::CheckerStatus::IN_INSTANCEOF_CONTEXT);

    return {tsType, opType};
}

bool ETSChecker::AdjustNumberLiteralType(ir::NumberLiteral *const literal, Type *literalType, Type *const otherType)
{
    if (otherType->IsETSObjectType()) {
        auto *const objectType = otherType->AsETSObjectType();
        if (objectType->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE) && !objectType->IsETSStringType()) {
            literal->RemoveBoxingUnboxingFlags(GetBoxingFlag(literalType));
            literalType = ETSBuiltinTypeAsPrimitiveType(objectType);
            literal->SetTsType(literalType);
            literal->AddBoxingUnboxingFlags(GetBoxingFlag(literalType));
            return true;
        }
    }
    return false;
}

Type *ETSChecker::CheckBinaryOperatorNullishCoalescing(ir::Expression *left, ir::Expression *right,
                                                       lexer::SourcePosition pos)
{
    auto *leftType = left->TsType();
    if (!IsReferenceType(leftType) && !leftType->IsETSEnumType()) {
        LogTypeError("Left-hand side of nullish-coalescing expression must be a reference or enum type.", pos);
        return leftType;
    }

    auto *rightType = right->TsType();

    if (leftType->IsETSEnumType()) {
        left->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
        leftType = leftType->AsETSEnumType()->GetDecl()->BoxedClass()->TsType();
    } else {
        leftType = GetNonNullishType(leftType);
    }

    if (rightType->IsETSEnumType()) {
        right->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
        rightType = rightType->AsETSEnumType()->GetDecl()->BoxedClass()->TsType();
    } else {
        rightType = MaybeBoxExpression(right);
    }

    if (IsTypeIdenticalTo(leftType, rightType)) {
        return leftType;
    }

    //  If possible and required update number literal type to the proper value (identical to left-side type)
    if (right->IsNumberLiteral() && AdjustNumberLiteralType(right->AsNumberLiteral(), rightType, leftType)) {
        return leftType;
    }

    return CreateETSUnionType({leftType, rightType});
}

using CheckBinaryFunction = std::function<checker::Type *(
    ETSChecker *, std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op,
    bool isEqualOp, std::tuple<checker::Type *, checker::Type *, Type *, Type *> types)>;

std::map<lexer::TokenType, CheckBinaryFunction> &GetCheckMap()
{
    static std::map<lexer::TokenType, CheckBinaryFunction> checkMap = {
        {lexer::TokenType::PUNCTUATOR_MULTIPLY, &ETSChecker::CheckBinaryOperatorMulDivMod},
        {lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL, &ETSChecker::CheckBinaryOperatorMulDivMod},
        {lexer::TokenType::PUNCTUATOR_DIVIDE, &ETSChecker::CheckBinaryOperatorMulDivMod},
        {lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL, &ETSChecker::CheckBinaryOperatorMulDivMod},
        {lexer::TokenType::PUNCTUATOR_MOD, &ETSChecker::CheckBinaryOperatorMulDivMod},
        {lexer::TokenType::PUNCTUATOR_MOD_EQUAL, &ETSChecker::CheckBinaryOperatorMulDivMod},

        {lexer::TokenType::PUNCTUATOR_MINUS, &ETSChecker::CheckBinaryOperatorPlus},
        {lexer::TokenType::PUNCTUATOR_MINUS_EQUAL, &ETSChecker::CheckBinaryOperatorPlus},
        {lexer::TokenType::PUNCTUATOR_PLUS, &ETSChecker::CheckBinaryOperatorPlus},
        {lexer::TokenType::PUNCTUATOR_PLUS_EQUAL, &ETSChecker::CheckBinaryOperatorPlus},

        {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT, &ETSChecker::CheckBinaryOperatorShift},
        {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL, &ETSChecker::CheckBinaryOperatorShift},
        {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT, &ETSChecker::CheckBinaryOperatorShift},
        {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL, &ETSChecker::CheckBinaryOperatorShift},
        {lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT, &ETSChecker::CheckBinaryOperatorShift},
        {lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL, &ETSChecker::CheckBinaryOperatorShift},

        {lexer::TokenType::PUNCTUATOR_BITWISE_OR, &ETSChecker::CheckBinaryOperatorBitwise},
        {lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL, &ETSChecker::CheckBinaryOperatorBitwise},
        {lexer::TokenType::PUNCTUATOR_BITWISE_AND, &ETSChecker::CheckBinaryOperatorBitwise},
        {lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL, &ETSChecker::CheckBinaryOperatorBitwise},
        {lexer::TokenType::PUNCTUATOR_BITWISE_XOR, &ETSChecker::CheckBinaryOperatorBitwise},
        {lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL, &ETSChecker::CheckBinaryOperatorBitwise},
    };

    return checkMap;
}

struct BinaryOperatorParams {
    ir::Expression *left;
    ir::Expression *right;
    ir::Expression *expr;
    lexer::TokenType operationType;
    lexer::SourcePosition pos;
    bool isEqualOp;
};

struct TypeParams {
    checker::Type *leftType;
    checker::Type *rightType;
    Type *unboxedL;
    Type *unboxedR;
};

static std::tuple<Type *, Type *> CheckBinaryOperatorHelper(ETSChecker *checker,
                                                            const BinaryOperatorParams &binaryParams,
                                                            const TypeParams &typeParams)
{
    ir::Expression *left = binaryParams.left;
    ir::Expression *right = binaryParams.right;
    lexer::SourcePosition pos = binaryParams.pos;
    checker::Type *const leftType = typeParams.leftType;
    checker::Type *const rightType = typeParams.rightType;
    checker::Type *tsType {};
    switch (binaryParams.operationType) {
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            tsType = checker->CheckBinaryOperatorLogical(left, right, binaryParams.expr, pos, leftType, rightType,
                                                         typeParams.unboxedL, typeParams.unboxedR);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            return checker->CheckBinaryOperatorStrictEqual(left, binaryParams.operationType, pos, leftType, rightType);
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            std::tuple<Type *, Type *> res =
                checker->CheckBinaryOperatorEqual(left, right, binaryParams.operationType, pos, leftType, rightType,
                                                  typeParams.unboxedL, typeParams.unboxedR);
            if (!(std::get<0>(res) == nullptr && std::get<1>(res) == nullptr)) {
                return res;
            }
            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            return checker->CheckBinaryOperatorLessGreater(left, right, binaryParams.operationType, pos,
                                                           binaryParams.isEqualOp, leftType, rightType,
                                                           typeParams.unboxedL, typeParams.unboxedR);
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            return checker->CheckBinaryOperatorInstanceOf(pos, leftType, rightType);
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            tsType = checker->CheckBinaryOperatorNullishCoalescing(left, right, pos);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return {tsType, tsType};
}

namespace {
bool IsStringEnum(const ir::Expression *expr)
{
    if (expr == nullptr) {
        return false;
    }
    if (expr->TsTypeOrError()->IsTypeError()) {
        return false;
    }

    auto type = expr->TsType();
    if (type == nullptr) {
        return false;
    }

    return type->IsETSStringEnumType();
}

bool IsIntEnum(const ir::Expression *expr)
{
    if (expr == nullptr) {
        return false;
    }
    if (expr->TsTypeOrError()->IsTypeError()) {
        return false;
    }

    auto type = expr->TsType();
    if (type == nullptr) {
        return false;
    }

    return type->IsETSIntEnumType();
}

bool CheckNumericOperatorContext(ir::Expression *expression, lexer::TokenType op)
{
    const bool isMultiplicative = op == lexer::TokenType::PUNCTUATOR_MULTIPLY ||
                                  op == lexer::TokenType::PUNCTUATOR_DIVIDE || op == lexer::TokenType::PUNCTUATOR_MOD;
    const bool isAdditive = op == lexer::TokenType::PUNCTUATOR_PLUS || op == lexer::TokenType::PUNCTUATOR_MINUS;
    const bool isShift = op == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT ||
                         op == lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT ||
                         op == lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT;
    const bool isRelational =
        op == lexer::TokenType::PUNCTUATOR_GREATER_THAN || op == lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL ||
        op == lexer::TokenType::PUNCTUATOR_LESS_THAN || op == lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL;
    const bool isEquality = op == lexer::TokenType::PUNCTUATOR_EQUAL || op == lexer::TokenType::PUNCTUATOR_NOT_EQUAL;
    const bool isBitwise = op == lexer::TokenType::PUNCTUATOR_BITWISE_AND ||
                           op == lexer::TokenType::PUNCTUATOR_BITWISE_OR ||
                           op == lexer::TokenType::PUNCTUATOR_BITWISE_XOR;
    const bool isConditionalAndOr =
        op == lexer::TokenType::PUNCTUATOR_LOGICAL_AND || op == lexer::TokenType::PUNCTUATOR_LOGICAL_OR;

    if (IsIntEnum(expression)) {
        if (isMultiplicative || isAdditive || isShift || isRelational || isEquality || isBitwise ||
            isConditionalAndOr) {
            expression->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
        }
        return true;
    }
    return false;
}

void CheckStringOperatorContext(ir::Expression *expression, checker::Type *otherType, lexer::TokenType op)
{
    if (IsStringEnum(expression) && (otherType->IsETSStringType() || otherType->IsETSStringEnumType())) {
        if (op == lexer::TokenType::PUNCTUATOR_PLUS) {
            expression->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
        }
    }
}

bool CheckRelationalOperatorsBetweenEnums(ir::Expression *left, ir::Expression *right, lexer::TokenType op)
{
    const bool isRelational =
        op == lexer::TokenType::PUNCTUATOR_GREATER_THAN || op == lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL ||
        op == lexer::TokenType::PUNCTUATOR_LESS_THAN || op == lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL;
    const bool isEquality = op == lexer::TokenType::PUNCTUATOR_EQUAL || op == lexer::TokenType::PUNCTUATOR_NOT_EQUAL;

    if (((IsStringEnum(left) && IsStringEnum(right)) ||
         (IsIntEnum(left) && IsIntEnum(right)))) {  // NOTE(psiket) In case of int enums it has been already checked in
                                                    // the CheckNumericOperatorContext function
        if (isRelational || isEquality) {
            left->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
            right->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
            return true;
        }
    }
    return false;
}

void CheckNeedToGenerateGetValueForBinaryExpression(ir::Expression *expression)
{
    if (!expression->IsBinaryExpression()) {
        return;
    }

    auto binaryExpression = expression->AsBinaryExpression();
    auto op = binaryExpression->OperatorType();
    auto leftExp = binaryExpression->Left();
    auto rightExp = binaryExpression->Right();

    // Numeric Operator Context
    auto leftIsIntEnum = CheckNumericOperatorContext(leftExp, op);
    auto rightIsIntEnum = CheckNumericOperatorContext(rightExp, op);
    if (leftIsIntEnum || rightIsIntEnum) {
        return;
    }

    // String Operator Context
    CheckStringOperatorContext(leftExp, rightExp->TsTypeOrError(), op);
    CheckStringOperatorContext(rightExp, leftExp->TsTypeOrError(), op);

    // Relational operators if both are enumeration Types
    if (CheckRelationalOperatorsBetweenEnums(leftExp, rightExp, op)) {
        return;
    }
}
}  // namespace

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperator(ir::Expression *left, ir::Expression *right,
                                                           ir::Expression *expr, lexer::TokenType operationType,
                                                           lexer::SourcePosition pos, bool forcePromotion)
{
    checker::Type *const leftType = left->Check(this);

    if (leftType == nullptr) {
        LogTypeError("Unexpected type error in binary expression", left->Start());
        auto rightType = right->Check(this);
        return {rightType, rightType};
    }

    if (operationType == lexer::TokenType::KEYW_INSTANCEOF) {
        AddStatus(checker::CheckerStatus::IN_INSTANCEOF_CONTEXT);
    }

    Context().CheckTestSmartCastCondition(operationType);

    checker::Type *rightType = right->Check(this);
    if (right->IsTypeNode()) {
        rightType = right->AsTypeNode()->GetType(this);
    }

    if (rightType == nullptr) {
        LogTypeError("Unexpected type error in binary expression", pos);
        return {leftType, leftType};
    }

    CheckNeedToGenerateGetValueForBinaryExpression(expr);

    const bool isLogicalExtendedOperator = (operationType == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) ||
                                           (operationType == lexer::TokenType::PUNCTUATOR_LOGICAL_OR);
    Type *unboxedL =
        isLogicalExtendedOperator ? ETSBuiltinTypeAsConditionalType(leftType) : ETSBuiltinTypeAsPrimitiveType(leftType);
    Type *unboxedR = isLogicalExtendedOperator ? ETSBuiltinTypeAsConditionalType(rightType)
                                               : ETSBuiltinTypeAsPrimitiveType(rightType);

    bool isEqualOp = (operationType > lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
                      operationType < lexer::TokenType::PUNCTUATOR_ARROW) &&
                     !forcePromotion;

    if (CheckBinaryOperatorForBigInt(leftType, rightType, operationType)) {
        switch (operationType) {
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
                return {GlobalETSBooleanType(), GlobalETSBooleanType()};
            default:
                return {leftType, rightType};
        }
    }

    auto checkMap = GetCheckMap();
    if (checkMap.find(operationType) != checkMap.end()) {
        auto check = checkMap[operationType];
        auto tsType = check(this, std::make_tuple(left, right, operationType, pos), isEqualOp,
                            std::make_tuple(leftType, rightType, unboxedL, unboxedR));
        return {tsType, tsType};
    }

    return CheckBinaryOperatorHelper(this, {left, right, expr, operationType, pos, isEqualOp},
                                     {leftType, rightType, unboxedL, unboxedR});
}

Type *ETSChecker::HandleArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC));

    if (left->IsDoubleType() || right->IsDoubleType()) {
        return PerformArithmeticOperationOnTypes<DoubleType>(left, right, operationType);
    }

    if (left->IsFloatType() || right->IsFloatType()) {
        return PerformArithmeticOperationOnTypes<FloatType>(left, right, operationType);
    }

    if (left->IsLongType() || right->IsLongType()) {
        return PerformArithmeticOperationOnTypes<LongType>(left, right, operationType);
    }

    return PerformArithmeticOperationOnTypes<IntType>(left, right, operationType);
}

Type *ETSChecker::HandleBitwiseOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC));

    if (left->IsDoubleType() || right->IsDoubleType()) {
        return HandleBitWiseArithmetic<DoubleType, LongType>(left, right, operationType);
    }

    if (left->IsFloatType() || right->IsFloatType()) {
        return HandleBitWiseArithmetic<FloatType, IntType>(left, right, operationType);
    }

    if (left->IsLongType() || right->IsLongType()) {
        return HandleBitWiseArithmetic<LongType>(left, right, operationType);
    }

    return HandleBitWiseArithmetic<IntType>(left, right, operationType);
}

void ETSChecker::FlagExpressionWithUnboxing(Type *type, Type *unboxedType, ir::Expression *typeExpression)
{
    if (type->IsETSObjectType() && (unboxedType != nullptr)) {
        typeExpression->AddBoxingUnboxingFlags(GetUnboxingFlag(unboxedType));
    }
}

}  // namespace ark::es2panda::checker
