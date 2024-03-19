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

#include "varbinder/variable.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::checker {

Type *ETSChecker::NegateNumericType(Type *type, ir::Expression *node)
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

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
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

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

bool ETSChecker::CheckBinaryOperatorForBigInt(Type *left, Type *right, ir::Expression *expr, lexer::TokenType op)
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

    if (expr->IsBinaryExpression()) {
        ir::BinaryExpression *be = expr->AsBinaryExpression();
        if (be->OperatorType() == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL) {
            // Handle strict comparison as normal comparison for bigint objects
            be->SetOperator(lexer::TokenType::PUNCTUATOR_EQUAL);
        }
    }

    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::KEYW_INSTANCEOF:
            // This is handled in the main CheckBinaryOperator function
            return false;
        default:
            break;
    }

    // Remove const flag - currently there are no compile time operations for bigint
    left->RemoveTypeFlag(TypeFlag::CONSTANT);
    right->RemoveTypeFlag(TypeFlag::CONSTANT);

    return true;
}

void ETSChecker::CheckBinaryPlusMultDivOperandsForUnionType(const Type *leftType, const Type *rightType,
                                                            const ir::Expression *left, const ir::Expression *right)
{
    std::stringstream ss;
    if (leftType->IsETSUnionType()) {
        leftType->AsETSUnionType()->ToString(ss, false);
        ThrowTypeError("Bad operand type: multiple types left in the normalized union type (" + ss.str() +
                           "). Unions are not allowed in binary expressions except equality.",
                       left->Start());
    }
    if (rightType->IsETSUnionType()) {
        rightType->AsETSUnionType()->ToString(ss, false);
        ThrowTypeError("Bad operand type: multiple types left in the normalized union type (" + ss.str() +
                           "). Unions are not allowed in binary expressions except equality.",
                       right->Start());
    }
}

checker::Type *ETSChecker::CheckBinaryOperatorMulDivMod(ir::Expression *left, ir::Expression *right,
                                                        lexer::TokenType operationType, lexer::SourcePosition pos,
                                                        bool isEqualOp, checker::Type *const leftType,
                                                        checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    checker::Type *tsType {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    CheckBinaryPlusMultDivOperandsForUnionType(leftType, rightType, left, right);

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
    }

    if (bothConst) {
        tsType = HandleArithmeticOperationOnTypes(leftType, rightType, operationType);
    }

    tsType = (tsType != nullptr) ? tsType : promotedType;
    return tsType;
}

checker::Type *ETSChecker::CheckBinaryOperatorPlus(ir::Expression *left, ir::Expression *right,
                                                   lexer::TokenType operationType, lexer::SourcePosition pos,
                                                   bool isEqualOp, checker::Type *const leftType,
                                                   checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    if (leftType->IsETSStringType() || rightType->IsETSStringType()) {
        if (operationType == lexer::TokenType::PUNCTUATOR_MINUS ||
            operationType == lexer::TokenType::PUNCTUATOR_MINUS_EQUAL) {
            ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
        }

        return HandleStringConcatenation(leftType, rightType);
    }

    CheckBinaryPlusMultDivOperandsForUnionType(leftType, rightType, left, right);

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type or String.", pos);
    }

    if (bothConst) {
        return HandleArithmeticOperationOnTypes(leftType, rightType, operationType);
    }

    return promotedType;
}

checker::Type *ETSChecker::CheckBinaryOperatorShift(ir::Expression *left, ir::Expression *right,
                                                    lexer::TokenType operationType, lexer::SourcePosition pos,
                                                    bool isEqualOp, checker::Type *const leftType,
                                                    checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    auto promotedLeftType = ApplyUnaryOperatorPromotion(unboxedL, false, !isEqualOp);
    auto promotedRightType = ApplyUnaryOperatorPromotion(unboxedR, false, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedLeftType == nullptr || !promotedLeftType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) ||
        promotedRightType == nullptr || !promotedRightType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
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

checker::Type *ETSChecker::CheckBinaryOperatorBitwise(ir::Expression *left, ir::Expression *right,
                                                      lexer::TokenType operationType, lexer::SourcePosition pos,
                                                      bool isEqualOp, checker::Type *const leftType,
                                                      checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    // NOTE (mmartin): These need to be done for other binary expressions, but currently it's not defined precisely when
    // to apply this conversion

    if (leftType->IsETSEnumType()) {
        left->AddAstNodeFlags(ir::AstNodeFlags::ENUM_GET_VALUE);
        unboxedL = GlobalIntType();
    }

    if (rightType->IsETSEnumType()) {
        right->AddAstNodeFlags(ir::AstNodeFlags::ENUM_GET_VALUE);
        unboxedR = GlobalIntType();
    }

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (unboxedL != nullptr && unboxedL->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) && unboxedR != nullptr &&
        unboxedR->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN)) {
        FlagExpressionWithUnboxing(leftType, unboxedL, left);
        FlagExpressionWithUnboxing(rightType, unboxedR, right);
        return HandleBooleanLogicalOperators(unboxedL, unboxedR, operationType);
    }

    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
    }

    if (bothConst) {
        return HandleBitwiseOperationOnTypes(leftType, rightType, operationType);
    }

    return SelectGlobalIntegerTypeForNumeric(promotedType);
}

checker::Type *ETSChecker::CheckBinaryOperatorLogical(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                                      lexer::SourcePosition pos, checker::Type *const leftType,
                                                      checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    if (unboxedL == nullptr || !unboxedL->IsConditionalExprType() || unboxedR == nullptr ||
        !unboxedR->IsConditionalExprType()) {
        ThrowTypeError("Bad operand type, the types of the operands must be of possible condition type.", pos);
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

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorStrictEqual(ir::Expression *left, lexer::SourcePosition pos,
                                                                      checker::Type *const leftType,
                                                                      checker::Type *const rightType)
{
    checker::Type *tsType {};
    if (!IsReferenceType(leftType) || !IsReferenceType(rightType)) {
        ThrowTypeError("Both operands have to be reference types", pos);
    }

    Relation()->SetNode(left);
    if (!Relation()->IsCastableTo(leftType, rightType) && !Relation()->IsCastableTo(rightType, leftType)) {
        ThrowTypeError("The operands of strict equality are not compatible with each other", pos);
    }
    tsType = GlobalETSBooleanType();
    if (rightType->IsETSDynamicType() && leftType->IsETSDynamicType()) {
        return {tsType, GlobalBuiltinJSValueType()};
    }
    return {tsType, GlobalETSObjectType()};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorEqual(
    ir::Expression *left, ir::Expression *right, lexer::TokenType operationType, lexer::SourcePosition pos,
    checker::Type *const leftType, checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    checker::Type *tsType {};
    if (leftType->IsETSEnumType() && rightType->IsETSEnumType()) {
        if (!leftType->AsETSEnumType()->IsSameEnumType(rightType->AsETSEnumType())) {
            ThrowTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
        }

        tsType = GlobalETSBooleanType();
        return {tsType, leftType};
    }

    if (leftType->IsETSStringEnumType() && rightType->IsETSStringEnumType()) {
        if (!leftType->AsETSStringEnumType()->IsSameEnumType(rightType->AsETSStringEnumType())) {
            ThrowTypeError("Bad operand type, the types of the operands must be the same enum type.", pos);
        }

        tsType = GlobalETSBooleanType();
        return {tsType, leftType};
    }

    if (leftType->IsETSDynamicType() || rightType->IsETSDynamicType()) {
        return CheckBinaryOperatorEqualDynamic(left, right, pos);
    }

    if (IsReferenceType(leftType) && IsReferenceType(rightType)) {
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
    ThrowTypeError("Unimplemented case in dynamic type comparison.", pos);
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorLessGreater(
    ir::Expression *left, ir::Expression *right, lexer::TokenType operationType, lexer::SourcePosition pos,
    bool isEqualOp, checker::Type *const leftType, checker::Type *const rightType, Type *unboxedL, Type *unboxedR)
{
    if ((leftType->IsETSUnionType() || rightType->IsETSUnionType()) &&
        operationType != lexer::TokenType::PUNCTUATOR_EQUAL &&
        operationType != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.", pos);
    }

    checker::Type *tsType {};
    auto [promotedType, bothConst] =
        ApplyBinaryOperatorPromotion(unboxedL, unboxedR, TypeFlag::ETS_NUMERIC, !isEqualOp);

    FlagExpressionWithUnboxing(leftType, unboxedL, left);
    FlagExpressionWithUnboxing(rightType, unboxedR, right);

    if (leftType->IsETSUnionType() || rightType->IsETSUnionType()) {
        return {GlobalETSBooleanType(), CreateETSUnionType({MaybeBoxExpression(left), MaybeBoxExpression(right)})};
    }

    if (promotedType == nullptr && !bothConst) {
        ThrowTypeError("Bad operand type, the types of the operands must be numeric type.", pos);
    }

    if (bothConst) {
        tsType = HandleRelationOperationOnTypes(leftType, rightType, operationType);
        return {tsType, tsType};
    }

    tsType = GlobalETSBooleanType();
    auto *opType = promotedType;
    return {tsType, opType};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperatorInstanceOf(lexer::SourcePosition pos,
                                                                     checker::Type *const leftType,
                                                                     checker::Type *const rightType)
{
    checker::Type *tsType {};
    if (!IsReferenceType(leftType) || !IsReferenceType(rightType)) {
        ThrowTypeError("Bad operand type, the types of the operands must be same type.", pos);
    }

    if (rightType->IsETSDynamicType() || leftType->IsETSDynamicType()) {
        if (!(rightType->IsETSDynamicType() && leftType->IsETSDynamicType())) {
            ThrowTypeError("Bad operand type, both types of the operands must be dynamic.", pos);
        }
    }

    tsType = GlobalETSBooleanType();
    checker::Type *opType = rightType->IsETSDynamicType() ? GlobalBuiltinJSValueType() : GlobalETSObjectType();
    ComputeApparentType(rightType);
    RemoveStatus(checker::CheckerStatus::IN_INSTANCEOF_CONTEXT);

    return {tsType, opType};
}

Type *ETSChecker::CheckBinaryOperatorNullishCoalescing(ir::Expression *right, lexer::SourcePosition pos,
                                                       checker::Type *const leftType,
                                                       [[maybe_unused]] checker::Type *const rightType)
{
    ASSERT(rightType == right->TsType());
    if (!IsReferenceType(leftType)) {
        ThrowTypeError("Left-hand side expression must be a reference type.", pos);
    }
    return CreateETSUnionType({GetNonNullishType(leftType), MaybeBoxExpression(right)});
}

using CheckBinaryFunction = std::function<checker::Type *(
    ETSChecker *, ir::Expression *left, ir::Expression *right, lexer::TokenType operationType,
    lexer::SourcePosition pos, bool isEqualOp, checker::Type *const leftType, checker::Type *const rightType,
    Type *unboxedL, Type *unboxedR)>;

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
            return checker->CheckBinaryOperatorStrictEqual(left, pos, leftType, rightType);
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
            tsType = checker->CheckBinaryOperatorNullishCoalescing(right, pos, leftType, rightType);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return {tsType, tsType};
}

std::tuple<Type *, Type *> ETSChecker::CheckBinaryOperator(ir::Expression *left, ir::Expression *right,
                                                           ir::Expression *expr, lexer::TokenType operationType,
                                                           lexer::SourcePosition pos, bool forcePromotion)
{
    checker::Type *const leftType = left->Check(this);

    if (leftType == nullptr) {
        ThrowTypeError("Unexpected type error in binary expression", left->Start());
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
        ThrowTypeError("Unexpected type error in binary expression", pos);
    }

    const bool isLogicalExtendedOperator = (operationType == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) ||
                                           (operationType == lexer::TokenType::PUNCTUATOR_LOGICAL_OR);
    Type *unboxedL =
        isLogicalExtendedOperator ? ETSBuiltinTypeAsConditionalType(leftType) : ETSBuiltinTypeAsPrimitiveType(leftType);
    Type *unboxedR = isLogicalExtendedOperator ? ETSBuiltinTypeAsConditionalType(rightType)
                                               : ETSBuiltinTypeAsPrimitiveType(rightType);

    checker::Type *tsType {};
    bool isEqualOp = (operationType > lexer::TokenType::PUNCTUATOR_SUBSTITUTION &&
                      operationType < lexer::TokenType::PUNCTUATOR_ARROW) &&
                     !forcePromotion;

    if (CheckBinaryOperatorForBigInt(leftType, rightType, expr, operationType)) {
        switch (operationType) {
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
                return {GlobalETSBooleanType(), GlobalETSBooleanType()};
            default:
                return {leftType, rightType};
        }
    };

    auto checkMap = GetCheckMap();
    if (checkMap.find(operationType) != checkMap.end()) {
        auto check = checkMap[operationType];
        tsType = check(this, left, right, operationType, pos, isEqualOp, leftType, rightType, unboxedL, unboxedR);
        return {tsType, tsType};
    }

    BinaryOperatorParams binaryParams {left, right, expr, operationType, pos, isEqualOp};
    TypeParams typeParams {leftType, rightType, unboxedL, unboxedR};
    return CheckBinaryOperatorHelper(this, binaryParams, typeParams);
}

Type *ETSChecker::HandleArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType)
{
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

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
    ASSERT(left->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC) &&
           right->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

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
