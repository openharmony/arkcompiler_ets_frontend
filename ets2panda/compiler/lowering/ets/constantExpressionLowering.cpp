/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "constantExpressionLowering.h"

#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "lexer/token/token.h"

namespace ark::es2panda::compiler {

void ConstantExpressionLowering::LogError(const diagnostic::DiagnosticKind &diagnostic,
                                          const util::DiagnosticMessageParams &diagnosticParams,
                                          const lexer::SourcePosition &pos) const
{
    context_->diagnosticEngine->LogDiagnostic(diagnostic, diagnosticParams, pos);
}

static bool IsSupportedLiteralForNumeric(ir::Literal *const node)
{
    return node->IsNumberLiteral() || node->IsCharLiteral() || node->IsBooleanLiteral();
}

static bool IsSupportedLiteral(ir::Expression *const node)
{
    if (!node->IsLiteral()) {
        return false;
    }

    auto literal = node->AsLiteral();
    return literal->IsNumberLiteral() || literal->IsCharLiteral() || literal->IsBooleanLiteral() ||
           literal->IsStringLiteral() || literal->IsUndefinedLiteral() || literal->IsNullLiteral();
}

static bool IsStringTypeReference(ir::ETSTypeReference *type)
{
    auto name = type->Part()->GetIdent()->Name();
    return name == "string" || name == "String";
}

static bool CheckIsBooleanConstantForUnary(ir::Literal *const unaryLiteral, lexer::TokenType opType)
{
    if (unaryLiteral->IsBooleanLiteral()) {
        return true;
    }
    return opType == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK;
}

static bool CheckIsBooleanConstantForBinary(ir::Literal *lhs, ir::Literal *rhs, lexer::TokenType opType)
{
    if (lhs->IsBooleanLiteral() && rhs->IsBooleanLiteral()) {
        return true;
    }
    return opType == lexer::TokenType::PUNCTUATOR_GREATER_THAN ||
           opType == lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL ||
           opType == lexer::TokenType::PUNCTUATOR_LESS_THAN || opType == lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL ||
           opType == lexer::TokenType::PUNCTUATOR_EQUAL || opType == lexer::TokenType::PUNCTUATOR_NOT_EQUAL ||
           opType == lexer::TokenType::PUNCTUATOR_LOGICAL_AND || opType == lexer::TokenType::PUNCTUATOR_LOGICAL_OR;
}

static bool CheckIsNumericConstant(ir::Literal *const left, ir::Literal *const right)
{
    return (left->IsNumberLiteral() || left->IsCharLiteral()) && (right->IsNumberLiteral() || right->IsCharLiteral());
}

template <typename TargetType>
static TargetType GetOperand(ir::Literal *const node)
{
    if (node->IsBooleanLiteral()) {
        return node->AsBooleanLiteral()->Value();
    }

    if (node->IsNumberLiteral()) {
        auto numNode = node->AsNumberLiteral();
        if (numNode->Number().IsInt()) {
            return numNode->Number().GetInt();
        }
        if (numNode->Number().IsLong()) {
            return numNode->Number().GetLong();
        }
        if (numNode->Number().IsFloat()) {
            return numNode->Number().GetFloat();
        }
        if (numNode->Number().IsDouble()) {
            return numNode->Number().GetDouble();
        }
        ES2PANDA_UNREACHABLE();
    }

    if (node->IsCharLiteral()) {
        return node->AsCharLiteral()->Char();
    }

    ES2PANDA_UNREACHABLE();
}

static TypeRank GetTypeRank(ir::Literal *const literal)
{
    if (literal->IsCharLiteral()) {
        return TypeRank::CHAR;
    }
    if (literal->IsNumberLiteral()) {
        auto number = literal->AsNumberLiteral()->Number();
        if (number.IsInt()) {
            return TypeRank::INT32;
        }
        if (number.IsLong()) {
            return TypeRank::INT64;
        }
        if (number.IsDouble()) {
            return TypeRank::DOUBLE;
        }
        return TypeRank::FLOAT;
    }
    ES2PANDA_UNREACHABLE();
}

static bool TestLiteralIsNotZero(ir::Literal *literal)
{
    ES2PANDA_ASSERT(literal->IsCharLiteral() || literal->IsNumberLiteral());
    if (literal->IsCharLiteral()) {
        return literal->AsCharLiteral()->Char() != 0;
    }

    auto number = literal->AsNumberLiteral()->Number();
    if (number.IsInt()) {
        return number.GetInt() != 0;
    }
    if (number.IsLong()) {
        return number.GetLong() != 0;
    }
    if (number.IsDouble()) {
        return number.GetDouble() != 0;
    }
    if (number.IsFloat()) {
        return number.GetFloat() != 0;
    }
    ES2PANDA_UNREACHABLE();
}

ir::AstNode *ConstantExpressionLowering::FoldTernaryConstant(ir::ConditionalExpression *cond)
{
    ir::AstNode *resNode {};

    auto const testCond = cond->Test()->AsLiteral();
    if (testCond->IsBooleanLiteral()) {
        resNode = testCond->AsBooleanLiteral()->Value() ? cond->Consequent() : cond->Alternate();
    }
    // 15.10.1 Extended Conditional Expression
    if (testCond->IsStringLiteral()) {
        resNode = !testCond->AsStringLiteral()->Str().Empty() ? cond->Consequent() : cond->Alternate();
    }
    if (testCond->IsNullLiteral() || testCond->IsUndefinedLiteral()) {
        resNode = cond->Alternate();
    }
    if (testCond->IsCharLiteral() || testCond->IsNumberLiteral()) {
        resNode = TestLiteralIsNotZero(testCond) ? cond->Consequent() : cond->Alternate();
    }

    if (resNode == nullptr) {
        return cond;
    }

    resNode->SetParent(cond->Parent());
    resNode->SetRange(cond->Range());
    return resNode;
}

template <typename InputType>
bool ConstantExpressionLowering::PerformRelationOperator(InputType left, InputType right, lexer::TokenType opType)
{
    switch (opType) {
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            return left > right;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            return left >= right;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            return left < right;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            return left <= right;
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            return left == right;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            return left != right;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

bool ConstantExpressionLowering::HandleRelationOperator(ir::Literal *left, ir::Literal *right, lexer::TokenType opType)
{
    if (left->IsBooleanLiteral()) {
        return PerformRelationOperator(GetOperand<bool>(left), GetOperand<bool>(right), opType);
    }
    if (left->IsStringLiteral()) {
        return PerformRelationOperator(left->AsStringLiteral()->Str(), right->AsStringLiteral()->Str(), opType);
    }

    TypeRank leftRank = GetTypeRank(left);
    TypeRank rightRank = GetTypeRank(right);
    TypeRank targetRank = std::max(leftRank, rightRank);
    switch (targetRank) {
        case TypeRank::DOUBLE: {
            return PerformRelationOperator(GetOperand<double>(left), GetOperand<double>(right), opType);
        }
        case TypeRank::FLOAT: {
            return PerformRelationOperator(GetOperand<float>(left), GetOperand<float>(right), opType);
        }
        case TypeRank::INT64: {
            return PerformRelationOperator(GetOperand<int64_t>(left), GetOperand<int64_t>(right), opType);
        }
        case TypeRank::INT32:
        case TypeRank::CHAR: {
            return PerformRelationOperator(GetOperand<int32_t>(left), GetOperand<int32_t>(right), opType);
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

bool ConstantExpressionLowering::HandleBitwiseLogicalOperator(ir::Literal *left, ir::Literal *right,
                                                              lexer::TokenType opType)
{
    bool leftValue = left->AsBooleanLiteral()->Value();
    bool rightValue = right->AsBooleanLiteral()->Value();
    switch (opType) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            return (static_cast<uint32_t>(leftValue) ^ static_cast<uint32_t>(rightValue)) != 0U;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            return (static_cast<uint32_t>(leftValue) & static_cast<uint32_t>(rightValue)) != 0U;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            return (static_cast<uint32_t>(leftValue) | static_cast<uint32_t>(rightValue)) != 0U;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

ir::AstNode *ConstantExpressionLowering::HandleLogicalOperator(ir::BinaryExpression *expr, lexer::TokenType opType)
{
    auto left = expr->Left();
    auto right = expr->Right();

    bool leftBoolValue = false;
    ir::AstNode *resultValueNode = nullptr;

    if (left->IsBooleanLiteral()) {
        leftBoolValue = left->AsBooleanLiteral()->Value();
    } else if (left->IsNumberLiteral() || left->IsCharLiteral()) {
        leftBoolValue = GetOperand<int32_t>(left->AsLiteral()) != 0;
    } else if (left->IsStringLiteral()) {
        leftBoolValue = left->AsStringLiteral()->Str().Length() != 0;
    } else if (left->IsNullLiteral() || left->IsUndefinedLiteral()) {
        leftBoolValue = false;
    } else {
        ES2PANDA_UNREACHABLE();
    }

    switch (opType) {
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            if (!leftBoolValue) {
                resultValueNode = left;
                break;
            }
            resultValueNode = right;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            if (leftBoolValue) {
                resultValueNode = left;
            } else {
                resultValueNode = right;
            }
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    resultValueNode->SetParent(expr->Parent());
    resultValueNode->SetRange({left->Range().start, right->Range().end});
    return resultValueNode;
}

ir::AstNode *ConstantExpressionLowering::FoldBinaryBooleanConstant(ir::BinaryExpression *expr)
{
    auto left = expr->Left()->AsLiteral();
    auto right = expr->Right()->AsLiteral();

    bool result {};
    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            if ((left->IsBooleanLiteral() && right->IsBooleanLiteral()) || CheckIsNumericConstant(left, right) ||
                (left->IsStringLiteral() && right->IsStringLiteral())) {
                result = HandleRelationOperator(left, right, expr->OperatorType());
                break;
            }
            return expr;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            if (left->IsBooleanLiteral() && right->IsBooleanLiteral()) {
                result = HandleBitwiseLogicalOperator(left, right, expr->OperatorType());
                break;
            }
            return expr;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            // Special because of extended conditional expression
            return HandleLogicalOperator(expr, expr->OperatorType());
        }
        default: {
            return expr;
        }
    }

    auto resNode = util::NodeAllocator::Alloc<ir::BooleanLiteral>(context_->allocator, result);
    ES2PANDA_ASSERT(resNode);
    resNode->SetParent(expr->Parent());
    resNode->SetRange(expr->Range());
    return resNode;
}

template <typename IntegerType>
IntegerType ConstantExpressionLowering::PerformBitwiseArithmetic(IntegerType left, IntegerType right,
                                                                 lexer::TokenType operationType)
{
    using UnsignedType = std::make_unsigned_t<IntegerType>;

    UnsignedType result = 0;
    UnsignedType unsignedLeftValue = left;
    UnsignedType unsignedRightValue = right;

    auto mask = std::numeric_limits<UnsignedType>::digits - 1U;
    auto shift = unsignedRightValue & mask;

    switch (operationType) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            result = unsignedLeftValue & unsignedRightValue;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            result = unsignedLeftValue | unsignedRightValue;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            result = unsignedLeftValue ^ unsignedRightValue;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT: {
            static_assert(sizeof(UnsignedType) == 4 || sizeof(UnsignedType) == 8);
            result = unsignedLeftValue << shift;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT: {
            static_assert(sizeof(IntegerType) == 4 || sizeof(IntegerType) == 8);
            result = static_cast<IntegerType>(unsignedLeftValue) >> shift;  // NOLINT(hicpp-signed-bitwise)
            break;
        }
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT: {
            static_assert(sizeof(UnsignedType) == 4 || sizeof(UnsignedType) == 8);
            result = unsignedLeftValue >> shift;
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    return result;
}

template <typename TargetType>
lexer::Number ConstantExpressionLowering::HandleBitwiseOperator(TargetType leftNum, TargetType rightNum,
                                                                lexer::TokenType operationType, TypeRank targetRank)
{
    switch (targetRank) {
        case TypeRank::DOUBLE: {
            return lexer::Number(PerformBitwiseArithmetic<int64_t>(leftNum, rightNum, operationType));
        }
        case TypeRank::FLOAT: {
            return lexer::Number(PerformBitwiseArithmetic<int32_t>(leftNum, rightNum, operationType));
        }
        case TypeRank::INT64: {
            return lexer::Number(PerformBitwiseArithmetic<int64_t>(leftNum, rightNum, operationType));
        }
        case TypeRank::INT32:
        case TypeRank::CHAR: {
            return lexer::Number(PerformBitwiseArithmetic<int32_t>(leftNum, rightNum, operationType));
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template <typename TargetType>
TargetType ConstantExpressionLowering::HandleArithmeticOperation(TargetType leftNum, TargetType rightNum,
                                                                 ir::BinaryExpression *expr)
{
    auto isForbiddenZeroDivision = [&rightNum]() { return std::is_integral<TargetType>::value && rightNum == 0; };
    auto operationType = expr->OperatorType();
    switch (operationType) {
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            return leftNum + rightNum;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            return leftNum - rightNum;
        }
        case lexer::TokenType::PUNCTUATOR_DIVIDE: {
            if (isForbiddenZeroDivision()) {
                LogError(diagnostic::DIVISION_BY_ZERO, {}, expr->Start());
                return rightNum;
            }
            return leftNum / rightNum;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
            return leftNum * rightNum;
        }
        case lexer::TokenType::PUNCTUATOR_MOD: {
            if (isForbiddenZeroDivision()) {
                LogError(diagnostic::DIVISION_BY_ZERO, {}, expr->Start());
                return rightNum;
            }
            if constexpr (std::is_integral_v<TargetType>) {
                return leftNum % rightNum;
            } else {
                return std::fmod(leftNum, rightNum);
            }
        }
        default:
            ES2PANDA_UNREACHABLE();
    }
}

template <typename InputType>
ir::AstNode *ConstantExpressionLowering::FoldBinaryNumericConstantHelper(ir::BinaryExpression *expr,
                                                                         TypeRank targetRank)
{
    auto const lhs = expr->Left()->AsLiteral();
    auto const rhs = expr->Right()->AsLiteral();
    lexer::Number resNum {};
    auto lhsNumber = GetOperand<InputType>(lhs);
    auto rhsNumber = GetOperand<InputType>(rhs);
    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
            auto num = HandleArithmeticOperation(lhsNumber, rhsNumber, expr);
            resNum = lexer::Number(num);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            resNum = HandleBitwiseOperator<InputType>(lhsNumber, rhsNumber, expr->OperatorType(), targetRank);
            break;
        }
        default: {
            // Operation might not support.
            return expr;
        }
    }

    ir::TypedAstNode *resNode = util::NodeAllocator::Alloc<ir::NumberLiteral>(context_->allocator, resNum);
    resNode->SetParent(expr->Parent());
    resNode->SetRange(expr->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldBinaryNumericConstant(ir::BinaryExpression *expr)
{
    auto left = expr->Left()->AsLiteral();
    auto right = expr->Right()->AsLiteral();
    if (!IsSupportedLiteralForNumeric(left) && !IsSupportedLiteralForNumeric(right)) {
        return expr;
    }

    TypeRank leftRank = GetTypeRank(left);
    TypeRank rightRank = GetTypeRank(right);
    TypeRank targetRank = std::max(leftRank, rightRank);
    switch (targetRank) {
        case TypeRank::DOUBLE: {
            return FoldBinaryNumericConstantHelper<double>(expr, targetRank);
        }
        case TypeRank::FLOAT: {
            return FoldBinaryNumericConstantHelper<float>(expr, targetRank);
        }
        case TypeRank::INT64: {
            return FoldBinaryNumericConstantHelper<int64_t>(expr, targetRank);
        }
        case TypeRank::INT32:
        case TypeRank::CHAR: {
            return FoldBinaryNumericConstantHelper<int32_t>(expr, targetRank);
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

ir::AstNode *ConstantExpressionLowering::FoldBinaryStringConstant(ir::BinaryExpression *const expr)
{
    if (expr->OperatorType() != lexer::TokenType::PUNCTUATOR_PLUS) {
        LogError(diagnostic::UNSUPPORTED_OPERATOR_FOR_STRING, {}, expr->Left()->Start());
        return expr;
    }

    auto const lhs = expr->Left()->AsLiteral();
    auto const rhs = expr->Right()->AsLiteral();
    auto const resStr = util::UString(lhs->ToString() + rhs->ToString(), context_->allocator).View();
    auto resNode = util::NodeAllocator::Alloc<ir::StringLiteral>(context_->allocator, resStr);
    ES2PANDA_ASSERT(resNode);
    resNode->SetParent(expr->Parent());
    resNode->SetRange(expr->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldBinaryConstant(ir::BinaryExpression *const expr)
{
    auto const lhs = expr->Left()->AsLiteral();
    auto const rhs = expr->Right()->AsLiteral();

    auto isBooleanConstant = CheckIsBooleanConstantForBinary(lhs, rhs, expr->OperatorType());
    if (isBooleanConstant) {
        return FoldBinaryBooleanConstant(expr);
    }
    if (lhs->IsStringLiteral() || rhs->IsStringLiteral()) {
        return FoldBinaryStringConstant(expr);
    }
    return FoldBinaryNumericConstant(expr);
}

template <typename InputType>
lexer::Number ConstantExpressionLowering::HandleBitwiseNegate(InputType value, TypeRank rank)
{
    switch (rank) {
        case TypeRank::DOUBLE:
        case TypeRank::INT64: {
            return lexer::Number(static_cast<int64_t>(~static_cast<uint64_t>(value)));
        }
        case TypeRank::FLOAT:
        case TypeRank::INT32:
        case TypeRank::CHAR: {
            return lexer::Number(static_cast<int32_t>(~static_cast<uint32_t>(value)));
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template <typename InputType>
ir::AstNode *ConstantExpressionLowering::FoldUnaryNumericConstantHelper(ir::UnaryExpression *unary, ir::Literal *node,
                                                                        TypeRank rank)
{
    auto value = GetOperand<InputType>(node);

    lexer::Number resNum {};
    switch (unary->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            resNum = lexer::Number(value);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            resNum = lexer::Number(-value);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            resNum = std::move(HandleBitwiseNegate(value, rank));
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    ir::TypedAstNode *resNode = util::NodeAllocator::Alloc<ir::NumberLiteral>(context_->allocator, resNum);
    resNode->SetParent(unary->Parent());
    resNode->SetRange(unary->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldUnaryNumericConstant(ir::UnaryExpression *unary)
{
    auto literal = unary->Argument()->AsLiteral();
    TypeRank rank = GetTypeRank(literal);

    switch (rank) {
        case TypeRank::DOUBLE: {
            return FoldUnaryNumericConstantHelper<double>(unary, literal, rank);
        }
        case TypeRank::FLOAT: {
            return FoldUnaryNumericConstantHelper<float>(unary, literal, rank);
        }
        case TypeRank::INT64: {
            return FoldUnaryNumericConstantHelper<int64_t>(unary, literal, rank);
        }
        case TypeRank::INT32:
        case TypeRank::CHAR: {
            return FoldUnaryNumericConstantHelper<int32_t>(unary, literal, rank);
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

ir::AstNode *ConstantExpressionLowering::FoldUnaryBooleanConstant(ir::UnaryExpression *unary)
{
    bool result {};
    auto *unaryLiteral = unary->Argument()->AsLiteral();

    if (unary->OperatorType() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        // 15.10.1 Extended Conditional Expression
        if (unaryLiteral->IsUndefinedLiteral() || unaryLiteral->IsNullLiteral()) {
            result = true;
        } else {
            bool value = GetOperand<bool>(unaryLiteral);
            result = !value;
        }
    } else {
        ES2PANDA_UNREACHABLE();
    }

    auto resNode = util::NodeAllocator::Alloc<ir::BooleanLiteral>(context_->allocator, result);
    ES2PANDA_ASSERT(resNode != nullptr);
    resNode->SetParent(unary->Parent());
    resNode->SetRange(unary->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldUnaryConstant(ir::UnaryExpression *const unary)
{
    auto unaryLiteral = unary->Argument()->AsLiteral();

    auto isBooleanConstant = CheckIsBooleanConstantForUnary(unaryLiteral, unary->OperatorType());
    if (isBooleanConstant) {
        return FoldUnaryBooleanConstant(unary);
    }

    return FoldUnaryNumericConstant(unary);
}

ir::AstNode *ConstantExpressionLowering::TryFoldTSAsExpressionForString(ir::TSAsExpression *expr)
{
    if (expr->Expr()->IsStringLiteral() && expr->TypeAnnotation()->IsETSTypeReference() &&
        IsStringTypeReference(expr->TypeAnnotation()->AsETSTypeReference())) {
        auto res = expr->Expr()->AsStringLiteral();
        res->SetParent(expr->Parent());
        res->SetRange(expr->Range());
        return res;
    }
    return expr;
}

ir::AstNode *ConstantExpressionLowering::FoldTSAsExpressionToChar(ir::TSAsExpression *expr)
{
    auto *sourceLiteral = expr->Expr()->AsLiteral();
    auto resChar = GetOperand<char16_t>(sourceLiteral);
    ir::TypedAstNode *resNode = util::NodeAllocator::Alloc<ir::CharLiteral>(context_->allocator, resChar);
    resNode->SetParent(expr->Parent());
    resNode->SetRange(expr->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldTSAsExpressionToBoolean(ir::TSAsExpression *expr)
{
    auto *sourceLiteral = expr->Expr()->AsLiteral();
    auto resBool = GetOperand<bool>(sourceLiteral);
    ir::TypedAstNode *resNode = util::NodeAllocator::Alloc<ir::BooleanLiteral>(context_->allocator, resBool);
    resNode->SetParent(expr->Parent());
    resNode->SetRange(expr->Range());
    return resNode;
}

ir::AstNode *ConstantExpressionLowering::FoldTSAsExpression(ir::TSAsExpression *const expr)
{
    if (expr->TypeAnnotation()->IsETSPrimitiveType()) {
        auto *sourceLiteral = expr->Expr()->AsLiteral();
        lexer::Number resNum;
        switch (expr->TypeAnnotation()->AsETSPrimitiveType()->GetPrimitiveType()) {
            case ir::PrimitiveType::CHAR: {
                return FoldTSAsExpressionToChar(expr);
            }
            case ir::PrimitiveType::BOOLEAN: {
                return FoldTSAsExpressionToBoolean(expr);
            }
            case ir::PrimitiveType::BYTE: {
                resNum = lexer::Number(GetOperand<int8_t>(sourceLiteral));
                break;
            }
            case ir::PrimitiveType::SHORT: {
                resNum = lexer::Number(GetOperand<int16_t>(sourceLiteral));
                break;
            }
            case ir::PrimitiveType::INT: {
                resNum = lexer::Number(GetOperand<int32_t>(sourceLiteral));
                break;
            }
            case ir::PrimitiveType::LONG: {
                resNum = lexer::Number(GetOperand<int64_t>(sourceLiteral));
                break;
            }
            case ir::PrimitiveType::FLOAT: {
                resNum = lexer::Number(GetOperand<float>(sourceLiteral));
                break;
            }
            case ir::PrimitiveType::DOUBLE: {
                resNum = lexer::Number(GetOperand<double>(sourceLiteral));
                break;
            }
            default: {
                return expr;
            }
        }
        ir::TypedAstNode *result = util::NodeAllocator::Alloc<ir::NumberLiteral>(context_->allocator, resNum);
        result->SetParent(expr->Parent());
        result->SetRange(expr->Range());
        return result;
    }
    return TryFoldTSAsExpressionForString(expr);
}

ir::AstNode *ConstantExpressionLowering::FoldMultilineString(ir::TemplateLiteral *expr)
{
    auto *result = util::NodeAllocator::Alloc<ir::StringLiteral>(context_->allocator, expr->GetMultilineString());
    ES2PANDA_ASSERT(result);
    result->SetParent(expr->Parent());
    result->SetRange(expr->Range());
    return result;
}

static bool IsEnumMemberInit(ir::AstNode *node)
{
    auto parent = node->Parent();
    if (node->IsMemberExpression()) {
        return node->AsMemberExpression()->Object()->IsIdentifier();
    }

    if (node->IsIdentifier()) {
        if (parent->IsTSEnumMember()) {
            return parent->AsTSEnumMember()->Init() == node;
        }
        return !parent->IsMemberExpression() && !parent->IsTSEnumDeclaration() && !parent->IsETSTypeReferencePart();
    }

    return false;
}

ir::AstNode *ConstantExpressionLowering::UnFoldEnumMemberExpression(ir::AstNode *constantNode)
{
    ir::NodeTransformer handleUnfoldEnumMember = [this, constantNode](ir::AstNode *const node) {
        if (IsEnumMemberInit(node) && constantNode->IsTSEnumDeclaration()) {
            return FindAndReplaceEnumMember(node, constantNode);
        }

        return node;
    };
    constantNode->TransformChildrenRecursivelyPostorder(handleUnfoldEnumMember, Name());
    return constantNode;
}

ir::AstNode *ConstantExpressionLowering::FindNameInEnumMember(ArenaVector<ir::AstNode *> *members,
                                                              util::StringView targetName)
{
    auto it = std::find_if(members->begin(), members->end(), [&targetName](ir::AstNode *member) {
        return member->AsTSEnumMember()->Key()->AsIdentifier()->Name() == targetName;
    });
    return (it != members->end()) ? *it : nullptr;
}

ir::AstNode *ConstantExpressionLowering::FindAndReplaceEnumMember(ir::AstNode *const expr, ir::AstNode *constantNode)
{
    auto objectName = expr->IsMemberExpression() ? expr->AsMemberExpression()->Object()->AsIdentifier()->Name()
                                                 : constantNode->AsTSEnumDeclaration()->Key()->AsIdentifier()->Name();
    auto propertyName = expr->IsMemberExpression() ? expr->AsMemberExpression()->Property()->AsIdentifier()->Name()
                                                   : expr->AsIdentifier()->Name();
    for (auto curScope = constantNode->Scope(); curScope != nullptr; curScope = curScope->Parent()) {
        auto *foundDecl = curScope->FindDecl(objectName);
        if (foundDecl == nullptr || !foundDecl->Node()->IsTSEnumDeclaration()) {
            continue;
        }

        auto members = foundDecl->Node()->AsTSEnumDeclaration()->Members();
        auto member = FindNameInEnumMember(&members, propertyName);
        if (member != nullptr) {
            auto *transformedInit = member->AsTSEnumMember()->Init();
            if (transformedInit == nullptr) {
                return expr;
            }

            auto clonedInit = transformedInit->Clone(context_->allocator, expr->Parent());
            clonedInit->SetRange(expr->Range());
            return UnFoldEnumMemberExpression(clonedInit);
        }
    }
    return expr;
}

varbinder::Variable *ConstantExpressionLowering::FindIdentifier(ir::Identifier *ident)
{
    auto localCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder_, NearestScope(ident));
    auto option = varbinder::ResolveBindingOptions::ALL_VARIABLES;
    auto localScope = localCtx.GetScope();
    ES2PANDA_ASSERT(localScope != nullptr);
    auto *resolved = localScope->FindInFunctionScope(ident->Name(), option).variable;
    if (resolved == nullptr) {
        resolved = localScope->FindInGlobal(ident->Name(), option).variable;
    }
    return resolved;
}

ir::AstNode *ConstantExpressionLowering::UnfoldConstIdentifier(ir::AstNode *node, ir::AstNode *originNode)
{
    ir::AstNode *resNode = nullptr;
    if (node->IsClassProperty()) {
        auto prop = node->AsClassElement();
        resNode = prop->Value()->Clone(context_->allocator, originNode->Parent());
        resNode->SetRange(originNode->Range());
    }
    if (node->Parent()->IsVariableDeclarator()) {
        resNode = node->Parent()->AsVariableDeclarator()->Init()->Clone(context_->allocator, originNode->Parent());
        resNode->SetRange(originNode->Range());
    }
    if (resNode == nullptr) {
        return node;
    }
    if (!resNode->IsIdentifier()) {
        return UnfoldConstIdentifiers(resNode);
    }
    auto *ident = resNode->AsIdentifier();
    auto *resolved = FindIdentifier(ident);
    if (resolved == nullptr) {
        return resNode;
    }
    if (!resolved->Declaration()->IsConstDecl()) {
        return resNode;
    }
    return UnfoldConstIdentifier(resolved->Declaration()->Node(), resNode);
}

ir::AstNode *ConstantExpressionLowering::UnfoldConstIdentifiers(ir::AstNode *constantNode)
{
    ir::NodeTransformer handleUnfoldIdentifiers = [this](ir::AstNode *const node) {
        if (node->IsIdentifier()) {
            auto *ident = node->AsIdentifier();
            auto *resolved = FindIdentifier(ident);
            if (resolved == nullptr) {
                return node;
            }
            if (!resolved->Declaration()->IsConstDecl()) {
                return node;
            }
            return UnfoldConstIdentifier(resolved->Declaration()->Node(), node);
        }
        return node;
    };
    constantNode->TransformChildrenRecursivelyPostorder(handleUnfoldIdentifiers, Name());
    return constantNode;
}

static bool IsPotentialConstant(const ir::AstNodeType type)
{
    return type == ir::AstNodeType::TEMPLATE_LITERAL || type == ir::AstNodeType::TS_AS_EXPRESSION ||
           type == ir::AstNodeType::UNARY_EXPRESSION || type == ir::AstNodeType::BINARY_EXPRESSION ||
           type == ir::AstNodeType::CONDITIONAL_EXPRESSION || type == ir::AstNodeType::IDENTIFIER;
}

ir::AstNode *ConstantExpressionLowering::FoldConstant(ir::AstNode *constantNode)
{
    ir::NodeTransformer handleFoldConstant = [this](ir::AstNode *const node) {
        if (node->IsTemplateLiteral()) {
            auto tmpLiteral = node->AsTemplateLiteral();
            if (tmpLiteral->Expressions().empty()) {
                return FoldMultilineString(tmpLiteral);
            }
            LogError(diagnostic::STRING_INTERPOLATION_NOT_CONSTANT, {}, node->Start());
        }
        if (node->IsTSAsExpression()) {
            auto tsAsExpr = node->AsTSAsExpression();
            if (IsSupportedLiteral(tsAsExpr->Expr())) {
                return FoldTSAsExpression(tsAsExpr);
            }
            LogError(diagnostic::ONLY_CONSTANT_EXPRESSION, {}, node->Start());
        }
        if (node->IsUnaryExpression()) {
            auto unaryOp = node->AsUnaryExpression();
            if (IsSupportedLiteral(unaryOp->Argument())) {
                return FoldUnaryConstant(unaryOp);
            }
            LogError(diagnostic::ONLY_CONSTANT_EXPRESSION, {}, node->Start());
        }
        if (node->IsBinaryExpression()) {
            auto binop = node->AsBinaryExpression();
            if (IsSupportedLiteral(binop->Left()) && IsSupportedLiteral(binop->Right())) {
                return FoldBinaryConstant(binop);
            }
            LogError(diagnostic::ONLY_CONSTANT_EXPRESSION, {}, node->Start());
        }
        if (node->IsConditionalExpression()) {
            auto condExp = node->AsConditionalExpression();
            if (IsSupportedLiteral(condExp->Test())) {
                return FoldTernaryConstant(condExp);
            }
            LogError(diagnostic::ONLY_CONSTANT_EXPRESSION, {}, node->Start());
        }
        return node;
    };
    constantNode->TransformChildrenRecursivelyPostorder(handleFoldConstant, Name());
    return constantNode;
}

// Note: memberExpression can be constant when it is enum property access, this check will be enabled after Issue23082.
// for package, we need to check whether its every immediate-initializers is const expression.
void ConstantExpressionLowering::IsInitByConstant(ir::AstNode *node)
{
    ir::AstNode *initTobeChecked = nullptr;
    if (node->IsExpressionStatement() && node->AsExpressionStatement()->GetExpression()->IsAssignmentExpression()) {
        auto assignExpr = node->AsExpressionStatement()->GetExpression()->AsAssignmentExpression();
        initTobeChecked = assignExpr->Right();
        if (initTobeChecked->IsExpression() && IsSupportedLiteral(initTobeChecked->AsExpression())) {
            return;
        }

        if (!IsPotentialConstant(initTobeChecked->Type())) {
            LogError(diagnostic::INVALID_INIT_IN_PACKAGE, {}, initTobeChecked->Start());
            return;
        }
        assignExpr->SetRight(FoldConstant(UnfoldConstIdentifiers(initTobeChecked))->AsExpression());
    }

    if (node->IsClassProperty()) {
        auto classProp = node->AsClassProperty();
        initTobeChecked = classProp->Value();
        if (initTobeChecked == nullptr) {
            return;
        }

        if (initTobeChecked->IsExpression() && IsSupportedLiteral(initTobeChecked->AsExpression())) {
            return;
        }

        if (!IsPotentialConstant(initTobeChecked->Type())) {
            LogError(diagnostic::INVALID_INIT_IN_PACKAGE, {}, initTobeChecked->Start());
            return;
        }
        classProp->SetValue(FoldConstant(UnfoldConstIdentifiers(initTobeChecked))->AsExpression());
    }
}

void ConstantExpressionLowering::TryFoldInitializerOfPackage(ir::ClassDefinition *globalClass)
{
    for (auto element : globalClass->Body()) {
        if (element->IsMethodDefinition()) {
            auto const *classMethod = element->AsMethodDefinition();
            if (!classMethod->Key()->IsIdentifier() ||
                !classMethod->Key()->AsIdentifier()->Name().Is(compiler::Signatures::INIT_METHOD)) {
                continue;
            }

            auto const *methodBody = classMethod->Value()->AsFunctionExpression()->Function()->Body();
            if (methodBody == nullptr || !methodBody->IsBlockStatement()) {
                continue;
            }
            auto const &initStatements = methodBody->AsBlockStatement()->Statements();
            std::for_each(initStatements.begin(), initStatements.end(),
                          [this](ir::AstNode *node) { IsInitByConstant(node); });
        }

        if (element->IsClassProperty() && element->AsClassProperty()->IsConst() &&
            !element->AsClassProperty()->NeedInitInStaticBlock()) {
            IsInitByConstant(element);
        }
    }
}

bool ConstantExpressionLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    if (program->GetFlag(parser::ProgramFlags::AST_CONSTANT_EXPRESSION_LOWERED)) {
        return true;
    }

    context_ = ctx;
    program_ = program;
    varbinder_ = ctx->parserProgram->VarBinder()->AsETSBinder();
    program->Ast()->TransformChildrenRecursively(
        [this](checker::AstNodePtr const node) -> checker::AstNodePtr {
            if (node->IsAnnotationDeclaration() || node->IsAnnotationUsage()) {
                return FoldConstant(UnfoldConstIdentifiers(node));
            }
            if (node->IsTSEnumDeclaration()) {
                return FoldConstant(UnFoldEnumMemberExpression(UnfoldConstIdentifiers(node)));
            }

            // Note: Package need to check whether its immediate initializer is const expression.
            if (this->program_->IsPackage() && node->IsClassDefinition() && node->AsClassDefinition()->IsGlobal()) {
                TryFoldInitializerOfPackage(node->AsClassDefinition());
            }
            return node;
        },
        Name());

    program->SetFlag(parser::ProgramFlags::AST_CONSTANT_EXPRESSION_LOWERED);
    return true;
}

}  // namespace ark::es2panda::compiler
