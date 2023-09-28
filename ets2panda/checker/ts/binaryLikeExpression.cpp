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

#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"

#include "plugins/ecmascript/es2panda/checker/TSchecker.h"

namespace panda::es2panda::checker {
Type *TSChecker::CheckBinaryOperator(Type *left_type, Type *right_type, ir::Expression *left_expr,
                                     ir::Expression *right_expr, ir::AstNode *expr, lexer::TokenType op)
{
    CheckNonNullType(left_type, left_expr->Start());
    CheckNonNullType(right_type, right_expr->Start());

    if (left_type->HasTypeFlag(TypeFlag::BOOLEAN_LIKE) && right_type->HasTypeFlag(TypeFlag::BOOLEAN_LIKE)) {
        lexer::TokenType suggested_op;
        switch (op) {
            case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
            case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL: {
                suggested_op = lexer::TokenType::PUNCTUATOR_LOGICAL_OR;
                break;
            }
            case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
            case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL: {
                suggested_op = lexer::TokenType::PUNCTUATOR_LOGICAL_AND;
                break;
            }
            case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
            case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL: {
                suggested_op = lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL;
                break;
            }
            default: {
                suggested_op = lexer::TokenType::EOS;
                break;
            }
        }

        if (suggested_op != lexer::TokenType::EOS) {
            ThrowTypeError(
                {"The ", op, " operator is not allowed for boolean types. Consider using ", suggested_op, " instead"},
                expr->Start());
        }
    }

    if (!left_type->HasTypeFlag(TypeFlag::VALID_ARITHMETIC_TYPE)) {
        ThrowTypeError(
            "The left-hand side of an arithmetic operation must be of type 'any', 'number', 'bigint' or an "
            "enum "
            "type.",
            expr->Start());
    }

    if (!right_type->HasTypeFlag(TypeFlag::VALID_ARITHMETIC_TYPE)) {
        ThrowTypeError(
            "The right-hand side of an arithmetic operation must be of type 'any', 'number', 'bigint' or an "
            "enum "
            "type.",
            right_expr->Start());
    }

    Type *result_type = nullptr;
    if ((left_type->IsAnyType() && right_type->IsAnyType()) ||
        !(left_type->HasTypeFlag(TypeFlag::BIGINT_LIKE) || right_type->HasTypeFlag(TypeFlag::BIGINT_LIKE))) {
        result_type = GlobalNumberType();
    } else if (left_type->HasTypeFlag(TypeFlag::BIGINT_LIKE) && right_type->HasTypeFlag(TypeFlag::BIGINT_LIKE)) {
        if (op == lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT ||
            op == lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL) {
            ThrowTypeError({"operator ", op, " cannot be applied to types 'bigint' and 'bigint'"}, expr->Start());
        }
        result_type = GlobalBigintType();
    } else {
        ThrowBinaryLikeError(op, left_type, right_type, expr->Start());
    }

    CheckAssignmentOperator(op, left_expr, left_type, result_type);
    return result_type;
}

Type *TSChecker::CheckPlusOperator(Type *left_type, Type *right_type, ir::Expression *left_expr,
                                   ir::Expression *right_expr, ir::AstNode *expr, lexer::TokenType op)
{
    if (!left_type->HasTypeFlag(TypeFlag::STRING_LIKE) && !right_type->HasTypeFlag(TypeFlag::STRING_LIKE)) {
        CheckNonNullType(left_type, left_expr->Start());
        CheckNonNullType(right_type, right_expr->Start());
    }

    Type *result_type = nullptr;
    if (IsTypeAssignableTo(left_type, GlobalNumberType()) && IsTypeAssignableTo(right_type, GlobalNumberType())) {
        result_type = GlobalNumberType();
    } else if (IsTypeAssignableTo(left_type, GlobalBigintType()) &&
               IsTypeAssignableTo(right_type, GlobalBigintType())) {
        result_type = GlobalBigintType();
    } else if (IsTypeAssignableTo(left_type, GlobalStringType()) ||
               IsTypeAssignableTo(right_type, GlobalStringType())) {
        result_type = GlobalStringType();
    } else if (MaybeTypeOfKind(left_type, TypeFlag::UNKNOWN)) {
        ThrowTypeError("object is of type 'unknown'", left_expr->Start());
    } else if (MaybeTypeOfKind(right_type, TypeFlag::UNKNOWN)) {
        ThrowTypeError("object is of type 'unknown'", right_expr->Start());
    } else if (left_type->IsAnyType() || right_type->IsAnyType()) {
        result_type = GlobalAnyType();
    } else {
        ThrowBinaryLikeError(op, left_type, right_type, expr->Start());
    }

    if (op == lexer::TokenType::PUNCTUATOR_PLUS_EQUAL) {
        CheckAssignmentOperator(op, left_expr, left_type, result_type);
    }

    return result_type;
}

Type *TSChecker::CheckCompareOperator(Type *left_type, Type *right_type, ir::Expression *left_expr,
                                      ir::Expression *right_expr, ir::AstNode *expr, lexer::TokenType op)
{
    CheckNonNullType(left_type, left_expr->Start());
    CheckNonNullType(right_type, right_expr->Start());

    if (AreTypesComparable(left_type, right_type) || (IsTypeAssignableTo(left_type, GlobalNumberOrBigintType()) &&
                                                      IsTypeAssignableTo(right_type, GlobalNumberOrBigintType()))) {
        return GlobalBooleanType();
    }

    ThrowBinaryLikeError(op, left_type, right_type, expr->Start());

    return GlobalAnyType();
}

Type *TSChecker::CheckAndOperator(Type *left_type, Type *right_type, ir::Expression *left_expr)
{
    CheckTruthinessOfType(left_type, left_expr->Start());

    if ((static_cast<uint64_t>(left_type->GetTypeFacts()) & static_cast<uint64_t>(TypeFacts::TRUTHY)) != 0U) {
        Type *result_type = CreateUnionType({ExtractDefinitelyFalsyTypes(right_type), right_type});
        return result_type;
    }

    return left_type;
}

Type *TSChecker::CheckOrOperator(Type *left_type, Type *right_type, ir::Expression *left_expr)
{
    CheckTruthinessOfType(left_type, left_expr->Start());

    if ((static_cast<uint64_t>(left_type->GetTypeFacts()) & static_cast<uint64_t>(TypeFacts::FALSY)) != 0U) {
        // TODO(aszilagyi): subtype reduction in the result union
        Type *result_type = CreateUnionType({RemoveDefinitelyFalsyTypes(left_type), right_type});
        return result_type;
    }

    return left_type;
}

static bool TypeHasCallOrConstructSignatures(Type *type)
{
    return type->IsObjectType() &&
           (!type->AsObjectType()->CallSignatures().empty() || !type->AsObjectType()->ConstructSignatures().empty());
}

Type *TSChecker::CheckInstanceofExpression(Type *left_type, Type *right_type, ir::Expression *right_expr,
                                           ir::AstNode *expr)
{
    if (left_type->TypeFlags() != TypeFlag::ANY && IsAllTypesAssignableTo(left_type, GlobalPrimitiveType())) {
        ThrowTypeError({"The left-hand side of an 'instanceof' expression must be of type 'any',",
                        " an object type or a type parameter."},
                       expr->Start());
    }

    // TODO(aszilagyi): Check if right type is subtype of globalFunctionType
    if (right_type->TypeFlags() != TypeFlag::ANY && !TypeHasCallOrConstructSignatures(right_type)) {
        ThrowTypeError({"The right-hand side of an 'instanceof' expression must be of type 'any'",
                        " or of a type assignable to the 'Function' interface type."},
                       right_expr->Start());
    }

    return GlobalBooleanType();
}

Type *TSChecker::CheckInExpression(Type *left_type, Type *right_type, ir::Expression *left_expr,
                                   ir::Expression *right_expr, ir::AstNode *expr)
{
    CheckNonNullType(left_type, left_expr->Start());
    CheckNonNullType(right_type, right_expr->Start());

    // TODO(aszilagyi): Check IsAllTypesAssignableTo with ESSymbol too
    if (left_type->TypeFlags() != TypeFlag::ANY && !IsAllTypesAssignableTo(left_type, GlobalStringOrNumberType())) {
        ThrowTypeError(
            {"The left-hand side of an 'in' expression must be of type 'any',", " 'string', 'number', or 'symbol'."},
            expr->Start());
    }

    // TODO(aszilagyi): Handle type parameters
    if (!IsAllTypesAssignableTo(right_type, GlobalNonPrimitiveType())) {
        ThrowTypeError("The right-hand side of an 'in' expression must not be a primitive.", right_expr->Start());
    }

    return GlobalBooleanType();
}

void TSChecker::CheckAssignmentOperator(lexer::TokenType op, ir::Expression *left_expr, Type *left_type,
                                        Type *value_type)
{
    if (IsAssignmentOperator(op)) {
        CheckReferenceExpression(
            left_expr, "the left hand side of an assignment expression must be a variable or a property access",
            "The left-hand side of an assignment expression may not be an optional property access.");

        if (!IsTypeAssignableTo(value_type, left_type)) {
            ThrowAssignmentError(value_type, left_type, left_expr->Start(),
                                 left_expr->Parent()->AsAssignmentExpression()->Right()->IsMemberExpression() ||
                                     left_expr->Parent()->AsAssignmentExpression()->Right()->IsChainExpression());
        }
    }
}
}  // namespace panda::es2panda::checker
