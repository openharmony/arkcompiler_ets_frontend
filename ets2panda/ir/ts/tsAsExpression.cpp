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

#include "tsAsExpression.h"

#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "checker/ets/castingContext.h"
#include "compiler/core/ETSGen.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literal.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/typeNode.h"
#include "ir/ets/etsFunctionType.h"

namespace panda::es2panda::ir {
Expression *TSAsExpression::Expr()
{
    return expression_;
}

void TSAsExpression::SetExpr(Expression *expr)
{
    expression_ = expr;
    SetStart(expression_->Start());
}

void TSAsExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expression_);
    cb(TypeAnnotation());
}

void TSAsExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSAsExpression"}, {"expression", expression_}, {"typeAnnotation", TypeAnnotation()}});
}

void TSAsExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void TSAsExpression::Compile(compiler::ETSGen *const etsg) const
{
    if (!etsg->TryLoadConstantExpression(expression_)) {
        expression_->Compile(etsg);
    }

    etsg->ApplyConversion(expression_, nullptr);

    const auto target_type_kind = checker::ETSChecker::TypeKind(TsType());
    switch (target_type_kind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            etsg->CastToBoolean(this);
            break;
        }
        case checker::TypeFlag::CHAR: {
            etsg->CastToChar(this);
            break;
        }
        case checker::TypeFlag::BYTE: {
            etsg->CastToByte(this);
            break;
        }
        case checker::TypeFlag::SHORT: {
            etsg->CastToShort(this);
            break;
        }
        case checker::TypeFlag::INT: {
            etsg->CastToInt(this);
            break;
        }
        case checker::TypeFlag::LONG: {
            etsg->CastToLong(this);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            etsg->CastToFloat(this);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            etsg->CastToDouble(this);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            etsg->CastToArrayOrObject(this, TsType(), is_unchecked_cast_);
            break;
        }
        case checker::TypeFlag::ETS_ENUM: {
            auto *const signature = TsType()->AsETSEnumType()->FromIntMethod().global_signature;
            ArenaVector<ir::Expression *> arguments(etsg->Allocator()->Adapter());
            arguments.push_back(expression_);
            etsg->CallStatic(this, signature, arguments);
            etsg->SetAccumulatorType(signature->ReturnType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

static bool IsValidConstAssertionArgument(checker::Checker *checker, const ir::AstNode *arg)
{
    switch (arg->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL:
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::BIGINT_LITERAL:
        case ir::AstNodeType::BOOLEAN_LITERAL:
        case ir::AstNodeType::ARRAY_EXPRESSION:
        case ir::AstNodeType::OBJECT_EXPRESSION:
        case ir::AstNodeType::TEMPLATE_LITERAL: {
            return true;
        }
        case ir::AstNodeType::UNARY_EXPRESSION: {
            const ir::UnaryExpression *unary_expr = arg->AsUnaryExpression();
            lexer::TokenType op = unary_expr->OperatorType();
            const ir::Expression *unary_arg = unary_expr->Argument();
            return (op == lexer::TokenType::PUNCTUATOR_MINUS && unary_arg->IsLiteral() &&
                    (unary_arg->AsLiteral()->IsNumberLiteral() || unary_arg->AsLiteral()->IsBigIntLiteral())) ||
                   (op == lexer::TokenType::PUNCTUATOR_PLUS && unary_arg->IsLiteral() &&
                    unary_arg->AsLiteral()->IsNumberLiteral());
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            const ir::MemberExpression *member_expr = arg->AsMemberExpression();
            if (member_expr->Object()->IsIdentifier()) {
                auto result = checker->Scope()->Find(member_expr->Object()->AsIdentifier()->Name());
                constexpr auto ENUM_LITERAL_TYPE = checker::EnumLiteralType::EnumLiteralTypeKind::LITERAL;
                if (result.variable != nullptr &&
                    result.variable->TsType()->HasTypeFlag(checker::TypeFlag::ENUM_LITERAL) &&
                    result.variable->TsType()->AsEnumLiteralType()->Kind() == ENUM_LITERAL_TYPE) {
                    return true;
                }
            }
            return false;
        }
        default:
            return false;
    }
}

checker::Type *TSAsExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (is_const_) {
        auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_CONST_CONTEXT);
        checker::Type *expr_type = expression_->Check(checker);

        if (!IsValidConstAssertionArgument(checker, expression_)) {
            checker->ThrowTypeError(
                "A 'const' assertions can only be applied to references to enum members, or string, number, "
                "boolean, array, or object literals.",
                expression_->Start());
        }

        return expr_type;
    }

    auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::NO_OPTS);

    TypeAnnotation()->Check(checker);
    checker::Type *expr_type = checker->GetBaseTypeOfLiteralType(expression_->Check(checker));
    checker::Type *target_type = TypeAnnotation()->GetType(checker);

    checker->IsTypeComparableTo(
        target_type, expr_type,
        {"Conversion of type '", expr_type, "' to type '", target_type,
         "' may be a mistake because neither type sufficiently overlaps with the other. If this was ",
         "intentional, convert the expression to 'unknown' first."},
        Start());

    return target_type;
}

checker::Type *TSAsExpression::Check(checker::ETSChecker *const checker)
{
    auto *const target_type = TypeAnnotation()->AsTypeNode()->GetType(checker);
    // Object expression requires that its type be set by the context before checking. in this case, the target type
    // provides that context.
    if (expression_->IsObjectExpression()) {
        expression_->AsObjectExpression()->SetPreferredType(target_type);
    }
    auto *const source_type = expression_->Check(checker);

    const checker::CastingContext ctx(checker->Relation(), expression_, source_type, target_type, expression_->Start(),
                                      {"Cannot cast type '", source_type, "' to '", target_type, "'"});

    if (source_type->IsETSDynamicType() && target_type->IsLambdaObject()) {
        // TODO(itrubachev) change target_type to created lambdaobject type.
        // Now target_type is not changed, only construct signature is added to it
        checker->BuildLambdaObjectClass(target_type->AsETSObjectType(),
                                        TypeAnnotation()->AsETSFunctionType()->ReturnType());
    }
    is_unchecked_cast_ = ctx.UncheckedCast();

    // Make sure the array type symbol gets created for the assembler to be able to emit checkcast.
    // Because it might not exist, if this particular array type was never created explicitly.
    if (!is_unchecked_cast_ && target_type->IsETSArrayType()) {
        auto *const target_array_type = target_type->AsETSArrayType();
        checker->CreateBuiltinArraySignature(target_array_type, target_array_type->Rank());
    }

    SetTsType(target_type);
    return TsType();
}
}  // namespace panda::es2panda::ir
