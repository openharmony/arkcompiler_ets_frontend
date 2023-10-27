/**
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

#include "unaryExpression.h"

#include "binder/variable.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"

namespace panda::es2panda::ir {
void UnaryExpression::TransformChildren(const NodeTransformer &cb)
{
    argument_ = cb(argument_)->AsExpression();
}

void UnaryExpression::Iterate(const NodeTraverser &cb) const
{
    cb(argument_);
}

void UnaryExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "UnaryExpression"}, {"operator", operator_}, {"prefix", true}, {"argument", argument_}});
}

void UnaryExpression::Compile(compiler::PandaGen *pg) const
{
    switch (operator_) {
        case lexer::TokenType::KEYW_DELETE: {
            if (argument_->IsIdentifier()) {
                auto result = pg->Scope()->Find(argument_->AsIdentifier()->Name());
                if (result.variable == nullptr ||
                    (result.scope->IsGlobalScope() && result.variable->IsGlobalVariable())) {
                    compiler::RegScope rs(pg);
                    compiler::VReg variable = pg->AllocReg();
                    compiler::VReg global = pg->AllocReg();

                    pg->LoadConst(this, compiler::Constant::JS_GLOBAL);
                    pg->StoreAccumulator(this, global);

                    pg->LoadAccumulatorString(this, argument_->AsIdentifier()->Name());
                    pg->StoreAccumulator(this, variable);

                    pg->DeleteObjProperty(this, global, variable);
                } else {
                    // Otherwise it is a local variable which can't be deleted and we just
                    // return false.
                    pg->LoadConst(this, compiler::Constant::JS_FALSE);
                }
            } else if (argument_->IsMemberExpression()) {
                compiler::RegScope rs(pg);
                compiler::VReg object = pg->AllocReg();
                compiler::VReg property = pg->AllocReg();

                argument_->AsMemberExpression()->CompileToRegs(pg, object, property);
                pg->DeleteObjProperty(this, object, property);
            } else {
                // compile the delete operand.
                argument_->Compile(pg);
                // Deleting any value or a result of an expression returns True.
                pg->LoadConst(this, compiler::Constant::JS_TRUE);
            }
            break;
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            if (argument_->IsIdentifier()) {
                const auto *ident = argument_->AsIdentifier();

                auto res = pg->Scope()->Find(ident->Name());
                if (res.variable == nullptr) {
                    pg->LoadConst(this, compiler::Constant::JS_GLOBAL);
                    pg->LoadObjByName(this, ident->Name());
                } else {
                    pg->LoadVar(ident, res);
                }
            } else {
                argument_->Compile(pg);
            }

            pg->TypeOf(this);
            break;
        }
        case lexer::TokenType::KEYW_VOID: {
            argument_->Compile(pg);
            pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
            break;
        }
        default: {
            argument_->Compile(pg);

            compiler::RegScope rs(pg);
            compiler::VReg operand_reg = pg->AllocReg();
            pg->StoreAccumulator(this, operand_reg);
            pg->Unary(this, operator_, operand_reg);
            break;
        }
    }
}

void UnaryExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    auto ttctx = compiler::TargetTypeContext(etsg, TsType());
    if (!etsg->TryLoadConstantExpression(argument_)) {
        argument_->Compile(etsg);
    }
    etsg->ApplyConversion(argument_, nullptr);
    etsg->Unary(this, operator_);
}

checker::Type *UnaryExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::Type *operand_type = argument_->Check(checker);

    if (operator_ == lexer::TokenType::KEYW_TYPEOF) {
        return operand_type;
    }

    if (operator_ == lexer::TokenType::KEYW_DELETE) {
        checker::Type *prop_type = argument_->Check(checker);

        if (!argument_->IsMemberExpression()) {
            checker->ThrowTypeError("The operand of a delete operator must be a property reference.",
                                    argument_->Start());
        }

        if (prop_type->Variable()->HasFlag(binder::VariableFlags::READONLY)) {
            checker->ThrowTypeError("The operand of a delete operator cannot be a readonly property.",
                                    argument_->Start());
        }

        if (!prop_type->Variable()->HasFlag(binder::VariableFlags::OPTIONAL)) {
            checker->ThrowTypeError("The operand of a delete operator must be a optional.", argument_->Start());
        }

        return checker->GlobalBooleanType();
    }

    if (argument_->IsLiteral()) {
        const ir::Literal *lit = argument_->AsLiteral();

        if (lit->IsNumberLiteral()) {
            auto number_value = lit->AsNumberLiteral()->Number().GetDouble();
            if (operator_ == lexer::TokenType::PUNCTUATOR_PLUS) {
                return checker->CreateNumberLiteralType(number_value);
            }

            if (operator_ == lexer::TokenType::PUNCTUATOR_MINUS) {
                return checker->CreateNumberLiteralType(-number_value);
            }
        } else if (lit->IsBigIntLiteral() && operator_ == lexer::TokenType::PUNCTUATOR_MINUS) {
            return checker->CreateBigintLiteralType(lit->AsBigIntLiteral()->Str(), true);
        }
    }

    switch (operator_) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            checker->CheckNonNullType(operand_type, Start());
            // TODO(aszilagyi): check Symbol like types

            if (operator_ == lexer::TokenType::PUNCTUATOR_PLUS) {
                if (checker::TSChecker::MaybeTypeOfKind(operand_type, checker::TypeFlag::BIGINT_LIKE)) {
                    checker->ThrowTypeError({"Operator '+' cannot be applied to type '", operand_type, "'"}, Start());
                }

                return checker->GlobalNumberType();
            }

            return checker->GetUnaryResultType(operand_type);
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            checker->CheckTruthinessOfType(operand_type, Start());
            auto facts = operand_type->GetTypeFacts();
            if ((facts & checker::TypeFacts::TRUTHY) != 0) {
                return checker->GlobalFalseType();
            }

            if ((facts & checker::TypeFacts::FALSY) != 0) {
                return checker->GlobalTrueType();
            }

            return checker->GlobalBooleanType();
        }
        default: {
            UNREACHABLE();
        }
    }

    return nullptr;
}

checker::Type *UnaryExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    auto arg_type = argument_->Check(checker);
    const auto is_cond_expr = operator_ == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK;
    checker::Type *operand_type = checker->ApplyUnaryOperatorPromotion(arg_type, true, true, is_cond_expr);
    auto unboxed_operand_type = is_cond_expr ? checker->ETSBuiltinTypeAsConditionalType(arg_type)
                                             : checker->ETSBuiltinTypeAsPrimitiveType(arg_type);

    switch (operator_) {
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            if (operand_type == nullptr || !operand_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                        argument_->Start());
            }

            if (operand_type->HasTypeFlag(checker::TypeFlag::CONSTANT) &&
                operator_ == lexer::TokenType::PUNCTUATOR_MINUS) {
                SetTsType(checker->NegateNumericType(operand_type, this));
                break;
            }

            SetTsType(operand_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            if (operand_type == nullptr || !operand_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be integral type.",
                                        argument_->Start());
            }

            if (operand_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                SetTsType(checker->BitwiseNegateIntegralType(operand_type, this));
                break;
            }

            SetTsType(operand_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            if (checker->IsNullOrVoidExpression(argument_)) {
                auto ts_type = checker->CreateETSBooleanType(true);
                ts_type->AddTypeFlag(checker::TypeFlag::CONSTANT);
                SetTsType(ts_type);
                break;
            }

            if (operand_type == nullptr || !operand_type->IsConditionalExprType()) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be boolean type.",
                                        argument_->Start());
            }

            auto expr_res = operand_type->ResolveConditionExpr();
            if (std::get<0>(expr_res)) {
                auto ts_type = checker->CreateETSBooleanType(!std::get<1>(expr_res));
                ts_type->AddTypeFlag(checker::TypeFlag::CONSTANT);
                SetTsType(ts_type);
                break;
            }

            SetTsType(operand_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR: {
            SetTsType(arg_type);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    if (arg_type->IsETSObjectType() && (unboxed_operand_type != nullptr) &&
        unboxed_operand_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        argument_->AddBoxingUnboxingFlag(checker->GetUnboxingFlag(unboxed_operand_type));
    }

    return TsType();
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *UnaryExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const argument = argument_ != nullptr ? argument_->Clone(allocator) : nullptr;

    if (auto *const clone = allocator->New<UnaryExpression>(argument, operator_); clone != nullptr) {
        if (argument != nullptr) {
            argument->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
