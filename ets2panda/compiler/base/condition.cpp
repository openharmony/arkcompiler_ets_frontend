/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "condition.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/expressions/binaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/unaryExpression.h"

namespace panda::es2panda::compiler {
void Condition::Compile(PandaGen *pg, const ir::Expression *expr, Label *false_label)
{
    if (expr->IsBinaryExpression()) {
        const auto *bin_expr = expr->AsBinaryExpression();

        switch (bin_expr->OperatorType()) {
            case lexer::TokenType::PUNCTUATOR_EQUAL:
            case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
            case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
            case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
                // This is a special case
                // These operators are expressed via cmp instructions and the following
                // if-else branches. Condition also expressed via cmp instruction and
                // the following if-else.
                // the goal of this method is to merge these two sequences of instructions.
                RegScope rs(pg);
                VReg lhs = pg->AllocReg();

                bin_expr->Left()->Compile(pg);
                pg->StoreAccumulator(bin_expr, lhs);
                bin_expr->Right()->Compile(pg);
                pg->Condition(bin_expr, bin_expr->OperatorType(), lhs, false_label);
                return;
            }
            case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
                bin_expr->Left()->Compile(pg);
                pg->ToBoolean(bin_expr);
                pg->BranchIfFalse(bin_expr, false_label);

                bin_expr->Right()->Compile(pg);
                pg->ToBoolean(bin_expr);
                pg->BranchIfFalse(bin_expr, false_label);
                return;
            }
            case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
                auto *end_label = pg->AllocLabel();

                bin_expr->Left()->Compile(pg);
                pg->ToBoolean(bin_expr);
                pg->BranchIfTrue(bin_expr, end_label);

                bin_expr->Right()->Compile(pg);
                pg->ToBoolean(bin_expr);
                pg->BranchIfFalse(bin_expr, false_label);
                pg->SetLabel(bin_expr, end_label);
                return;
            }
            default: {
                break;
            }
        }
    } else if (expr->IsUnaryExpression() &&
               expr->AsUnaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        expr->AsUnaryExpression()->Argument()->Compile(pg);

        pg->Negate(expr);
        pg->BranchIfFalse(expr, false_label);
        return;
    }

    // General case including some binExpr i.E.(a+b)
    expr->Compile(pg);
    pg->ToBoolean(expr);
    pg->BranchIfFalse(expr, false_label);
}

Condition::Result Condition::CheckConstantExpr(const ir::Expression *expr)
{
    if (expr->TsType()->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        auto res = expr->TsType()->AsETSBooleanType()->GetValue();
        return res ? Result::CONST_TRUE : Result::CONST_FALSE;
    }

    return Result::UNKNOWN;
}

void Condition::Compile(ETSGen *etsg, const ir::Expression *expr, Label *false_label)
{
    if (expr->IsBinaryExpression()) {
        const auto *bin_expr = expr->AsBinaryExpression();

        switch (bin_expr->OperatorType()) {
            case lexer::TokenType::PUNCTUATOR_EQUAL:
            case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN:
            case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
            case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
            case lexer::TokenType::KEYW_INSTANCEOF: {
                auto ttctx = TargetTypeContext(etsg, bin_expr->OperationType());

                RegScope rs(etsg);
                VReg lhs = etsg->AllocReg();

                bin_expr->Left()->Compile(etsg);
                etsg->ApplyConversionAndStoreAccumulator(bin_expr->Left(), lhs, bin_expr->OperationType());
                bin_expr->Right()->Compile(etsg);
                etsg->ApplyConversion(bin_expr->Right(), bin_expr->OperationType());
                etsg->Condition(bin_expr, bin_expr->OperatorType(), lhs, false_label);
                return;
            }
            case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
                bin_expr->Left()->Compile(etsg);
                etsg->ApplyConversion(bin_expr->Left(), bin_expr->OperationType());
                etsg->BranchIfFalse(bin_expr, false_label);

                bin_expr->Right()->Compile(etsg);
                etsg->ApplyConversion(bin_expr->Right(), bin_expr->OperationType());
                etsg->BranchIfFalse(bin_expr, false_label);
                return;
            }
            case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
                auto *end_label = etsg->AllocLabel();

                bin_expr->Left()->Compile(etsg);
                etsg->ApplyConversion(bin_expr->Left(), bin_expr->OperationType());
                etsg->BranchIfTrue(bin_expr, end_label);

                bin_expr->Right()->Compile(etsg);
                etsg->ApplyConversion(bin_expr->Right(), bin_expr->OperationType());
                etsg->BranchIfFalse(bin_expr, false_label);
                etsg->SetLabel(bin_expr, end_label);
                return;
            }
            default: {
                break;
            }
        }
    } else if (expr->IsUnaryExpression() &&
               expr->AsUnaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        expr->AsUnaryExpression()->Argument()->Compile(etsg);
        etsg->ApplyConversion(expr->AsUnaryExpression()->Argument(), etsg->Checker()->GlobalETSBooleanType());
        etsg->BranchIfTrue(expr, false_label);
        return;
    }

    // TODO(user): Handle implicit bool conversion: not zero int == true, not null obj ref == true, otherwise false
    ASSERT(expr->TsType()->IsETSBooleanType() ||
           (expr->TsType()->IsETSObjectType() &&
            expr->TsType()->AsETSObjectType()->HasObjectFlag(
                checker::ETSObjectFlags::BUILTIN_BOOLEAN)));  // already checked by checker::CheckTruthinessOfType()
    expr->Compile(etsg);
    etsg->ApplyConversion(expr, etsg->Checker()->GlobalETSBooleanType());
    etsg->BranchIfFalse(expr, false_label);
}
}  // namespace panda::es2panda::compiler
