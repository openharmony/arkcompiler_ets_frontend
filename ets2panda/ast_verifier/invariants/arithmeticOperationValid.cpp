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

#include "arithmeticOperationValid.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/base/classDefinition.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ast_verifier/helpers.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult ArithmeticOperationValid::operator()(const ir::AstNode *ast)
{
    if (auto [decision, action] = CheckCompound(ast); action == CheckAction::SKIP_SUBTREE) {
        return {decision, action};
    }
    if (!ast->IsBinaryExpression() || !ast->AsBinaryExpression()->IsArithmetic()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    if ((ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS ||
         ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS_EQUAL) &&
        (IsStringType(ast->AsBinaryExpression()->Left()) || IsStringType(ast->AsBinaryExpression()->Right()))) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
    bool isBitwise = ast->AsBinaryExpression()->IsBitwise();
    ast->Iterate([this, &result, &isBitwise](ir::AstNode *child) {
        if (!IsValidTypeForBinaryOp(child, isBitwise)) {
            AddCheckMessage("Not a numeric type", *child);
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
    });
    return result;
}

CheckResult ArithmeticOperationValid::CheckCompound(const ir::AstNode *ast)
{
    if (ast->IsTSInterfaceDeclaration()) {
        for (const auto &member : ast->AsTSInterfaceDeclaration()->Body()->Body()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsTSEnumDeclaration()) {
        for (const auto &member : ast->AsTSEnumDeclaration()->Members()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsClassDefinition()) {
        for (const auto &member : ast->AsClassDefinition()->Body()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
