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

#include "modifierAccessValid.h"
#include "ast_verifier/helpers.h"
#include "varbinder/variableFlags.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/callExpression.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult ModifierAccessValid::operator()(const ir::AstNode *ast)
{
    if (auto [decision, action] = HandleMethodExpression(ast); decision == CheckDecision::INCORRECT) {
        return {decision, action};
    }
    if (auto [decision, action] = HandleCallExpression(ast); decision == CheckDecision::INCORRECT) {
        return {decision, action};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

CheckResult ModifierAccessValid::HandleMethodExpression(const ir::AstNode *ast)
{
    if (!ast->IsMemberExpression()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto *propVar = ast->AsMemberExpression()->PropVar();
    if (propVar != nullptr && propVar->HasFlag(varbinder::VariableFlags::PROPERTY) &&
        !ValidateVariableAccess(propVar, ast->AsMemberExpression())) {
        AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE", *ast);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

CheckResult ModifierAccessValid::HandleCallExpression(const ir::AstNode *ast)
{
    if (!ast->IsCallExpression()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto *callExpr = ast->AsCallExpression();
    const auto *callee = callExpr->Callee();
    if (callee != nullptr && callee->IsMemberExpression()) {
        const auto *calleeMember = callee->AsMemberExpression();
        const auto *propVarCallee = calleeMember->PropVar();
        if (propVarCallee != nullptr && propVarCallee->HasFlag(varbinder::VariableFlags::METHOD) &&
            !ValidateMethodAccess(calleeMember, ast->AsCallExpression())) {
            AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE", *callee);
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
