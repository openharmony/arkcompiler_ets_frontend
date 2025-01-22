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

#include "sequenceExpressionHasLastType.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/sequenceExpression.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult SequenceExpressionHasLastType::operator()(const ir::AstNode *ast)
{
    if (ast->IsScriptFunction() && ast->AsScriptFunction()->IsExternal()) {
        // Identifiers in external functions' definitions are not resolved, so skip it
        ES2PANDA_ASSERT(!ast->AsScriptFunction()->IsExternalOverload());
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (!ast->IsSequenceExpression()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto *expr = ast->AsSequenceExpression();
    const auto *last = expr->Sequence().back();
    if (expr->TsType() == nullptr) {
        AddCheckMessage("Sequence expression type is null", *expr);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    if (last->TsType() == nullptr) {
        AddCheckMessage("Sequence expression last type is null", *last);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    if (expr->TsType() != last->TsType()) {
        AddCheckMessage("Sequence expression type and last expression type are not the same", *expr);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
