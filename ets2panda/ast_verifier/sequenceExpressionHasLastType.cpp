/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "ir/expressions/sequenceExpression.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult SequenceExpressionHasLastType::operator()(CheckContext &ctx, const ir::AstNode *ast)
{
    if (!ast->IsSequenceExpression()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto *expr = ast->AsSequenceExpression();
    const auto *last = expr->Sequence().back();
    if (expr->TsType() == nullptr) {
        ctx.AddCheckMessage("Sequence expression type is null", *expr, expr->Start());
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    if (last->TsType() == nullptr) {
        ctx.AddCheckMessage("Sequence expression last type is null", *last, last->Start());
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    if (expr->TsType() != last->TsType()) {
        ctx.AddCheckMessage("Sequence expression type and last expression type are not the same", *expr, expr->Start());
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
