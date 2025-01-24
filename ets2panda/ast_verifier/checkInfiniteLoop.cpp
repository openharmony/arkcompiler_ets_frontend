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

#include "checkInfiniteLoop.h"
#include "ir/expression.h"
#include "ir/statements/forUpdateStatement.h"
#include "checker/types/type.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/whileStatement.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult CheckInfiniteLoop::operator()(const ir::AstNode *ast)
{
    if (ast->IsDoWhileStatement()) {
        return HandleDoWhileStatement(ast->AsDoWhileStatement());
    }

    if (ast->IsWhileStatement()) {
        return HandleWhileStatement(ast->AsWhileStatement());
    }

    if (ast->IsForUpdateStatement()) {
        return HandleForUpdateStatement(ast->AsForUpdateStatement());
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

bool CheckInfiniteLoop::ConditionIsAlwaysTrue(const ir::Expression *const test) const
{
    ASSERT(test);
    auto const *const type = test->TsType();
    if (type == nullptr) {
        return false;
    }

    if (!type->IsConditionalExprType()) {
        // Cannot be tested for truthiness
        return false;
    }

    const auto [constant, truthy] = type->ResolveConditionExpr();
    return (constant && truthy);
}

bool CheckInfiniteLoop::HasBreakOrReturnStatement(const ir::Statement *const body) const
{
    ASSERT(body);
    bool hasExit = body->IsBreakStatement() || body->IsReturnStatement();
    body->IterateRecursively(
        [&hasExit](ir::AstNode *child) { hasExit |= child->IsBreakStatement() || child->IsReturnStatement(); });

    return hasExit;
}

[[nodiscard]] CheckResult CheckInfiniteLoop::HandleWhileStatement(const ir::WhileStatement *const stmt)
{
    auto const *body = stmt->Body();
    auto const *test = stmt->Test();
    if ((body == nullptr) || (test == nullptr)) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    if (ConditionIsAlwaysTrue(test)) {
        if (!HasBreakOrReturnStatement(body)) {
            AddCheckMessage("INFINITE LOOP", *stmt);
        }
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

[[nodiscard]] CheckResult CheckInfiniteLoop::HandleDoWhileStatement(const ir::DoWhileStatement *const stmt)
{
    auto const *body = stmt->Body();
    auto const *test = stmt->Test();
    if ((body == nullptr) || (test == nullptr)) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    if (ConditionIsAlwaysTrue(test)) {
        if (!HasBreakOrReturnStatement(body)) {
            AddCheckMessage("INFINITE LOOP", *stmt);
        }
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

[[nodiscard]] CheckResult CheckInfiniteLoop::HandleForUpdateStatement(const ir::ForUpdateStatement *const stmt)
{
    auto const *body = stmt->Body();
    if (body == nullptr) {
        // Body existence is checked in ForLoopCorrectlyInitialized
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    // Test can be null for for-update statements
    auto const *test = stmt->Test();
    if (test == nullptr || ConditionIsAlwaysTrue(test)) {
        if (!HasBreakOrReturnStatement(body)) {
            AddCheckMessage("INFINITE LOOP", *stmt);
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}
}  // namespace ark::es2panda::compiler::ast_verifier
