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

#include "helpers.h"
#include "identifierHasVariable.h"
#include "variableHasScope.h"
#include "ir/base/scriptFunction.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/typeNode.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult VariableHasScope::operator()(CheckContext &ctx, const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        // Check invariant of Identifier only
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    // we will check invariant for only local variables of identifiers
    if (const auto maybeVar = GetLocalScopeVariable(allocator_, ctx, ast); maybeVar.has_value()) {
        const auto var = *maybeVar;
        const auto scope = var->GetScope();
        if (scope == nullptr) {
            ctx.AddCheckMessage("NULL_SCOPE_LOCAL_VAR", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        if (!ScopeEncloseVariable(ctx, var)) {
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        return result;
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

std::optional<varbinder::LocalVariable *> VariableHasScope::GetLocalScopeVariable(ArenaAllocator &allocator,
                                                                                  CheckContext &ctx,
                                                                                  const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        return std::nullopt;
    }

    auto invariantHasVariable = IdentifierHasVariable {allocator};
    const auto variable = ast->AsIdentifier()->Variable();
    const auto [decision, action] = invariantHasVariable(ctx, ast);

    if (variable == nullptr) {
        // NOTE(kkonkuznetsov): variable should not be null
        // but currently some identifiers do not have variables,
        // see exceptions in IdentifierHasVariable check
        return std::nullopt;
    }

    if (decision == CheckDecision::CORRECT && variable->IsLocalVariable()) {
        const auto localVar = variable->AsLocalVariable();
        if (localVar->HasFlag(varbinder::VariableFlags::LOCAL)) {
            return localVar;
        }
    }

    return std::nullopt;
}

bool VariableHasScope::ScopeEncloseVariable(CheckContext &ctx, const varbinder::LocalVariable *var)
{
    ASSERT(var);

    const auto scope = var->GetScope();
    if (scope == nullptr || var->Declaration() == nullptr) {
        return true;
    }

    const auto node = var->Declaration()->Node();
    if (node == nullptr) {
        return true;
    }

    const auto varStart = node->Start();
    bool isOk = true;
    if (scope->Bindings().count(var->Name()) == 0) {
        ctx.AddCheckMessage("SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR", *node, varStart);
        isOk = false;
    }

    const auto scopeNode = scope->Node();
    const auto varNode = node;
    bool skip = CheckAstExceptions(varNode);

    if (!IsContainedIn(varNode, scopeNode) || scopeNode == nullptr) {
        if (!skip) {
            ctx.AddCheckMessage("SCOPE_NODE_DONT_DOMINATE_VAR_NODE", *node, varStart);
            isOk = false;
        }
    }

    const auto &decls = scope->Decls();
    const auto declDominate = std::count(decls.begin(), decls.end(), var->Declaration());
    if (declDominate == 0) {
        if (!skip) {
            ctx.AddCheckMessage("SCOPE_DECL_DONT_DOMINATE_VAR_DECL", *node, varStart);
            isOk = false;
        }
    }

    return isOk;
}

bool VariableHasScope::CheckAstExceptions(const ir::AstNode *ast)
{
    // Labels are attached to loop scopes,
    // however label identifier is outside of loop.
    // Example:
    //
    // ```
    // loop: for (let i = 0; i < 10; i++) {
    // }
    // ```
    return ast->IsLabelledStatement();
}

}  // namespace ark::es2panda::compiler::ast_verifier
