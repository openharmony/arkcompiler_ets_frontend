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

#include "../helpers.h"
#include "variableHasScope.h"
#include "ir/base/scriptFunction.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/typeNode.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult VariableHasScope::operator()(const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        // Check invariant of Identifier only
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    // we will check invariant for only local variables of identifiers
    if (const auto var = TryGetLocalScopeVariable(ast->AsIdentifier()); var != nullptr) {
        const auto scope = var->GetScope();
        if (scope == nullptr) {
            AddCheckMessage("NULL_SCOPE_LOCAL_VAR", *ast);
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        if (!ScopeEncloseVariable(var)) {
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        return result;
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

bool VariableHasScope::ScopeEncloseVariable(const varbinder::LocalVariable *var)
{
    ES2PANDA_ASSERT(var);

    const auto scope = var->GetScope();
    if (scope == nullptr || var->Declaration() == nullptr) {
        return true;
    }

    const auto node = var->Declaration()->Node();
    if (node == nullptr) {
        return true;
    }

    bool isOk = true;
    if (scope->Bindings().count(var->Name()) == 0) {
        AddCheckMessage("SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR", *node);
        isOk = false;
    }

    const auto scopeNode = scope->Node();
    const auto varNode = node;
    bool skip = CheckAstExceptions(varNode);

    if (!IsContainedIn(varNode, scopeNode) || scopeNode == nullptr) {
        if (!skip) {
            AddCheckMessage("SCOPE_NODE_DONT_DOMINATE_VAR_NODE", *node);
            isOk = false;
        }
    }

    const auto &decls = scope->Decls();
    const auto declDominate = std::count(decls.begin(), decls.end(), var->Declaration());
    if (declDominate == 0) {
        if (!skip) {
            AddCheckMessage("SCOPE_DECL_DONT_DOMINATE_VAR_DECL", *node);
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
