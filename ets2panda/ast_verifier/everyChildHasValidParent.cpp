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

#include "everyChildHasValidParent.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult EveryChildHasValidParent::operator()(CheckContext &ctx, const ir::AstNode *ast)
{
    auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
    if (ast->IsETSScript()) {
        return result;
    }

    ast->Iterate([&](const ir::AstNode *node) {
        if (ir::AstNode const *parent = node->Parent(); ast != parent) {
            //  NOTE: Temporary suppress.
            //  Should be removed after special lowering for lambda-functions will be implemented: #14376
            if ((ast->IsScriptFunction() || ast->IsETSFunctionType()) && parent != nullptr &&
                parent->IsScriptFunction()) {
                return;
            }

            //  NOTE: Temporary suppress.
            //  Should be removed after new ENUMs support will be implemented: #14443
            if (ast->IsClassDeclaration() && parent != nullptr && parent->IsETSNewClassInstanceExpression()) {
                return;
            }

            ctx.AddCheckMessage("INCORRECT_PARENT_REF", *node, node->Start());
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
    });

    return result;
}

}  // namespace ark::es2panda::compiler::ast_verifier
