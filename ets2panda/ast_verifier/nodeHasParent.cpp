/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "nodeHasParent.h"

#include "ir/statements/blockStatement.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult NodeHasParent::operator()(const ir::AstNode *ast)
{
    const auto isETSModule = ast->IsETSModule() || (ast->IsBlockStatement() && ast->AsBlockStatement()->IsProgram());
    const auto hasParent = ast->Parent() != nullptr;
    if (!isETSModule && !hasParent) {
        AddCheckMessage("NULL_PARENT", *ast);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }

    if (ast->IsProgram()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
