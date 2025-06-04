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

#include "nodeHasSourceRange.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult NodeHasSourceRange::operator()(const ir::AstNode *ast)
{
    const auto hasRange =
        ast->Start().line != 0 || ast->Start().index != 0 || ast->End().line != 0 || ast->End().index != 0;
    if (!hasRange) {
        AddCheckMessage("NULL_RANGE", *ast);
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
