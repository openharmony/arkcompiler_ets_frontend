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

#include "variableNameIdentifierNameSame.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/ets/etsImportDeclaration.h"

namespace ark::es2panda::compiler::ast_verifier {

[[nodiscard]] CheckResult VariableNameIdentifierNameSame::operator()(const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto *id = ast->AsIdentifier();
    const auto variable = ast->AsIdentifier()->Variable();
    if (variable == nullptr || variable->Declaration() == nullptr || variable->Declaration()->Node() == nullptr) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    const auto variableNode = variable->Declaration()->Node();
    // NOTE(psaykerone): skip because, this exceptions need to be fixed in checker and lowering
    if (variableNode->IsExported() || variableNode->IsExportedType() || variableNode->IsDefaultExported() ||
        id->Name().Utf8().find("field") == 0 || variable->Name().Utf8().find("field") == 0) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
    if (id->Name() == variable->Name()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    // For dynamic imports imported identifier name does not match variable name
    // Example:
    // import { A as AA } from "dynamic_import_tests"
    // Variable name will be AA
    // But imported identifier name is A
    auto parent = ast->Parent();
    while (parent != nullptr) {
        if (parent->IsETSImportDeclaration() && parent->AsETSImportDeclaration()->IsPureDynamic()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        parent = parent->Parent();
    }

    AddCheckMessage("IDENTIFIER_NAME_DIFFERENCE", *id);
    return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
