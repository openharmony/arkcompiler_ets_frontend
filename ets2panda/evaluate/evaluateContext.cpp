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

#include "evaluate/evaluateContext.h"
#include "ir/base/classDefinition.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/functionExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "parser/program/program.h"

#include <algorithm>

namespace ark::es2panda::evaluate {

void EvaluateContext::FindEvaluationMethod(parser::Program *evalMethodProgram)
{
    ES2PANDA_ASSERT(evalMethodProgram);
    auto &topLevelStatements = evalMethodProgram->Ast()->Statements();

    // Find evaluation class.
    auto evalClassDefIter = std::find_if(topLevelStatements.begin(), topLevelStatements.end(), [](auto *stmt) {
        return stmt->IsClassDeclaration() &&
               !stmt->AsClassDeclaration()->Definition()->Ident()->Name().Is(compiler::Signatures::ETS_GLOBAL);
    });
    ES2PANDA_ASSERT(evalClassDefIter != topLevelStatements.end());
    auto *methodClass = (*evalClassDefIter)->AsClassDeclaration()->Definition();
    const auto &expectedMethodName = methodClass->Ident()->Name();

    // Find evaluation method.
    auto evalMethodIter =
        std::find_if(methodClass->Body().begin(), methodClass->Body().end(), [expectedMethodName](auto *iter) {
            return iter->IsMethodDefinition() &&
                   iter->AsMethodDefinition()->Key()->AsIdentifier()->Name() == expectedMethodName;
        });
    ES2PANDA_ASSERT(evalMethodIter != methodClass->Body().end());
    auto *method = (*evalMethodIter)->AsMethodDefinition();
    auto *scriptFunction = method->Value()->AsFunctionExpression()->Function();
    ES2PANDA_ASSERT(scriptFunction != nullptr);

    // Extract method statements and last statement.
    methodStatements = scriptFunction->Body()->AsBlockStatement();
    ES2PANDA_ASSERT(!methodStatements->Statements().empty());
    auto *stmt = methodStatements->Statements().back();
    if (stmt->IsExpressionStatement()) {
        lastStatement = stmt->AsExpressionStatement();
    }
}

}  // namespace ark::es2panda::evaluate
