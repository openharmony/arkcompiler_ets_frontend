/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "checkerPhase.h"
#include "checker/checker.h"
#include "checker/typeChecker/TypeChecker.h"
#include "compiler/core/ASTVerifier.h"
#include "varbinder/ETSBinder.h"
#include "compiler/core/compilerContext.h"

namespace ark::es2panda::compiler {
bool CheckerPhase::Perform(public_lib::Context *ctx, [[maybe_unused]] parser::Program *program)
{
    auto checkerResult =
        ctx->checker->StartChecker(ctx->compilerContext->VarBinder(), *ctx->compilerContext->Options());
    auto typeCheckerResult = checker::RunTypeChecker(ctx->checker, program->Extension(), program->Ast());
    return checkerResult && typeCheckerResult;
}

}  // namespace ark::es2panda::compiler
