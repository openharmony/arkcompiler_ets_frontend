/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

namespace ark::es2panda::compiler {
bool CheckerPhase::Perform(public_lib::Context *ctx, [[maybe_unused]] parser::Program *program)
{
    for (auto [_, programList] : program->ExternalSources()) {
        for (auto prog : programList) {
            for (auto stmt : prog->Ast()->Statements()) {
                stmt->AddAstNodeFlags(ir::AstNodeFlags::NOCLEANUP);
            }
        }
    }
    for (auto stmt : program->Ast()->Statements()) {
        stmt->AddAstNodeFlags(ir::AstNodeFlags::NOCLEANUP);
    }
    auto checkerResult = ctx->checker->StartChecker(ctx->parserProgram->VarBinder(), *ctx->config->options);
    return checkerResult;
}

}  // namespace ark::es2panda::compiler
