/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "phase.h"
#include "checker/checker.h"
#include "compiler/core/compilerContext.h"
#include "lexer/token/sourceLocation.h"
#include "compiler/lowering/ets/opAssignment.h"

namespace panda::es2panda::compiler {

std::vector<Phase *> GetEmptyPhaseList()
{
    return std::vector<Phase *> {};
}

static OpAssignmentLowering OP_ASSIGNMENT_LOWERING;

std::vector<Phase *> GetETSPhaseList()
{
    return std::vector<Phase *> {
        &OP_ASSIGNMENT_LOWERING,
    };
}

void Phase::Apply(CompilerContext *ctx, parser::Program *program)
{
    const auto *options = ctx->Options();
    if (options->skip_phases.count(Name()) > 0) {
        return;
    }

    if (options->dump_before_phases.count(Name()) > 0) {
        std::cout << "Before phase " << Name() << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

#ifndef NDEBUG
    if (!Precondition(ctx, program)) {
        ctx->Checker()->ThrowTypeError({"Precondition check failed for ", Name()}, lexer::SourcePosition {});
    }
#endif

    Perform(ctx, program);

    if (options->dump_after_phases.count(Name()) > 0) {
        std::cout << "After phase " << Name() << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

#ifndef NDEBUG
    if (!Postcondition(ctx, program)) {
        ctx->Checker()->ThrowTypeError({"Postcondition check failed for ", Name()}, lexer::SourcePosition {});
    }
#endif
}

}  // namespace panda::es2panda::compiler
