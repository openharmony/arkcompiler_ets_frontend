/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
#include "compiler/core/ASTVerifier.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/ets/objectIndexAccess.h"
#include "lexer/token/sourceLocation.h"
#include "compiler/lowering/checkerPhase.h"
#include "compiler/lowering/plugin_phase.h"
#include "compiler/lowering/ets/generateDeclarations.h"
#include "compiler/lowering/ets/lambdaLowering.h"
#include "compiler/lowering/ets/opAssignment.h"
#include "compiler/lowering/ets/tupleLowering.h"
#include "compiler/lowering/ets/unionLowering.h"
#include "public/es2panda_lib.h"

namespace panda::es2panda::compiler {

static CheckerPhase CHECKER_PHASE;

std::vector<Phase *> GetTrivialPhaseList()
{
    return std::vector<Phase *> {
        &CHECKER_PHASE,
    };
}

static GenerateTsDeclarationsPhase GENERATE_TS_DECLARATIONS_PHASE;
static LambdaLowering LAMBDA_LOWERING;
static OpAssignmentLowering OP_ASSIGNMENT_LOWERING;
static ObjectIndexLowering OBJECT_INDEX_LOWERING;
static TupleLowering TUPLE_LOWERING;  // Can be only applied after checking phase, and OP_ASSIGNMENT_LOWERING phase
static UnionLowering UNION_LOWERING;
static PluginPhase PLUGINS_AFTER_PARSE {"plugins-after-parse", ES2PANDA_STATE_PARSED, &util::Plugin::AfterParse};
static PluginPhase PLUGINS_AFTER_CHECK {"plugins-after-check", ES2PANDA_STATE_CHECKED, &util::Plugin::AfterCheck};
static PluginPhase PLUGINS_AFTER_LOWERINGS {"plugins-after-lowering", ES2PANDA_STATE_LOWERED,
                                            &util::Plugin::AfterLowerings};

std::vector<Phase *> GetETSPhaseList()
{
    return std::vector<Phase *> {
        &PLUGINS_AFTER_PARSE,
        &LAMBDA_LOWERING,
        &CHECKER_PHASE,
        &PLUGINS_AFTER_CHECK,
        &GENERATE_TS_DECLARATIONS_PHASE,
        &OP_ASSIGNMENT_LOWERING,
        &OBJECT_INDEX_LOWERING,
        &TUPLE_LOWERING,
        &UNION_LOWERING,
        &PLUGINS_AFTER_LOWERINGS,
    };
}

bool Phase::Apply(public_lib::Context *ctx, parser::Program *program)
{
    const auto *options = ctx->compiler_context->Options();
    const auto name = std::string {Name()};
    if (options->skip_phases.count(name) > 0) {
        return true;
    }

    if (options->dump_before_phases.count(name) > 0) {
        std::cout << "Before phase " << Name() << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

#ifndef NDEBUG
    ASTVerifier ast_before;
    if (!ast_before.IsCorrectProgram(program)) {
        // NOTE(tatiana): Add some error processing
    }
    if (!Precondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Precondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    if (!Perform(ctx, program)) {
        return false;
    }

    if (options->dump_after_phases.count(name) > 0) {
        std::cout << "After phase " << Name() << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

#ifndef NDEBUG
    ASTVerifier ast_after;
    if (!ast_after.IsCorrectProgram(program)) {
        // NOTE(tatiana): Add some error processing
    }
    if (!Postcondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Postcondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    return true;
}

}  // namespace panda::es2panda::compiler
