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
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/ets/expandBrackets.h"
#include "compiler/lowering/ets/generateDeclarations.h"
#include "compiler/lowering/ets/lambdaLowering.h"
#include "compiler/lowering/ets/opAssignment.h"
#include "compiler/lowering/ets/tupleLowering.h"
#include "compiler/lowering/ets/unionLowering.h"
#include "public/es2panda_lib.h"
#include "compiler/lowering/ets/promiseVoid.h"

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
static ExpandBracketsPhase EXPAND_BRACKETS_PHASE;
static PromiseVoidLowering PROMISE_VOID_LOWERING;
static PluginPhase PLUGINS_AFTER_PARSE {"plugins-after-parse", ES2PANDA_STATE_PARSED, &util::Plugin::AfterParse};
static PluginPhase PLUGINS_AFTER_CHECK {"plugins-after-check", ES2PANDA_STATE_CHECKED, &util::Plugin::AfterCheck};
static PluginPhase PLUGINS_AFTER_LOWERINGS {"plugins-after-lowering", ES2PANDA_STATE_LOWERED,
                                            &util::Plugin::AfterLowerings};

std::vector<Phase *> GetPhaseList(ScriptExtension ext)
{
    static ScopesInitPhaseETS scopes_phase_ets;
    static ScopesInitPhaseAS scopes_phase_as;
    static ScopesInitPhaseTs scopes_phase_ts;
    static ScopesInitPhaseJs scopes_phase_js;

    switch (ext) {
        case ScriptExtension::ETS:
            return {
                &scopes_phase_ets,               &PLUGINS_AFTER_PARSE,    &PROMISE_VOID_LOWERING,
                &LAMBDA_LOWERING,                &CHECKER_PHASE,          &PLUGINS_AFTER_CHECK,
                &GENERATE_TS_DECLARATIONS_PHASE, &OP_ASSIGNMENT_LOWERING, &OBJECT_INDEX_LOWERING,
                &TUPLE_LOWERING,                 &UNION_LOWERING,         &EXPAND_BRACKETS_PHASE,
                &PLUGINS_AFTER_LOWERINGS,
            };
        case ScriptExtension::AS:
            return std::vector<Phase *> {
                &scopes_phase_as,
                &CHECKER_PHASE,
            };
        case ScriptExtension::TS:
            return std::vector<Phase *> {
                &scopes_phase_ts,
                &CHECKER_PHASE,
            };
        case ScriptExtension::JS:
            return std::vector<Phase *> {
                &scopes_phase_js,
                &CHECKER_PHASE,
            };
        default:
            UNREACHABLE();
    }
}

bool Phase::Apply(public_lib::Context *ctx, parser::Program *program)
{
#ifndef NDEBUG
    const auto check_program = [](const parser::Program *p) {
        ASTVerifier verifier {p->Allocator(), false, p->SourceCode()};
        ArenaVector<const ir::BlockStatement *> to_check {p->Allocator()->Adapter()};
        to_check.push_back(p->Ast());
        for (const auto &external_source : p->ExternalSources()) {
            for (const auto external : external_source.second) {
                to_check.push_back(external->Ast());
            }
        }
        for (const auto *ast : to_check) {
            if (!verifier.VerifyFull(ast)) {
                return false;
            }
        }
        return true;
    };
#endif

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
    check_program(program);

    if (!Postcondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Postcondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    return true;
}

}  // namespace panda::es2panda::compiler
