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

#include "phase.h"
#include "checker/checker.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/checkerPhase.h"
#include "compiler/lowering/ets/defaultParameterLowering.h"
#include "compiler/lowering/ets/expandBrackets.h"
#include "compiler/lowering/ets/recordLowering.h"
#include "compiler/lowering/ets/topLevelStmts/topLevelStmts.h"
#include "compiler/lowering/ets/lambdaLowering.h"
#include "compiler/lowering/ets/interfacePropertyDeclarations.h"
#include "compiler/lowering/ets/objectIndexAccess.h"
#include "compiler/lowering/ets/objectIterator.h"
#include "compiler/lowering/ets/localClassLowering.h"
#include "compiler/lowering/ets/opAssignment.h"
#include "compiler/lowering/ets/objectLiteralLowering.h"
#include "compiler/lowering/ets/optionalLowering.h"
#include "compiler/lowering/ets/promiseVoid.h"
#include "compiler/lowering/ets/structLowering.h"
#include "compiler/lowering/ets/tupleLowering.h"
#include "compiler/lowering/ets/bigintLowering.h"
#include "compiler/lowering/ets/unionLowering.h"
#include "compiler/lowering/plugin_phase.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ets/defaultParameterLowering.h"
#include "lexer/token/sourceLocation.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::compiler {

static CheckerPhase g_checkerPhase;

std::vector<Phase *> GetTrivialPhaseList()
{
    return std::vector<Phase *> {
        &g_checkerPhase,
    };
}

static BigIntLowering g_bigintLowering;
static InterfacePropertyDeclarationsPhase g_interfacePropDeclPhase;
static LambdaConstructionPhase g_lambdaConstructionPhase;
static OpAssignmentLowering g_opAssignmentLowering;
static ObjectIndexLowering g_objectIndexLowering;
static ObjectIteratorLowering g_objectIteratorLowering;
static ObjectLiteralLowering g_objectLiteralLowering;
static TupleLowering g_tupleLowering;  // Can be only applied after checking phase, and OP_ASSIGNMENT_LOWERING phase
static UnionLowering g_unionLowering;
static OptionalLowering g_optionalLowering;
static ExpandBracketsPhase g_expandBracketsPhase;
static PromiseVoidInferencePhase g_promiseVoidInferencePhase;
static RecordLowering g_recordLowering;
static StructLowering g_structLowering;
static DefaultParameterLowering g_defaultParameterLowering;
static TopLevelStatements g_topLevelStatements;
static LocalClassConstructionPhase g_localClassLowering;
static PluginPhase g_pluginsAfterParse {"plugins-after-parse", ES2PANDA_STATE_PARSED, &util::Plugin::AfterParse};
static PluginPhase g_pluginsAfterCheck {"plugins-after-check", ES2PANDA_STATE_CHECKED, &util::Plugin::AfterCheck};
static PluginPhase g_pluginsAfterLowerings {"plugins-after-lowering", ES2PANDA_STATE_LOWERED,
                                            &util::Plugin::AfterLowerings};
// NOLINTBEGIN(fuchsia-statically-constructed-objects)
static InitScopesPhaseETS g_initScopesPhaseEts;
static InitScopesPhaseAS g_initScopesPhaseAs;
static InitScopesPhaseTs g_initScopesPhaseTs;
static InitScopesPhaseJs g_initScopesPhaseJs;
// NOLINTEND(fuchsia-statically-constructed-objects)

static void CheckOptionsBeforePhase(const CompilerOptions *options, const parser::Program *program,
                                    const std::string &name);
static void CheckOptionsAfterPhase(const CompilerOptions *options, const parser::Program *program,
                                   const std::string &name);

std::vector<Phase *> GetETSPhaseList()
{
    return {
        &g_pluginsAfterParse,
        &g_topLevelStatements,
        &g_defaultParameterLowering,
        &g_bigintLowering,
        &g_initScopesPhaseEts,
        &g_optionalLowering,
        &g_promiseVoidInferencePhase,
        &g_structLowering,
        &g_lambdaConstructionPhase,
        &g_interfacePropDeclPhase,
        &g_checkerPhase,
        &g_pluginsAfterCheck,
        &g_opAssignmentLowering,
        &g_recordLowering,
        &g_objectIndexLowering,
        &g_objectIteratorLowering,
        &g_tupleLowering,
        &g_unionLowering,
        &g_expandBracketsPhase,
        &g_localClassLowering,
        &g_objectLiteralLowering,
        &g_pluginsAfterLowerings,
    };
}

std::vector<Phase *> GetASPhaseList()
{
    return {
        &g_initScopesPhaseAs,
        &g_checkerPhase,
    };
}

std::vector<Phase *> GetTSPhaseList()
{
    return {
        &g_initScopesPhaseTs,
        &g_checkerPhase,
    };
}

std::vector<Phase *> GetJSPhaseList()
{
    return {
        &g_initScopesPhaseJs,
        &g_checkerPhase,
    };
}

std::vector<Phase *> GetPhaseList(ScriptExtension ext)
{
    switch (ext) {
        case ScriptExtension::ETS:
            return GetETSPhaseList();
        case ScriptExtension::AS:
            return GetASPhaseList();
        case ScriptExtension::TS:
            return GetTSPhaseList();
        case ScriptExtension::JS:
            return GetJSPhaseList();
        default:
            UNREACHABLE();
    }
}

bool Phase::Apply(public_lib::Context *ctx, parser::Program *program)
{
    const auto *options = ctx->compilerContext->Options();
    const auto name = std::string {Name()};
    if (options->skipPhases.count(name) > 0) {
        return true;
    }

    CheckOptionsBeforePhase(options, program, name);

#ifndef NDEBUG
    if (!Precondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Precondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    if (!Perform(ctx, program)) {
        return false;
    }

    CheckOptionsAfterPhase(options, program, name);

#ifndef NDEBUG
    if (!Postcondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Postcondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    return true;
}

static void CheckOptionsBeforePhase(const CompilerOptions *options, const parser::Program *program,
                                    const std::string &name)
{
    if (options->dumpBeforePhases.count(name) > 0) {
        std::cout << "Before phase " << name << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

    if (options->dumpEtsSrcBeforePhases.count(name) > 0) {
        std::cout << "Before phase " << name << " ets source"
                  << ":" << std::endl;
        std::cout << program->Ast()->DumpEtsSrc() << std::endl;
    }
}

static void CheckOptionsAfterPhase(const CompilerOptions *options, const parser::Program *program,
                                   const std::string &name)
{
    if (options->dumpAfterPhases.count(name) > 0) {
        std::cout << "After phase " << name << ":" << std::endl;
        std::cout << program->Dump() << std::endl;
    }

    if (options->dumpEtsSrcAfterPhases.count(name) > 0) {
        std::cout << "After phase " << name << " ets source"
                  << ":" << std::endl;
        std::cout << program->Ast()->DumpEtsSrc() << std::endl;
    }
}

}  // namespace ark::es2panda::compiler
