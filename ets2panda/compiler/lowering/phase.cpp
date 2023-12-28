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
#include "compiler/lowering/ets/interfacePropertyDeclarations.h"
#include "compiler/lowering/ets/opAssignment.h"
#include "compiler/lowering/ets/tupleLowering.h"
#include "compiler/lowering/ets/unionLowering.h"
#include "public/es2panda_lib.h"
#include "compiler/lowering/ets/promiseVoid.h"

namespace panda::es2panda::compiler {

static CheckerPhase g_checkerPhase;

std::vector<Phase *> GetTrivialPhaseList()
{
    return std::vector<Phase *> {
        &g_checkerPhase,
    };
}

static InterfacePropertyDeclarationsPhase g_interfacePropDeclPhase;
static GenerateTsDeclarationsPhase g_generateTsDeclarationsPhase;
static LambdaLowering g_lambdaLowering;
static OpAssignmentLowering g_opAssignmentLowering;
static ObjectIndexLowering g_objectIndexLowering;
static TupleLowering g_tupleLowering;  // Can be only applied after checking phase, and OP_ASSIGNMENT_LOWERING phase
static UnionLowering g_unionLowering;
static ExpandBracketsPhase g_expandBracketsPhase;
static PromiseVoidLowering g_promiseVoidLowering;
static PluginPhase g_pluginsAfterParse {"plugins-after-parse", ES2PANDA_STATE_PARSED, &util::Plugin::AfterParse};
static PluginPhase g_pluginsAfterCheck {"plugins-after-check", ES2PANDA_STATE_CHECKED, &util::Plugin::AfterCheck};
static PluginPhase g_pluginsAfterLowerings {"plugins-after-lowering", ES2PANDA_STATE_LOWERED,
                                            &util::Plugin::AfterLowerings};

std::vector<Phase *> GetPhaseList(ScriptExtension ext)
{
    static ScopesInitPhaseETS scopesPhaseEts;
    static ScopesInitPhaseAS scopesPhaseAs;
    static ScopesInitPhaseTs scopesPhaseTs;
    static ScopesInitPhaseJs scopesPhaseJs;

    switch (ext) {
        case ScriptExtension::ETS:
            return {
                &scopesPhaseEts,           &g_pluginsAfterParse,
                &g_promiseVoidLowering,    &g_lambdaLowering,
                &g_interfacePropDeclPhase, &g_checkerPhase,
                &g_pluginsAfterCheck,      &g_generateTsDeclarationsPhase,
                &g_opAssignmentLowering,   &g_objectIndexLowering,
                &g_tupleLowering,          &g_unionLowering,
                &g_expandBracketsPhase,    &g_pluginsAfterLowerings,
            };

        case ScriptExtension::AS:
            return std::vector<Phase *> {
                &scopesPhaseAs,
                &g_checkerPhase,
            };
        case ScriptExtension::TS:
            return std::vector<Phase *> {
                &scopesPhaseTs,
                &g_checkerPhase,
            };
        case ScriptExtension::JS:
            return std::vector<Phase *> {
                &scopesPhaseJs,
                &g_checkerPhase,
            };
        default:
            UNREACHABLE();
    }
}

bool Phase::Apply(public_lib::Context *ctx, parser::Program *program)
{
#ifndef NDEBUG
    const auto checkProgram = [](const parser::Program *p) {
        ASTVerifier verifier {p->Allocator(), false, p->SourceCode()};
        ArenaVector<const ir::BlockStatement *> toCheck {p->Allocator()->Adapter()};
        toCheck.push_back(p->Ast());
        for (const auto &externalSource : p->ExternalSources()) {
            for (const auto external : externalSource.second) {
                toCheck.push_back(external->Ast());
            }
        }
        for (const auto *ast : toCheck) {
            if (!verifier.VerifyFull(ast)) {
                return false;
            }
        }
        return true;
    };
#endif

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
    checkProgram(program);

    if (!Postcondition(ctx, program)) {
        ctx->checker->ThrowTypeError({"Postcondition check failed for ", util::StringView {Name()}},
                                     lexer::SourcePosition {});
    }
#endif

    return true;
}

void Phase::CheckOptionsBeforePhase(const CompilerOptions *options, const parser::Program *program,
                                    const std::string &name) const
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

void Phase::CheckOptionsAfterPhase(const CompilerOptions *options, const parser::Program *program,
                                   const std::string &name) const
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

}  // namespace panda::es2panda::compiler
