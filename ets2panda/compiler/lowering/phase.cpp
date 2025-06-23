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

#include "phase.h"
#include "checker/checker.h"
#include "compiler/lowering/checkerPhase.h"
#include "compiler/lowering/ets/asyncMethodLowering.h"
#include "compiler/lowering/ets/bigintLowering.h"
#include "compiler/lowering/ets/boxedTypeLowering.h"
#include "compiler/lowering/ets/boxingForLocals.h"
#include "compiler/lowering/ets/capturedVariables.h"
#include "compiler/lowering/ets/constStringToCharLowering.h"
#include "compiler/lowering/ets/constantExpressionLowering.h"
#include "compiler/lowering/ets/declareOverloadLowering.h"
#include "compiler/lowering/ets/cfgBuilderPhase.h"
#include "compiler/lowering/ets/defaultParametersInConstructorLowering.h"
#include "compiler/lowering/ets/defaultParametersLowering.h"
#include "compiler/lowering/ets/enumLowering.h"
#include "compiler/lowering/ets/enumPostCheckLowering.h"
#include "compiler/lowering/ets/restTupleLowering.h"
#include "compiler/lowering/ets/expandBrackets.h"
#include "compiler/lowering/ets/expressionLambdaLowering.h"
#include "compiler/lowering/ets/extensionAccessorLowering.h"
#include "compiler/lowering/ets/genericBridgesLowering.h"
#include "compiler/lowering/ets/interfaceObjectLiteralLowering.h"
#include "compiler/lowering/ets/interfacePropertyDeclarations.h"
#include "compiler/lowering/ets/lambdaLowering.h"
#include "compiler/lowering/ets/objectIndexAccess.h"
#include "compiler/lowering/ets/objectIterator.h"
#include "compiler/lowering/ets/objectLiteralLowering.h"
#include "compiler/lowering/ets/opAssignment.h"
#include "compiler/lowering/ets/optionalArgumentsLowering.h"
#include "compiler/lowering/ets/optionalLowering.h"
#include "compiler/lowering/ets/packageImplicitImport.h"
#include "compiler/lowering/ets/partialExportClassGen.h"
#include "compiler/lowering/ets/promiseVoid.h"
#include "compiler/lowering/ets/recordLowering.h"
#include "compiler/lowering/ets/setJumpTarget.h"
#include "compiler/lowering/ets/spreadLowering.h"
#include "compiler/lowering/ets/stringComparison.h"
#include "compiler/lowering/ets/stringConstantsLowering.h"
#include "compiler/lowering/ets/stringConstructorLowering.h"
#include "compiler/lowering/ets/topLevelStmts/topLevelStmts.h"
#include "compiler/lowering/ets/unionLowering.h"
#include "compiler/lowering/plugin_phase.h"
#include "compiler/lowering/resolveIdentifiers.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ets/ambientLowering.h"
#include "generated/diagnostic.h"
#include "lexer/token/sourceLocation.h"
#include "public/es2panda_lib.h"
#include "util/options.h"

namespace ark::es2panda::compiler {

static CheckerPhase g_checkerPhase;
static SetJumpTargetPhase g_setJumpTargetPhase;
static CFGBuilderPhase g_cfgBuilderPhase;
static ResolveIdentifiers g_resolveIdentifiers {};
static AmbientLowering g_ambientLowering;
static BigIntLowering g_bigintLowering;
static StringConstructorLowering g_stringConstructorLowering;
static ConstantExpressionLowering g_constantExpressionLowering;
static ConstStringToCharLowering g_constStringToCharLowering;
static InterfacePropertyDeclarationsPhase g_interfacePropDeclPhase;  // NOLINT(fuchsia-statically-constructed-objects)
static EnumLoweringPhase g_enumLoweringPhase;
static EnumPostCheckLoweringPhase g_enumPostCheckLoweringPhase;
static RestTupleConstructionPhase g_restTupleConstructionPhase;
static SpreadConstructionPhase g_spreadConstructionPhase;
static ExtensionAccessorPhase g_extensionAccessorPhase;
static ExpressionLambdaConstructionPhase g_expressionLambdaConstructionPhase;
static OpAssignmentLowering g_opAssignmentLowering;
static BoxingForLocals g_boxingForLocals;
static CapturedVariables g_capturedVariables {};
static LambdaConversionPhase g_lambdaConversionPhase;
static ObjectIndexLowering g_objectIndexLowering;
static ObjectIteratorLowering g_objectIteratorLowering;
static ObjectLiteralLowering g_objectLiteralLowering;
static InterfaceObjectLiteralLowering g_interfaceObjectLiteralLowering;
static UnionLowering g_unionLowering;
static OptionalLowering g_optionalLowering;
static ExpandBracketsPhase g_expandBracketsPhase;
static PromiseVoidInferencePhase g_promiseVoidInferencePhase;
static RecordLowering g_recordLowering;
static DeclareOverloadLowering g_declareOverloadLowering;
static DefaultParametersLowering g_defaultParametersLowering;
static DefaultParametersInConstructorLowering g_defaultParametersInConstructorLowering;
static OptionalArgumentsLowering g_optionalArgumentsLowering;
static TopLevelStatements g_topLevelStatements;
static StringComparisonLowering g_stringComparisonLowering;
static StringConstantsLowering g_stringConstantsLowering;
static PartialExportClassGen g_partialExportClassGen;
static PackageImplicitImport g_packageImplicitImport;
static GenericBridgesPhase g_genericBridgesLowering;
static BoxedTypeLowering g_boxedTypeLowering;
static AsyncMethodLowering g_asyncMethodLowering;
static PluginPhase g_pluginsAfterParse {"plugins-after-parse", ES2PANDA_STATE_PARSED, &util::Plugin::AfterParse};
static PluginPhase g_pluginsAfterBind {"plugins-after-bind", ES2PANDA_STATE_BOUND, &util::Plugin::AfterBind};
static PluginPhase g_pluginsAfterCheck {"plugins-after-check", ES2PANDA_STATE_CHECKED, &util::Plugin::AfterCheck};
static PluginPhase g_pluginsAfterLowerings {"plugins-after-lowering", ES2PANDA_STATE_LOWERED,
                                            &util::Plugin::AfterLowerings};
// NOLINTBEGIN(fuchsia-statically-constructed-objects)
static InitScopesPhaseETS g_initScopesPhaseEts;
static InitScopesPhaseAS g_initScopesPhaseAs;
static InitScopesPhaseTs g_initScopesPhaseTs;
static InitScopesPhaseJs g_initScopesPhaseJs;
// NOLINTEND(fuchsia-statically-constructed-objects)

// CC-OFFNXT(huge_method, G.FUN.01-CPP) long initialization list
std::vector<Phase *> GetETSPhaseList()
{
    // clang-format off
    // NOLINTBEGIN
    return {
        &g_pluginsAfterParse,
        &g_stringConstantsLowering,
        &g_packageImplicitImport,
        &g_topLevelStatements,
        &g_expressionLambdaConstructionPhase,
        &g_defaultParametersInConstructorLowering,
        &g_defaultParametersLowering,
        &g_ambientLowering,
        &g_restTupleConstructionPhase,
        &g_initScopesPhaseEts,
        &g_optionalLowering,
        &g_promiseVoidInferencePhase,
        &g_interfacePropDeclPhase,
        &g_constantExpressionLowering,
        &g_enumLoweringPhase,
        &g_resolveIdentifiers,
        &g_pluginsAfterBind,
        &g_capturedVariables,
        &g_setJumpTargetPhase,
        &g_cfgBuilderPhase,
        &g_checkerPhase,        // please DO NOT change order of these two phases: checkerPhase and pluginsAfterCheck
        &g_pluginsAfterCheck,   // pluginsAfterCheck has to go right after checkerPhase, nothing should be between them
        &g_asyncMethodLowering,
        &g_declareOverloadLowering,
        &g_enumPostCheckLoweringPhase,
        &g_spreadConstructionPhase,
        &g_bigintLowering,
        &g_opAssignmentLowering,
        &g_extensionAccessorPhase,
        &g_constStringToCharLowering,
        &g_boxingForLocals,
        &g_recordLowering,
        &g_boxedTypeLowering,
        &g_objectIndexLowering,
        &g_objectIteratorLowering,
        &g_lambdaConversionPhase,
        &g_unionLowering,
        &g_expandBracketsPhase,
        &g_interfaceObjectLiteralLowering,
        &g_objectLiteralLowering,
        &g_stringConstructorLowering,
        &g_stringComparisonLowering,
        &g_partialExportClassGen,
        &g_optionalArgumentsLowering, // #22952 could be moved to earlier phase
        &g_genericBridgesLowering,
        &g_pluginsAfterLowerings,  // pluginsAfterLowerings has to come at the very end, nothing should go after it
    };
    // NOLINTEND
    // clang-format on
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

thread_local PhaseManager *g_phaseManager {nullptr};

PhaseManager *GetPhaseManager()
{
    ES2PANDA_ASSERT(g_phaseManager != nullptr && g_phaseManager->IsInitialized());
    return g_phaseManager;
}

void SetPhaseManager(PhaseManager *phaseManager)
{
    g_phaseManager = phaseManager;
}

bool Phase::Apply(public_lib::Context *ctx, parser::Program *program)
{
    SetPhaseManager(ctx->phaseManager);
    GetPhaseManager()->SetCurrentPhaseId(id_);

#ifndef NDEBUG
    if (!Precondition(ctx, program)) {
        ctx->checker->LogError(diagnostic::PRECOND_FAILED, {Name()}, lexer::SourcePosition {});
        return false;
    }
#endif

    if (!Perform(ctx, program)) {
        return false;  // NOLINT(readability-simplify-boolean-expr)
    }

#ifndef NDEBUG
    if (!Postcondition(ctx, program)) {
        ctx->checker->LogError(diagnostic::POSTCOND_FAILED, {Name()}, lexer::SourcePosition {});
        return false;
    }
#endif

    return true;
}

bool PhaseForDeclarations::Precondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            if (!Precondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return PreconditionForModule(ctx, program);
}

bool PhaseForDeclarations::Perform(public_lib::Context *ctx, parser::Program *program)
{
    bool result = true;
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            result &= Perform(ctx, extProg);
        }
    }

    result &= PerformForModule(ctx, program);
    return result;
}

bool PhaseForDeclarations::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return PostconditionForModule(ctx, program);
}

bool PhaseForBodies::Precondition(public_lib::Context *ctx, const parser::Program *program)
{
    auto checkExternalPrograms = [this, ctx](const ArenaVector<parser::Program *> &programs) {
        for (auto *p : programs) {
            if (!Precondition(ctx, p)) {
                return false;
            }
        }
        return true;
    };

    if (ctx->config->options->GetCompilationMode() == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, extPrograms] : program->ExternalSources()) {
            (void)_;
            if (!checkExternalPrograms(extPrograms)) {
                return false;
            };
        }
    }

    return PreconditionForModule(ctx, program);
}

bool PhaseForBodies::Perform(public_lib::Context *ctx, parser::Program *program)
{
    bool result = true;
    if (ctx->config->options->GetCompilationMode() == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, extPrograms] : program->ExternalSources()) {
            (void)_;
            for (auto *extProg : extPrograms) {
                result &= Perform(ctx, extProg);
            }
        }
    }

    result &= PerformForModule(ctx, program);
    return result;
}

bool PhaseForBodies::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    auto checkExternalPrograms = [this, ctx](const ArenaVector<parser::Program *> &programs) {
        for (auto *p : programs) {
            if (!Postcondition(ctx, p)) {
                return false;
            }
        }
        return true;
    };

    if (ctx->config->options->GetCompilationMode() == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, extPrograms] : program->ExternalSources()) {
            (void)_;
            if (!checkExternalPrograms(extPrograms)) {
                return false;
            };
        }
    }

    return PostconditionForModule(ctx, program);
}

void PhaseManager::InitializePhases()
{
    switch (ext_) {
        case ScriptExtension::ETS:
            phases_ = GetETSPhaseList();
            break;
        case ScriptExtension::AS:
            phases_ = GetASPhaseList();
            break;
        case ScriptExtension::TS:
            phases_ = GetTSPhaseList();
            break;
        case ScriptExtension::JS:
            phases_ = GetJSPhaseList();
            break;
        default:
            ES2PANDA_UNREACHABLE();
    }

    int id = 0;
    for (auto phase : phases_) {
        phase->id_ = id++;
    }
}

std::vector<Phase *> PhaseManager::AllPhases()
{
    ES2PANDA_ASSERT(IsInitialized());
    return phases_;
}

std::vector<Phase *> PhaseManager::RebindPhases()
{
    ES2PANDA_ASSERT(IsInitialized());
    return {
        &g_initScopesPhaseEts,
        &g_resolveIdentifiers,
    };
}

std::vector<Phase *> PhaseManager::RecheckPhases()
{
    ES2PANDA_ASSERT(IsInitialized());
    return {
        &g_initScopesPhaseEts,
        &g_resolveIdentifiers,
        &g_capturedVariables,
        &g_checkerPhase,
    };
}

}  // namespace ark::es2panda::compiler
