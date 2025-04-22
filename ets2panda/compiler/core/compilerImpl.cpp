/**
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

#include "compilerImpl.h"

#include "ast_verifier/ASTVerifier.h"
#include "es2panda.h"
#include "checker/ETSAnalyzer.h"
#include "checker/TSAnalyzer.h"
#include "compiler/core/compileQueue.h"
#include "compiler/core/compilerImpl.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSCompiler.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/JSCompiler.h"
#include "compiler/core/JSemitter.h"
#include "compiler/core/ETSemitter.h"
#include "compiler/lowering/phase.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/checkerPhase.h"
#include "evaluate/scopedDebugInfoPlugin.h"
#include "parser/parserImpl.h"
#include "parser/JSparser.h"
#include "parser/ASparser.h"
#include "parser/TSparser.h"
#include "parser/ETSparser.h"
#include "parser/program/program.h"
#include "varbinder/JSBinder.h"
#include "varbinder/ASBinder.h"
#include "varbinder/TSBinder.h"
#include "varbinder/ETSBinder.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ASchecker.h"
#include "checker/JSchecker.h"
#include "public/public.h"

namespace ark::es2panda::compiler {

void CompilerImpl::HandleContextLiterals(public_lib::Context *context)
{
    auto *emitter = context->emitter;

    uint32_t index = 0;
    for (const auto &buff : context->contextLiterals) {
        emitter->AddLiteralBuffer(buff, index++);
    }

    emitter->LiteralBufferIndex() += context->contextLiterals.size();
}

ark::pandasm::Program *CompilerImpl::Emit(public_lib::Context *context)
{
    HandleContextLiterals(context);

    queue_.Schedule(context);

    /* Main thread can also be used instead of idling */
    queue_.Consume();
    auto *emitter = context->emitter;
    queue_.Wait([emitter](CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });

    return emitter->Finalize(context->config->options->IsDumpDebugInfo(), Signatures::ETS_GLOBAL);
}

template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter, typename AstCompiler>
static public_lib::Context::CodeGenCb MakeCompileJob()
{
    return [](public_lib::Context *context, varbinder::FunctionScope *scope,
              compiler::ProgramElement *programElement) -> void {
        RegSpiller regSpiller;
        ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
        AstCompiler astcompiler;
        CodeGen cg(&allocator, &regSpiller, context, std::make_tuple(scope, programElement, &astcompiler));
        FunctionEmitter funcEmitter(&cg, programElement);
        funcEmitter.Generate();
    };
}

static bool CheckOptionsBeforePhase(const util::Options &options, const parser::Program &program,
                                    const std::string &name)
{
    if (options.GetDumpBeforePhases().count(name) > 0U) {
        std::cout << "Before phase " << name << ":\n";
        std::cout << program.Dump() << std::endl;
    }

    if (options.GetDumpEtsSrcBeforePhases().count(name) > 0U) {
        std::cout << "Before phase " << name << " ets source:\n";
        std::cout << program.Ast()->DumpEtsSrc() << std::endl;
    }

    return options.GetExitBeforePhase() == name;
}

static bool CheckOptionsAfterPhase(const util::Options &options, const parser::Program &program,
                                   const std::string &name)
{
    if (options.GetDumpAfterPhases().count(name) > 0U) {
        std::cout << "After phase " << name << ":\n";
        std::cout << program.Dump() << std::endl;
    }

    if (options.GetDumpEtsSrcAfterPhases().count(name) > 0U) {
        std::cout << "After phase " << name << " ets source:\n";
        std::cout << program.Ast()->DumpEtsSrc() << std::endl;
    }

    return options.GetExitAfterPhase() == name;
}

static bool RunVerifierAndPhases(public_lib::Context &context, parser::Program &program)
{
    const auto &options = *context.config->options;
    const auto verifierEachPhase = options.IsAstVerifierEachPhase();

    ast_verifier::ASTVerifier verifier(context, program);

    while (auto phase = context.phaseManager->NextPhase()) {
        const auto name = std::string {phase->Name()};
        if (options.GetSkipPhases().count(name) > 0) {
            continue;
        }

        if (CheckOptionsBeforePhase(options, program, name) || !phase->Apply(&context, &program) ||
            CheckOptionsAfterPhase(options, program, name)) {
            return false;
        }

        if (verifier.IntroduceNewInvariants(phase->Name());
            verifierEachPhase || options.HasVerifierPhase(phase->Name())) {
            verifier.Verify(phase->Name());
        }

        // Stop lowerings processing after Checker phase if any error happened.
        if (phase->Name() == compiler::CheckerPhase::NAME && context.diagnosticEngine->IsAnyError()) {
            return false;
        }
    }

    return true;
}

static bool RunPhases(public_lib::Context &context, parser::Program &program)
{
    const auto &options = *context.config->options;

    while (auto phase = context.phaseManager->NextPhase()) {
        const auto name = std::string {phase->Name()};
        if (options.GetSkipPhases().count(name) > 0) {
            continue;
        }

        if (CheckOptionsBeforePhase(options, program, name)) {
            return false;
        }

        if (!phase->Apply(&context, &program)) {
            return false;
        }

        if (CheckOptionsAfterPhase(options, program, name)) {
            return false;
        }
    }

    return true;
}

static void CreateDebuggerEvaluationPlugin(checker::ETSChecker &checker, ArenaAllocator &allocator,
                                           parser::Program *program, const util::Options &options)
{
    // Sometimes evaluation mode might work without project context.
    // In this case, users might omit context files.
    if (options.IsDebuggerEval() && !options.GetDebuggerEvalPandaFiles().empty()) {
        auto *plugin = allocator.New<evaluate::ScopedDebugInfoPlugin>(program, &checker, options);
        checker.SetDebugInfoPlugin(plugin);
    }
}

template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
          typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
// CC-OFFNXT(huge_method, G.FUN.01-CPP) solid logic
static pandasm::Program *Compile(const CompilationUnit &unit, CompilerImpl *compilerImpl)
{
    ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    auto program = parser::Program::NewProgram<VarBinder>(&allocator);
    auto parser =
        Parser(&program, unit.options, unit.diagnosticEngine, static_cast<parser::ParserStatus>(unit.rawParserStatus));
    auto checker = Checker(unit.diagnosticEngine);
    auto analyzer = Analyzer(&checker);
    auto phaseManager = compiler::PhaseManager(unit.ext, &allocator);
    checker.SetAnalyzer(&analyzer);

    auto *varbinder = program.VarBinder();
    varbinder->SetProgram(&program);

    if constexpr (std::is_same_v<Checker, checker::ETSChecker>) {
        CreateDebuggerEvaluationPlugin(checker, allocator, &program, unit.options);
    }

    public_lib::Context context;

    auto config = public_lib::ConfigImpl {};
    context.config = &config;
    context.config->options = &unit.options;
    context.sourceFile = &unit.input;
    context.allocator = &allocator;
    context.queue = compilerImpl->Queue();
    context.plugins = &compilerImpl->Plugins();
    context.parser = &parser;
    context.checker = &checker;
    context.analyzer = checker.GetAnalyzer();
    context.parserProgram = &program;
    context.codeGenCb = MakeCompileJob<CodeGen, RegSpiller, FunctionEmitter, Emitter, AstCompiler>();
    context.diagnosticEngine = &unit.diagnosticEngine;
    context.phaseManager = &phaseManager;

    auto emitter = Emitter(&context);
    context.emitter = &emitter;

    varbinder->SetContext(&context);
    context.checker->Initialize(varbinder);

    parser.ParseScript(unit.input, unit.options.GetCompilationMode() == CompilationMode::GEN_STD_LIB);

    //  We have to check the return status of 'RunVerifierAndPhase` and 'RunPhases` separately because there can be
    //  some internal errors (say, in Post-Conditional check) or terminate options (say in 'CheckOptionsAfterPhase')
    //  that were not reported to the log.
    if (unit.ext == ScriptExtension::ETS) {
        if (!RunVerifierAndPhases(context, program)) {
            return nullptr;
        }
    } else if (context.diagnosticEngine->IsAnyError()) {
        if (unit.options.IsDumpAst()) {
            std::cout << program.Dump() << std::endl;
        }
    } else if (!RunPhases(context, program)) {
        return nullptr;
    }

    if (context.diagnosticEngine->IsAnyError()) {
        return nullptr;
    }

    emitter.GenAnnotation();
    return compilerImpl->Emit(&context);
}

pandasm::Program *CompilerImpl::Compile(const CompilationUnit &unit)
{
    switch (unit.ext) {
        case ScriptExtension::TS: {
            return compiler::Compile<parser::TSParser, varbinder::TSBinder, checker::TSChecker, checker::TSAnalyzer,
                                     compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                     compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, this);
        }
        case ScriptExtension::AS: {
            return compiler::Compile<parser::ASParser, varbinder::ASBinder, checker::ASChecker, checker::TSAnalyzer,
                                     compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                     compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, this);
        }
        case ScriptExtension::ETS: {
            return compiler::Compile<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                                     compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                                     compiler::ETSFunctionEmitter, compiler::ETSEmitter>(unit, this);
        }
        case ScriptExtension::JS: {
            return compiler::Compile<parser::JSParser, varbinder::JSBinder, checker::JSChecker, checker::TSAnalyzer,
                                     compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                     compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, this);
        }
        default: {
            ES2PANDA_UNREACHABLE();
            return nullptr;
        }
    }
}

void CompilerImpl::DumpAsm(const ark::pandasm::Program *prog)
{
    Emitter::DumpAsm(prog);
}

std::string CompilerImpl::GetPhasesList(const ScriptExtension ext)
{
    std::stringstream ss;
    auto phaseManager = compiler::PhaseManager(ext, nullptr);
    while (auto phase = phaseManager.NextPhase()) {
        ss << " " << phase->Name() << std::endl;
    }
    return ss.str();
}

}  // namespace ark::es2panda::compiler
