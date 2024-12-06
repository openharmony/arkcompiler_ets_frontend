/**
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

#ifndef NDEBUG

static bool RunVerifierAndPhases(CompilerImpl *compilerImpl, public_lib::Context &context,
                                 const std::vector<Phase *> &phases, parser::Program &program)
{
    auto verifier = ast_verifier::ASTVerifier(context, program);
    const auto verifierEachPhase = context.config->options->IsVerifierInvariantsEachPhase();

    for (auto *phase : phases) {
        if (!phase->Apply(&context, &program)) {
            compilerImpl->SetIsAnyError(context.checker->ErrorLogger()->IsAnyError() ||
                                        context.parser->ErrorLogger()->IsAnyError());
            return false;
        }
        if (verifierEachPhase) {
            verifier.Verify(phase->Name());
        }
        verifier.IntroduceNewInvariants(phase->Name());
    }

    if (!verifierEachPhase) {
        verifier.Verify("AfterAllPhases");
    }

    auto verifierResult = verifier.DumpMessages();
    if (auto warnings = verifierResult.Warnings().Build(); warnings != "[]") {
        LOG(WARNING, ES2PANDA) << warnings;
    }

    if (auto errors = verifierResult.Errors().Build(); errors != "[]") {
        ASSERT_PRINT(false, errors);
    }

    return true;
}
#endif

static bool RunPhases(CompilerImpl *compilerImpl, public_lib::Context &context, const std::vector<Phase *> &phases,
                      parser::Program &program)
{
    for (auto *phase : phases) {
        if (!phase->Apply(&context, &program)) {
            compilerImpl->SetIsAnyError(context.checker->ErrorLogger()->IsAnyError() ||
                                        context.parser->ErrorLogger()->IsAnyError());
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

using EmitCb = std::function<pandasm::Program *(public_lib::Context *)>;
using PhaseListGetter = std::function<std::vector<compiler::Phase *>(ScriptExtension)>;

static bool ParserErrorChecker(bool isAnyError, parser::Program *program, CompilerImpl *compilerImpl,
                               const CompilationUnit &unit)
{
    if (isAnyError) {
        compilerImpl->SetIsAnyError(isAnyError);
        if (unit.options.IsDumpAst()) {
            std::cout << program->Dump() << std::endl;
        }
        return false;
    }
    return true;
}

template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
          typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
static pandasm::Program *CreateCompiler(const CompilationUnit &unit, const PhaseListGetter &getPhases,
                                        CompilerImpl *compilerImpl)
{
    ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    auto program = parser::Program::NewProgram<VarBinder>(&allocator);
    program.MarkEntry();
    auto parser = Parser(&program, unit.options, static_cast<parser::ParserStatus>(unit.rawParserStatus));
    auto checker = Checker();
    auto analyzer = Analyzer(&checker);
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

    auto emitter = Emitter(&context);
    context.emitter = &emitter;

    varbinder->SetContext(&context);

    parser.ParseScript(unit.input, unit.options.GetCompilationMode() == CompilationMode::GEN_STD_LIB);
    if (!ParserErrorChecker(parser.ErrorLogger()->IsAnyError(), &program, compilerImpl, unit)) {
        return nullptr;
    }
#ifndef NDEBUG
    if (unit.ext == ScriptExtension::STS) {
        if (!RunVerifierAndPhases(compilerImpl, context, getPhases(unit.ext), program)) {
            return nullptr;
        }
    } else if (!RunPhases(compilerImpl, context, getPhases(unit.ext), program)) {
        return nullptr;
    }
#else
    if (!RunPhases(compilerImpl, context, getPhases(unit.ext), program)) {
        return nullptr;
    }
#endif

    emitter.GenAnnotation();

    return compilerImpl->Emit(&context);
}

pandasm::Program *CompilerImpl::Compile(const CompilationUnit &unit)
{
    switch (unit.ext) {
        case ScriptExtension::TS: {
            return CreateCompiler<parser::TSParser, varbinder::TSBinder, checker::TSChecker, checker::TSAnalyzer,
                                  compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                  compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, compiler::GetPhaseList, this);
        }
        case ScriptExtension::AS: {
            return CreateCompiler<parser::ASParser, varbinder::ASBinder, checker::ASChecker, checker::TSAnalyzer,
                                  compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                  compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, compiler::GetPhaseList, this);
        }
        case ScriptExtension::STS: {
            return CreateCompiler<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                                  compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                                  compiler::ETSFunctionEmitter, compiler::ETSEmitter>(unit, compiler::GetPhaseList,
                                                                                      this);
        }
        case ScriptExtension::JS: {
            return CreateCompiler<parser::JSParser, varbinder::JSBinder, checker::JSChecker, checker::TSAnalyzer,
                                  compiler::JSCompiler, compiler::PandaGen, compiler::DynamicRegSpiller,
                                  compiler::JSFunctionEmitter, compiler::JSEmitter>(unit, compiler::GetPhaseList, this);
        }
        default: {
            UNREACHABLE();
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
    for (auto phase : compiler::GetPhaseList(ext)) {
        ss << " " << phase->Name() << std::endl;
    }
    return ss.str();
}

}  // namespace ark::es2panda::compiler
