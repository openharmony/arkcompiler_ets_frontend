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

#include "compiler/core/ASTVerifier.h"
#include "es2panda.h"
#include "checker/ETSAnalyzer.h"
#include "checker/TSAnalyzer.h"
#include "compiler/core/compilerContext.h"
#include "compiler/core/compileQueue.h"
#include "compiler/core/compilerImpl.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSCompiler.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/JSCompiler.h"
#include "compiler/core/JSemitter.h"
#include "compiler/core/ETSemitter.h"
#include "compiler/lowering/phase.h"
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

void CompilerImpl::HandleContextLiterals(CompilerContext *context)
{
    auto *emitter = context->GetEmitter();

    uint32_t index = 0;
    for (const auto &buff : context->ContextLiterals()) {
        emitter->AddLiteralBuffer(buff, index++);
    }

    emitter->LiteralBufferIndex() += context->ContextLiterals().size();
}

ark::pandasm::Program *CompilerImpl::Emit(CompilerContext *context)
{
    HandleContextLiterals(context);

    queue_.Schedule(context);

    /* Main thread can also be used instead of idling */
    queue_.Consume();
    auto *emitter = context->GetEmitter();
    queue_.Wait([emitter](CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });

    return emitter->Finalize(context->DumpDebugInfo(), Signatures::ETS_GLOBAL);
}

class ASTVerificationRunner {
public:
    class Result {
    public:
        explicit Result(JsonArrayBuilder &&warnings, JsonArrayBuilder &&errors)
            : warnings_ {std::move(warnings)}, errors_ {std::move(errors)}
        {
        }

        JsonArrayBuilder &&Warnings()
        {
            return std::move(warnings_);
        }

        JsonArrayBuilder &&Errors()
        {
            return std::move(errors_);
        }

    private:
        JsonArrayBuilder warnings_;
        JsonArrayBuilder errors_;
    };

    using AstPath = std::string;
    using PhaseName = std::string;
    using Source = std::tuple<AstPath, PhaseName>;
    using AstToCheck = ArenaMap<AstPath, const ir::AstNode *>;
    using GroupedMessages = std::map<Source, ast_verifier::Messages>;

    ASTVerificationRunner(ArenaAllocator &allocator, const CompilerContext &context)
        : checkFullProgram_ {context.Options()->verifierFullProgram},
          verifier_ {&allocator},
          treatAsWarnings_ {context.Options()->verifierWarnings},
          treatAsErrors_ {context.Options()->verifierErrors}
    {
    }

    void Verify(const AstToCheck &astToCheck, const PhaseName &phaseName,
                const ast_verifier::InvariantNameSet &accumulatedChecks)
    {
        for (const auto &[sourceName, ast] : astToCheck) {
            const auto source = Source(sourceName, phaseName);
            auto messages = verifier_.Verify(ast, accumulatedChecks);
            auto &sourcedReport = report_[source];
            std::copy(messages.begin(), messages.end(), std::back_inserter(sourcedReport));
        }
    }

    Result DumpMessages()
    {
        auto warnings = JsonArrayBuilder {};
        auto errors = JsonArrayBuilder {};
        const auto filterMessages = [this, &warnings, &errors](const ast_verifier::CheckMessage &message,
                                                               const std::string &sourceName,
                                                               const std::string &phaseName) {
            auto invariant = message.Invariant();
            if (auto found = treatAsWarnings_.find(invariant); found != treatAsWarnings_.end()) {
                warnings.Add(message.DumpJSON(ast_verifier::CheckSeverity::WARNING, sourceName, phaseName));
                return;
            }
            if (auto found = treatAsErrors_.find(invariant); found != treatAsErrors_.end()) {
                errors.Add(message.DumpJSON(ast_verifier::CheckSeverity::ERROR, sourceName, phaseName));
            }
        };

        for (const auto &[source, messages] : report_) {
            const auto &[sourceName, phaseName] = source;
            for (const auto &message : messages) {
                filterMessages(message, sourceName, phaseName);
            }
        }

        return Result {std::move(warnings), std::move(errors)};
    }

    ASTVerificationRunner::AstToCheck ExtractAst(const parser::Program &p)
    {
        auto &allocator = *p.Allocator();
        auto astToCheck = ASTVerificationRunner::AstToCheck {allocator.Adapter()};
        astToCheck.insert(std::make_pair(p.SourceFilePath(), p.Ast()));
        if (checkFullProgram_) {
            for (const auto &externalSource : p.ExternalSources()) {
                for (auto *external : externalSource.second) {
                    astToCheck.insert(std::make_pair(external->SourceFilePath(), external->Ast()));
                }
            }
        }
        return astToCheck;
    }

private:
    bool checkFullProgram_;
    GroupedMessages report_;
    ast_verifier::ASTVerifier verifier_;
    std::unordered_set<std::string> treatAsWarnings_;
    std::unordered_set<std::string> treatAsErrors_;
};

template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter, typename AstCompiler>
static CompilerContext::CodeGenCb MakeCompileJob()
{
    return [](CompilerContext *context, varbinder::FunctionScope *scope,
              compiler::ProgramElement *programElement) -> void {
        RegSpiller regSpiller;
        ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
        AstCompiler astcompiler;
        CodeGen cg(&allocator, &regSpiller, context, scope, programElement, &astcompiler);
        FunctionEmitter funcEmitter(&cg, programElement);
        funcEmitter.Generate();
    };
}

static void SetupPublicContext(public_lib::Context *context, const SourceFile *sourceFile, ArenaAllocator *allocator,
                               CompileQueue *queue, std::vector<util::Plugin> const *plugins,
                               parser::ParserImpl *parser, CompilerContext *compilerContext)
{
    context->sourceFile = sourceFile;
    context->allocator = allocator;
    context->queue = queue;
    context->plugins = plugins;
    context->parser = parser;
    context->checker = compilerContext->Checker();
    context->analyzer = context->checker->GetAnalyzer();
    context->compilerContext = compilerContext;
    context->emitter = compilerContext->GetEmitter();
}

#ifndef NDEBUG

static bool RunVerifierAndPhases(ArenaAllocator &allocator, const CompilerContext &context,
                                 public_lib::Context &publicContext, const std::vector<Phase *> &phases,
                                 parser::Program &program)
{
    auto runner = ASTVerificationRunner(allocator, context);
    auto verificationCtx = ast_verifier::VerificationContext {};
    const auto runAllChecks = context.Options()->verifierAllChecks;

    for (auto *phase : phases) {
        if (!phase->Apply(&publicContext, &program)) {
            return false;
        }

        if (runAllChecks) {
            auto ast = runner.ExtractAst(program);
            runner.Verify(ast, std::string {phase->Name()}, verificationCtx.AccumulatedChecks());
        }
        verificationCtx.IntroduceNewInvariants(phase->Name());
    }

    if (!runAllChecks) {
        auto ast = runner.ExtractAst(program);
        runner.Verify(ast, "AfterAllPhases", verificationCtx.AccumulatedChecks());
    }

    auto result = runner.DumpMessages();
    if (auto warnings = result.Warnings().Build(); warnings != "[]") {
        LOG(WARNING, ES2PANDA) << warnings;
    }

    if (auto errors = result.Errors().Build(); errors != "[]") {
        ASSERT_PRINT(false, errors);
    }

    return true;
}
#endif

using EmitCb = std::function<pandasm::Program *(compiler::CompilerContext *)>;
using PhaseListGetter = std::function<std::vector<compiler::Phase *>(ScriptExtension)>;

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

    CompilerContext context(varbinder, &checker, unit.options,
                            MakeCompileJob<CodeGen, RegSpiller, FunctionEmitter, Emitter, AstCompiler>());
    varbinder->SetCompilerContext(&context);

    auto emitter = Emitter(&context);
    context.SetEmitter(&emitter);
    context.SetParser(&parser);

    public_lib::Context publicContext;
    SetupPublicContext(&publicContext, &unit.input, &allocator, compilerImpl->Queue(), &compilerImpl->Plugins(),
                       &parser, &context);

    parser.ParseScript(unit.input, unit.options.compilationMode == CompilationMode::GEN_STD_LIB);
    const auto phases = getPhases(unit.ext);
#ifndef NDEBUG
    if (unit.ext == ScriptExtension::ETS) {
        if (!RunVerifierAndPhases(allocator, context, publicContext, phases, program)) {
            return nullptr;
        }
    } else {
        for (auto *phase : phases) {
            if (!phase->Apply(&publicContext, &program)) {
                return nullptr;
            }
        }
    }
#else
    for (auto *phase : phases) {
        if (!phase->Apply(&publicContext, &program)) {
            return nullptr;
        }
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
        case ScriptExtension::ETS: {
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
}  // namespace ark::es2panda::compiler
