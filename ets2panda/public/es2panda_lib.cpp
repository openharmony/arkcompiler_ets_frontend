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

#include "es2panda_lib.h"
#include <memory>

#include "generated/signatures.h"
#include "es2panda.h"
#include "assembler/assembly-program.h"
#include "binder/ETSBinder.h"
#include "checker/ETSAnalyzer.h"
#include "checker/ETSchecker.h"
#include "compiler/core/compileQueue.h"
#include "compiler/core/ETSCompiler.h"
#include "compiler/core/ETSemitter.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regSpiller.h"
#include "compiler/lowering/phase.h"
#include "ir/astNode.h"
#include "ir/expressions/identifier.h"
#include "parser/ETSparser.h"
#include "parser/context/parserContext.h"
#include "parser/program/program.h"
#include "util/generateBin.h"
#include "util/options.h"

namespace panda::es2panda::public_lib {
struct ConfigImpl {
    std::unique_ptr<util::Options> options;
};

struct Context {
    ConfigImpl *config = nullptr;
    std::string source_file_name;
    std::string input;
    std::unique_ptr<SourceFile> source_file;
    std::unique_ptr<ArenaAllocator> allocator;
    std::unique_ptr<compiler::CompileQueue> queue;

    std::unique_ptr<parser::Program> parser_program;
    std::unique_ptr<parser::ETSParser> parser;
    std::unique_ptr<checker::ETSChecker> checker;
    std::unique_ptr<checker::ETSAnalyzer> analyzer;
    std::unique_ptr<compiler::CompilerContext> compiler_context;
    std::unique_ptr<compiler::ETSEmitter> emitter;
    std::unique_ptr<pandasm::Program> program;

    es2panda_ContextState state = ES2PANDA_STATE_NEW;
    std::string error_message;
};

extern "C" es2panda_Config *CreateConfig(int args, char const **argv)
{
    constexpr auto COMPILER_SIZE = 256_MB;

    mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
    PoolManager::Initialize(PoolType::MMAP);

    auto options = std::make_unique<util::Options>();
    if (!options->Parse(args, argv)) {
        // TODO(gogabr): report option errors properly.
        std::cerr << options->ErrorMsg() << std::endl;
        return nullptr;
    }
    Logger::ComponentMask mask {};
    mask.set(Logger::Component::ES2PANDA);
    Logger::InitializeStdLogging(Logger::LevelFromString(options->LogLevel()), mask);

    auto *res = new ConfigImpl;
    res->options = std::move(options);
    return reinterpret_cast<es2panda_Config *>(res);
}

extern "C" void DestroyConfig(es2panda_Config *config)
{
    PoolManager::Finalize();
    mem::MemConfig::Finalize();

    delete reinterpret_cast<ConfigImpl *>(config);
}

static void CompileJob(compiler::CompilerContext *context, binder::FunctionScope *scope,
                       compiler::ProgramElement *program_element)
{
    compiler::StaticRegSpiller reg_spiller;
    ArenaAllocator allocator {SpaceType::SPACE_TYPE_COMPILER, nullptr, true};
    compiler::ETSCompiler ast_compiler {};
    compiler::ETSGen cg {&allocator, &reg_spiller, context, scope, program_element, &ast_compiler};
    compiler::ETSFunctionEmitter func_emitter {&cg, program_element};
    func_emitter.Generate();
}

static es2panda_Context *CreateContext(es2panda_Config *config, std::string const &&source,
                                       std::string const &&file_name)
{
    auto *cfg = reinterpret_cast<ConfigImpl *>(config);
    auto *res = new Context;
    res->config = cfg;
    res->input = source;
    res->source_file_name = file_name;

    try {
        res->source_file = std::make_unique<SourceFile>(res->source_file_name, res->input, cfg->options->ParseModule());
        res->allocator = std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
        res->queue = std::make_unique<compiler::CompileQueue>(cfg->options->ThreadCount());

        auto *binder = res->allocator->New<binder::ETSBinder>(res->allocator.get());
        res->parser_program = std::make_unique<parser::Program>(res->allocator.get(), binder);
        res->parser_program->MarkEntry();
        res->parser = std::make_unique<parser::ETSParser>(res->parser_program.get(), cfg->options->CompilerOptions(),
                                                          parser::ParserStatus::NO_OPTS);
        res->checker = std::make_unique<checker::ETSChecker>();
        res->analyzer = std::make_unique<checker::ETSAnalyzer>(res->checker.get());
        res->checker->SetAnalyzer(res->analyzer.get());

        binder->SetProgram(res->parser_program.get());

        res->compiler_context = std::make_unique<compiler::CompilerContext>(
            binder, res->checker.get(), cfg->options->CompilerOptions(), CompileJob);
        binder->SetCompilerContext(res->compiler_context.get());
        res->emitter = std::make_unique<compiler::ETSEmitter>(res->compiler_context.get());
        res->compiler_context->SetEmitter(res->emitter.get());
        res->program = nullptr;
        res->state = ES2PANDA_STATE_NEW;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        res->error_message = ss.str();
        res->state = ES2PANDA_STATE_ERROR;
    }
    return reinterpret_cast<es2panda_Context *>(res);
}

extern "C" es2panda_Context *CreateContextFromFile(es2panda_Config *config, char const *source_file_name)
{
    std::ifstream input_stream;
    input_stream.open(source_file_name);
    if (input_stream.fail()) {
        auto *res = new Context;
        res->error_message = "Failed to open file: ";
        res->error_message.append(source_file_name);
        return reinterpret_cast<Context *>(res);
    }
    std::stringstream ss;
    ss << input_stream.rdbuf();
    if (input_stream.fail()) {
        auto *res = new Context;
        res->error_message = "Failed to read file: ";
        res->error_message.append(source_file_name);
        return reinterpret_cast<Context *>(res);
    }
    return CreateContext(config, ss.str(), source_file_name);
}

extern "C" es2panda_Context *CreateContextFromString(es2panda_Config *config, char const *source, char const *file_name)
{
    // TODO(gogabr): avoid copying source.
    return CreateContext(config, source, file_name);
}

static Context *Parse(Context *ctx)
{
    if (ctx->state != ES2PANDA_STATE_NEW) {
        ctx->state = ES2PANDA_STATE_ERROR;
        ctx->error_message = "Bad state at entry to Parse, needed NEW";
        return ctx;
    }
    try {
        ctx->parser->ParseScript(*ctx->source_file, ctx->config->options->CompilerOptions().compilation_mode ==
                                                        CompilationMode::GEN_STD_LIB);
        ctx->state = ES2PANDA_STATE_PARSED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->error_message = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }

    return ctx;
}

static Context *Check(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_PARSED) {
        ctx = Parse(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_PARSED);

    try {
        ctx->compiler_context->Checker()->StartChecker(ctx->compiler_context->Binder(),
                                                       ctx->config->options->CompilerOptions());
        ctx->state = ES2PANDA_STATE_CHECKED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->error_message = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
    return ctx;
}

static Context *Lower(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_CHECKED) {
        ctx = Check(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_CHECKED);

    try {
        for (auto *phase : compiler::GetETSPhaseList()) {
            phase->Apply(ctx->compiler_context.get(), ctx->compiler_context->Binder()->Program());
        }

        ctx->state = ES2PANDA_STATE_LOWERED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->error_message = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }

    return ctx;
}

static Context *GenerateAsm(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_LOWERED) {
        ctx = Lower(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_LOWERED);

    auto *emitter = ctx->compiler_context->GetEmitter();
    try {
        emitter->GenAnnotation();

        // Handle context literals.
        uint32_t index = 0;
        for (const auto &buff : ctx->compiler_context->ContextLiterals()) {
            emitter->AddLiteralBuffer(buff, index++);
        }

        emitter->LiteralBufferIndex() += ctx->compiler_context->ContextLiterals().size();

        /* Main thread can also be used instead of idling */
        ctx->queue->Schedule(ctx->compiler_context.get());
        ctx->queue->Consume();
        ctx->queue->Wait(
            [emitter](compiler::CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });
        ASSERT(ctx->program == nullptr);
        ctx->program = std::unique_ptr<pandasm::Program> {
            emitter->Finalize(ctx->compiler_context->DumpDebugInfo(), compiler::Signatures::ETS_GLOBAL)};

        ctx->state = ES2PANDA_STATE_ASM_GENERATED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->error_message = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
    return ctx;
}

Context *GenerateBin(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_ASM_GENERATED) {
        ctx = GenerateAsm(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_ASM_GENERATED);

    try {
        ASSERT(ctx->program != nullptr);
        util::GenerateProgram(ctx->program.get(), ctx->config->options.get(),
                              [ctx](const std::string &str) { ctx->error_message = str; });

        ctx->state = ES2PANDA_STATE_BIN_GENERATED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->error_message = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
    return ctx;
}

extern "C" es2panda_Context *ProceedToState(es2panda_Context *context, es2panda_ContextState state)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    switch (state) {
        case ES2PANDA_STATE_NEW:
            break;
        case ES2PANDA_STATE_PARSED:
            ctx = Parse(ctx);
            break;
        case ES2PANDA_STATE_CHECKED:
            ctx = Check(ctx);
            break;
        case ES2PANDA_STATE_LOWERED:
            ctx = Lower(ctx);
            break;
        case ES2PANDA_STATE_ASM_GENERATED:
            ctx = GenerateAsm(ctx);
            break;
        case ES2PANDA_STATE_BIN_GENERATED:
            ctx = GenerateBin(ctx);
            break;
        default:
            ctx->error_message = "It does not make sense to request stage";
            ctx->state = ES2PANDA_STATE_ERROR;
            break;
    }
    return reinterpret_cast<es2panda_Context *>(ctx);
}

extern "C" void DestroyContext(es2panda_Context *context)
{
    auto *s = reinterpret_cast<Context *>(context);
    delete s;
}

extern "C" es2panda_ContextState ContextState(es2panda_Context *context)
{
    auto *s = reinterpret_cast<Context *>(context);
    return s->state;
}

extern "C" char const *ContextErrorMessage(es2panda_Context *context)
{
    auto *s = reinterpret_cast<Context *>(context);
    return s->error_message.c_str();
}

es2panda_Impl IMPL = {ES2PANDA_LIB_VERSION,

                      CreateConfig,          DestroyConfig,

                      CreateContextFromFile, CreateContextFromString, ProceedToState, DestroyContext,

                      ContextState,          ContextErrorMessage};

}  // namespace panda::es2panda::public_lib

extern "C" es2panda_Impl const *es2panda_GetImpl(int version)
{
    if (version != ES2PANDA_LIB_VERSION) {
        return nullptr;
    }
    return &panda::es2panda::public_lib::IMPL;
}
