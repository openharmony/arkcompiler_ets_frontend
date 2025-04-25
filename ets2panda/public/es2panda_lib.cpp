/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <cstring>
#include <cstdint>

#include "util/diagnostic.h"
#include "varbinder/varbinder.h"
#include "varbinder/scope.h"
#include "public/public.h"
#include "generated/signatures.h"
#include "es2panda.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSAnalyzer.h"
#include "checker/ETSchecker.h"
#include "compiler/core/compileQueue.h"
#include "compiler/core/ETSCompiler.h"
#include "compiler/core/ETSemitter.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regSpiller.h"
#include "compiler/lowering/phase.h"
#include "compiler/lowering/checkerPhase.h"
#include "compiler/lowering/resolveIdentifiers.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/astNode.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/expressions/callExpression.h"
#include "ir/base/classProperty.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/statements/ifStatement.h"
#include "ir/base/methodDefinition.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsNewArrayInstanceExpression.h"
#include "ir/ets/etsNewMultiDimArrayInstanceExpression.h"
#include "parser/ETSparser.h"
#include "parser/context/parserContext.h"
#include "parser/program/program.h"
#include "util/generateBin.h"
#include "util/options.h"
#include "compiler/lowering/util.h"
#include "generated/es2panda_lib/es2panda_lib_include.inc"
#include "declgen_ets2ts/declgenEts2Ts.h"

// NOLINTBEGIN

namespace ark::es2panda::public_lib {

struct TokenTypeToStr {
    lexer::TokenType token;
    char const *str;
};

__attribute__((unused)) lexer::TokenType StrToToken(TokenTypeToStr const *table, char const *str)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (auto *tp = table; tp->str != nullptr; tp++) {
        if (strcmp(str, tp->str) == 0) {
            return tp->token;
        }
    }
    ES2PANDA_UNREACHABLE();
}

__attribute__((unused)) char const *TokenToStr(TokenTypeToStr const *table, lexer::TokenType token)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (auto *tp = table; tp->str != nullptr; tp++) {
        if (tp->token == token) {
            return tp->str;
        }
    }
    ES2PANDA_UNREACHABLE();
}

char *StringViewToCString(ArenaAllocator *allocator, std::string_view const utf8)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    if (!utf8.empty() && (utf8.back() == '\0')) {
        // Avoid superfluous allocation.
        return const_cast<char *>(utf8.data());
    }
    char *res = reinterpret_cast<char *>(allocator->Alloc(utf8.size() + 1));
    if (!utf8.empty()) {
        [[maybe_unused]] auto err = memmove_s(res, utf8.size() + 1, utf8.cbegin(), utf8.size());
        ES2PANDA_ASSERT(err == EOK);
    }
    res[utf8.size()] = '\0';
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

__attribute__((unused)) char *StringViewToCString(ArenaAllocator *allocator, util::StringView const sv)
{
    return StringViewToCString(allocator, sv.Utf8());
}

__attribute__((unused)) char *StdStringToCString(ArenaAllocator *allocator, std::string str)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    char *res = reinterpret_cast<char *>(allocator->Alloc(str.length() + 1));
    [[maybe_unused]] auto err = memcpy_s(res, str.length() + 1, str.c_str(), str.length() + 1);
    ES2PANDA_ASSERT(err == EOK);
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

__attribute__((unused)) char *UStringToCString(ArenaAllocator *allocator, util::UString const sv)
{
    return StringViewToCString(allocator, sv.View());
}

__attribute__((unused)) es2panda_variantDoubleCharArrayBool EnumMemberResultToEs2pandaVariant(
    ArenaAllocator *allocator, varbinder::EnumMemberResult variant)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    es2panda_variantDoubleCharArrayBool es2panda_variant;
    es2panda_variant.index = variant.index();
    switch (es2panda_variant.index) {
        case es2panda_variantIndex::CAPI_DOUBLE:
            es2panda_variant.variant.d = std::get<double>(variant);
            break;
        case es2panda_variantIndex::CAPI_CHAR:
            es2panda_variant.variant.c = StringViewToCString(allocator, std::get<util::StringView>(variant));
            break;
        case es2panda_variantIndex::CAPI_BOOL:
            es2panda_variant.variant.b = std::get<bool>(variant);
            break;
        default:
            break;
    }
    return es2panda_variant;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    // NOLINTEND(cppcoreguidelines-pro-type-union-access)
}

__attribute__((unused)) es2panda_DynamicImportData *DynamicImportDataToE2pPtr(
    ArenaAllocator *allocator, const varbinder::DynamicImportData *dynamicImportData)
{
    auto import = reinterpret_cast<const es2panda_AstNode *>(dynamicImportData->import);
    auto specifier = reinterpret_cast<const es2panda_AstNode *>(dynamicImportData->specifier);
    auto variable = reinterpret_cast<es2panda_Variable *>(dynamicImportData->variable);
    auto es2pandaDynamicImportData = allocator->New<es2panda_DynamicImportData>();
    es2pandaDynamicImportData->import = import;
    es2pandaDynamicImportData->specifier = specifier;
    es2pandaDynamicImportData->variable = variable;
    return es2pandaDynamicImportData;
}

__attribute__((unused)) es2panda_DynamicImportData DynamicImportDataToE2p(
    const varbinder::DynamicImportData dynamicImportData)
{
    auto import = reinterpret_cast<const es2panda_AstNode *>(dynamicImportData.import);
    auto specifier = reinterpret_cast<const es2panda_AstNode *>(dynamicImportData.specifier);
    auto variable = reinterpret_cast<es2panda_Variable *>(dynamicImportData.variable);
    es2panda_DynamicImportData es2pandaDynamicImportData;
    es2pandaDynamicImportData.import = import;
    es2pandaDynamicImportData.specifier = specifier;
    es2pandaDynamicImportData.variable = variable;
    return es2pandaDynamicImportData;
}

__attribute__((unused)) es2panda_OverloadInfo *OverloadInfoToE2pPtr(ArenaAllocator *allocator,
                                                                    const ir::OverloadInfo *overloadInfo)
{
    auto es2pandaOverloadInfo = allocator->New<es2panda_OverloadInfo>();
    es2pandaOverloadInfo->minArg = overloadInfo->minArg;
    es2pandaOverloadInfo->maxArg = overloadInfo->maxArg;
    es2pandaOverloadInfo->needHelperOverload = overloadInfo->needHelperOverload;
    es2pandaOverloadInfo->isDeclare = overloadInfo->isDeclare;
    es2pandaOverloadInfo->hasRestVar = overloadInfo->hasRestVar;
    es2pandaOverloadInfo->returnVoid = overloadInfo->returnVoid;
    return es2pandaOverloadInfo;
}

__attribute__((unused)) es2panda_OverloadInfo OverloadInfoToE2p(const ir::OverloadInfo overloadInfo)
{
    es2panda_OverloadInfo es2pandaOverloadInfo;
    es2pandaOverloadInfo.minArg = overloadInfo.minArg;
    es2pandaOverloadInfo.maxArg = overloadInfo.maxArg;
    es2pandaOverloadInfo.needHelperOverload = overloadInfo.needHelperOverload;
    es2pandaOverloadInfo.isDeclare = overloadInfo.isDeclare;
    es2pandaOverloadInfo.hasRestVar = overloadInfo.hasRestVar;
    es2pandaOverloadInfo.returnVoid = overloadInfo.returnVoid;
    return es2pandaOverloadInfo;
}

__attribute__((unused)) char const *ArenaStrdup(ArenaAllocator *allocator, char const *src)
{
    size_t len = strlen(src);
    char *res = reinterpret_cast<char *>(allocator->Alloc(len + 1));
    [[maybe_unused]] auto err = memmove_s(res, len + 1, src, len);
    ES2PANDA_ASSERT(err == EOK);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res[len] = '\0';
    return res;
}

extern "C" es2panda_Config *CreateConfig(int args, char const *const *argv)
{
    mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
    PoolManager::Initialize(PoolType::MMAP);
    auto diagnosticEngine = new util::DiagnosticEngine();
    auto *options = new util::Options(argv[0], *diagnosticEngine);
    if (!options->Parse(Span(argv, args))) {
        return nullptr;
    }
    ark::Logger::ComponentMask mask {};
    mask.set(ark::Logger::Component::ES2PANDA);
    ark::Logger::InitializeStdLogging(options->LogLevel(), mask);

    auto *res = new ConfigImpl;
    res->options = options;
    res->diagnosticEngine = diagnosticEngine;
    return reinterpret_cast<es2panda_Config *>(res);
}

extern "C" void DestroyConfig(es2panda_Config *config)
{
    PoolManager::Finalize();
    mem::MemConfig::Finalize();

    auto *cfg = reinterpret_cast<ConfigImpl *>(config);
    if (cfg == nullptr) {
        return;
    }

    delete cfg->options;
    delete cfg->diagnosticEngine;
    delete cfg;
}

extern "C" const es2panda_Options *ConfigGetOptions(es2panda_Config *config)
{
    auto options = reinterpret_cast<ConfigImpl *>(config)->options;
    return reinterpret_cast<const es2panda_Options *>(options);
}

static void CompileJob(public_lib::Context *context, varbinder::FunctionScope *scope,
                       compiler::ProgramElement *programElement)
{
    compiler::StaticRegSpiller regSpiller;
    ArenaAllocator allocator {SpaceType::SPACE_TYPE_COMPILER, nullptr, true};
    compiler::ETSCompiler astCompiler {};
    compiler::ETSGen cg {&allocator, &regSpiller, context, std::make_tuple(scope, programElement, &astCompiler)};
    compiler::ETSFunctionEmitter funcEmitter {&cg, programElement};
    funcEmitter.Generate();
}

__attribute__((unused)) static es2panda_Context *CreateContext(es2panda_Config *config, std::string &&source,
                                                               const char *fileName)
{
    auto *cfg = reinterpret_cast<ConfigImpl *>(config);
    auto *res = new Context;
    res->input = std::move(source);
    res->sourceFileName = fileName;
    res->config = cfg;

    if (cfg == nullptr) {
        res->errorMessage = "Config is nullptr.";
        res->state = ES2PANDA_STATE_ERROR;
        return reinterpret_cast<es2panda_Context *>(res);
    }

    if (cfg->options->GetExtension() != ScriptExtension::ETS) {
        res->errorMessage = "Invalid extension. Plugin API supports only ETS.";
        res->state = ES2PANDA_STATE_ERROR;
        return reinterpret_cast<es2panda_Context *>(res);
    }

    res->sourceFile = new SourceFile(res->sourceFileName, res->input, cfg->options->IsModule());
    res->allocator = new ArenaAllocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    res->queue = new compiler::CompileQueue(cfg->options->GetThread());

    auto *varbinder = res->allocator->New<varbinder::ETSBinder>(res->allocator);
    res->parserProgram = new parser::Program(res->allocator, varbinder);
    res->diagnosticEngine = cfg->diagnosticEngine;
    res->parser =
        new parser::ETSParser(res->parserProgram, *cfg->options, *cfg->diagnosticEngine, parser::ParserStatus::NO_OPTS);
    res->checker = new checker::ETSChecker(*res->diagnosticEngine);
    res->analyzer = new checker::ETSAnalyzer(res->checker);
    res->checker->SetAnalyzer(res->analyzer);

    varbinder->SetProgram(res->parserProgram);

    varbinder->SetContext(res);
    res->codeGenCb = CompileJob;
    res->phaseManager = new compiler::PhaseManager(ScriptExtension::ETS, res->allocator);
    res->emitter = new compiler::ETSEmitter(res);
    res->program = nullptr;
    res->state = ES2PANDA_STATE_NEW;
    return reinterpret_cast<es2panda_Context *>(res);
}

extern "C" __attribute__((unused)) es2panda_Context *CreateContextFromFile(es2panda_Config *config,
                                                                           char const *sourceFileName)
{
    std::ifstream inputStream;
    inputStream.open(sourceFileName);
    if (inputStream.fail()) {
        auto *res = new Context;
        res->errorMessage = "Failed to open file: ";
        res->errorMessage.append(sourceFileName);
        return reinterpret_cast<es2panda_Context *>(res);
    }
    std::stringstream ss;
    ss << inputStream.rdbuf();
    if (inputStream.fail()) {
        auto *res = new Context;
        res->errorMessage = "Failed to read file: ";
        res->errorMessage.append(sourceFileName);
        return reinterpret_cast<es2panda_Context *>(res);
    }
    return CreateContext(config, ss.str(), sourceFileName);
}

extern "C" __attribute__((unused)) es2panda_Context *CreateContextFromString(es2panda_Config *config,
                                                                             const char *source, char const *fileName)
{
    // NOTE: gogabr. avoid copying source.
    return CreateContext(config, std::string(source), fileName);
}

__attribute__((unused)) static Context *Parse(Context *ctx)
{
    if (ctx->state != ES2PANDA_STATE_NEW) {
        ctx->state = ES2PANDA_STATE_ERROR;
        ctx->errorMessage = "Bad state at entry to Parse, needed NEW";
        return ctx;
    }

    ctx->phaseManager->Restart();
    ctx->parser->ParseScript(*ctx->sourceFile,
                             ctx->config->options->GetCompilationMode() == CompilationMode::GEN_STD_LIB);
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_PARSED : ES2PANDA_STATE_ERROR;
    return ctx;
}

__attribute__((unused)) static Context *Bind(Context *ctx)
{
    // NOTE: Remove duplicated code in all phases
    if (ctx->state < ES2PANDA_STATE_PARSED) {
        ctx = Parse(ctx);
    }
    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ES2PANDA_ASSERT(ctx->state == ES2PANDA_STATE_PARSED);
    while (auto phase = ctx->phaseManager->NextPhase()) {
        phase->Apply(ctx, ctx->parserProgram);
        if (phase->Name() == compiler::ResolveIdentifiers::NAME) {
            break;
        }
    }
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_BOUND : ES2PANDA_STATE_ERROR;
    return ctx;
}

__attribute__((unused)) static Context *Check(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_PARSED) {
        ctx = Parse(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ES2PANDA_ASSERT(ctx->state >= ES2PANDA_STATE_PARSED && ctx->state < ES2PANDA_STATE_CHECKED);
    while (auto phase = ctx->phaseManager->NextPhase()) {
        phase->Apply(ctx, ctx->parserProgram);
        if (phase->Name() == compiler::CheckerPhase::NAME) {
            break;
        }
    }
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_CHECKED : ES2PANDA_STATE_ERROR;
    return ctx;
}

__attribute__((unused)) static Context *Lower(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_CHECKED) {
        ctx = Check(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ES2PANDA_ASSERT(ctx->state == ES2PANDA_STATE_CHECKED);
    while (auto phase = ctx->phaseManager->NextPhase()) {
        phase->Apply(ctx, ctx->parserProgram);
    }
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_LOWERED : ES2PANDA_STATE_ERROR;
    return ctx;
}

__attribute__((unused)) static Context *GenerateAsm(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_LOWERED) {
        ctx = Lower(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ES2PANDA_ASSERT(ctx->state == ES2PANDA_STATE_LOWERED);

    auto *emitter = ctx->emitter;
    emitter->GenAnnotation();

    // Handle context literals.
    uint32_t index = 0;
    for (const auto &buff : ctx->contextLiterals) {
        emitter->AddLiteralBuffer(buff, index++);
    }

    emitter->LiteralBufferIndex() += ctx->contextLiterals.size();

    /* Main thread can also be used instead of idling */
    ctx->queue->Schedule(ctx);
    ctx->queue->Consume();
    ctx->queue->Wait([emitter](compiler::CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });
    ES2PANDA_ASSERT(ctx->program == nullptr);
    ctx->program = emitter->Finalize(ctx->config->options->IsDumpDebugInfo(), compiler::Signatures::ETS_GLOBAL);
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_ASM_GENERATED : ES2PANDA_STATE_ERROR;
    return ctx;
}

__attribute__((unused)) Context *GenerateBin(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_ASM_GENERATED) {
        ctx = GenerateAsm(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ES2PANDA_ASSERT(ctx->state == ES2PANDA_STATE_ASM_GENERATED);

    ES2PANDA_ASSERT(ctx->program != nullptr);
    util::GenerateProgram(ctx->program, *ctx->config->options,
                          [ctx](const diagnostic::DiagnosticKind &kind, const util::DiagnosticMessageParams &params) {
                              ctx->diagnosticEngine->LogDiagnostic(kind, params);
                          });
    ctx->state = !ctx->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_BIN_GENERATED : ES2PANDA_STATE_ERROR;
    return ctx;
}

extern "C" __attribute__((unused)) es2panda_Context *ProceedToState(es2panda_Context *context,
                                                                    es2panda_ContextState state)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    switch (state) {
        case ES2PANDA_STATE_NEW:
            break;
        case ES2PANDA_STATE_PARSED:
            ctx = Parse(ctx);
            break;
        case ES2PANDA_STATE_BOUND:
            ctx = Bind(ctx);
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
            ctx->errorMessage = "It does not make sense to request stage";
            ctx->state = ES2PANDA_STATE_ERROR;
            break;
    }
    return reinterpret_cast<es2panda_Context *>(ctx);
}

extern "C" __attribute__((unused)) void DestroyContext(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    delete ctx->program;
    delete ctx->emitter;
    delete ctx->analyzer;
    delete ctx->checker;
    delete ctx->parser;
    delete ctx->parserProgram;
    delete ctx->queue;
    delete ctx->allocator;
    delete ctx->sourceFile;
    delete ctx->phaseManager;
    delete ctx;
}

extern "C" __attribute__((unused)) es2panda_ContextState ContextState(es2panda_Context *context)
{
    auto *s = reinterpret_cast<Context *>(context);
    return s->state;
}

extern "C" __attribute__((unused)) char const *ContextErrorMessage(es2panda_Context *context)
{
    auto *s = reinterpret_cast<Context *>(context);
    return s->errorMessage.c_str();
}

extern "C" __attribute__((unused)) es2panda_Program *ContextProgram(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    return reinterpret_cast<es2panda_Program *>(ctx->parserProgram);
}

using ExternalSourceEntry = std::pair<char *, ArenaVector<parser::Program *> *>;

__attribute__((unused)) static es2panda_ExternalSource **ExternalSourcesToE2p(
    ArenaAllocator *allocator, const parser::Program::ExternalSource &externalSources, size_t *lenP)
{
    auto *vec = allocator->New<ArenaVector<ExternalSourceEntry *>>(allocator->Adapter());

    for (auto &[e_name, e_programs] : externalSources) {
        vec->push_back(allocator->New<ExternalSourceEntry>(StringViewToCString(allocator, e_name),
                                                           const_cast<ArenaVector<parser::Program *> *>(&e_programs)));
    }

    *lenP = vec->size();
    return reinterpret_cast<es2panda_ExternalSource **>(vec->data());
}

extern "C" __attribute__((unused)) char const *ExternalSourceName(es2panda_ExternalSource *eSource)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(eSource);
    return entry->first;
}

extern "C" __attribute__((unused)) es2panda_Program **ExternalSourcePrograms(es2panda_ExternalSource *eSource,
                                                                             size_t *lenP)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(eSource);
    *lenP = entry->second->size();
    return reinterpret_cast<es2panda_Program **>(entry->second->data());
}

extern "C" void AstNodeForEach(es2panda_AstNode *ast, void (*func)(es2panda_AstNode *, void *), void *arg)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    func(ast, arg);
    node->IterateRecursively([=](ir::AstNode *child) { func(reinterpret_cast<es2panda_AstNode *>(child), arg); });
}

#define SET_NUMBER_LITERAL_IMPL(name, type)                                        \
    extern "C" bool NumberLiteralSet##name(es2panda_AstNode *node, type new_value) \
    {                                                                              \
        auto &n = reinterpret_cast<ir::NumberLiteral *>(node)->Number();           \
        if (!n.Is##name()) {                                                       \
            /* CC-OFFNXT(G.PRE.05) function gen */                                 \
            return false;                                                          \
        }                                                                          \
        n.SetValue<type>(std::move(new_value));                                    \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. */        \
        return true;                                                               \
    }

SET_NUMBER_LITERAL_IMPL(Int, int32_t)
SET_NUMBER_LITERAL_IMPL(Long, int64_t)
SET_NUMBER_LITERAL_IMPL(Double, double)
SET_NUMBER_LITERAL_IMPL(Float, float)

#undef SET_NUMBER_LITERAL_IMPL

template <typename T>
es2panda_AstNode *CreateNumberLiteral(es2panda_Context *ctx, T value)
{
    auto number = ark::es2panda::lexer::Number(value);
    auto allocator = reinterpret_cast<Context *>(ctx)->allocator;
    auto node = allocator->New<ir::NumberLiteral>(number);
    return reinterpret_cast<es2panda_AstNode *>(node);
}

template <typename T>
es2panda_AstNode *UpdateNumberLiteral(es2panda_Context *ctx, es2panda_AstNode *original, T value)
{
    auto number = ark::es2panda::lexer::Number(value);
    auto allocator = reinterpret_cast<Context *>(ctx)->allocator;
    auto node = allocator->New<ir::NumberLiteral>(number);
    auto *e2pOriginal = reinterpret_cast<ir::AstNode *>(original);
    node->SetOriginalNode(e2pOriginal);
    node->SetParent(e2pOriginal->Parent());
    node->SetRange(e2pOriginal->Range());
    return reinterpret_cast<es2panda_AstNode *>(node);
}

extern "C" void *AllocMemory(es2panda_Context *context, size_t numberOfElements, size_t sizeOfElement)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    void *ptr = allocator->Alloc(numberOfElements * sizeOfElement);
    return ptr;
}

extern "C" es2panda_SourcePosition *CreateSourcePosition(es2panda_Context *context, size_t index, size_t line)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    return reinterpret_cast<es2panda_SourcePosition *>(
        allocator->New<lexer::SourcePosition>(index, line, reinterpret_cast<Context *>(context)->parserProgram));
}

extern "C" es2panda_SourceRange *CreateSourceRange(es2panda_Context *context, es2panda_SourcePosition *start,
                                                   es2panda_SourcePosition *end)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    auto startE2p = *(reinterpret_cast<lexer::SourcePosition *>(start));
    auto endE2p = *(reinterpret_cast<lexer::SourcePosition *>(end));
    return reinterpret_cast<es2panda_SourceRange *>(allocator->New<lexer::SourceRange>(startE2p, endE2p));
}

extern "C" const es2panda_DiagnosticKind *CreateDiagnosticKind(es2panda_Context *context, const char *dmessage)
{
    auto ctx = reinterpret_cast<Context *>(context);
    auto id = ctx->config->diagnosticKindStorage.size() + 1;
    ctx->config->diagnosticKindStorage.emplace_back(util::DiagnosticType::PLUGIN, id, dmessage);
    return reinterpret_cast<const es2panda_DiagnosticKind *>(&ctx->config->diagnosticKindStorage.back());
}

extern "C" void LogDiagnostic(es2panda_Context *context, const es2panda_DiagnosticKind *ekind, const char **args,
                              size_t argc, es2panda_SourcePosition *pos)
{
    auto ctx = reinterpret_cast<Context *>(context);
    auto kind = reinterpret_cast<const diagnostic::DiagnosticKind *>(ekind);
    util::DiagnosticMessageParams params;
    for (size_t i = 0; i < argc; ++i) {
        params.push_back(args[i]);
    }
    auto posE2p = reinterpret_cast<lexer::SourcePosition *>(pos);
    ctx->diagnosticEngine->LogDiagnostic(*kind, params, *posE2p);
}

const es2panda_DiagnosticStorage *GetDiagnostics(es2panda_Context *context, size_t etype)
{
    auto ctx = reinterpret_cast<Context *>(context);
    auto type = static_cast<util::DiagnosticType>(etype);
    return reinterpret_cast<const es2panda_DiagnosticStorage *>(&ctx->diagnosticEngine->GetDiagnosticStorage(type));
}

extern "C" const es2panda_DiagnosticStorage *GetSemanticErrors(es2panda_Context *context)
{
    return GetDiagnostics(context, util::DiagnosticType::SEMANTIC);
}

extern "C" const es2panda_DiagnosticStorage *GetSyntaxErrors(es2panda_Context *context)
{
    return GetDiagnostics(context, util::DiagnosticType::SYNTAX);
}

extern "C" const es2panda_DiagnosticStorage *GetPluginErrors(es2panda_Context *context)
{
    return GetDiagnostics(context, util::DiagnosticType::PLUGIN);
}

extern "C" const es2panda_DiagnosticStorage *GetWarnings(es2panda_Context *context)
{
    return GetDiagnostics(context, util::DiagnosticType::WARNING);
}

extern "C" size_t SourcePositionIndex([[maybe_unused]] es2panda_Context *context, es2panda_SourcePosition *position)
{
    return reinterpret_cast<lexer::SourcePosition *>(position)->index;
}

extern "C" size_t SourcePositionLine([[maybe_unused]] es2panda_Context *context, es2panda_SourcePosition *position)
{
    return reinterpret_cast<lexer::SourcePosition *>(position)->line;
}

extern "C" es2panda_SourcePosition *SourceRangeStart([[maybe_unused]] es2panda_Context *context,
                                                     es2panda_SourceRange *range)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    auto E2pRange = reinterpret_cast<lexer::SourceRange *>(range);
    return reinterpret_cast<es2panda_SourcePosition *>(allocator->New<lexer::SourcePosition>(E2pRange->start));
}

extern "C" es2panda_SourcePosition *SourceRangeEnd([[maybe_unused]] es2panda_Context *context,
                                                   es2panda_SourceRange *range)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    auto E2pRange = reinterpret_cast<lexer::SourceRange *>(range);
    return reinterpret_cast<es2panda_SourcePosition *>(allocator->New<lexer::SourcePosition>(E2pRange->end));
}

extern "C" es2panda_Scope *AstNodeFindNearestScope([[maybe_unused]] es2panda_Context *ctx, es2panda_AstNode *node)
{
    auto E2pNode = reinterpret_cast<ir::AstNode *>(node);
    return reinterpret_cast<es2panda_Scope *>(compiler::NearestScope(E2pNode));
}

extern "C" es2panda_Scope *AstNodeRebind(es2panda_Context *ctx, es2panda_AstNode *node)
{
    auto E2pNode = reinterpret_cast<ir::AstNode *>(node);
    auto context = reinterpret_cast<Context *>(ctx);
    auto varbinder = context->parserProgram->VarBinder()->AsETSBinder();
    auto phaseManager = context->phaseManager;
    if (E2pNode->IsScriptFunction() ||
        E2pNode->FindChild([](ir::AstNode *n) { return n->IsScriptFunction(); }) != nullptr) {
        while (!E2pNode->IsProgram()) {
            E2pNode = E2pNode->Parent();
        }
    }
    return reinterpret_cast<es2panda_Scope *>(compiler::Rebind(phaseManager, varbinder, E2pNode));
}

extern "C" void AstNodeRecheck(es2panda_Context *ctx, es2panda_AstNode *node)
{
    auto E2pNode = reinterpret_cast<ir::AstNode *>(node);
    auto context = reinterpret_cast<Context *>(ctx);
    auto varbinder = context->parserProgram->VarBinder()->AsETSBinder();
    auto checker = context->checker->AsETSChecker();
    auto phaseManager = context->phaseManager;
    if (E2pNode->IsScriptFunction() ||
        E2pNode->FindChild([](ir::AstNode *n) { return n->IsScriptFunction(); }) != nullptr) {
        while (!E2pNode->IsProgram()) {
            E2pNode = E2pNode->Parent();
        }
    }
    compiler::Recheck(phaseManager, varbinder, checker, E2pNode);
    context->state = !context->diagnosticEngine->IsAnyError() ? ES2PANDA_STATE_CHECKED : ES2PANDA_STATE_ERROR;
    return;
}

#include "generated/es2panda_lib/es2panda_lib_impl.inc"

extern "C" Es2pandaEnum Es2pandaEnumFromString([[maybe_unused]] es2panda_Context *ctx, const char *str)
{
    return IrToE2pEnum(es2panda::util::gen::ast_verifier::FromString(str));
}

extern "C" char *Es2pandaEnumToString(es2panda_Context *ctx, Es2pandaEnum id)
{
    auto *allocator = reinterpret_cast<Context *>(ctx)->allocator;
    return StringViewToCString(allocator, es2panda::util::gen::ast_verifier::ToString(E2pToIrEnum(id)));
}

extern "C" es2panda_AstNode *DeclarationFromIdentifier([[maybe_unused]] es2panda_Context *ctx, es2panda_AstNode *node)
{
    auto E2pNode = reinterpret_cast<ir::Identifier *>(node);
    return reinterpret_cast<es2panda_AstNode *>(compiler::DeclarationFromIdentifier(E2pNode));
}

extern "C" __attribute__((unused)) int GenerateTsDeclarationsFromContext(es2panda_Context *ctx,
                                                                         const char *outputDeclEts,
                                                                         const char *outputEts, bool exportAll)
{
    auto *ctxImpl = reinterpret_cast<Context *>(ctx);
    auto *checker = reinterpret_cast<ark::es2panda::checker::ETSChecker *>(ctxImpl->checker);

    ark::es2panda::declgen_ets2ts::DeclgenOptions declgenOptions;
    declgenOptions.exportAll = exportAll;
    declgenOptions.outputDeclEts = outputDeclEts ? outputDeclEts : "";
    declgenOptions.outputEts = outputEts ? outputEts : "";

    return ark::es2panda::declgen_ets2ts::GenerateTsDeclarations(checker, ctxImpl->parserProgram, declgenOptions) ? 0
                                                                                                                  : 1;
}

extern "C" void InsertETSImportDeclarationAndParse(es2panda_Context *context, es2panda_Program *program,
                                                   es2panda_AstNode *importDeclaration)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *parserProgram = reinterpret_cast<parser::Program *>(program);
    auto *importDeclE2p = reinterpret_cast<ir::ETSImportDeclaration *>(importDeclaration);

    parserProgram->Ast()->Statements().insert(parserProgram->Ast()->Statements().begin(), importDeclE2p);
    importDeclE2p->SetParent(parserProgram->Ast());

    ctx->parser->AsETSParser()->AddExternalSource(ctx->parser->AsETSParser()->ParseSources());

    for ([[maybe_unused]] auto *specific : importDeclE2p->Specifiers()) {
        ES2PANDA_ASSERT(specific->Parent() != nullptr);
    }
}

es2panda_Impl g_impl = {
    ES2PANDA_LIB_VERSION,

    CreateConfig,
    DestroyConfig,
    ConfigGetOptions,
    CreateContextFromFile,
    CreateContextFromString,
    ProceedToState,
    DestroyContext,
    ContextState,
    ContextErrorMessage,
    ContextProgram,
    ExternalSourceName,
    ExternalSourcePrograms,
    AstNodeForEach,
    NumberLiteralSetInt,
    NumberLiteralSetLong,
    NumberLiteralSetDouble,
    NumberLiteralSetFloat,
    CreateNumberLiteral<int32_t>,
    UpdateNumberLiteral<int32_t>,
    CreateNumberLiteral<int64_t>,
    UpdateNumberLiteral<int64_t>,
    CreateNumberLiteral<double>,
    UpdateNumberLiteral<double>,
    CreateNumberLiteral<float>,
    UpdateNumberLiteral<float>,
    AllocMemory,
    CreateSourcePosition,
    CreateSourceRange,
    SourcePositionIndex,
    SourcePositionLine,
    SourceRangeStart,
    SourceRangeEnd,
    CreateDiagnosticKind,
    LogDiagnostic,
    GetSemanticErrors,
    GetSyntaxErrors,
    GetPluginErrors,
    GetWarnings,
    AstNodeFindNearestScope,
    AstNodeRebind,
    AstNodeRecheck,
    Es2pandaEnumFromString,
    Es2pandaEnumToString,
    DeclarationFromIdentifier,
    GenerateTsDeclarationsFromContext,
    InsertETSImportDeclarationAndParse,

#include "generated/es2panda_lib/es2panda_lib_list.inc"

};

}  // namespace ark::es2panda::public_lib

extern "C" es2panda_Impl const *es2panda_GetImpl(int version)
{
    if (version != ES2PANDA_LIB_VERSION) {
        return nullptr;
    }
    return &ark::es2panda::public_lib::g_impl;
}

// NOLINTEND
