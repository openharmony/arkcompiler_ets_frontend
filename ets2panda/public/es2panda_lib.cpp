/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cstring>
#include <cstdint>
#include <variant>

#include "varbinder/varbinder.h"
#include "varbinder/scope.h"
#include "varbinder/variable.h"
#include "public/public.h"
#include "generated/signatures.h"
#include "es2panda.h"
#include "assembler/assembly-program.h"
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
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/core/labelPair.h"
#include "ir/astNode.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/chainExpression.h"
#include "ir/statements/classDeclaration.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classElement.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/base/classProperty.h"
#include "ir/base/scriptFunctionSignature.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/expressions/functionExpression.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/ifStatement.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/importExpression.h"
#include "ir/module/importSpecifier.h"
#include "ir/base/methodDefinition.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsNewArrayInstanceExpression.h"
#include "ir/ets/etsNewMultiDimArrayInstanceExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "parser/ETSparser.h"
#include "parser/context/parserContext.h"
#include "parser/program/program.h"
#include "util/generateBin.h"
#include "util/language.h"
#include "util/options.h"
#include "generated/es2panda_lib/es2panda_lib_include.inc"

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
    UNREACHABLE();
}

__attribute__((unused)) char const *TokenToStr(TokenTypeToStr const *table, lexer::TokenType token)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (auto *tp = table; tp->str != nullptr; tp++) {
        if (tp->token == token) {
            return tp->str;
        }
    }
    UNREACHABLE();
}

__attribute__((unused)) char *StringViewToCString(ArenaAllocator *allocator, util::StringView const sv)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    std::string_view utf8 = sv.Utf8();
    if (utf8.data()[utf8.size()] == '\0') {
        // Avoid superfluous allocation.
        return const_cast<char *>(utf8.data());
    }
    char *res = reinterpret_cast<char *>(allocator->Alloc(utf8.size() + 1));
    [[maybe_unused]] auto err = memmove_s(res, utf8.size() + 1, utf8.cbegin(), utf8.size());
    ASSERT(err == EOK);
    res[utf8.size()] = '\0';
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

char *StringViewToCString(ArenaAllocator *allocator, std::string_view const utf8)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    if (utf8.data()[utf8.size()] == '\0') {
        // Avoid superfluous allocation.
        return const_cast<char *>(utf8.data());
    }
    char *res = reinterpret_cast<char *>(allocator->Alloc(utf8.size() + 1));
    [[maybe_unused]] auto err = memmove_s(res, utf8.size() + 1, utf8.cbegin(), utf8.size());
    ASSERT(err == EOK);
    res[utf8.size()] = '\0';
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

__attribute__((unused)) char *StdStringToCString(ArenaAllocator *allocator, std::string str)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    char *res = reinterpret_cast<char *>(allocator->Alloc(str.length() + 1));
    [[maybe_unused]] auto err = memcpy_s(res, str.length() + 1, str.c_str(), str.length() + 1);
    ASSERT(err == EOK);
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
        case es2panda_variantIndex::DOUBLE:
            es2panda_variant.variant.d = std::get<double>(variant);
            break;
        case es2panda_variantIndex::CHAR:
            es2panda_variant.variant.c = StringViewToCString(allocator, std::get<util::StringView>(variant));
            break;
        case es2panda_variantIndex::BOOL:
            es2panda_variant.variant.b = std::get<bool>(variant);
            break;
        default:
            break;
    }
    return es2panda_variant;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    // NOLINTEND(cppcoreguidelines-pro-type-union-access)
}

__attribute__((unused)) es2panda_DynamicImportData *DynamicImportDataToE2p(
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

__attribute__((unused)) char const *ArenaStrdup(ArenaAllocator *allocator, char const *src)
{
    size_t len = strlen(src);
    char *res = reinterpret_cast<char *>(allocator->Alloc(len + 1));
    [[maybe_unused]] auto err = memmove_s(res, len + 1, src, len);
    ASSERT(err == EOK);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res[len] = '\0';
    return res;
}

extern "C" es2panda_Config *CreateConfig(int args, char const **argv)
{
    constexpr auto COMPILER_SIZE = 256_MB;

    mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
    PoolManager::Initialize(PoolType::MMAP);

    auto *options = new util::Options();
    if (!options->Parse(args, argv)) {
        // NOTE: gogabr. report option errors properly.
        std::cerr << options->ErrorMsg() << std::endl;
        return nullptr;
    }
    Logger::ComponentMask mask {};
    mask.set(Logger::Component::ES2PANDA);
    Logger::InitializeStdLogging(Logger::LevelFromString(options->LogLevel()), mask);

    auto *res = new ConfigImpl;
    res->options = options;
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
    delete cfg;
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

__attribute__((unused)) static es2panda_Context *CreateContext(es2panda_Config *config, std::string const &&source,
                                                               std::string const &&fileName)
{
    auto *cfg = reinterpret_cast<ConfigImpl *>(config);
    auto *res = new Context;
    res->input = source;
    res->sourceFileName = fileName;
    res->config = cfg;

    try {
        res->sourceFile = new SourceFile(res->sourceFileName, res->input, cfg->options->ParseModule());
        res->allocator = new ArenaAllocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
        res->queue = new compiler::CompileQueue(cfg->options->ThreadCount());

        auto *varbinder = res->allocator->New<varbinder::ETSBinder>(res->allocator);
        res->parserProgram = new parser::Program(res->allocator, varbinder);
        res->parserProgram->MarkEntry();
        res->parser =
            new parser::ETSParser(res->parserProgram, cfg->options->CompilerOptions(), parser::ParserStatus::NO_OPTS);
        res->checker = new checker::ETSChecker();
        res->checker->ErrorLogger()->SetOstream(nullptr);
        res->analyzer = new checker::ETSAnalyzer(res->checker);
        res->checker->SetAnalyzer(res->analyzer);

        varbinder->SetProgram(res->parserProgram);

        varbinder->SetContext(res);
        res->codeGenCb = CompileJob;
        res->phases = compiler::GetPhaseList(ScriptExtension::ETS);
        res->currentPhase = 0;
        res->emitter = new compiler::ETSEmitter(res);
        res->program = nullptr;
        res->state = ES2PANDA_STATE_NEW;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        res->errorMessage = ss.str();
        res->state = ES2PANDA_STATE_ERROR;
    }
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
                                                                             char const *source, char const *fileName)
{
    // NOTE: gogabr. avoid copying source.
    return CreateContext(config, source, fileName);
}

__attribute__((unused)) static Context *Parse(Context *ctx)
{
    if (ctx->state != ES2PANDA_STATE_NEW) {
        ctx->state = ES2PANDA_STATE_ERROR;
        ctx->errorMessage = "Bad state at entry to Parse, needed NEW";
        return ctx;
    }
    auto handleError = [ctx](Error const &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    };

    try {
        ctx->parser->ParseScript(*ctx->sourceFile, ctx->config->options->CompilerOptions().compilationMode ==
                                                       CompilationMode::GEN_STD_LIB);
        ctx->state = ES2PANDA_STATE_PARSED;
        if (ctx->parser->ErrorLogger()->IsAnyError()) {
            handleError(ctx->parser->ErrorLogger()->Log()[0]);
        }
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }

    return ctx;
}

__attribute__((unused)) static Context *InitScopes(Context *ctx)
{
    // NOTE: Remove duplicated code in all phases
    if (ctx->state < ES2PANDA_STATE_PARSED) {
        ctx = Parse(ctx);
    }
    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_PARSED);

    try {
        compiler::InitScopesPhaseETS scopesInit;
        scopesInit.Perform(ctx, ctx->parserProgram);
        do {
            if (ctx->currentPhase >= ctx->phases.size()) {
                break;
            }
            ctx->phases[ctx->currentPhase]->Apply(ctx, ctx->parserProgram);
        } while (ctx->phases[ctx->currentPhase++]->Name() != compiler::ScopesInitPhase::NAME);
        ctx->state = ES2PANDA_STATE_SCOPE_INITED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
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

    ASSERT(ctx->state >= ES2PANDA_STATE_PARSED && ctx->state < ES2PANDA_STATE_CHECKED);

    auto handleError = [ctx](Error const &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    };

    try {
        do {
            if (ctx->currentPhase >= ctx->phases.size()) {
                break;
            }

            ctx->phases[ctx->currentPhase]->Apply(ctx, ctx->parserProgram);
        } while (ctx->phases[ctx->currentPhase++]->Name() != compiler::CheckerPhase::NAME);
        if (ctx->checker->ErrorLogger()->IsAnyError()) {
            handleError(ctx->checker->ErrorLogger()->Log()[0]);
        } else if (ctx->parser->ErrorLogger()->IsAnyError()) {
            handleError(ctx->parser->ErrorLogger()->Log()[0]);
        } else {
            ctx->state = ES2PANDA_STATE_CHECKED;
        }
    } catch (Error &e) {
        handleError(e);
    }
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

    ASSERT(ctx->state == ES2PANDA_STATE_CHECKED);

    try {
        while (ctx->currentPhase < ctx->phases.size()) {
            ctx->phases[ctx->currentPhase++]->Apply(ctx, ctx->parserProgram);
        }

        ctx->state = ES2PANDA_STATE_LOWERED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }

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

    ASSERT(ctx->state == ES2PANDA_STATE_LOWERED);

    auto *emitter = ctx->emitter;
    try {
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
        ctx->queue->Wait(
            [emitter](compiler::CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });
        ASSERT(ctx->program == nullptr);
        ctx->program =
            emitter->Finalize(ctx->config->options->CompilerOptions().dumpDebugInfo, compiler::Signatures::ETS_GLOBAL);

        ctx->state = ES2PANDA_STATE_ASM_GENERATED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
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

    ASSERT(ctx->state == ES2PANDA_STATE_ASM_GENERATED);

    try {
        ASSERT(ctx->program != nullptr);
        util::GenerateProgram(ctx->program, ctx->config->options,
                              [ctx](const std::string &str) { ctx->errorMessage = str; });

        ctx->state = ES2PANDA_STATE_BIN_GENERATED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }
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
        case ES2PANDA_STATE_SCOPE_INITED:
            ctx = InitScopes(ctx);
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

extern "C" __attribute__((unused)) es2panda_AstNode *ProgramAst(es2panda_Program *program)
{
    auto *pgm = reinterpret_cast<parser::Program *>(program);
    return reinterpret_cast<es2panda_AstNode *>(pgm->Ast());
}

using ExternalSourceEntry = std::pair<char const *, ArenaVector<parser::Program *> *>;

extern "C" __attribute__((unused)) es2panda_ExternalSource **ProgramExternalSources(es2panda_Program *program,
                                                                                    size_t *lenP)
{
    auto *pgm = reinterpret_cast<parser::Program *>(program);
    auto *allocator = pgm->VarBinder()->Allocator();
    auto *vec = allocator->New<ArenaVector<ExternalSourceEntry *>>(allocator->Adapter());

    for (auto &[e_name, e_programs] : pgm->ExternalSources()) {
        vec->push_back(allocator->New<ExternalSourceEntry>(StringViewToCString(allocator, e_name), &e_programs));
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
    extern "C" bool SetNumberLiteral##name(es2panda_AstNode *node, type new_value) \
    {                                                                              \
        auto &n = reinterpret_cast<ir::NumberLiteral *>(node)->Number();           \
        if (!n.Is##name()) {                                                       \
            return false;                                                          \
        }                                                                          \
        n.SetValue<type>(std::move(new_value));                                    \
        return true;                                                               \
    }

SET_NUMBER_LITERAL_IMPL(Int, int32_t)
SET_NUMBER_LITERAL_IMPL(Long, int64_t)
SET_NUMBER_LITERAL_IMPL(Double, double)
SET_NUMBER_LITERAL_IMPL(Float, float)

#undef SET_NUMBER_LITERAL_IMPL

void *AllocMemory(es2panda_Context *context, size_t numberOfElements, size_t sizeOfElement)
{
    auto *allocator = reinterpret_cast<Context *>(context)->allocator;
    void *ptr = allocator->Alloc(numberOfElements * sizeOfElement);
    return ptr;
}

#include "generated/es2panda_lib/es2panda_lib_impl.inc"

es2panda_Impl g_impl = {
    ES2PANDA_LIB_VERSION,

    CreateConfig,
    DestroyConfig,
    CreateContextFromFile,
    CreateContextFromString,
    ProceedToState,
    DestroyContext,
    ContextState,
    ContextErrorMessage,
    ContextProgram,
    ProgramAst,
    ProgramExternalSources,
    ExternalSourceName,
    ExternalSourcePrograms,
    AstNodeForEach,
    SetNumberLiteralInt,
    SetNumberLiteralLong,
    SetNumberLiteralDouble,
    SetNumberLiteralFloat,
    AllocMemory,

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
