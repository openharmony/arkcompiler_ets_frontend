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

#include "es2panda_lib.h"
#include <memory>

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
#include "compiler/lowering/util.h"
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

namespace panda::es2panda::public_lib {

struct TokenTypeToStr {
    lexer::TokenType token;
    char const *str;
};

static lexer::TokenType StrToToken(TokenTypeToStr const *table, char const *str)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (auto *tp = table; tp->str != nullptr; tp++) {
        if (strcmp(str, tp->str) == 0) {
            return tp->token;
        }
    }
    UNREACHABLE();
}

static char const *TokenToStr(TokenTypeToStr const *table, lexer::TokenType token)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (auto *tp = table; tp->str != nullptr; tp++) {
        if (tp->token == token) {
            return tp->str;
        }
    }
    UNREACHABLE();
}

static char const *StringViewToCString(ArenaAllocator *allocator, util::StringView const sv)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    std::string_view utf8 = sv.Utf8();
    if (utf8.data()[utf8.size()] == '\0') {
        // Avoid superfluous allocation.
        return utf8.data();
    }
    char *res = reinterpret_cast<char *>(allocator->Alloc(utf8.size() + 1));
    memmove(res, utf8.cbegin(), utf8.size());
    res[utf8.size()] = '\0';
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

static char const *ArenaStrdup(ArenaAllocator *allocator, char const *src)
{
    size_t len = strlen(src);
    char *res = reinterpret_cast<char *>(allocator->Alloc(len + 1));
    memmove(res, src, len);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res[len] = '\0';
    return res;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FOR_ALL_MODIFIER_FLAGS(_) \
    _(STATIC)                     \
    _(ASYNC)                      \
    _(PUBLIC)                     \
    _(PROTECTED)                  \
    _(PRIVATE)                    \
    _(DECLARE)                    \
    _(READONLY)                   \
    _(OPTIONAL)                   \
    _(DEFINITE)                   \
    _(ABSTRACT)                   \
    _(CONST)                      \
    _(FINAL)                      \
    _(NATIVE)                     \
    _(OVERRIDE)                   \
    _(CONSTRUCTOR)                \
    _(SYNCHRONIZED)               \
    _(FUNCTIONAL)                 \
    _(IN)                         \
    _(OUT)                        \
    _(INTERNAL)                   \
    _(NULL_ASSIGNABLE)            \
    _(UNDEFINED_ASSIGNABLE)       \
    _(EXPORT)                     \
    _(SETTER)                     \
    _(DEFAULT_EXPORT)

static ir::ModifierFlags E2pToIrModifierFlags(es2panda_ModifierFlags e2p_flags)
{
    ir::ModifierFlags ir_flags {ir::ModifierFlags::NONE};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_FLAG(FL)                                  \
    if ((e2p_flags & ES2PANDA_MODIFIER_##FL) != 0) { \
        ir_flags |= ir::ModifierFlags::FL;           \
    }

    FOR_ALL_MODIFIER_FLAGS(DO_FLAG)

#undef DO_FLAG

    return ir_flags;
}

static es2panda_ModifierFlags IrToE2pModifierFlags(ir::ModifierFlags ir_flags)
{
    es2panda_ModifierFlags e2p_flags {ES2PANDA_MODIFIER_NONE};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_FLAG(FL)                                                                          \
    if ((ir_flags & ir::ModifierFlags::FL) != 0) {                                           \
        e2p_flags = static_cast<es2panda_ModifierFlags>(e2p_flags | ES2PANDA_MODIFIER_##FL); \
    }

    FOR_ALL_MODIFIER_FLAGS(DO_FLAG)

#undef DO_FLAG

    return e2p_flags;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FOR_ALL_SCRIPT_FUNCTION_FLAGS(_) \
    _(GENERATOR)                         \
    _(ASYNC)                             \
    _(ARROW)                             \
    _(EXPRESSION)                        \
    _(OVERLOAD)                          \
    _(CONSTRUCTOR)                       \
    _(METHOD)                            \
    _(STATIC_BLOCK)                      \
    _(HIDDEN)                            \
    _(IMPLICIT_SUPER_CALL_NEEDED)        \
    _(ENUM)                              \
    _(EXTERNAL)                          \
    _(PROXY)                             \
    _(THROWS)                            \
    _(RETHROWS)                          \
    _(GETTER)                            \
    _(SETTER)                            \
    _(DEFAULT_PARAM_PROXY)               \
    _(ENTRY_POINT)                       \
    _(INSTANCE_EXTENSION_METHOD)         \
    _(HAS_RETURN)

static ir::ScriptFunctionFlags E2pToIrScriptFunctionFlags(es2panda_ScriptFunctionFlags e2p_flags)
{
    ir::ScriptFunctionFlags ir_flags {ir::ScriptFunctionFlags::NONE};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_FLAG(FL)                                         \
    if ((e2p_flags & ES2PANDA_SCRIPT_FUNCTION_##FL) != 0) { \
        ir_flags |= ir::ScriptFunctionFlags::FL;            \
    }

    FOR_ALL_SCRIPT_FUNCTION_FLAGS(DO_FLAG)

#undef DO_FLAG

    return ir_flags;
}

static es2panda_ScriptFunctionFlags IrToE2pScriptFunctionFlags(ir::ScriptFunctionFlags ir_flags)
{
    es2panda_ScriptFunctionFlags e2p_flags {ES2PANDA_SCRIPT_FUNCTION_NONE};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_FLAG(FL)                                                                                       \
    if ((ir_flags & ir::ScriptFunctionFlags::FL) != 0) {                                                  \
        e2p_flags = static_cast<es2panda_ScriptFunctionFlags>(e2p_flags | ES2PANDA_SCRIPT_FUNCTION_##FL); \
    }

    FOR_ALL_SCRIPT_FUNCTION_FLAGS(DO_FLAG)

#undef DO_FLAG

    return e2p_flags;
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

    delete cfg->options;
    delete cfg;
}

static void CompileJob(compiler::CompilerContext *context, varbinder::FunctionScope *scope,
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
    res->input = source;
    res->source_file_name = file_name;

    try {
        res->source_file = new SourceFile(res->source_file_name, res->input, cfg->options->ParseModule());
        res->allocator = new ArenaAllocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
        res->queue = new compiler::CompileQueue(cfg->options->ThreadCount());

        auto *varbinder = res->allocator->New<varbinder::ETSBinder>(res->allocator);
        res->parser_program = new parser::Program(res->allocator, varbinder);
        res->parser_program->MarkEntry();
        res->parser =
            new parser::ETSParser(res->parser_program, cfg->options->CompilerOptions(), parser::ParserStatus::NO_OPTS);
        res->checker = new checker::ETSChecker();
        res->analyzer = new checker::ETSAnalyzer(res->checker);
        res->checker->SetAnalyzer(res->analyzer);

        varbinder->SetProgram(res->parser_program);

        res->compiler_context =
            new compiler::CompilerContext(varbinder, res->checker, cfg->options->CompilerOptions(), CompileJob);
        varbinder->SetCompilerContext(res->compiler_context);
        res->phases = compiler::GetETSPhaseList();
        res->current_phase = 0;
        res->emitter = new compiler::ETSEmitter(res->compiler_context);
        res->compiler_context->SetEmitter(res->emitter);
        res->compiler_context->SetParser(res->parser);
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
        return reinterpret_cast<es2panda_Context *>(res);
    }
    std::stringstream ss;
    ss << input_stream.rdbuf();
    if (input_stream.fail()) {
        auto *res = new Context;
        res->error_message = "Failed to read file: ";
        res->error_message.append(source_file_name);
        return reinterpret_cast<es2panda_Context *>(res);
    }
    return CreateContext(config, ss.str(), source_file_name);
}

extern "C" es2panda_Context *CreateContextFromString(es2panda_Config *config, char const *source, char const *file_name)
{
    // NOTE: gogabr. avoid copying source.
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
        ctx->parser->ParseScript(*ctx->source_file,
                                 ctx->compiler_context->Options()->compilation_mode == CompilationMode::GEN_STD_LIB);
        ctx->parser_program = ctx->compiler_context->VarBinder()->Program();
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
        do {
            if (ctx->current_phase >= ctx->phases.size()) {
                break;
            }

            ctx->phases[ctx->current_phase]->Apply(ctx, ctx->parser_program);
        } while (ctx->phases[ctx->current_phase++]->Name() != "checker");
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
        while (ctx->current_phase < ctx->phases.size()) {
            ctx->phases[ctx->current_phase++]->Apply(ctx, ctx->parser_program);
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
        ctx->queue->Schedule(ctx->compiler_context);
        ctx->queue->Consume();
        ctx->queue->Wait(
            [emitter](compiler::CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });
        ASSERT(ctx->program == nullptr);
        ctx->program = emitter->Finalize(ctx->compiler_context->DumpDebugInfo(), compiler::Signatures::ETS_GLOBAL);

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
        util::GenerateProgram(ctx->program, ctx->config->options,
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
    auto *ctx = reinterpret_cast<Context *>(context);
    delete ctx->program;
    delete ctx->emitter;
    delete ctx->compiler_context;
    delete ctx->analyzer;
    delete ctx->checker;
    delete ctx->parser;
    delete ctx->parser_program;
    delete ctx->queue;
    delete ctx->allocator;
    delete ctx->source_file;
    delete ctx;
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

extern "C" es2panda_Program *ContextProgram(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    return reinterpret_cast<es2panda_Program *>(ctx->compiler_context->VarBinder()->Program());
}

extern "C" es2panda_AstNode *ProgramAst(es2panda_Program *program)
{
    auto *pgm = reinterpret_cast<parser::Program *>(program);
    return reinterpret_cast<es2panda_AstNode *>(pgm->Ast());
}

using ExternalSourceEntry = std::pair<char const *, ArenaVector<parser::Program *> *>;

extern "C" es2panda_ExternalSource **ProgramExternalSources(es2panda_Program *program, size_t *len_p)
{
    auto *pgm = reinterpret_cast<parser::Program *>(program);
    auto *allocator = pgm->VarBinder()->Allocator();
    auto *vec = allocator->New<ArenaVector<ExternalSourceEntry *>>(allocator->Adapter());

    for (auto &[e_name, e_programs] : pgm->ExternalSources()) {
        vec->push_back(allocator->New<ExternalSourceEntry>(StringViewToCString(allocator, e_name), &e_programs));
    }

    *len_p = vec->size();
    return reinterpret_cast<es2panda_ExternalSource **>(vec->data());
}

extern "C" char const *ExternalSourceName(es2panda_ExternalSource *e_source)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(e_source);
    return entry->first;
}

extern "C" es2panda_Program **ExternalSourcePrograms(es2panda_ExternalSource *e_source, size_t *len_p)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(e_source);
    *len_p = entry->second->size();
    return reinterpret_cast<es2panda_Program **>(entry->second->data());
}

extern "C" es2panda_Type *AstNodeType(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    // Need to work with other TypeAstNodes
    if (node->IsExpression()) {
        return reinterpret_cast<es2panda_Type *>(node->AsExpression()->TsType());
    }
    return nullptr;
}

extern "C" es2panda_AstNode *const *AstNodeDecorators(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    if (node->CanHaveDecorator(false)) {
        auto *decorators = node->DecoratorsPtr();
        *size_p = decorators->size();
        return reinterpret_cast<es2panda_AstNode *const *>(decorators->data());
    }
    *size_p = 0;
    return nullptr;
}

extern "C" es2panda_ModifierFlags AstNodeModifierFlags(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    return IrToE2pModifierFlags(node->Modifiers());
}

extern "C" void AstNodeSetDecorators(es2panda_Context *context, es2panda_AstNode *ast, es2panda_AstNode **decorators,
                                     size_t n_decorators)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *node = reinterpret_cast<ir::AstNode *>(ast);

    ArenaVector<ir::Decorator *> decorators_vector {allocator->Adapter()};
    for (size_t i = 0; i < n_decorators; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        decorators_vector.push_back(reinterpret_cast<ir::AstNode *>(decorators[i])->AsDecorator());
    }
    node->AddDecorators(std::move(decorators_vector));
}

extern "C" void AstNodeSetType(es2panda_AstNode *ast, es2panda_Type *type)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    auto *tp = reinterpret_cast<checker::Type *>(type);
    // Need to work with other TypedAstNodes
    if (node->IsExpression()) {
        node->AsExpression()->SetTsType(tp);
    } else {
        UNREACHABLE();
    }
}

extern "C" void AstNodeForEach(es2panda_AstNode *ast, void (*func)(es2panda_AstNode *, void *), void *arg)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    func(ast, arg);
    node->IterateRecursively([=](ir::AstNode *child) { func(reinterpret_cast<es2panda_AstNode *>(child), arg); });
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define IS(public_name, e2p_name)                          \
    extern "C" bool Is##public_name(es2panda_AstNode *ast) \
    {                                                      \
        auto *node = reinterpret_cast<ir::AstNode *>(ast); \
        return node->Is##e2p_name();                       \
    }

IS(ArrowFunctionExpression, ArrowFunctionExpression)
IS(AsExpression, TSAsExpression)
IS(AssignmentExpression, AssignmentExpression)
IS(BinaryExpression, BinaryExpression)
IS(BlockStatement, BlockStatement)
IS(CallExpression, CallExpression)
IS(ChainExpression, ChainExpression)
IS(ClassDeclaration, ClassDeclaration)
IS(ClassDefinition, ClassDefinition)
IS(ClassImplementsClause, TSClassImplements)
IS(ClassProperty, ClassProperty)
IS(ExpressionStatement, ExpressionStatement)
IS(FunctionDeclaration, FunctionDeclaration)
IS(FunctionExpression, FunctionExpression)
IS(FunctionTypeNode, TSFunctionType)
IS(Identifier, Identifier)
IS(IfStatement, IfStatement)
IS(ImportDeclaration, ImportDeclaration)
IS(ImportExpression, ImportExpression)
IS(ImportSpecifier, ImportSpecifier)
IS(MemberExpression, MemberExpression)
IS(MethodDefinition, MethodDefinition)
IS(NewClassInstanceExpression, ETSNewClassInstanceExpression)
IS(NewArrayInstanceExpression, ETSNewArrayInstanceExpression)
IS(NewMultiDimArrayInstanceExpression, ETSNewMultiDimArrayInstanceExpression)
IS(NonNullExpression, TSNonNullExpression)
IS(NumberLiteral, NumberLiteral)
IS(ObjectExpression, ObjectExpression)
IS(ParameterDeclaration, ETSParameterExpression)
IS(PrimitiveTypeNode, ETSPrimitiveType)
IS(ReturnStatement, ReturnStatement)
IS(ScriptFunction, ScriptFunction)
IS(StringLiteral, StringLiteral)
IS(ThisExpression, ThisExpression)
IS(TypeParameter, TSTypeParameter)
IS(TypeParameterDeclaration, TSTypeParameterDeclaration)
IS(TypeParameterInstantiation, TSTypeParameterInstantiation)
IS(TypeReferenceNode, ETSTypeReference)
IS(TypeReferencePart, ETSTypeReferencePart)
IS(UnionTypeNode, TSUnionType)
IS(VariableDeclaration, VariableDeclaration)
IS(VariableDeclarator, VariableDeclarator)

#undef IS

extern "C" es2panda_AstNode *CreateArrowFunctionExpression(es2panda_Context *context, es2panda_AstNode *script_function)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *func = reinterpret_cast<ir::AstNode *>(script_function)->AsScriptFunction();
    auto *allocator = ctx->allocator;

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ArrowFunctionExpression>(allocator, func));
}

extern "C" es2panda_AstNode *ArrowFunctionExpressionScriptFunction(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsArrowFunctionExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Function());
}

extern "C" es2panda_AstNode *CreateAsExpression(es2panda_Context *context, es2panda_AstNode *expr,
                                                es2panda_AstNode *type_annotation, bool is_const)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *left_expr = reinterpret_cast<ir::AstNode *>(expr)->AsExpression();
    auto *tp = reinterpret_cast<ir::AstNode *>(type_annotation)->AsExpression()->AsTypeNode();
    auto *allocator = ctx->allocator;

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSAsExpression>(left_expr, tp, is_const));
}

extern "C" es2panda_AstNode *AsExpressionExpr(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Expr());
}

extern "C" es2panda_AstNode *AsExpressionTypeAnnotation(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Type());
}

extern "C" bool AsExpressionIsConst(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    return node->IsConst();
}

extern "C" void AsExpressionSetExpr(es2panda_AstNode *ast, es2panda_AstNode *expr)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    auto *new_expr = reinterpret_cast<ir::AstNode *>(expr)->AsExpression();
    node->SetExpr(new_expr);
}

extern "C" void AsExpressionSetTypeAnnotation(es2panda_AstNode *ast, es2panda_AstNode *type_annotation)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    auto *tp = reinterpret_cast<ir::AstNode *>(type_annotation)->AsExpression()->AsTypeNode();
    node->SetTsTypeAnnotation(tp);
}

static constexpr std::array<TokenTypeToStr, 18U> ASSIGNMENT_TOKEN_TYPES {
    {{lexer::TokenType::PUNCTUATOR_SUBSTITUTION, "="},
     {lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL, ">>>="},
     {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL, ">>="},
     {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL, "<<="},
     {lexer::TokenType::PUNCTUATOR_PLUS_EQUAL, "+="},
     {lexer::TokenType::PUNCTUATOR_MINUS_EQUAL, "-="},
     {lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL, "*="},
     {lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL, "/="},
     {lexer::TokenType::PUNCTUATOR_MOD_EQUAL, "%="},
     {lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL, "&="},
     {lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL, "|="},
     {lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL, "^="},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_AND_EQUAL, "&&="},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_OR_EQUAL, "||="},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL, "\?\?="},
     {lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL, "**="},
     {lexer::TokenType::EOS, nullptr}}};

extern "C" es2panda_AstNode *CreateAssignmentExpression(es2panda_Context *context, es2panda_AstNode *left,
                                                        es2panda_AstNode *right, char const *operator_type)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *left_node = reinterpret_cast<ir::AstNode *>(left)->AsExpression();
    auto *right_node = reinterpret_cast<ir::AstNode *>(right)->AsExpression();
    lexer::TokenType tok = StrToToken(ASSIGNMENT_TOKEN_TYPES.data(), operator_type);
    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::AssignmentExpression>(left_node, right_node, tok));
}

extern "C" es2panda_AstNode *AssignmentExpressionLeft(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsAssignmentExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Left());
}

extern "C" es2panda_AstNode *AssignmentExpressionRight(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsAssignmentExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Right());
}

extern "C" char const *AssignmentExpressionOperatorType(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsAssignmentExpression();
    return TokenToStr(ASSIGNMENT_TOKEN_TYPES.data(), node->OperatorType());
}

extern "C" void AssignmentExpressionSetOperatorType(es2panda_AstNode *ast, char const *operator_type)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsAssignmentExpression();
    auto tok = StrToToken(ASSIGNMENT_TOKEN_TYPES.data(), operator_type);
    node->SetOperatorType(tok);
}

static constexpr std::array<TokenTypeToStr, 26U> BINARY_OP_TOKEN_TYPES {
    {{lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT, ">>>"},
     {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT, ">>"},
     {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT, "<<"},
     {lexer::TokenType::PUNCTUATOR_PLUS, "+"},
     {lexer::TokenType::PUNCTUATOR_MINUS, "-"},
     {lexer::TokenType::PUNCTUATOR_MULTIPLY, "*"},
     {lexer::TokenType::PUNCTUATOR_DIVIDE, "/"},
     {lexer::TokenType::PUNCTUATOR_MOD, "%"},
     {lexer::TokenType::PUNCTUATOR_BITWISE_AND, "&"},
     {lexer::TokenType::PUNCTUATOR_BITWISE_OR, "|"},
     {lexer::TokenType::PUNCTUATOR_BITWISE_XOR, "^"},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_AND, "&&"},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_OR, "||"},
     {lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING, "??"},
     {lexer::TokenType::PUNCTUATOR_EXPONENTIATION, "**"},
     {lexer::TokenType::PUNCTUATOR_EQUAL, "=="},
     {lexer::TokenType::PUNCTUATOR_NOT_EQUAL, "/="},
     {lexer::TokenType::PUNCTUATOR_STRICT_EQUAL, "==="},
     {lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL, "/=="},
     {lexer::TokenType::PUNCTUATOR_LESS_THAN, "<"},
     {lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL, "<="},
     {lexer::TokenType::PUNCTUATOR_GREATER_THAN, ">"},
     {lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL, ">="},
     {lexer::TokenType::KEYW_IN, "in"},
     {lexer::TokenType::KEYW_INSTANCEOF, "instanceof"},
     {lexer::TokenType::EOS, nullptr}}};

extern "C" es2panda_AstNode *CreateBinaryExpression(es2panda_Context *context, es2panda_AstNode *left,
                                                    es2panda_AstNode *right, char const *operator_type)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *left_expr = reinterpret_cast<ir::AstNode *>(left)->AsExpression();
    auto *right_expr = reinterpret_cast<ir::AstNode *>(right)->AsExpression();
    auto tok = StrToToken(BINARY_OP_TOKEN_TYPES.data(), operator_type);

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::BinaryExpression>(left_expr, right_expr, tok));
}

extern "C" es2panda_AstNode *BinaryExpressionLeft(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBinaryExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Left());
}

extern "C" es2panda_AstNode *BinaryExpressionRight(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBinaryExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Right());
}

extern "C" char const *BinaryExpressionOperator(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBinaryExpression();
    return TokenToStr(BINARY_OP_TOKEN_TYPES.data(), node->OperatorType());
}

extern "C" void BinaryExpressionSetOperator(es2panda_AstNode *ast, char const *operator_type)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBinaryExpression();
    auto op = StrToToken(BINARY_OP_TOKEN_TYPES.data(), operator_type);
    node->SetOperator(op);
}

extern "C" es2panda_AstNode *CreateBlockStatement(es2panda_Context *context, es2panda_AstNode *in_scope_of)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *parent = reinterpret_cast<ir::AstNode *>(in_scope_of);
    auto *parent_scope = compiler::NearestScope(parent);

    auto *scope = allocator->New<varbinder::LocalScope>(allocator, parent_scope);
    ArenaVector<ir::Statement *> stmts {allocator->Adapter()};
    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::BlockStatement>(allocator, scope, std::move(stmts)));
}

extern "C" es2panda_AstNode **BlockStatementStatements(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBlockStatement();
    *size_p = node->Statements().size();
    return reinterpret_cast<es2panda_AstNode **>(node->Statements().data());
}

extern "C" void BlockStatementAddStatement(es2panda_AstNode *ast, es2panda_AstNode *statement)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBlockStatement();
    auto *stmt = reinterpret_cast<ir::AstNode *>(statement)->AsBlockStatement();
    node->Statements().push_back(stmt);
}

extern "C" es2panda_AstNode *CreateCallExpression(es2panda_Context *context, es2panda_AstNode *callee,
                                                  es2panda_AstNode *type_arguments, es2panda_AstNode **arguments,
                                                  size_t n_arguments, bool is_optional)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *callee_node = reinterpret_cast<ir::AstNode *>(callee)->AsExpression();

    ir::TSTypeParameterInstantiation *type_args = nullptr;
    if (type_arguments != nullptr) {
        type_args = reinterpret_cast<ir::AstNode *>(type_arguments)->AsTSTypeParameterInstantiation();
    }

    ArenaVector<ir::Expression *> args {allocator->Adapter()};
    for (size_t i = 0; i < n_arguments; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        args.push_back(reinterpret_cast<ir::AstNode *>(arguments[i])->AsExpression());
    }
    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::CallExpression>(callee_node, std::move(args), type_args, is_optional));
}

extern "C" es2panda_AstNode const *CallExpressionCallee(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    return reinterpret_cast<es2panda_AstNode const *>(node->Callee());
}

extern "C" es2panda_AstNode const *CallExpressionTypeArguments(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    return reinterpret_cast<es2panda_AstNode const *>(node->TypeParams());
}

extern "C" es2panda_AstNode **CallExpressionArguments(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    *size_p = node->Arguments().size();
    return reinterpret_cast<es2panda_AstNode **>(node->Arguments().data());
}

extern "C" bool CallExpressionIsOptional(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    return node->IsOptional();
}

extern "C" void CallExpressionSetTypeArguments(es2panda_AstNode *ast, es2panda_AstNode *type_arguments)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    auto *type_args = reinterpret_cast<ir::AstNode *>(type_arguments)->AsTSTypeParameterInstantiation();
    node->SetTypeParams(type_args);
}

extern "C" es2panda_AstNode *CreateChainExpression(es2panda_Context *context, es2panda_AstNode *child)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *child_expr = reinterpret_cast<ir::AstNode *>(child)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ChainExpression>(child_expr));
}

extern "C" es2panda_AstNode const *ChainExpressionChild(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsChainExpression();
    return reinterpret_cast<es2panda_AstNode const *>(node->GetExpression());
}

extern "C" es2panda_AstNode *CreateClassDeclaration(es2panda_Context *context, es2panda_AstNode *definition)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *dfn = reinterpret_cast<ir::AstNode *>(definition)->AsClassDefinition();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ClassDeclaration>(dfn, allocator));
}

extern "C" es2panda_AstNode *ClassDeclarationDefinition(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDeclaration();
    return reinterpret_cast<es2panda_AstNode *>(node->Definition());
}

extern "C" es2panda_AstNode *CreateClassDefinition(es2panda_Context *context, es2panda_AstNode *in_scope_of,
                                                   es2panda_AstNode *identifier, es2panda_ModifierFlags flags)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *parent = reinterpret_cast<ir::AstNode *>(in_scope_of);
    auto *parent_scope = compiler::NearestScope(parent);
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();

    auto *scope = allocator->New<varbinder::LocalScope>(allocator, parent_scope);
    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ClassDefinition>(allocator, scope, id, ir::ClassDefinitionModifiers::NONE,
                                            E2pToIrModifierFlags(flags), Language::FromString("ets").value()));
}

extern "C" es2panda_AstNode *ClassDefinitionIdentifier(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    return reinterpret_cast<es2panda_AstNode *>(node->Ident());
}

extern "C" es2panda_AstNode *ClassDefinitionTypeParameters(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeParams());
}

extern "C" es2panda_AstNode *ClassDefinitionSuperClass(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    return reinterpret_cast<es2panda_AstNode *>(node->Super());
}

extern "C" es2panda_AstNode **ClassDefinitionImplements(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &impl_vec = node->Implements();
    *size_p = impl_vec.size();
    return reinterpret_cast<es2panda_AstNode **>(impl_vec.data());
}

extern "C" es2panda_AstNode *ClassDefinitionConstructor(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    return reinterpret_cast<es2panda_AstNode *>(node->Ctor());
}

extern "C" es2panda_AstNode **ClassDefinitionBody(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &body_vec = node->Body();
    *size_p = body_vec.size();
    return reinterpret_cast<es2panda_AstNode **>(body_vec.data());
}

extern "C" void ClassDefinitionSetIdentifier(es2panda_AstNode *ast, es2panda_AstNode *identifier)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();
    node->SetIdent(id);
}

extern "C" void ClassDefinitionSetTypeParameters(es2panda_AstNode *ast, es2panda_AstNode *type_params)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *tpd = reinterpret_cast<ir::AstNode *>(type_params)->AsTSTypeParameterDeclaration();
    node->SetTypeParams(tpd);
}

extern "C" void ClassDefinitionSetSuperClass(es2panda_AstNode *ast, es2panda_AstNode *super_class)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *super = reinterpret_cast<ir::AstNode *>(super_class)->AsExpression();
    node->SetSuper(super);
}

extern "C" void ClassDefinitionSetImplements(es2panda_AstNode *ast, es2panda_AstNode **implements, size_t n_implements)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &impl_vec = node->Implements();
    impl_vec.resize(0);
    for (size_t i = 0; i < n_implements; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        impl_vec.push_back(reinterpret_cast<ir::AstNode *>(implements[i])->AsTSClassImplements());
    }
}

extern "C" void ClassDefinitionAddImplements(es2panda_AstNode *ast, es2panda_AstNode *implements)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &impl_vec = node->Implements();
    impl_vec.push_back(reinterpret_cast<ir::AstNode *>(implements)->AsTSClassImplements());
}

extern "C" void ClassDefinitionSetConstructor(es2panda_AstNode *ast, es2panda_AstNode *constructor)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *ctor = reinterpret_cast<ir::AstNode *>(constructor)->AsMethodDefinition();
    node->SetCtor(ctor);
}

extern "C" void ClassDefinitionSetBody(es2panda_AstNode *ast, es2panda_AstNode **body, size_t n_elems)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &body_vec = node->Body();
    body_vec.resize(0);
    for (size_t i = 0; i < n_elems; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        body_vec.push_back(reinterpret_cast<ir::AstNode *>(body[i]));
    }
}

extern "C" void ClassDefinitionAddToBody(es2panda_AstNode *ast, es2panda_AstNode *body_elem)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *elem = reinterpret_cast<ir::AstNode *>(body_elem);
    auto &body_vec = node->Body();
    body_vec.push_back(reinterpret_cast<ir::AstNode *>(elem));
}

extern "C" es2panda_AstNode *ClassElementKey(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassElement();
    return reinterpret_cast<es2panda_AstNode *>(node->Key());
}

extern "C" es2panda_AstNode *ClassElementValue(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassElement();
    return reinterpret_cast<es2panda_AstNode *>(node->Value());
}

extern "C" es2panda_AstNode *CreateClassImplementsClause(es2panda_Context *context, es2panda_AstNode *expression,
                                                         es2panda_AstNode *type_arguments)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *expr = reinterpret_cast<ir::AstNode *>(expression)->AsExpression();
    auto *targs = type_arguments == nullptr
                      ? nullptr
                      : reinterpret_cast<ir::AstNode *>(type_arguments)->AsTSTypeParameterInstantiation();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSClassImplements>(expr, targs));
}

extern "C" es2panda_AstNode *ClassImplementsClauseExpression(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSClassImplements();
    return reinterpret_cast<es2panda_AstNode *>(node->Expr());
}

extern "C" es2panda_AstNode const *ClassImplementsClauseTypeArguments(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSClassImplements();
    return reinterpret_cast<es2panda_AstNode const *>(node->TypeParameters());
}

extern "C" es2panda_AstNode *CreateClassProperty(es2panda_Context *context, es2panda_AstNode *key,
                                                 es2panda_AstNode *value, es2panda_AstNode *type_annotation,
                                                 es2panda_ModifierFlags modifier_flags, bool is_computed)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ekey = reinterpret_cast<ir::AstNode *>(key)->AsExpression();
    auto *evalue = value == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(value)->AsExpression();
    auto *tp_ann = type_annotation == nullptr
                       ? nullptr
                       : reinterpret_cast<ir::AstNode *>(type_annotation)->AsExpression()->AsTypeNode();
    auto modifiers = E2pToIrModifierFlags(modifier_flags);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ClassProperty>(ekey, evalue, tp_ann, modifiers, allocator, is_computed));
}

extern "C" es2panda_AstNode *ClassPropertyTypeAnnotation(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassProperty();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeAnnotation());
}

extern "C" es2panda_AstNode *CreateExpressionStatement(es2panda_Context *context, es2panda_AstNode *expression)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *expr = reinterpret_cast<ir::AstNode *>(expression)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ExpressionStatement>(expr));
}

extern "C" es2panda_AstNode *ExpressionStatementExpression(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsExpressionStatement();
    return reinterpret_cast<es2panda_AstNode *>(node->GetExpression());
}

extern "C" es2panda_AstNode *CreateFunctionDeclaration(es2panda_Context *context, es2panda_AstNode *function)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *func = reinterpret_cast<ir::AstNode *>(function)->AsScriptFunction();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::FunctionDeclaration>(allocator, func));
}

extern "C" es2panda_AstNode *FunctionDeclarationFunction(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsFunctionDeclaration();
    return reinterpret_cast<es2panda_AstNode *>(node->Function());
}

extern "C" es2panda_AstNode *CreateFunctionExpression(es2panda_Context *context, es2panda_AstNode *function)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *func = reinterpret_cast<ir::AstNode *>(function)->AsScriptFunction();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::FunctionExpression>(func));
}

extern "C" es2panda_AstNode *FunctionExpressionFunction(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsFunctionExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Function());
}

extern "C" es2panda_AstNode *CreateFunctionTypeNode(es2panda_Context *context, es2panda_AstNode *in_scope_of,
                                                    es2panda_AstNode *type_params, es2panda_AstNode **params,
                                                    size_t n_params, es2panda_AstNode *return_type,
                                                    es2panda_ScriptFunctionFlags func_flags)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *parent = reinterpret_cast<ir::AstNode *>(in_scope_of);
    auto *parent_scope = compiler::NearestScope(parent);
    auto *tpar =
        type_params == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(type_params)->AsTSTypeParameterDeclaration();
    auto *tret =
        return_type == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(return_type)->AsExpression()->AsTypeNode();
    auto flags = E2pToIrScriptFunctionFlags(func_flags);

    auto *scope = allocator->New<varbinder::FunctionParamScope>(allocator, parent_scope);

    ArenaVector<ir::Expression *> par {allocator->Adapter()};
    for (size_t i = 0; i < n_params; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        par.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSFunctionType>(scope, std::move(par), tpar, tret, flags));
}

extern "C" es2panda_AstNode const *FunctionTypeNodeTypeParams(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    return reinterpret_cast<es2panda_AstNode const *>(node->TypeParams());
}

extern "C" es2panda_AstNode *const *FunctionTypeNodeParams(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    auto &params = node->Params();
    *size_p = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *FunctionTypeNodeReturnType(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    return reinterpret_cast<es2panda_AstNode *>(node->ReturnType());
}

extern "C" es2panda_ScriptFunctionFlags FunctionTypeNodeFlags(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    return IrToE2pScriptFunctionFlags(node->Flags());
}

extern "C" es2panda_AstNode *CreateIdentifier(es2panda_Context *context, char const *name,
                                              es2panda_AstNode *type_annotations)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *name_copy = ArenaStrdup(ctx->allocator, name);
    auto *tp_ann = type_annotations == nullptr
                       ? nullptr
                       : reinterpret_cast<ir::AstNode *>(type_annotations)->AsExpression()->AsTypeNode();

    auto *res = allocator->New<ir::Identifier>(util::StringView {name_copy}, tp_ann, allocator);

    return reinterpret_cast<es2panda_AstNode *>(res);
}

extern "C" char const *IdentifierName(es2panda_Context *context, es2panda_AstNode *identifier)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *id = reinterpret_cast<ir::AstNode *>(identifier);
    ASSERT(id->IsIdentifier());

    return StringViewToCString(ctx->allocator, id->AsIdentifier()->Name());
}

extern "C" es2panda_AstNode *IdentifierTypeAnnotation(es2panda_AstNode *identifier)
{
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();
    return reinterpret_cast<es2panda_AstNode *>(id->TypeAnnotation());
}

extern "C" es2panda_Variable *IdentifierVariable(es2panda_AstNode *identifier)
{
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();

    return reinterpret_cast<es2panda_Variable *>(id->Variable());
}

extern "C" void IdentifierSetVariable(es2panda_AstNode *identifier, es2panda_Variable *variable)
{
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();
    auto *var = reinterpret_cast<varbinder::Variable *>(variable);

    id->SetVariable(var);
}

extern "C" es2panda_AstNode *CreateIfStatement(es2panda_Context *context, es2panda_AstNode *test,
                                               es2panda_AstNode *consequent, es2panda_AstNode *alternate)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *t = reinterpret_cast<ir::AstNode *>(test)->AsExpression();
    auto *conseq = reinterpret_cast<ir::AstNode *>(consequent)->AsStatement();
    auto *alt = reinterpret_cast<ir::AstNode *>(alternate)->AsStatement();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::IfStatement>(t, conseq, alt));
}

extern "C" es2panda_AstNode const *IfStatementTest(es2panda_AstNode *identifier)
{
    auto *if_stat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(if_stat->Test());
}

extern "C" es2panda_AstNode const *IfStatementConsequent(es2panda_AstNode *identifier)
{
    auto *if_stat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(if_stat->Consequent());
}

extern "C" es2panda_AstNode const *IfStatementAlternate(es2panda_AstNode *identifier)
{
    auto *if_stat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(if_stat->Alternate());
}

extern "C" es2panda_AstNode *CreateImportDeclaration(es2panda_Context *context, es2panda_AstNode *source,
                                                     es2panda_AstNode **specifiers, size_t n_specifiers)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *src = reinterpret_cast<ir::AstNode *>(source)->AsStringLiteral();

    ArenaVector<ir::AstNode *> specs {allocator->Adapter()};
    for (size_t i = 0; i < n_specifiers; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        specs.push_back(reinterpret_cast<ir::AstNode *>(specifiers[i]));
    }

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ImportDeclaration>(src, std::move(specs)));
}

extern "C" es2panda_AstNode const *ImportDeclarationSource(es2panda_AstNode *ast)
{
    auto *decl = reinterpret_cast<ir::AstNode *>(ast)->AsImportDeclaration();

    return reinterpret_cast<es2panda_AstNode const *>(decl->Source());
}

extern "C" es2panda_AstNode *const *ImportDeclarationSpecifiers(es2panda_AstNode *ast, size_t *size_p)
{
    auto *decl = reinterpret_cast<ir::AstNode *>(ast)->AsImportDeclaration();
    auto &specs = decl->Specifiers();

    *size_p = specs.size();

    return reinterpret_cast<es2panda_AstNode *const *>(specs.data());
}

extern "C" es2panda_AstNode *CreateImportExpression(es2panda_Context *context, es2panda_AstNode *source)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *src = reinterpret_cast<ir::AstNode *>(source)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ImportExpression>(src));
}

extern "C" es2panda_AstNode *ImportExpressionSource(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsImportExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Source());
}

extern "C" es2panda_AstNode *CreateImportSpecifier(es2panda_Context *context, es2panda_AstNode *imported,
                                                   es2panda_AstNode *local)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_imported = reinterpret_cast<ir::AstNode *>(imported)->AsIdentifier();
    auto *ir_local = reinterpret_cast<ir::AstNode *>(local)->AsIdentifier();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ImportSpecifier>(ir_imported, ir_local));
}

extern "C" es2panda_AstNode *ImportSpecifierImported(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsImportSpecifier();
    return reinterpret_cast<es2panda_AstNode *>(node->Imported());
}

extern "C" es2panda_AstNode *ImportSpecifierLocal(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsImportSpecifier();
    return reinterpret_cast<es2panda_AstNode *>(node->Local());
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FOR_ALL_MEMBER_EXPRESSION_KINDS(_) \
    _(ELEMENT_ACCESS)                      \
    _(PROPERTY_ACCESS)                     \
    _(GETTER)                              \
    _(SETTER)

static ir::MemberExpressionKind E2pToIrMemberExpressionKind(es2panda_MemberExpressionKind e2p_kind)
{
    ir::MemberExpressionKind ir_kind = ir::MemberExpressionKind::NONE;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_KIND(K)                                               \
    if ((e2p_kind & ES2PANDA_MEMBER_EXPRESSION_KIND_##K) != 0) { \
        ir_kind |= ir::MemberExpressionKind::K;                  \
    }

    FOR_ALL_MEMBER_EXPRESSION_KINDS(DO_KIND)

#undef DO_KIND

    return ir_kind;
}

static es2panda_MemberExpressionKind IrToE2pMemberExpressionKind(ir::MemberExpressionKind ir_kind)
{
    es2panda_MemberExpressionKind e2p_kind = ES2PANDA_MEMBER_EXPRESSION_KIND_NONE;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DO_KIND(K)                                                                                             \
    if ((ir_kind & ir::MemberExpressionKind::K) != 0) {                                                        \
        e2p_kind = static_cast<es2panda_MemberExpressionKind>(e2p_kind | ES2PANDA_MEMBER_EXPRESSION_KIND_##K); \
    }

    FOR_ALL_MEMBER_EXPRESSION_KINDS(DO_KIND)

#undef DO_KIND

    return e2p_kind;
}

extern "C" es2panda_AstNode *CreateMemberExpression(es2panda_Context *context, es2panda_AstNode *object,
                                                    es2panda_AstNode *property, es2panda_MemberExpressionKind kind,
                                                    bool is_computed, bool is_optional)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto ir_object = reinterpret_cast<ir::AstNode *>(object)->AsExpression();
    auto ir_property = reinterpret_cast<ir::AstNode *>(property)->AsExpression();
    auto ir_kind = E2pToIrMemberExpressionKind(kind);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::MemberExpression>(ir_object, ir_property, ir_kind, is_computed, is_optional));
}

extern "C" es2panda_AstNode *MemberExpressionObject(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMemberExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Object());
}

extern "C" es2panda_AstNode *MemberExpressionProperty(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMemberExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Property());
}

extern "C" es2panda_MemberExpressionKind MemberExpressionKind(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMemberExpression();
    return IrToE2pMemberExpressionKind(node->Kind());
}

extern "C" bool MemberExpressionIsComputed(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMemberExpression();
    return node->IsComputed();
}

extern "C" bool MemberExpressionIsOptional(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMemberExpression();
    return node->IsOptional();
}

struct MethodDefinitionKindToStrStruct {
    ir::MethodDefinitionKind kind;
    char const *str;
};

static constexpr std::array<MethodDefinitionKindToStrStruct, 5U> METHOD_DEFINITION_KIND_TO_STR {{
    {ir::MethodDefinitionKind::CONSTRUCTOR, "constructor"},
    {ir::MethodDefinitionKind::METHOD, "method"},
    {ir::MethodDefinitionKind::EXTENSION_METHOD, "extension method"},
    {ir::MethodDefinitionKind::GET, "get"},
    {ir::MethodDefinitionKind::SET, "set"},
}};

static ir::MethodDefinitionKind StrToMethodDefinitionKind(char const *str)
{
    for (auto &elem : METHOD_DEFINITION_KIND_TO_STR) {
        if (strcmp(elem.str, str) == 0) {
            return elem.kind;
        }
    }
    return ir::MethodDefinitionKind::NONE;
}

static char const *MethodDefinitionKindToStr(ir::MethodDefinitionKind kind)
{
    for (auto &elem : METHOD_DEFINITION_KIND_TO_STR) {
        if (elem.kind == kind) {
            return elem.str;
        }
    }
    return "unknown";
}

extern "C" es2panda_AstNode *CreateMethodDefinition(es2panda_Context *context, char const *kind, es2panda_AstNode *key,
                                                    es2panda_AstNode *value, es2panda_ModifierFlags modifiers,
                                                    bool is_computed)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto ir_kind = StrToMethodDefinitionKind(kind);
    auto *ir_key = reinterpret_cast<ir::AstNode *>(key)->AsExpression();
    auto *ir_value = reinterpret_cast<ir::AstNode *>(value)->AsExpression();
    auto ir_flags = E2pToIrModifierFlags(modifiers);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::MethodDefinition>(ir_kind, ir_key, ir_value, ir_flags, allocator, is_computed));
}

extern "C" char const *MethodDefinitionKind(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    return MethodDefinitionKindToStr(node->Kind());
}

extern "C" es2panda_AstNode const *MethodDefinitionKey(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    return reinterpret_cast<es2panda_AstNode const *>(node->Key());
}

extern "C" es2panda_AstNode const *MethodDefinitionValue(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    return reinterpret_cast<es2panda_AstNode const *>(node->Value());
}

extern "C" es2panda_ModifierFlags MethodDefinitionModifiers(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    return IrToE2pModifierFlags(node->Modifiers());
}

extern "C" bool MethodDefinitionIsComputed(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    return node->IsComputed();
}

extern "C" es2panda_AstNode *const *MethodDefinitionOverloads(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    auto const &overloads = node->Overloads();
    *size_p = overloads.size();
    return reinterpret_cast<es2panda_AstNode *const *>(overloads.data());
}

extern "C" void MethodDefinitionSetOverloads(es2panda_AstNode *ast, es2panda_AstNode **overloads, size_t n_overloads)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    ArenaVector<ir::MethodDefinition *> ir_overloads {node->Overloads().get_allocator()};
    ir_overloads.reserve(n_overloads);
    for (size_t i = 0; i < n_overloads; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_overloads.push_back(reinterpret_cast<ir::AstNode *>(overloads[i])->AsMethodDefinition());
    }
    node->SetOverloads(std::move(ir_overloads));
}

extern "C" void MethodDefinitionAddOverload(es2panda_AstNode *ast, es2panda_AstNode *overload)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    auto *ir_overload = reinterpret_cast<ir::AstNode *>(overload)->AsMethodDefinition();
    node->AddOverload(ir_overload);
}

extern "C" es2panda_AstNode *CreateNewClassInstanceExpression(es2panda_Context *context,
                                                              es2panda_AstNode *type_reference,
                                                              es2panda_AstNode **arguments, size_t n_arguments,
                                                              es2panda_AstNode *class_definition)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_typeref = reinterpret_cast<ir::AstNode *>(type_reference)->AsExpression();

    ArenaVector<ir::Expression *> args {allocator->Adapter()};
    for (size_t i = 0; i < n_arguments; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        args.push_back(reinterpret_cast<ir::AstNode *>(arguments[i])->AsExpression());
    }

    auto *ir_classdef =
        class_definition == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(class_definition)->AsClassDefinition();

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSNewClassInstanceExpression>(ir_typeref, std::move(args), ir_classdef));
}

extern "C" es2panda_AstNode *NewClassInstanceExpressionTypeReference(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->GetTypeRef());
}

extern "C" es2panda_AstNode *const *NewClassInstanceExpressionArguments(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    auto const &args = node->GetArguments();

    *size_p = args.size();
    return reinterpret_cast<es2panda_AstNode *const *>(args.data());
}

extern "C" es2panda_AstNode *NewClassInstanceExpressionClassDefinition(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->ClassDefinition());
}

extern "C" es2panda_AstNode *CreateNewArrayInstanceExpression(es2panda_Context *context,
                                                              es2panda_AstNode *type_reference,
                                                              es2panda_AstNode *dimension)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_typeref = reinterpret_cast<ir::AstNode *>(type_reference)->AsExpression()->AsTypeNode();
    auto *ir_dim = reinterpret_cast<ir::AstNode *>(dimension)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSNewArrayInstanceExpression>(ir_typeref, ir_dim));
}

extern "C" es2panda_AstNode *NewArrayInstanceExpressionTypeReference(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewArrayInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeReference());
}

extern "C" es2panda_AstNode *NewArrayInstanceExpressionDimension(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewArrayInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Dimension());
}

extern "C" es2panda_AstNode *CreateNewMultiDimArrayInstanceExpression(es2panda_Context *context,
                                                                      es2panda_AstNode *type_reference,
                                                                      es2panda_AstNode **dimensions,
                                                                      size_t n_dimensions)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_typeref = reinterpret_cast<ir::AstNode *>(type_reference)->AsExpression()->AsTypeNode();

    ArenaVector<ir::Expression *> ir_dims {allocator->Adapter()};
    for (size_t i = 0; i < n_dimensions; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_dims.push_back(reinterpret_cast<ir::AstNode *>(dimensions[i])->AsExpression());
    }

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSNewMultiDimArrayInstanceExpression>(ir_typeref, std::move(ir_dims)));
}

extern "C" es2panda_AstNode *NewMultiDimArrayInstanceExpressionTypeReference(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewMultiDimArrayInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeReference());
}

extern "C" es2panda_AstNode *const *NewMultiDimArrayInstanceExpressionDimensions(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewMultiDimArrayInstanceExpression();
    auto const &dims = node->Dimensions();

    *size_p = dims.size();
    return reinterpret_cast<es2panda_AstNode *const *>(dims.data());
}

extern "C" es2panda_AstNode *CreateParameterDeclaration(es2panda_Context *context,
                                                        es2panda_AstNode *identifier_or_spread,
                                                        es2panda_AstNode *initializer)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    auto *ir_ident_or_spread_raw = reinterpret_cast<ir::AstNode *>(identifier_or_spread)->AsExpression();
    ir::AnnotatedExpression *ir_ident_or_spread;
    if (ir_ident_or_spread_raw->IsIdentifier()) {
        ir_ident_or_spread = ir_ident_or_spread_raw->AsIdentifier();
    } else if (ir_ident_or_spread_raw->IsSpreadElement()) {
        ir_ident_or_spread = ir_ident_or_spread_raw->AsSpreadElement();
    } else {
        UNREACHABLE();
    }

    auto *ir_initializer =
        initializer == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(initializer)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSParameterExpression>(ir_ident_or_spread, ir_initializer));
}

extern "C" es2panda_AstNode *ParameterDeclarationIdentifierOrSpread(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSParameterExpression();

    ir::AstNode *res;
    if (node->IsRestParameter()) {
        res = node->RestParameter();
    } else {
        res = node->Ident();
    }
    return reinterpret_cast<es2panda_AstNode *>(res);
}

extern "C" es2panda_AstNode *ParameterDeclarationInitializer(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSParameterExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Initializer());
}

struct PrimitiveTypeToStrStruct {
    ir::PrimitiveType type;
    char const *str;
};

static constexpr std::array<PrimitiveTypeToStrStruct, 9U> PRIMITIVE_TYPE_TO_STR {{
    {ir::PrimitiveType::BYTE, "byte"},
    {ir::PrimitiveType::INT, "int"},
    {ir::PrimitiveType::LONG, "long"},
    {ir::PrimitiveType::SHORT, "short"},
    {ir::PrimitiveType::FLOAT, "float"},
    {ir::PrimitiveType::DOUBLE, "double"},
    {ir::PrimitiveType::BOOLEAN, "boolean"},
    {ir::PrimitiveType::CHAR, "char"},
    {ir::PrimitiveType::VOID, "void"},
}};

static ir::PrimitiveType StrToPrimitiveType(char const *str)
{
    for (auto &elem : PRIMITIVE_TYPE_TO_STR) {
        if (strcmp(elem.str, str) == 0) {
            return elem.type;
        }
    }
    return ir::PrimitiveType::VOID;
}

static char const *PrimitiveTypeToStr(ir::PrimitiveType type)
{
    for (auto &elem : PRIMITIVE_TYPE_TO_STR) {
        if (elem.type == type) {
            return elem.str;
        }
    }
    return "unknown";
}

extern "C" es2panda_AstNode *CreatePrimitiveTypeNode(es2panda_Context *context, char const *type)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto tp = StrToPrimitiveType(type);

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSPrimitiveType>(tp));
}

extern "C" char const *PrimitiveTypeNodeType(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSPrimitiveType();
    return PrimitiveTypeToStr(node->GetPrimitiveType());
}

extern "C" es2panda_AstNode *CreateReturnStatement(es2panda_Context *context, es2panda_AstNode *argument)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_arg = argument == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(argument)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ReturnStatement>(ir_arg));
}

extern "C" es2panda_AstNode *ReturnStatementArgument(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsReturnStatement();
    return reinterpret_cast<es2panda_AstNode *>(node->Argument());
}

extern "C" es2panda_Type *ReturnStatementReturnType(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsReturnStatement();
    return reinterpret_cast<es2panda_Type *>(node->ReturnType());
}

extern "C" es2panda_AstNode *CreateScriptFunction(es2panda_Context *context, es2panda_AstNode *type_params,
                                                  es2panda_AstNode **params, size_t n_params,
                                                  es2panda_AstNode *return_type_annotation,
                                                  es2panda_ScriptFunctionFlags function_flags,
                                                  es2panda_ModifierFlags modifier_flags, bool is_declare,
                                                  es2panda_AstNode *in_scope_of)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_type_params =
        type_params == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(type_params)->AsTSTypeParameterDeclaration();

    // NOTE(gogabr): without explicit reference to scope, scopes within params will be broken
    ArenaVector<ir::Expression *> ir_params {allocator->Adapter()};
    for (size_t i = 0; i < n_params; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_params.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }

    auto ir_return_type_annotation =
        return_type_annotation == nullptr
            ? nullptr
            : reinterpret_cast<ir::AstNode *>(return_type_annotation)->AsExpression()->AsTypeNode();
    auto ir_function_flags = E2pToIrScriptFunctionFlags(function_flags);
    auto ir_modifier_flags = E2pToIrModifierFlags(modifier_flags);

    auto *outer_scope = ir_type_params == nullptr ? compiler::NearestScope(reinterpret_cast<ir::AstNode *>(in_scope_of))
                                                  : ir_type_params->Scope();
    auto *parameter_scope = allocator->New<varbinder::FunctionParamScope>(allocator, outer_scope);
    auto *body_scope = allocator->New<varbinder::FunctionScope>(allocator, parameter_scope);
    parameter_scope->BindFunctionScope(body_scope);
    body_scope->BindParamScope(parameter_scope);

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ScriptFunction>(
        body_scope, std::move(ir_params), ir_type_params, nullptr, ir_return_type_annotation, ir_function_flags,
        ir_modifier_flags, is_declare, Language::FromString("ets").value()));
}

extern "C" es2panda_AstNode *ScriptFunctionTypeParams(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeParams());
}

extern "C" es2panda_AstNode *const *ScriptFunctionParams(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto &params = node->Params();

    *size_p = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *ScriptFunctionReturnTypeAnnotation(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return reinterpret_cast<es2panda_AstNode *>(node->ReturnTypeAnnotation());
}

extern "C" es2panda_ScriptFunctionFlags ScriptFunctionScriptFunctionFlags(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return IrToE2pScriptFunctionFlags(node->Flags());
}

extern "C" bool ScriptFunctionIsDeclare(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return node->Declare();
}

extern "C" es2panda_AstNode *ScriptFunctionIdentifier(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return reinterpret_cast<es2panda_AstNode *>(node->Id());
}

extern "C" es2panda_AstNode *ScriptFunctionBody(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return reinterpret_cast<es2panda_AstNode *>(node->Body());
}

extern "C" void ScriptFunctionSetIdentifier(es2panda_AstNode *ast, es2panda_AstNode *identifier)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();

    node->SetIdent(id);
}

extern "C" void ScriptFunctionSetBody(es2panda_AstNode *ast, es2panda_AstNode *body)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto *ir_body = reinterpret_cast<ir::AstNode *>(body);

    node->SetBody(ir_body);
}

extern "C" void ScriptFunctionSetParams(es2panda_AstNode *ast, es2panda_AstNode **params, size_t n_params)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto &ir_params = node->Params();

    ir_params.clear();
    for (size_t i = 0; i < n_params; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_params.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }
}

extern "C" void ScripFunctionAddParam(es2panda_AstNode *ast, es2panda_AstNode *param)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto *ir_param = reinterpret_cast<ir::AstNode *>(param)->AsExpression();

    node->Params().push_back(ir_param);
}

extern "C" es2panda_AstNode *CreateStringLiteral(es2panda_Context *context, char const *string)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *str = ArenaStrdup(allocator, string);

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::StringLiteral>(str));
}

extern "C" char const *StringLiteralString(es2panda_Context *context, es2panda_AstNode *ast)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsStringLiteral();
    return StringViewToCString(allocator, node->Str());
}

extern "C" es2panda_AstNode *CreateThisExpression(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ThisExpression>());
}

extern "C" es2panda_AstNode *CreateTypeParameter(es2panda_Context *context, es2panda_AstNode *name,
                                                 es2panda_AstNode *constraint, es2panda_AstNode *default_type)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *nm = reinterpret_cast<ir::AstNode *>(name)->AsIdentifier();
    auto *constr =
        constraint == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(constraint)->AsExpression()->AsTypeNode();
    auto *dflt =
        default_type == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(default_type)->AsExpression()->AsTypeNode();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSTypeParameter>(nm, constr, dflt));
}

extern "C" es2panda_AstNode const *TypeParameterName(es2panda_AstNode *ast)
{
    auto *tp = reinterpret_cast<ir::AstNode *>(ast)->AsTSTypeParameter();
    return reinterpret_cast<es2panda_AstNode const *>(tp->Name());
}

extern "C" es2panda_AstNode const *TypeParameterConstraint(es2panda_AstNode *ast)
{
    auto *tp = reinterpret_cast<ir::AstNode *>(ast)->AsTSTypeParameter();
    return reinterpret_cast<es2panda_AstNode const *>(tp->Constraint());
}

extern "C" es2panda_AstNode const *TypeParameterDefaultType(es2panda_AstNode *ast)
{
    auto *tp = reinterpret_cast<ir::AstNode *>(ast)->AsTSTypeParameter();
    return reinterpret_cast<es2panda_AstNode const *>(tp->DefaultType());
}

extern "C" es2panda_AstNode *CreateTypeParameterDeclaration(es2panda_Context *context, es2panda_AstNode *in_scope_of)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *parent = reinterpret_cast<ir::AstNode *>(in_scope_of);
    auto *parent_scope = compiler::NearestScope(parent);

    auto *scope = allocator->New<varbinder::LocalScope>(allocator, parent_scope);
    ArenaVector<ir::TSTypeParameter *> params {allocator->Adapter()};
    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::TSTypeParameterDeclaration>(scope, std::move(params), 0));
}

extern "C" void TypeParameterDeclarationAddTypeParameter(es2panda_AstNode *ast, es2panda_AstNode *type_parameter)
{
    auto *tpd = reinterpret_cast<ir::AstNode *>(ast)->AsTSTypeParameterDeclaration();
    auto *param = reinterpret_cast<ir::AstNode *>(type_parameter)->AsTSTypeParameter();

    tpd->AddParam(param);
}

extern "C" es2panda_AstNode *const *TypeParameterDeclarationTypeParameters(es2panda_AstNode *ast, size_t *size_p)
{
    auto *tpd = reinterpret_cast<ir::AstNode const *>(ast)->AsTSTypeParameterDeclaration();
    auto const &params = tpd->Params();
    *size_p = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *CreateTypeParameterInstantiation(es2panda_Context *context,
                                                              es2panda_AstNode **type_parameters, size_t n_params)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::TypeNode *> params {allocator->Adapter()};
    for (size_t i = 0; i < n_params; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        params.push_back(reinterpret_cast<ir::AstNode *>(type_parameters[i])->AsExpression()->AsTypeNode());
    }
    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSTypeParameterInstantiation>(std::move(params)));
}

extern "C" es2panda_AstNode *const *TypeParameterInstantiationTypeParameters(es2panda_AstNode *ast, size_t *size_p)
{
    auto *tpi = reinterpret_cast<ir::AstNode const *>(ast)->AsTSTypeParameterInstantiation();
    auto const &params = tpi->Params();
    *size_p = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *CreateTypeReferenceNode(es2panda_Context *context, es2panda_AstNode *part)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_part = reinterpret_cast<ir::AstNode *>(part)->AsETSTypeReferencePart();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSTypeReference>(ir_part));
}

extern "C" es2panda_AstNode *TypeReferenceNodePart(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode const *>(ast)->AsETSTypeReference();
    return reinterpret_cast<es2panda_AstNode *>(node->Part());
}

extern "C" es2panda_AstNode *CreateTypeReferencePart(es2panda_Context *context, es2panda_AstNode *name,
                                                     es2panda_AstNode *type_arguments, es2panda_AstNode *previous)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ir_name = reinterpret_cast<ir::AstNode *>(name)->AsExpression();
    auto *ir_type_args = type_arguments == nullptr
                             ? nullptr
                             : reinterpret_cast<ir::AstNode *>(type_arguments)->AsTSTypeParameterInstantiation();
    auto *ir_prev = previous == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(previous)->AsETSTypeReferencePart();

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSTypeReferencePart>(ir_name, ir_type_args, ir_prev));
}

extern "C" es2panda_AstNode *TypeReferencePartName(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSTypeReferencePart();
    return reinterpret_cast<es2panda_AstNode *>(node->Name());
}

extern "C" es2panda_AstNode *TypeReferencePartTypeArguments(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSTypeReferencePart();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeParams());
}

extern "C" es2panda_AstNode *TypeReferencePartPrevious(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSTypeReferencePart();
    return reinterpret_cast<es2panda_AstNode *>(node->Previous());
}

extern "C" es2panda_AstNode *CreateUnionTypeNode(es2panda_Context *context, es2panda_AstNode **types, size_t n_types)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::TypeNode *> ir_types {allocator->Adapter()};
    for (size_t i = 0; i < n_types; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_types.push_back(reinterpret_cast<ir::AstNode *>(types[i])->AsExpression()->AsTypeNode());
    }

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSUnionType>(std::move(ir_types)));
}

extern "C" es2panda_AstNode *const *UnionTypeNodeTypes(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSUnionType();
    auto &ir_types = node->Types();

    *size_p = ir_types.size();
    return reinterpret_cast<es2panda_AstNode *const *>(ir_types.data());
}

struct VariableDeclarationKindToStrStruct {
    ir::VariableDeclaration::VariableDeclarationKind kind;
    char const *str;
};

static constexpr std::array<VariableDeclarationKindToStrStruct, 3U> VARIABLE_DECLARATION_KIND_TO_STR {{
    {ir::VariableDeclaration::VariableDeclarationKind::CONST, "const"},
    {ir::VariableDeclaration::VariableDeclarationKind::LET, "let"},
    {ir::VariableDeclaration::VariableDeclarationKind::VAR, "var"},
}};

static ir::VariableDeclaration::VariableDeclarationKind StrToVariableDeclarationKind(char const *str)
{
    for (auto &elem : VARIABLE_DECLARATION_KIND_TO_STR) {
        if (strcmp(elem.str, str) == 0) {
            return elem.kind;
        }
    }

    // NOTE(gogabr): handle errors
    UNREACHABLE();
}

static char const *VariableDeclarationKindToStr(ir::VariableDeclaration::VariableDeclarationKind kind)
{
    for (auto &elem : VARIABLE_DECLARATION_KIND_TO_STR) {
        if (elem.kind == kind) {
            return elem.str;
        }
    }
    return "unknown";
}

extern "C" es2panda_AstNode *CreateVariableDeclaration(es2panda_Context *context, char const *kind,
                                                       es2panda_AstNode **declarators, size_t n_declarators,
                                                       bool is_declare)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto ir_kind = StrToVariableDeclarationKind(kind);

    ArenaVector<ir::VariableDeclarator *> ir_declarators {allocator->Adapter()};
    for (size_t i = 0; i < n_declarators; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ir_declarators.push_back(reinterpret_cast<ir::AstNode *>(declarators[i])->AsVariableDeclarator());
    }

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::VariableDeclaration>(ir_kind, allocator, std::move(ir_declarators), is_declare));
}

extern "C" char const *VariableDeclarationKind(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclaration();
    return VariableDeclarationKindToStr(node->Kind());
}

extern "C" es2panda_AstNode *const *VariableDeclarationDeclarators(es2panda_AstNode *ast, size_t *size_p)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclaration();
    auto const &declarators = node->Declarators();
    *size_p = declarators.size();
    return reinterpret_cast<es2panda_AstNode *const *>(declarators.data());
}

extern "C" bool VariableDeclarationIsDeclare(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclaration();
    return node->Declare();
}

extern "C" es2panda_AstNode *CreateVariableDeclarator(es2panda_Context *context, es2panda_AstNode *identifier,
                                                      es2panda_AstNode *initializer)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ident = reinterpret_cast<ir::AstNode *>(identifier)->AsExpression();
    auto *init = initializer == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(initializer)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::VariableDeclarator>(ident, init));
}

extern "C" es2panda_AstNode *VariableDeclaratorIdentifier(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclarator();
    return reinterpret_cast<es2panda_AstNode *>(node->Id());
}

extern "C" es2panda_AstNode *VariableDeclaratorInitializer(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclarator();
    return reinterpret_cast<es2panda_AstNode *>(node->Init());
}

es2panda_Impl IMPL = {
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

    AstNodeType,
    AstNodeSetType,

    AstNodeDecorators,
    AstNodeSetDecorators,

    AstNodeModifierFlags,

    AstNodeForEach,

    IsArrowFunctionExpression,
    CreateArrowFunctionExpression,
    ArrowFunctionExpressionScriptFunction,

    IsAsExpression,
    CreateAsExpression,
    AsExpressionExpr,
    AsExpressionTypeAnnotation,
    AsExpressionIsConst,
    AsExpressionSetExpr,
    AsExpressionSetTypeAnnotation,

    IsAssignmentExpression,
    CreateAssignmentExpression,
    AssignmentExpressionLeft,
    AssignmentExpressionRight,
    AssignmentExpressionOperatorType,
    AssignmentExpressionSetOperatorType,

    IsBinaryExpression,
    CreateBinaryExpression,
    BinaryExpressionLeft,
    BinaryExpressionRight,
    BinaryExpressionOperator,
    BinaryExpressionSetOperator,

    IsBlockStatement,
    CreateBlockStatement,
    BlockStatementStatements,
    BlockStatementAddStatement,

    IsCallExpression,
    CreateCallExpression,
    CallExpressionCallee,
    CallExpressionTypeArguments,
    CallExpressionArguments,
    CallExpressionIsOptional,
    CallExpressionSetTypeArguments,

    IsChainExpression,
    CreateChainExpression,
    ChainExpressionChild,

    IsClassDeclaration,
    CreateClassDeclaration,
    ClassDeclarationDefinition,

    IsClassDefinition,
    CreateClassDefinition,
    ClassDefinitionIdentifier,
    ClassDefinitionTypeParameters,
    ClassDefinitionSuperClass,
    ClassDefinitionImplements,
    ClassDefinitionConstructor,
    ClassDefinitionBody,
    ClassDefinitionSetIdentifier,
    ClassDefinitionSetTypeParameters,
    ClassDefinitionSetSuperClass,
    ClassDefinitionSetImplements,
    ClassDefinitionAddImplements,
    ClassDefinitionSetConstructor,
    ClassDefinitionSetBody,
    ClassDefinitionAddToBody,

    ClassElementKey,
    ClassElementValue,

    IsClassImplementsClause,
    CreateClassImplementsClause,
    ClassImplementsClauseExpression,
    ClassImplementsClauseTypeArguments,

    IsClassProperty,
    CreateClassProperty,
    ClassPropertyTypeAnnotation,

    IsExpressionStatement,
    CreateExpressionStatement,
    ExpressionStatementExpression,

    IsFunctionDeclaration,
    CreateFunctionDeclaration,
    FunctionDeclarationFunction,

    IsFunctionExpression,
    CreateFunctionExpression,
    FunctionExpressionFunction,

    IsFunctionTypeNode,
    CreateFunctionTypeNode,
    FunctionTypeNodeTypeParams,
    FunctionTypeNodeParams,
    FunctionTypeNodeReturnType,
    FunctionTypeNodeFlags,

    IsIdentifier,
    CreateIdentifier,
    IdentifierName,
    IdentifierTypeAnnotation,
    IdentifierVariable,
    IdentifierSetVariable,

    IsIfStatement,
    CreateIfStatement,
    IfStatementTest,
    IfStatementConsequent,
    IfStatementAlternate,

    IsImportDeclaration,
    CreateImportDeclaration,
    ImportDeclarationSource,
    ImportDeclarationSpecifiers,

    IsImportExpression,
    CreateImportExpression,
    ImportExpressionSource,

    IsImportSpecifier,
    CreateImportSpecifier,
    ImportSpecifierImported,
    ImportSpecifierLocal,

    IsMemberExpression,
    CreateMemberExpression,
    MemberExpressionObject,
    MemberExpressionProperty,
    MemberExpressionKind,
    MemberExpressionIsComputed,
    MemberExpressionIsOptional,

    IsMethodDefinition,
    CreateMethodDefinition,
    MethodDefinitionKind,
    MethodDefinitionKey,
    MethodDefinitionValue,
    MethodDefinitionModifiers,
    MethodDefinitionIsComputed,
    MethodDefinitionOverloads,
    MethodDefinitionSetOverloads,
    MethodDefinitionAddOverload,

    IsNewClassInstanceExpression,
    CreateNewClassInstanceExpression,
    NewClassInstanceExpressionTypeReference,
    NewClassInstanceExpressionArguments,
    NewClassInstanceExpressionClassDefinition,

    IsNewArrayInstanceExpression,
    CreateNewArrayInstanceExpression,
    NewArrayInstanceExpressionTypeReference,
    NewArrayInstanceExpressionDimension,

    IsNewMultiDimArrayInstanceExpression,
    CreateNewMultiDimArrayInstanceExpression,
    NewMultiDimArrayInstanceExpressionTypeReference,
    NewMultiDimArrayInstanceExpressionDimensions,

    IsNonNullExpression,
    IsNumberLiteral,
    IsObjectExpression,

    IsParameterDeclaration,
    CreateParameterDeclaration,
    ParameterDeclarationIdentifierOrSpread,
    ParameterDeclarationInitializer,

    IsPrimitiveTypeNode,
    CreatePrimitiveTypeNode,
    PrimitiveTypeNodeType,

    IsReturnStatement,
    CreateReturnStatement,
    ReturnStatementArgument,
    ReturnStatementReturnType,

    IsScriptFunction,
    CreateScriptFunction,
    ScriptFunctionTypeParams,
    ScriptFunctionParams,
    ScriptFunctionReturnTypeAnnotation,
    ScriptFunctionScriptFunctionFlags,
    ScriptFunctionIsDeclare,
    ScriptFunctionIdentifier,
    ScriptFunctionBody,
    ScriptFunctionSetIdentifier,
    ScriptFunctionSetBody,
    ScriptFunctionSetParams,
    ScripFunctionAddParam,

    IsStringLiteral,
    CreateStringLiteral,
    StringLiteralString,

    IsThisExpression,
    CreateThisExpression,

    IsTypeParameter,
    CreateTypeParameter,
    TypeParameterName,
    TypeParameterConstraint,
    TypeParameterDefaultType,

    IsTypeParameterDeclaration,
    CreateTypeParameterDeclaration,
    TypeParameterDeclarationAddTypeParameter,
    TypeParameterDeclarationTypeParameters,

    IsTypeParameterInstantiation,
    CreateTypeParameterInstantiation,
    TypeParameterInstantiationTypeParameters,

    IsTypeReferenceNode,
    CreateTypeReferenceNode,
    TypeReferenceNodePart,

    IsTypeReferencePart,
    CreateTypeReferencePart,
    TypeReferencePartName,
    TypeReferencePartTypeArguments,
    TypeReferencePartPrevious,

    IsUnionTypeNode,
    CreateUnionTypeNode,
    UnionTypeNodeTypes,

    IsVariableDeclaration,
    CreateVariableDeclaration,
    VariableDeclarationKind,
    VariableDeclarationDeclarators,
    VariableDeclarationIsDeclare,

    IsVariableDeclarator,
    CreateVariableDeclarator,
    VariableDeclaratorIdentifier,
    VariableDeclaratorInitializer,
};

}  // namespace panda::es2panda::public_lib

extern "C" es2panda_Impl const *es2panda_GetImpl(int version)
{
    if (version != ES2PANDA_LIB_VERSION) {
        return nullptr;
    }
    return &panda::es2panda::public_lib::IMPL;
}
