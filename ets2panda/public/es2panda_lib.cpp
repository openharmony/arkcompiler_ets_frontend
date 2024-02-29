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

#include "es2panda_lib.h"
#include <memory>
#include "compiler/lowering/scopesInit/scopesInitPhase.h"

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

namespace ark::es2panda::public_lib {

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

static ir::ModifierFlags E2pToIrAccessFlags(es2panda_ModifierFlags e2pFlags)
{
    ir::ModifierFlags irFlags {ir::ModifierFlags::NONE};
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_PUBLIC) != 0 ? ir::ModifierFlags::PUBLIC : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_PROTECTED) != 0 ? ir::ModifierFlags::PROTECTED : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_PRIVATE) != 0 ? ir::ModifierFlags::PRIVATE : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_INTERNAL) != 0 ? ir::ModifierFlags::INTERNAL : ir::ModifierFlags::NONE;

    return irFlags;
}

static ir::ModifierFlags E2pToIrMethodFlags(es2panda_ModifierFlags e2pFlags)
{
    ir::ModifierFlags irFlags {ir::ModifierFlags::NONE};
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_STATIC) != 0 ? ir::ModifierFlags::STATIC : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_ABSTRACT) != 0 ? ir::ModifierFlags::ABSTRACT : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_FINAL) != 0 ? ir::ModifierFlags::FINAL : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_NATIVE) != 0 ? ir::ModifierFlags::NATIVE : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_OVERRIDE) != 0 ? ir::ModifierFlags::OVERRIDE : ir::ModifierFlags::NONE;

    return irFlags;
}

static ir::ModifierFlags E2pToIrModifierFlags(es2panda_ModifierFlags e2pFlags)
{
    ir::ModifierFlags irFlags {ir::ModifierFlags::NONE};
    irFlags |= E2pToIrAccessFlags(e2pFlags);
    irFlags |= E2pToIrMethodFlags(e2pFlags);
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_ASYNC) != 0 ? ir::ModifierFlags::ASYNC : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_DECLARE) != 0 ? ir::ModifierFlags::DECLARE : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_READONLY) != 0 ? ir::ModifierFlags::READONLY : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_OPTIONAL) != 0 ? ir::ModifierFlags::OPTIONAL : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_DEFINITE) != 0 ? ir::ModifierFlags::DEFINITE : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_CONST) != 0 ? ir::ModifierFlags::CONST : ir::ModifierFlags::NONE;
    irFlags |=
        (e2pFlags & ES2PANDA_MODIFIER_CONSTRUCTOR) != 0 ? ir::ModifierFlags::CONSTRUCTOR : ir::ModifierFlags::NONE;
    irFlags |=
        (e2pFlags & ES2PANDA_MODIFIER_SYNCHRONIZED) != 0 ? ir::ModifierFlags::SYNCHRONIZED : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_FUNCTIONAL) != 0 ? ir::ModifierFlags::FUNCTIONAL : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_IN) != 0 ? ir::ModifierFlags::IN : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_OUT) != 0 ? ir::ModifierFlags::OUT : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_EXPORT) != 0 ? ir::ModifierFlags::EXPORT : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_SETTER) != 0 ? ir::ModifierFlags::SETTER : ir::ModifierFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_MODIFIER_DEFAULT_EXPORT) != 0 ? ir::ModifierFlags::DEFAULT_EXPORT
                                                                  : ir::ModifierFlags::NONE;

    return irFlags;
}

static es2panda_ModifierFlags IrToE2pAccessFlags(es2panda_ModifierFlags e2pFlags, ir::ModifierFlags irFlags)
{
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::PUBLIC) != 0 ? e2pFlags | ES2PANDA_MODIFIER_PUBLIC : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::PROTECTED) != 0 ? e2pFlags | ES2PANDA_MODIFIER_PROTECTED : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::PRIVATE) != 0 ? e2pFlags | ES2PANDA_MODIFIER_PRIVATE : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::INTERNAL) != 0 ? e2pFlags | ES2PANDA_MODIFIER_INTERNAL : e2pFlags);

    return e2pFlags;
}

static es2panda_ModifierFlags IrToE2pMethodFlags(es2panda_ModifierFlags e2pFlags, ir::ModifierFlags irFlags)
{
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::STATIC) != 0 ? e2pFlags | ES2PANDA_MODIFIER_STATIC : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::ABSTRACT) != 0 ? e2pFlags | ES2PANDA_MODIFIER_ABSTRACT : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::FINAL) != 0 ? e2pFlags | ES2PANDA_MODIFIER_FINAL : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::NATIVE) != 0 ? e2pFlags | ES2PANDA_MODIFIER_NATIVE : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::OVERRIDE) != 0 ? e2pFlags | ES2PANDA_MODIFIER_OVERRIDE : e2pFlags);

    return e2pFlags;
}

static es2panda_ModifierFlags IrToE2pModifierFlags(ir::ModifierFlags irFlags)
{
    es2panda_ModifierFlags e2pFlags {ES2PANDA_MODIFIER_NONE};
    e2pFlags = IrToE2pAccessFlags(e2pFlags, irFlags);
    e2pFlags = IrToE2pMethodFlags(e2pFlags, irFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::ASYNC) != 0 ? e2pFlags | ES2PANDA_MODIFIER_ASYNC : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::DECLARE) != 0 ? e2pFlags | ES2PANDA_MODIFIER_DECLARE : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::READONLY) != 0 ? e2pFlags | ES2PANDA_MODIFIER_READONLY : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::OPTIONAL) != 0 ? e2pFlags | ES2PANDA_MODIFIER_OPTIONAL : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::DEFINITE) != 0 ? e2pFlags | ES2PANDA_MODIFIER_DEFINITE : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::CONST) != 0 ? e2pFlags | ES2PANDA_MODIFIER_CONST : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::CONSTRUCTOR) != 0 ? e2pFlags | ES2PANDA_MODIFIER_CONSTRUCTOR : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::SYNCHRONIZED) != 0 ? e2pFlags | ES2PANDA_MODIFIER_SYNCHRONIZED : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::FUNCTIONAL) != 0 ? e2pFlags | ES2PANDA_MODIFIER_FUNCTIONAL : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::IN) != 0 ? e2pFlags | ES2PANDA_MODIFIER_IN : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::OUT) != 0 ? e2pFlags | ES2PANDA_MODIFIER_OUT : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::EXPORT) != 0 ? e2pFlags | ES2PANDA_MODIFIER_EXPORT : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::SETTER) != 0 ? e2pFlags | ES2PANDA_MODIFIER_SETTER : e2pFlags);
    e2pFlags = static_cast<es2panda_ModifierFlags>(
        (irFlags & ir::ModifierFlags::DEFAULT_EXPORT) != 0 ? e2pFlags | ES2PANDA_MODIFIER_DEFAULT_EXPORT : e2pFlags);

    return e2pFlags;
}

static ir::ScriptFunctionFlags E2pToIrTypeScriptFunctionFlags(es2panda_ScriptFunctionFlags e2pFlags)
{
    ir::ScriptFunctionFlags irFlags {ir::ScriptFunctionFlags::NONE};
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_GENERATOR) != 0 ? ir::ScriptFunctionFlags::GENERATOR
                                                                    : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_ARROW) != 0 ? ir::ScriptFunctionFlags::ARROW
                                                                : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_CONSTRUCTOR) != 0 ? ir::ScriptFunctionFlags::CONSTRUCTOR
                                                                      : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_METHOD) != 0 ? ir::ScriptFunctionFlags::METHOD
                                                                 : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_STATIC_BLOCK) != 0 ? ir::ScriptFunctionFlags::STATIC_BLOCK
                                                                       : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_PROXY) != 0 ? ir::ScriptFunctionFlags::PROXY
                                                                : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_GETTER) != 0 ? ir::ScriptFunctionFlags::GETTER
                                                                 : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_SETTER) != 0 ? ir::ScriptFunctionFlags::SETTER
                                                                 : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_INSTANCE_EXTENSION_METHOD) != 0
                   ? ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD
                   : ir::ScriptFunctionFlags::NONE;

    return irFlags;
}

static ir::ScriptFunctionFlags E2pToIrScriptFunctionFlags(es2panda_ScriptFunctionFlags e2pFlags)
{
    ir::ScriptFunctionFlags irFlags {ir::ScriptFunctionFlags::NONE};
    irFlags |= E2pToIrTypeScriptFunctionFlags(e2pFlags);
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_ASYNC) != 0 ? ir::ScriptFunctionFlags::ASYNC
                                                                : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_EXPRESSION) != 0 ? ir::ScriptFunctionFlags::EXPRESSION
                                                                     : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_OVERLOAD) != 0 ? ir::ScriptFunctionFlags::OVERLOAD
                                                                   : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_HIDDEN) != 0 ? ir::ScriptFunctionFlags::HIDDEN
                                                                 : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_IMPLICIT_SUPER_CALL_NEEDED) != 0
                   ? ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED
                   : ir::ScriptFunctionFlags::NONE;
    irFlags |=
        (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_ENUM) != 0 ? ir::ScriptFunctionFlags::ENUM : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_EXTERNAL) != 0 ? ir::ScriptFunctionFlags::EXTERNAL
                                                                   : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_THROWS) != 0 ? ir::ScriptFunctionFlags::THROWS
                                                                 : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_RETHROWS) != 0 ? ir::ScriptFunctionFlags::RETHROWS
                                                                   : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_ENTRY_POINT) != 0 ? ir::ScriptFunctionFlags::ENTRY_POINT
                                                                      : ir::ScriptFunctionFlags::NONE;
    irFlags |= (e2pFlags & ES2PANDA_SCRIPT_FUNCTION_HAS_RETURN) != 0 ? ir::ScriptFunctionFlags::HAS_RETURN
                                                                     : ir::ScriptFunctionFlags::NONE;

    return irFlags;
}

static es2panda_ScriptFunctionFlags IrToE2pTypeScriptFunctionFlags(es2panda_ScriptFunctionFlags e2pFlags,
                                                                   ir::ScriptFunctionFlags irFlags)
{
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::GENERATOR) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_GENERATOR : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::ARROW) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_ARROW : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::CONSTRUCTOR) != 0
                                                             ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_CONSTRUCTOR
                                                             : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::METHOD) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_METHOD : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::STATIC_BLOCK) != 0
                                                             ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_STATIC_BLOCK
                                                             : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::PROXY) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_PROXY : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::GETTER) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_GETTER : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::SETTER) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_SETTER : e2pFlags);
    e2pFlags =
        static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD) != 0
                                                      ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_INSTANCE_EXTENSION_METHOD
                                                      : e2pFlags);

    return e2pFlags;
}

static es2panda_ScriptFunctionFlags IrToE2pScriptFunctionFlags(ir::ScriptFunctionFlags irFlags)
{
    es2panda_ScriptFunctionFlags e2pFlags {ES2PANDA_SCRIPT_FUNCTION_NONE};
    e2pFlags = IrToE2pTypeScriptFunctionFlags(e2pFlags, irFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::ASYNC) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_ASYNC : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::EXPRESSION) != 0
                                                             ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_EXPRESSION
                                                             : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::OVERLOAD) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_OVERLOAD : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::HIDDEN) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_HIDDEN : e2pFlags);
    e2pFlags =
        static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED) != 0
                                                      ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_IMPLICIT_SUPER_CALL_NEEDED
                                                      : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::ENUM) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_ENUM : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::EXTERNAL) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_EXTERNAL : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::THROWS) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_THROWS : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>(
        (irFlags & ir::ScriptFunctionFlags::RETHROWS) != 0 ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_RETHROWS : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::ENTRY_POINT) != 0
                                                             ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_ENTRY_POINT
                                                             : e2pFlags);
    e2pFlags = static_cast<es2panda_ScriptFunctionFlags>((irFlags & ir::ScriptFunctionFlags::HAS_RETURN) != 0
                                                             ? e2pFlags | ES2PANDA_SCRIPT_FUNCTION_HAS_RETURN
                                                             : e2pFlags);

    return e2pFlags;
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

static void CompileJob(compiler::CompilerContext *context, varbinder::FunctionScope *scope,
                       compiler::ProgramElement *programElement)
{
    compiler::StaticRegSpiller regSpiller;
    ArenaAllocator allocator {SpaceType::SPACE_TYPE_COMPILER, nullptr, true};
    compiler::ETSCompiler astCompiler {};
    compiler::ETSGen cg {&allocator, &regSpiller, context, scope, programElement, &astCompiler};
    compiler::ETSFunctionEmitter funcEmitter {&cg, programElement};
    funcEmitter.Generate();
}

static es2panda_Context *CreateContext(es2panda_Config *config, std::string const &&source,
                                       std::string const &&fileName)
{
    auto *cfg = reinterpret_cast<ConfigImpl *>(config);
    auto *res = new Context;
    res->input = source;
    res->sourceFileName = fileName;

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
        res->analyzer = new checker::ETSAnalyzer(res->checker);
        res->checker->SetAnalyzer(res->analyzer);

        varbinder->SetProgram(res->parserProgram);

        res->compilerContext =
            new compiler::CompilerContext(varbinder, res->checker, cfg->options->CompilerOptions(), CompileJob);
        varbinder->SetCompilerContext(res->compilerContext);
        res->phases = compiler::GetPhaseList(ScriptExtension::ETS);
        res->currentPhase = 0;
        res->emitter = new compiler::ETSEmitter(res->compilerContext);
        res->compilerContext->SetEmitter(res->emitter);
        res->compilerContext->SetParser(res->parser);
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

extern "C" es2panda_Context *CreateContextFromFile(es2panda_Config *config, char const *sourceFileName)
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

extern "C" es2panda_Context *CreateContextFromString(es2panda_Config *config, char const *source, char const *fileName)
{
    // NOTE: gogabr. avoid copying source.
    return CreateContext(config, source, fileName);
}

static Context *Parse(Context *ctx)
{
    if (ctx->state != ES2PANDA_STATE_NEW) {
        ctx->state = ES2PANDA_STATE_ERROR;
        ctx->errorMessage = "Bad state at entry to Parse, needed NEW";
        return ctx;
    }
    try {
        ctx->parser->ParseScript(*ctx->sourceFile,
                                 ctx->compilerContext->Options()->compilationMode == CompilationMode::GEN_STD_LIB);
        ctx->parserProgram = ctx->compilerContext->VarBinder()->Program();
        ctx->state = ES2PANDA_STATE_PARSED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
        ctx->state = ES2PANDA_STATE_ERROR;
    }

    return ctx;
}

static Context *InitScopes(Context *ctx)
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
        } while (ctx->phases[ctx->currentPhase++]->Name() != "scopes");
        ctx->state = ES2PANDA_STATE_SCOPE_INITED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
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

    ASSERT(ctx->state >= ES2PANDA_STATE_PARSED && ctx->state < ES2PANDA_STATE_CHECKED);

    try {
        do {
            if (ctx->currentPhase >= ctx->phases.size()) {
                break;
            }

            ctx->phases[ctx->currentPhase]->Apply(ctx, ctx->parserProgram);
        } while (ctx->phases[ctx->currentPhase++]->Name() != "checker");
        ctx->state = ES2PANDA_STATE_CHECKED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
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

static Context *GenerateAsm(Context *ctx)
{
    if (ctx->state < ES2PANDA_STATE_LOWERED) {
        ctx = Lower(ctx);
    }

    if (ctx->state == ES2PANDA_STATE_ERROR) {
        return ctx;
    }

    ASSERT(ctx->state == ES2PANDA_STATE_LOWERED);

    auto *emitter = ctx->compilerContext->GetEmitter();
    try {
        emitter->GenAnnotation();

        // Handle context literals.
        uint32_t index = 0;
        for (const auto &buff : ctx->compilerContext->ContextLiterals()) {
            emitter->AddLiteralBuffer(buff, index++);
        }

        emitter->LiteralBufferIndex() += ctx->compilerContext->ContextLiterals().size();

        /* Main thread can also be used instead of idling */
        ctx->queue->Schedule(ctx->compilerContext);
        ctx->queue->Consume();
        ctx->queue->Wait(
            [emitter](compiler::CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });
        ASSERT(ctx->program == nullptr);
        ctx->program = emitter->Finalize(ctx->compilerContext->DumpDebugInfo(), compiler::Signatures::ETS_GLOBAL);

        ctx->state = ES2PANDA_STATE_ASM_GENERATED;
    } catch (Error &e) {
        std::stringstream ss;
        ss << e.TypeString() << ": " << e.Message() << "[" << e.File() << ":" << e.Line() << "," << e.Col() << "]";
        ctx->errorMessage = ss.str();
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

extern "C" es2panda_Context *ProceedToState(es2panda_Context *context, es2panda_ContextState state)
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

extern "C" void DestroyContext(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    delete ctx->program;
    delete ctx->emitter;
    delete ctx->compilerContext;
    delete ctx->analyzer;
    delete ctx->checker;
    delete ctx->parser;
    delete ctx->parserProgram;
    delete ctx->queue;
    delete ctx->allocator;
    delete ctx->sourceFile;
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
    return s->errorMessage.c_str();
}

extern "C" es2panda_Program *ContextProgram(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    return reinterpret_cast<es2panda_Program *>(ctx->compilerContext->VarBinder()->Program());
}

extern "C" es2panda_AstNode *ProgramAst(es2panda_Program *program)
{
    auto *pgm = reinterpret_cast<parser::Program *>(program);
    return reinterpret_cast<es2panda_AstNode *>(pgm->Ast());
}

using ExternalSourceEntry = std::pair<char const *, ArenaVector<parser::Program *> *>;

extern "C" es2panda_ExternalSource **ProgramExternalSources(es2panda_Program *program, size_t *lenP)
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

extern "C" char const *ExternalSourceName(es2panda_ExternalSource *eSource)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(eSource);
    return entry->first;
}

extern "C" es2panda_Program **ExternalSourcePrograms(es2panda_ExternalSource *eSource, size_t *lenP)
{
    auto *entry = reinterpret_cast<ExternalSourceEntry *>(eSource);
    *lenP = entry->second->size();
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

extern "C" es2panda_AstNode *const *AstNodeDecorators(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    if (node->CanHaveDecorator(false)) {
        auto *decorators = node->DecoratorsPtr();
        *sizeP = decorators->size();
        return reinterpret_cast<es2panda_AstNode *const *>(decorators->data());
    }
    *sizeP = 0;
    return nullptr;
}

extern "C" es2panda_ModifierFlags AstNodeModifierFlags(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast);
    return IrToE2pModifierFlags(node->Modifiers());
}

extern "C" void AstNodeSetDecorators(es2panda_Context *context, es2panda_AstNode *ast, es2panda_AstNode **decorators,
                                     size_t nDecorators)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *node = reinterpret_cast<ir::AstNode *>(ast);

    ArenaVector<ir::Decorator *> decoratorsVector {allocator->Adapter()};
    for (size_t i = 0; i < nDecorators; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        decoratorsVector.push_back(reinterpret_cast<ir::AstNode *>(decorators[i])->AsDecorator());
    }
    node->AddDecorators(std::move(decoratorsVector));
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

extern "C" es2panda_AstNode *CreateArrowFunctionExpression(es2panda_Context *context, es2panda_AstNode *scriptFunction)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *func = reinterpret_cast<ir::AstNode *>(scriptFunction)->AsScriptFunction();
    auto *allocator = ctx->allocator;

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ArrowFunctionExpression>(allocator, func));
}

extern "C" es2panda_AstNode *ArrowFunctionExpressionScriptFunction(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsArrowFunctionExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->Function());
}

extern "C" es2panda_AstNode *CreateAsExpression(es2panda_Context *context, es2panda_AstNode *expr,
                                                es2panda_AstNode *typeAnnotation, bool isConst)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *leftExpr = reinterpret_cast<ir::AstNode *>(expr)->AsExpression();
    auto *tp = reinterpret_cast<ir::AstNode *>(typeAnnotation)->AsExpression()->AsTypeNode();
    auto *allocator = ctx->allocator;

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSAsExpression>(leftExpr, tp, isConst));
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
    auto *newExpr = reinterpret_cast<ir::AstNode *>(expr)->AsExpression();
    node->SetExpr(newExpr);
}

extern "C" void AsExpressionSetTypeAnnotation(es2panda_AstNode *ast, es2panda_AstNode *typeAnnotation)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSAsExpression();
    auto *tp = reinterpret_cast<ir::AstNode *>(typeAnnotation)->AsExpression()->AsTypeNode();
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
                                                        es2panda_AstNode *right, char const *operatorType)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *leftNode = reinterpret_cast<ir::AstNode *>(left)->AsExpression();
    auto *rightNode = reinterpret_cast<ir::AstNode *>(right)->AsExpression();
    lexer::TokenType tok = StrToToken(ASSIGNMENT_TOKEN_TYPES.data(), operatorType);
    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::AssignmentExpression>(leftNode, rightNode, tok));
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

extern "C" void AssignmentExpressionSetOperatorType(es2panda_AstNode *ast, char const *operatorType)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsAssignmentExpression();
    auto tok = StrToToken(ASSIGNMENT_TOKEN_TYPES.data(), operatorType);
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
                                                    es2panda_AstNode *right, char const *operatorType)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *leftExpr = reinterpret_cast<ir::AstNode *>(left)->AsExpression();
    auto *rightExpr = reinterpret_cast<ir::AstNode *>(right)->AsExpression();
    auto tok = StrToToken(BINARY_OP_TOKEN_TYPES.data(), operatorType);

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::BinaryExpression>(leftExpr, rightExpr, tok));
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

extern "C" void BinaryExpressionSetOperator(es2panda_AstNode *ast, char const *operatorType)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBinaryExpression();
    auto op = StrToToken(BINARY_OP_TOKEN_TYPES.data(), operatorType);
    node->SetOperator(op);
}

extern "C" es2panda_AstNode *CreateBlockStatement(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Statement *> stmts {allocator->Adapter()};
    auto block = allocator->New<ir::BlockStatement>(allocator, std::move(stmts));
    return reinterpret_cast<es2panda_AstNode *>(block);
}

extern "C" es2panda_AstNode **BlockStatementStatements(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBlockStatement();
    *sizeP = node->Statements().size();
    return reinterpret_cast<es2panda_AstNode **>(node->Statements().data());
}

extern "C" void BlockStatementAddStatement(es2panda_AstNode *ast, es2panda_AstNode *statement)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsBlockStatement();
    auto *stmt = reinterpret_cast<ir::AstNode *>(statement)->AsBlockStatement();
    node->Statements().push_back(stmt);
    stmt->SetParent(node);
}

extern "C" es2panda_AstNode *CreateCallExpression(es2panda_Context *context, es2panda_AstNode *callee,
                                                  es2panda_AstNode *typeArguments, es2panda_AstNode **arguments,
                                                  size_t nArguments, bool isOptional)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *calleeNode = reinterpret_cast<ir::AstNode *>(callee)->AsExpression();

    ir::TSTypeParameterInstantiation *typeArgs = nullptr;
    if (typeArguments != nullptr) {
        typeArgs = reinterpret_cast<ir::AstNode *>(typeArguments)->AsTSTypeParameterInstantiation();
    }

    ArenaVector<ir::Expression *> args {allocator->Adapter()};
    for (size_t i = 0; i < nArguments; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        args.push_back(reinterpret_cast<ir::AstNode *>(arguments[i])->AsExpression());
    }
    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::CallExpression>(calleeNode, std::move(args), typeArgs, isOptional));
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

extern "C" es2panda_AstNode **CallExpressionArguments(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    *sizeP = node->Arguments().size();
    return reinterpret_cast<es2panda_AstNode **>(node->Arguments().data());
}

extern "C" bool CallExpressionIsOptional(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    return node->IsOptional();
}

extern "C" void CallExpressionSetTypeArguments(es2panda_AstNode *ast, es2panda_AstNode *typeArguments)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsCallExpression();
    auto *typeArgs = reinterpret_cast<ir::AstNode *>(typeArguments)->AsTSTypeParameterInstantiation();
    node->SetTypeParams(typeArgs);
}

extern "C" es2panda_AstNode *CreateChainExpression(es2panda_Context *context, es2panda_AstNode *child)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *childExpr = reinterpret_cast<ir::AstNode *>(child)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ChainExpression>(childExpr));
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

extern "C" es2panda_AstNode *CreateClassDefinition(es2panda_Context *context, es2panda_AstNode *identifier,
                                                   es2panda_ModifierFlags flags)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();

    auto classDef =
        allocator->New<ir::ClassDefinition>(allocator, id, ir::ClassDefinitionModifiers::NONE,
                                            E2pToIrModifierFlags(flags), Language::FromString("ets").value());
    return reinterpret_cast<es2panda_AstNode *>(classDef);
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

extern "C" es2panda_AstNode **ClassDefinitionImplements(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &implVec = node->Implements();
    *sizeP = implVec.size();
    return reinterpret_cast<es2panda_AstNode **>(implVec.data());
}

extern "C" es2panda_AstNode *ClassDefinitionConstructor(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    return reinterpret_cast<es2panda_AstNode *>(node->Ctor());
}

extern "C" es2panda_AstNode **ClassDefinitionBody(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &bodyVec = node->Body();
    *sizeP = bodyVec.size();
    return reinterpret_cast<es2panda_AstNode **>(bodyVec.data());
}

extern "C" void ClassDefinitionSetIdentifier(es2panda_AstNode *ast, es2panda_AstNode *identifier)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *id = reinterpret_cast<ir::AstNode *>(identifier)->AsIdentifier();
    node->SetIdent(id);
}

extern "C" void ClassDefinitionSetTypeParameters(es2panda_AstNode *ast, es2panda_AstNode *typeParams)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *tpd = reinterpret_cast<ir::AstNode *>(typeParams)->AsTSTypeParameterDeclaration();
    node->SetTypeParams(tpd);
}

extern "C" void ClassDefinitionSetSuperClass(es2panda_AstNode *ast, es2panda_AstNode *superClass)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *super = reinterpret_cast<ir::AstNode *>(superClass)->AsExpression();
    node->SetSuper(super);
}

extern "C" void ClassDefinitionSetImplements(es2panda_AstNode *ast, es2panda_AstNode **implements, size_t nImplements)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &implVec = node->Implements();
    implVec.resize(0);
    for (size_t i = 0; i < nImplements; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        implVec.push_back(reinterpret_cast<ir::AstNode *>(implements[i])->AsTSClassImplements());
    }
}

extern "C" void ClassDefinitionAddImplements(es2panda_AstNode *ast, es2panda_AstNode *implements)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &implVec = node->Implements();
    implVec.push_back(reinterpret_cast<ir::AstNode *>(implements)->AsTSClassImplements());
}

extern "C" void ClassDefinitionSetConstructor(es2panda_AstNode *ast, es2panda_AstNode *constructor)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *ctor = reinterpret_cast<ir::AstNode *>(constructor)->AsMethodDefinition();
    node->SetCtor(ctor);
}

extern "C" void ClassDefinitionSetBody(es2panda_AstNode *ast, es2panda_AstNode **body, size_t nElems)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto &bodyVec = node->Body();
    bodyVec.resize(0);
    for (size_t i = 0; i < nElems; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        bodyVec.push_back(reinterpret_cast<ir::AstNode *>(body[i]));
    }
}

extern "C" void ClassDefinitionAddToBody(es2panda_AstNode *ast, es2panda_AstNode *bodyElem)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsClassDefinition();
    auto *elem = reinterpret_cast<ir::AstNode *>(bodyElem);
    auto &bodyVec = node->Body();
    bodyVec.push_back(reinterpret_cast<ir::AstNode *>(elem));
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
                                                         es2panda_AstNode *typeArguments)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *expr = reinterpret_cast<ir::AstNode *>(expression)->AsExpression();
    auto *targs = typeArguments == nullptr
                      ? nullptr
                      : reinterpret_cast<ir::AstNode *>(typeArguments)->AsTSTypeParameterInstantiation();

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
                                                 es2panda_AstNode *value, es2panda_AstNode *typeAnnotation,
                                                 es2panda_ModifierFlags modifierFlags, bool isComputed)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *ekey = reinterpret_cast<ir::AstNode *>(key)->AsExpression();
    auto *evalue = value == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(value)->AsExpression();
    auto *tpAnn = typeAnnotation == nullptr
                      ? nullptr
                      : reinterpret_cast<ir::AstNode *>(typeAnnotation)->AsExpression()->AsTypeNode();
    auto modifiers = E2pToIrModifierFlags(modifierFlags);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ClassProperty>(ekey, evalue, tpAnn, modifiers, allocator, isComputed));
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

extern "C" es2panda_AstNode *CreateFunctionTypeNode(es2panda_Context *context, es2panda_AstNode *typeParams,
                                                    es2panda_AstNode **params, size_t nParams,
                                                    es2panda_AstNode *returnType,
                                                    es2panda_ScriptFunctionFlags funcFlags)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *tpar =
        typeParams == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(typeParams)->AsTSTypeParameterDeclaration();
    auto *tret =
        returnType == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(returnType)->AsExpression()->AsTypeNode();
    auto flags = E2pToIrScriptFunctionFlags(funcFlags);

    ArenaVector<ir::Expression *> par {allocator->Adapter()};
    for (size_t i = 0; i < nParams; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        par.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }

    auto signature = ir::FunctionSignature(tpar, std::move(par), tret);
    auto func = allocator->New<ir::ETSFunctionType>(std::move(signature), flags);
    return reinterpret_cast<es2panda_AstNode *>(func);
}

extern "C" es2panda_AstNode const *FunctionTypeNodeTypeParams(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    return reinterpret_cast<es2panda_AstNode const *>(node->TypeParams());
}

extern "C" es2panda_AstNode *const *FunctionTypeNodeParams(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSFunctionType();
    auto &params = node->Params();
    *sizeP = params.size();
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
                                              es2panda_AstNode *typeAnnotations)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *nameCopy = ArenaStrdup(ctx->allocator, name);
    auto *tpAnn = typeAnnotations == nullptr
                      ? nullptr
                      : reinterpret_cast<ir::AstNode *>(typeAnnotations)->AsExpression()->AsTypeNode();

    auto *res = allocator->New<ir::Identifier>(util::StringView {nameCopy}, tpAnn, allocator);

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
    auto *ifStat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(ifStat->Test());
}

extern "C" es2panda_AstNode const *IfStatementConsequent(es2panda_AstNode *identifier)
{
    auto *ifStat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(ifStat->Consequent());
}

extern "C" es2panda_AstNode const *IfStatementAlternate(es2panda_AstNode *identifier)
{
    auto *ifStat = reinterpret_cast<ir::AstNode *>(identifier)->AsIfStatement();

    return reinterpret_cast<es2panda_AstNode const *>(ifStat->Alternate());
}

extern "C" es2panda_AstNode *CreateImportDeclaration(es2panda_Context *context, es2panda_AstNode *source,
                                                     es2panda_AstNode **specifiers, size_t nSpecifiers)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *src = reinterpret_cast<ir::AstNode *>(source)->AsStringLiteral();

    ArenaVector<ir::AstNode *> specs {allocator->Adapter()};
    for (size_t i = 0; i < nSpecifiers; i++) {
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

extern "C" es2panda_AstNode *const *ImportDeclarationSpecifiers(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *decl = reinterpret_cast<ir::AstNode *>(ast)->AsImportDeclaration();
    auto &specs = decl->Specifiers();

    *sizeP = specs.size();

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
    auto *irImported = reinterpret_cast<ir::AstNode *>(imported)->AsIdentifier();
    auto *irLocal = reinterpret_cast<ir::AstNode *>(local)->AsIdentifier();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ImportSpecifier>(irImported, irLocal));
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

static ir::MemberExpressionKind E2pToIrMemberExpressionKind(es2panda_MemberExpressionKind e2pKind)
{
    ir::MemberExpressionKind irKind = ir::MemberExpressionKind::NONE;
    irKind |= (e2pKind & ES2PANDA_MEMBER_EXPRESSION_KIND_ELEMENT_ACCESS) != 0 ? ir::MemberExpressionKind::ELEMENT_ACCESS
                                                                              : ir::MemberExpressionKind::NONE;
    irKind |= (e2pKind & ES2PANDA_MEMBER_EXPRESSION_KIND_PROPERTY_ACCESS) != 0
                  ? ir::MemberExpressionKind::PROPERTY_ACCESS
                  : ir::MemberExpressionKind::NONE;
    irKind |= (e2pKind & ES2PANDA_MEMBER_EXPRESSION_KIND_GETTER) != 0 ? ir::MemberExpressionKind::GETTER
                                                                      : ir::MemberExpressionKind::NONE;
    irKind |= (e2pKind & ES2PANDA_MEMBER_EXPRESSION_KIND_SETTER) != 0 ? ir::MemberExpressionKind::SETTER
                                                                      : ir::MemberExpressionKind::NONE;

    return irKind;
}

static es2panda_MemberExpressionKind IrToE2pMemberExpressionKind(ir::MemberExpressionKind irKind)
{
    es2panda_MemberExpressionKind e2pKind = ES2PANDA_MEMBER_EXPRESSION_KIND_NONE;
    e2pKind = static_cast<es2panda_MemberExpressionKind>((irKind & ir::MemberExpressionKind::ELEMENT_ACCESS) != 0
                                                             ? e2pKind | ES2PANDA_MEMBER_EXPRESSION_KIND_ELEMENT_ACCESS
                                                             : e2pKind);
    e2pKind = static_cast<es2panda_MemberExpressionKind>((irKind & ir::MemberExpressionKind::PROPERTY_ACCESS) != 0
                                                             ? e2pKind | ES2PANDA_MEMBER_EXPRESSION_KIND_PROPERTY_ACCESS
                                                             : e2pKind);
    e2pKind = static_cast<es2panda_MemberExpressionKind>(
        (irKind & ir::MemberExpressionKind::GETTER) != 0 ? e2pKind | ES2PANDA_MEMBER_EXPRESSION_KIND_GETTER : e2pKind);
    e2pKind = static_cast<es2panda_MemberExpressionKind>(
        (irKind & ir::MemberExpressionKind::SETTER) != 0 ? e2pKind | ES2PANDA_MEMBER_EXPRESSION_KIND_SETTER : e2pKind);

    return e2pKind;
}

extern "C" es2panda_AstNode *CreateMemberExpression(es2panda_Context *context, es2panda_AstNode *object,
                                                    es2panda_AstNode *property, es2panda_MemberExpressionKind kind,
                                                    bool isComputed, bool isOptional)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto irObject = reinterpret_cast<ir::AstNode *>(object)->AsExpression();
    auto irProperty = reinterpret_cast<ir::AstNode *>(property)->AsExpression();
    auto irKind = E2pToIrMemberExpressionKind(kind);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::MemberExpression>(irObject, irProperty, irKind, isComputed, isOptional));
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
                                                    bool isComputed)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto irKind = StrToMethodDefinitionKind(kind);
    auto *irKey = reinterpret_cast<ir::AstNode *>(key)->AsExpression();
    auto *irValue = reinterpret_cast<ir::AstNode *>(value)->AsExpression();
    auto irFlags = E2pToIrModifierFlags(modifiers);

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::MethodDefinition>(irKind, irKey, irValue, irFlags, allocator, isComputed));
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

extern "C" es2panda_AstNode *const *MethodDefinitionOverloads(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    auto const &overloads = node->Overloads();
    *sizeP = overloads.size();
    return reinterpret_cast<es2panda_AstNode *const *>(overloads.data());
}

extern "C" void MethodDefinitionSetOverloads(es2panda_AstNode *ast, es2panda_AstNode **overloads, size_t nOverloads)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    ArenaVector<ir::MethodDefinition *> irOverloads {node->Overloads().get_allocator()};
    irOverloads.reserve(nOverloads);
    for (size_t i = 0; i < nOverloads; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irOverloads.push_back(reinterpret_cast<ir::AstNode *>(overloads[i])->AsMethodDefinition());
    }
    node->SetOverloads(std::move(irOverloads));
}

extern "C" void MethodDefinitionAddOverload(es2panda_AstNode *ast, es2panda_AstNode *overload)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsMethodDefinition();
    auto *irOverload = reinterpret_cast<ir::AstNode *>(overload)->AsMethodDefinition();
    node->AddOverload(irOverload);
}

extern "C" es2panda_AstNode *CreateNewClassInstanceExpression(es2panda_Context *context,
                                                              es2panda_AstNode *typeReference,
                                                              es2panda_AstNode **arguments, size_t nArguments,
                                                              es2panda_AstNode *classDefinition)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irTyperef = reinterpret_cast<ir::AstNode *>(typeReference)->AsExpression();

    ArenaVector<ir::Expression *> args {allocator->Adapter()};
    for (size_t i = 0; i < nArguments; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        args.push_back(reinterpret_cast<ir::AstNode *>(arguments[i])->AsExpression());
    }

    auto *irClassdef =
        classDefinition == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(classDefinition)->AsClassDefinition();

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSNewClassInstanceExpression>(irTyperef, std::move(args), irClassdef));
}

extern "C" es2panda_AstNode *NewClassInstanceExpressionTypeReference(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->GetTypeRef());
}

extern "C" es2panda_AstNode *const *NewClassInstanceExpressionArguments(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    auto const &args = node->GetArguments();

    *sizeP = args.size();
    return reinterpret_cast<es2panda_AstNode *const *>(args.data());
}

extern "C" es2panda_AstNode *NewClassInstanceExpressionClassDefinition(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewClassInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->ClassDefinition());
}

extern "C" es2panda_AstNode *CreateNewArrayInstanceExpression(es2panda_Context *context,
                                                              es2panda_AstNode *typeReference,
                                                              es2panda_AstNode *dimension)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irTyperef = reinterpret_cast<ir::AstNode *>(typeReference)->AsExpression()->AsTypeNode();
    auto *irDim = reinterpret_cast<ir::AstNode *>(dimension)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSNewArrayInstanceExpression>(irTyperef, irDim));
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
                                                                      es2panda_AstNode *typeReference,
                                                                      es2panda_AstNode **dimensions, size_t nDimensions)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irTyperef = reinterpret_cast<ir::AstNode *>(typeReference)->AsExpression()->AsTypeNode();

    ArenaVector<ir::Expression *> irDims {allocator->Adapter()};
    for (size_t i = 0; i < nDimensions; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irDims.push_back(reinterpret_cast<ir::AstNode *>(dimensions[i])->AsExpression());
    }

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSNewMultiDimArrayInstanceExpression>(irTyperef, std::move(irDims)));
}

extern "C" es2panda_AstNode *NewMultiDimArrayInstanceExpressionTypeReference(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewMultiDimArrayInstanceExpression();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeReference());
}

extern "C" es2panda_AstNode *const *NewMultiDimArrayInstanceExpressionDimensions(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsETSNewMultiDimArrayInstanceExpression();
    auto const &dims = node->Dimensions();

    *sizeP = dims.size();
    return reinterpret_cast<es2panda_AstNode *const *>(dims.data());
}

extern "C" es2panda_AstNode *CreateParameterDeclaration(es2panda_Context *context, es2panda_AstNode *identifierOrSpread,
                                                        es2panda_AstNode *initializer)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    auto *irIdentOrSpreadRaw = reinterpret_cast<ir::AstNode *>(identifierOrSpread)->AsExpression();
    ir::AnnotatedExpression *irIdentOrSpread;
    if (irIdentOrSpreadRaw->IsIdentifier()) {
        irIdentOrSpread = irIdentOrSpreadRaw->AsIdentifier();
    } else if (irIdentOrSpreadRaw->IsSpreadElement()) {
        irIdentOrSpread = irIdentOrSpreadRaw->AsSpreadElement();
    } else {
        UNREACHABLE();
    }

    auto *irInitializer =
        initializer == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(initializer)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::ETSParameterExpression>(irIdentOrSpread, irInitializer));
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
    auto *irArg = argument == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(argument)->AsExpression();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ReturnStatement>(irArg));
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

extern "C" es2panda_AstNode *CreateScriptFunction(es2panda_Context *context, es2panda_AstNode *typeParams,
                                                  es2panda_AstNode **params, size_t nParams,
                                                  es2panda_AstNode *returnTypeAnnotation,
                                                  es2panda_ScriptFunctionFlags functionFlags,
                                                  es2panda_ModifierFlags modifierFlags, bool isDeclare)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irTypeParams =
        typeParams == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(typeParams)->AsTSTypeParameterDeclaration();

    ArenaVector<ir::Expression *> irParams {allocator->Adapter()};
    for (size_t i = 0; i < nParams; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irParams.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }

    auto irReturnTypeAnnotation =
        returnTypeAnnotation == nullptr
            ? nullptr
            : reinterpret_cast<ir::AstNode *>(returnTypeAnnotation)->AsExpression()->AsTypeNode();

    auto irFunctionFlags = E2pToIrScriptFunctionFlags(functionFlags);
    auto irModifierFlags = E2pToIrModifierFlags(modifierFlags);

    ir::FunctionSignature sig(irTypeParams, std::move(irParams), irReturnTypeAnnotation);
    auto func = allocator->New<ir::ScriptFunction>(
        allocator,
        ir::ScriptFunction::ScriptFunctionData {nullptr, std::move(sig), irFunctionFlags, irModifierFlags, isDeclare});
    return reinterpret_cast<es2panda_AstNode *>(func);
}

extern "C" es2panda_AstNode *ScriptFunctionTypeParams(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    return reinterpret_cast<es2panda_AstNode *>(node->TypeParams());
}

extern "C" es2panda_AstNode *const *ScriptFunctionParams(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto &params = node->Params();

    *sizeP = params.size();
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
    auto *irBody = reinterpret_cast<ir::AstNode *>(body);

    node->SetBody(irBody);
}

extern "C" void ScriptFunctionSetParams(es2panda_AstNode *ast, es2panda_AstNode **params, size_t nParams)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto &irParams = node->Params();

    irParams.clear();
    for (size_t i = 0; i < nParams; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irParams.push_back(reinterpret_cast<ir::AstNode *>(params[i])->AsExpression());
    }
}

extern "C" void ScripFunctionAddParam(es2panda_AstNode *ast, es2panda_AstNode *param)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsScriptFunction();
    auto *irParam = reinterpret_cast<ir::AstNode *>(param)->AsExpression();

    node->Params().push_back(irParam);
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
                                                 es2panda_AstNode *constraint, es2panda_AstNode *defaultType)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *nm = reinterpret_cast<ir::AstNode *>(name)->AsIdentifier();
    auto *constr =
        constraint == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(constraint)->AsExpression()->AsTypeNode();
    auto *dflt =
        defaultType == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(defaultType)->AsExpression()->AsTypeNode();

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

extern "C" es2panda_AstNode *CreateTypeParameterDeclaration(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::TSTypeParameter *> params {allocator->Adapter()};
    auto typeParams = allocator->New<ir::TSTypeParameterDeclaration>(std::move(params), 0);
    return reinterpret_cast<es2panda_AstNode *>(typeParams);
}

extern "C" void TypeParameterDeclarationAddTypeParameter(es2panda_AstNode *ast, es2panda_AstNode *typeParameter)
{
    auto *tpd = reinterpret_cast<ir::AstNode *>(ast)->AsTSTypeParameterDeclaration();
    auto *param = reinterpret_cast<ir::AstNode *>(typeParameter)->AsTSTypeParameter();

    tpd->AddParam(param);
}

extern "C" es2panda_AstNode *const *TypeParameterDeclarationTypeParameters(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *tpd = reinterpret_cast<ir::AstNode const *>(ast)->AsTSTypeParameterDeclaration();
    auto const &params = tpd->Params();
    *sizeP = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *CreateTypeParameterInstantiation(es2panda_Context *context,
                                                              es2panda_AstNode **typeParameters, size_t nParams)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::TypeNode *> params {allocator->Adapter()};
    for (size_t i = 0; i < nParams; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        params.push_back(reinterpret_cast<ir::AstNode *>(typeParameters[i])->AsExpression()->AsTypeNode());
    }
    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSTypeParameterInstantiation>(std::move(params)));
}

extern "C" es2panda_AstNode *const *TypeParameterInstantiationTypeParameters(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *tpi = reinterpret_cast<ir::AstNode const *>(ast)->AsTSTypeParameterInstantiation();
    auto const &params = tpi->Params();
    *sizeP = params.size();
    return reinterpret_cast<es2panda_AstNode *const *>(params.data());
}

extern "C" es2panda_AstNode *CreateTypeReferenceNode(es2panda_Context *context, es2panda_AstNode *part)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irPart = reinterpret_cast<ir::AstNode *>(part)->AsETSTypeReferencePart();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSTypeReference>(irPart));
}

extern "C" es2panda_AstNode *TypeReferenceNodePart(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode const *>(ast)->AsETSTypeReference();
    return reinterpret_cast<es2panda_AstNode *>(node->Part());
}

extern "C" es2panda_AstNode *CreateTypeReferencePart(es2panda_Context *context, es2panda_AstNode *name,
                                                     es2panda_AstNode *typeArguments, es2panda_AstNode *previous)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto *irName = reinterpret_cast<ir::AstNode *>(name)->AsExpression();
    auto *irTypeArgs = typeArguments == nullptr
                           ? nullptr
                           : reinterpret_cast<ir::AstNode *>(typeArguments)->AsTSTypeParameterInstantiation();
    auto *irPrev = previous == nullptr ? nullptr : reinterpret_cast<ir::AstNode *>(previous)->AsETSTypeReferencePart();

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::ETSTypeReferencePart>(irName, irTypeArgs, irPrev));
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

extern "C" es2panda_AstNode *CreateUnionTypeNode(es2panda_Context *context, es2panda_AstNode **types, size_t nTypes)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;

    ArenaVector<ir::TypeNode *> irTypes {allocator->Adapter()};
    for (size_t i = 0; i < nTypes; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irTypes.push_back(reinterpret_cast<ir::AstNode *>(types[i])->AsExpression()->AsTypeNode());
    }

    return reinterpret_cast<es2panda_AstNode *>(allocator->New<ir::TSUnionType>(std::move(irTypes)));
}

extern "C" es2panda_AstNode *const *UnionTypeNodeTypes(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsTSUnionType();
    auto &irTypes = node->Types();

    *sizeP = irTypes.size();
    return reinterpret_cast<es2panda_AstNode *const *>(irTypes.data());
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
                                                       es2panda_AstNode **declarators, size_t nDeclarators,
                                                       bool isDeclare)
{
    auto *ctx = reinterpret_cast<Context *>(context);
    auto *allocator = ctx->allocator;
    auto irKind = StrToVariableDeclarationKind(kind);

    ArenaVector<ir::VariableDeclarator *> irDeclarators {allocator->Adapter()};
    for (size_t i = 0; i < nDeclarators; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        irDeclarators.push_back(reinterpret_cast<ir::AstNode *>(declarators[i])->AsVariableDeclarator());
    }

    return reinterpret_cast<es2panda_AstNode *>(
        allocator->New<ir::VariableDeclaration>(irKind, allocator, std::move(irDeclarators), isDeclare));
}

extern "C" char const *VariableDeclarationKind(es2panda_AstNode *ast)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclaration();
    return VariableDeclarationKindToStr(node->Kind());
}

extern "C" es2panda_AstNode *const *VariableDeclarationDeclarators(es2panda_AstNode *ast, size_t *sizeP)
{
    auto *node = reinterpret_cast<ir::AstNode *>(ast)->AsVariableDeclaration();
    auto const &declarators = node->Declarators();
    *sizeP = declarators.size();
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

    auto varDecl = allocator->New<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::UNKNOWN, ident, init);
    return reinterpret_cast<es2panda_AstNode *>(varDecl);
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

}  // namespace ark::es2panda::public_lib

extern "C" es2panda_Impl const *es2panda_GetImpl(int version)
{
    if (version != ES2PANDA_LIB_VERSION) {
        return nullptr;
    }
    return &ark::es2panda::public_lib::g_impl;
}
