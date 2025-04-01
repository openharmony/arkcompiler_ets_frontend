/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
#include "util.h"
#include "public/es2panda_lib.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;

static std::string source = R"(
let a: number = 2;
let b: () => int = () => 2 ;
class A {
    b: number = 2
    c: string = '2'
    f: () => int = () => 2
    get d() : int { return 2}
    set d(v : int) { }
}
function Afoo(this: A) : number { return this.b }
function main() {
    let Ainst = new A();
    a + b();
    Ainst.Afoo() + 1;
    Ainst.f();
    Ainst?.f();
    Ainst.f = () => 2;
    Ainst.c + '1';
    Ainst.c = '2';
    Ainst.d + 2;
    Ainst.d = 2;
    Ainst.c.length + 1;
    Ainst?.c?.length;
    let d : int[] = [1, 2, 3]
    d[Ainst.d];
}
)";

static std::vector<es2panda_AstNode *> *idents = nullptr;
static es2panda_AstNode *mainScriptFunc = nullptr;
static es2panda_Context *ctx = nullptr;

es2panda_AstNode *parNode;
es2panda_Context *newCtx;

static void FindIdentifier(es2panda_AstNode *ast)
{
    if (!impl->IsIdentifier(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindIdentifier);
        return;
    }
    idents->push_back(ast);
    impl->AstNodeIterateConst(ctx, ast, FindIdentifier);
}

static void FindMainDef(es2panda_AstNode *ast)
{
    if (!impl->IsMethodDefinition(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindMainDef);
        return;
    }
    auto scriptFunc = impl->MethodDefinitionFunction(ctx, ast);
    if (scriptFunc == nullptr ||
        std::string("main") != impl->IdentifierName(ctx, impl->ScriptFunctionId(ctx, scriptFunc))) {
        impl->AstNodeIterateConst(ctx, ast, FindMainDef);
        return;
    }
    mainScriptFunc = scriptFunc;
}

static bool FindIdentifierDecl(es2panda_Context *context, es2panda_AstNode *ast)
{
    ctx = context;
    impl->AstNodeIterateConst(context, ast, FindMainDef);
    if (mainScriptFunc == nullptr) {
        std::cerr << "CANT FIND MAIN FUNCTION" << std::endl;
        return false;
    }
    impl->AstNodeIterateConst(context, mainScriptFunc, FindIdentifier);
    for (auto ident : *idents) {
        if (ident == nullptr) {
            std::cerr << "FIND NULL IDENTIFIER" << std::endl;
            return false;
        }
        auto *def = impl->DeclarationFromIdentifier(context, ident);
        if (def == nullptr) {
            std::cerr << "CANT FIND DECLARATION FROM IDENTIFIER" << std::endl;
            return false;
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();
    std::cout << "LOAD SUCCESS" << std::endl;
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = impl->CreateConfig(argc - 1, args);
    auto context = impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
    if (context != nullptr) {
        std::cout << "CREATE CONTEXT SUCCESS" << std::endl;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BOUND);
    CheckForErrors("BOUND", context);

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    CheckForErrors("CHECKED", context);

    auto ast = impl->ProgramAst(context, impl->ContextProgram(context));

    idents = new std::vector<es2panda_AstNode *>();
    auto testResult = FindIdentifierDecl(context, ast);
    delete idents;
    idents = nullptr;
    if (!testResult) {
        return TEST_ERROR_CODE;
    }

    impl->AstNodeRecheck(context, ast);

    impl->ProceedToState(context, ES2PANDA_STATE_LOWERED);
    CheckForErrors("LOWERED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_ASM_GENERATED);
    CheckForErrors("ASM", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    CheckForErrors("BIN", context);
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }
    impl->DestroyContext(context);
    impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
