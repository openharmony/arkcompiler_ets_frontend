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
function goo() : int { return 2}
function goo(a: int) : int { return a}
class A {
    foo() : int { return 2}
    clen: (p: string) => number = (p: string) => p.length + 1
    foo(a: int) : int { return a}
}
function Afoo(this: A) : number { return 2 }
function main() {
    let a = new A();
    a.foo(2);
    a.foo();
    a?.foo();
    a?.foo(2);
    a.clen('1');
    a.Afoo();
    a.clen = (p: string) => p.length + 2
    goo(2);
    goo();
})";

static std::vector<es2panda_AstNode *> *memberExprs = nullptr;
static std::vector<es2panda_AstNode *> *callExprs = nullptr;
static es2panda_AstNode *scriptFunc = nullptr;
static es2panda_Context *ctx = nullptr;

es2panda_AstNode *parNode;
es2panda_Context *newCtx;

static void FindMemberExpr(es2panda_AstNode *ast)
{
    if (!impl->IsMemberExpression(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindMemberExpr);
        return;
    }
    memberExprs->push_back(ast);
    impl->AstNodeIterateConst(ctx, ast, FindMemberExpr);
}

static void FindScriptFunc(es2panda_AstNode *ast)
{
    if (!impl->IsScriptFunction(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindScriptFunc);
        return;
    }
    scriptFunc = ast;
}

static void FindCallExpr(es2panda_AstNode *ast)
{
    if (!impl->IsCallExpression(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindCallExpr);
        return;
    }
    callExprs->push_back(ast);
    impl->AstNodeIterateConst(ctx, ast, FindCallExpr);
}

static bool CheckMethodDecl(es2panda_Context *context, es2panda_AstNode *ident)
{
    if (!impl->IsIdentifier(ident)) {
        return true;
    }
    auto *def = impl->DeclarationFromIdentifier(context, ident);
    if (def == nullptr) {
        std::cerr << "CANT FIND METHOD DEFINITION FROM CALL IDENTIFIER" << std::endl;
        return false;
    }

    size_t argsCallExpr = 0;
    size_t argsFuncSignature = 0;
    es2panda_AstNode *callExpr = ident;
    while (callExpr != nullptr && !impl->IsCallExpression(callExpr)) {
        callExpr = impl->AstNodeParent(context, callExpr);
    }
    if (callExpr == nullptr) {
        return true;
    }
    impl->CallExpressionArgumentsConst(context, callExpr, &argsCallExpr);
    impl->AstNodeIterateConst(context, impl->ClassElementValue(context, def), FindScriptFunc);
    if (scriptFunc == nullptr) {
        std::cerr << "CANT FIND SCRIPT FUNC FROM DEF" << std::endl;
        return false;
    }
    impl->ScriptFunctionParams(context, scriptFunc, &argsFuncSignature);

    if (argsCallExpr != argsFuncSignature) {
        std::cerr << "FOUND INCORRECT METHOD DEFINITION" << std::endl;
        std::cerr << "METHOD DEFINITION PARAMS COUNT: " << argsFuncSignature << std::endl;
        std::cerr << "CALL EXPR PARAMS COUNT: " << argsCallExpr << std::endl;
        return false;
    }

    return true;
}

static bool FindMethodDecl(es2panda_Context *context, es2panda_AstNode *ast)
{
    ctx = context;
    impl->AstNodeIterateConst(context, ast, FindMemberExpr);
    impl->AstNodeIterateConst(context, ast, FindCallExpr);
    for (auto memberExpr : *memberExprs) {
        if (memberExpr == nullptr) {
            std::cerr << "CANT FIND MEMBER EXPRESSION" << std::endl;
            return false;
        }
        auto ident = impl->MemberExpressionProperty(context, memberExpr);
        if (!CheckMethodDecl(context, ident)) {
            return false;
        }
    }

    for (auto callExpr : *callExprs) {
        if (callExpr == nullptr) {
            std::cerr << "CANT FIND CALL EXPRESSION" << std::endl;
            return false;
        }
        auto ident = impl->CallExpressionCallee(context, callExpr);
        if (!CheckMethodDecl(context, ident)) {
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

    memberExprs = new std::vector<es2panda_AstNode *>();
    callExprs = new std::vector<es2panda_AstNode *>();
    auto testResult = FindMethodDecl(context, ast);
    delete memberExprs;
    delete callExprs;
    memberExprs = nullptr;
    callExprs = nullptr;
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
