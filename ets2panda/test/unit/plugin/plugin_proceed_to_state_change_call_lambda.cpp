/**
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

#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include "public/es2panda_lib.h"
#include "os/library_loader.h"

// NOLINTBEGIN

static const char *LIBNAME = "es2panda-public";
static const int MIN_ARGC = 3;
static const int NULLPTR_IMPL_ERROR_CODE = 2;
static const std::string funcName = "foo";

static es2panda_Impl *impl = nullptr;

es2panda_Impl *GetImpl()
{
    if (impl != nullptr) {
        return impl;
    }

    std::string soName = ark::os::library_loader::DYNAMIC_LIBRARY_PREFIX + std::string(LIBNAME) +
                         ark::os::library_loader::DYNAMIC_LIBRARY_SUFFIX;
    auto libraryRes = ark::os::library_loader::Load(soName);
    if (!libraryRes.HasValue()) {
        std::cout << "Error in load lib" << std::endl;
        return nullptr;
    }

    auto library = std::move(libraryRes.Value());
    auto getImpl = ark::os::library_loader::ResolveSymbol(library, "es2panda_GetImpl");
    if (!getImpl.HasValue()) {
        std::cout << "Error in load func get impl" << std::endl;
        return nullptr;
    }

    auto getImplFunc = reinterpret_cast<const es2panda_Impl *(*)(int)>(getImpl.Value());
    if (getImplFunc != nullptr) {
        return const_cast<es2panda_Impl *>(getImplFunc(ES2PANDA_LIB_VERSION));
    }
    return nullptr;
}

es2panda_AstNode *parNode;
es2panda_Context *newCtx;

static void changeParent(es2panda_AstNode *child)
{
    impl->AstNodeSetParent(newCtx, child, parNode);
}

static void SetRightParent(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *ctx = static_cast<es2panda_Context *>(arg);
    newCtx = ctx;
    parNode = node;
    impl->AstNodeIterateConst(ctx, node, changeParent);
}

static void UpdateCall(es2panda_AstNode *ast, es2panda_Context *ctx)
{
    size_t n = 0;
    auto **statements = impl->BlockStatementStatementsConst(ctx, ast, &n);
    auto *exprStatement = statements[1];
    auto *callExpr = const_cast<es2panda_AstNode *>(impl->ExpressionStatementGetExpressionConst(ctx, exprStatement));
    auto *arrowFunc = impl->CallExpressionArgumentsConst(ctx, callExpr, &n)[0];
    auto *body = const_cast<es2panda_AstNode *>(
        impl->ScriptFunctionBodyConst(ctx, impl->ArrowFunctionExpressionFunction(ctx, arrowFunc)));
    auto *funcSignature = impl->CreateFunctionSignature(
        ctx, nullptr, nullptr, 0, impl->CreateETSPrimitiveType(ctx, Es2pandaPrimitiveType::PRIMITIVE_TYPE_VOID));
    auto *scriptFunc = impl->CreateScriptFunction(ctx, body, funcSignature,
                                                  Es2pandaScriptFunctionFlags::SCRIPT_FUNCTION_FLAGS_ARROW, 0);
    impl->AstNodeSetParent(ctx, body, scriptFunc);
    auto *newArrowFunc = impl->CreateArrowFunctionExpression(ctx, scriptFunc);
    auto *newId =
        impl->UpdateIdentifier1(ctx, impl->CallExpressionCallee(ctx, callExpr), const_cast<char *>(funcName.c_str()));
    auto *newCallExpr = impl->UpdateCallExpression(ctx, callExpr, newId, &newArrowFunc, 1, nullptr, false, false);
    impl->AstNodeSetParent(ctx, newId, newCallExpr);
    impl->AstNodeSetParent(ctx, newArrowFunc, newCallExpr);
    auto *newStatement = impl->UpdateExpressionStatement(ctx, exprStatement, newCallExpr);
    impl->AstNodeSetParent(ctx, newCallExpr, newStatement);
    es2panda_AstNode *newStatements[] = {statements[0], newStatement};
    const int numOfNewStatements = 2;
    impl->BlockStatementSetStatements(ctx, ast, newStatements, numOfNewStatements);
    impl->AstNodeForEach(ast, SetRightParent, ctx);
}

void CheckForErrors(std::string StateName, es2panda_Context *context)
{
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        std::cout << "PROCEED TO " << StateName << " ERROR" << std::endl;
        std::cout << impl->ContextErrorMessage << std::endl;
    } else {
        std::cout << "PROCEED TO " << StateName << " SUCCESS" << std::endl;
    }
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
    auto src = std::string("function foo(builder: () => void) {}\nfoo(() => {})");
    auto context = impl->CreateContextFromString(config, src.c_str(), argv[argc - 1]);
    if (context != nullptr) {
        std::cout << "CREATE CONTEXT SUCCESS" << std::endl;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    auto *programNode = impl->ProgramAst(impl->ContextProgram(context));
    std::cout << std::endl << "SRC DUMP BEFORE CHANGE CALL:" << std::endl;
    std::cout << impl->AstNodeDumpEtsSrcConst(context, programNode) << std::endl << std::endl;
    UpdateCall(programNode, context);
    std::cout << std::endl << "SRC DUMP AFTER CHANGE CALL:" << std::endl;
    std::cout << impl->AstNodeDumpEtsSrcConst(context, programNode) << std::endl << std::endl;

    impl->ProceedToState(context, ES2PANDA_STATE_SCOPE_INITED);
    CheckForErrors("SCOPE INITED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    CheckForErrors("CHECKED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_LOWERED);
    CheckForErrors("LOWERED", context);

    impl->ProceedToState(context, ES2PANDA_STATE_ASM_GENERATED);
    CheckForErrors("ASM", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    CheckForErrors("BIN", context);
    impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND