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

// Test case: run plugin in .ts mode should not crash with Segfault.

#include <iostream>
#include <algorithm>
#include <cstring>

#include "public/es2panda_lib.h"
#include "util.h"

/*
 * Found unique words after 'impl->' and before '(':
 * - AllocMemory
 * - AstNodeDumpEtsSrcConst
 * - AstNodeDumpJSONConst
 * - AstNodeIterateConst
 * - AstNodeRecheck
 * - AstNodeSetParent
 * - BlockStatementSetStatements
 * - BlockStatementStatements
 * - ContextProgram
 * - ContextState
 * - CreateConfig
 * - CreateContextFromString
 * - CreateExpressionStatement
 * - CreateIdentifier
 * - CreateTSNonNullExpression
 * - DestroyConfig
 * - DestroyContext
 * - ExpressionStatementSetExpression
 * - IdentifierName
 * - IdentifierSetName
 * - IsMethodDefinition
 * - MethodDefinitionFunction
 * - ProceedToState
 * - ProgramAst
 * - ScriptFunctionBody
 * - ScriptFunctionId
 *
 * Total unique words found: 26
 */

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;
static es2panda_AstNode *program = nullptr;
static es2panda_AstNode *scriptFunc = nullptr;
static es2panda_Context *context = nullptr;
static const char *funcName = "foo";

static std::string originalSourceCode = "type tmp = Int | null;\n\nfunction foo(t: tmp) : void {\n\n}\n";

static void FindFuncDef(es2panda_AstNode *ast)
{
    if (!impl->IsMethodDefinition(ast)) {
        impl->AstNodeIterateConst(context, ast, FindFuncDef);
        return;
    }
    auto tmpScriptFunc = impl->MethodDefinitionFunction(context, ast);
    if (tmpScriptFunc == nullptr ||
        std::string(funcName) != impl->IdentifierName(context, impl->ScriptFunctionId(context, tmpScriptFunc))) {
        impl->AstNodeIterateConst(context, ast, FindFuncDef);
        return;
    }
    scriptFunc = tmpScriptFunc;
}

void AppendStatement(es2panda_AstNode *blockStatement, es2panda_AstNode *statement)
{
    if (!blockStatement || !statement) {
        return;
    }
    size_t sizeOfStatements = 0;
    auto *statements = impl->BlockStatementStatements(context, blockStatement, &sizeOfStatements);
    if (!statements) {
        return;
    }
    auto *newStatements =
        static_cast<es2panda_AstNode **>(impl->AllocMemory(context, sizeOfStatements + 1, sizeof(es2panda_AstNode *)));
    if (!newStatements) {
        return;
    }
    for (size_t i = 0; i < sizeOfStatements; i++) {
        newStatements[i] = statements[i];
    }
    newStatements[sizeOfStatements] = statement;
    impl->BlockStatementSetStatements(context, blockStatement, newStatements, sizeOfStatements + 1);
    impl->AstNodeSetParent(context, statement, blockStatement);
}

void CreateNonNullExpression()
{
    impl->AstNodeIterateConst(context, program, FindFuncDef);
    if (scriptFunc == nullptr) {
        return;
    }
    auto funcBody = impl->ScriptFunctionBody(context, scriptFunc);
    auto exprStatement = impl->CreateExpressionStatement(context, nullptr);
    if (!funcBody || !exprStatement) {
        return;
    }

    auto *identifier = impl->CreateIdentifier(context);
    if (!identifier) {
        return;
    }
    auto *memForName = static_cast<char *>(impl->AllocMemory(context, strlen("t") + 1, 1));
    if (!memForName) {
        return;
    }
    std::copy_n("t", strlen("t") + 1, memForName);
    impl->IdentifierSetName(context, identifier, memForName);

    auto *nonNullExpr = impl->CreateTSNonNullExpression(context, identifier);
    if (!nonNullExpr) {
        return;
    }

    impl->AstNodeSetParent(context, exprStatement, funcBody);
    impl->AstNodeSetParent(context, nonNullExpr, exprStatement);
    impl->AstNodeSetParent(context, identifier, nonNullExpr);
    impl->ExpressionStatementSetExpression(context, exprStatement, nonNullExpr);
    AppendStatement(funcBody, exprStatement);
    impl->AstNodeRecheck(context, exprStatement);
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return INVALID_ARGC_ERROR_CODE;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    impl = GetImpl();

    auto config = impl->CreateConfig(argc - 1, argv + 1);
    context = impl->CreateContextFromString(config, originalSourceCode.c_str(), argv[argc - 1]);

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    CheckForErrors("CHECKED", context);

    program = impl->ProgramAst(context, impl->ContextProgram(context));
    CreateNonNullExpression();

    const char *src = impl->AstNodeDumpEtsSrcConst(context, program);
    const char *expected = "t!";
    if (strstr(src, expected) == nullptr) {
        return 1;
    }

    impl->AstNodeRecheck(context, program);

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