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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or g_implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <ir/expression.h>
#include <ostream>
#include <string>
#include "test/unit/plugin/util.h"
#include "public/es2panda_lib.h"

// NOLINTBEGIN

/*
 * Covered C API List:
 *   AstNodeDumpEtsSrcConst
 *   AstNodeDumpJSONConst
 *   AstNodeForEach
 *   AstNodeIterateConst
 *   AstNodeRebind
 *   AstNodeRecheck
 *   AstNodeSetParent
 *   BinaryExpressionIsArithmeticConst
 *   BinaryExpressionIsBitwiseConst
 *   BinaryExpressionIsLogicalConst
 *   BinaryExpressionIsLogicalExtendedConst
 *   BinaryExpressionLeft
 *   BinaryExpressionLeftConst
 *   BinaryExpressionOperationType
 *   BinaryExpressionOperationTypeConst
 *   BinaryExpressionOperatorTypeConst
 *   BinaryExpressionResult
 *   BinaryExpressionResultConst
 *   BinaryExpressionRight
 *   BinaryExpressionRightConst
 *   BinaryExpressionSetLeft
 *   BinaryExpressionSetOperationType
 *   BinaryExpressionSetOperator
 *   BinaryExpressionSetResult
 *   BinaryExpressionSetRight
 *   BlockStatementSetStatements
 *   ContextProgram
 *   ContextState
 *   CreateBinaryExpression
 *   CreateConfig
 *   CreateContextFromString
 *   CreateDoubleType
 *   CreateExpressionStatement
 *   CreateNumberLiteral
 *   DestroyConfig
 *   DestroyContext
 *   FunctionDeclarationFunction
 *   IdentifierName
 *   IsBinaryExpression
 *   IsFunctionDeclaration
 *   ProceedToState
 *   ProgramAst
 *   ScriptFunctionBody
 *   ScriptFunctionId
 *   UpdateBinaryExpression
 */

static std::string source = R"(
function main() {
    1 + 2;
}
)";

static es2panda_Impl *g_impl = nullptr;
static es2panda_AstNode *binExpr = nullptr;
static es2panda_AstNode *mainScriptFunc = nullptr;
static es2panda_Context *g_ctx = nullptr;

es2panda_AstNode *parNode = nullptr;
es2panda_Context *newCtx = nullptr;

static void FindBinaryExpression(es2panda_AstNode *ast)
{
    if (!g_impl->IsBinaryExpression(ast)) {
        g_impl->AstNodeIterateConst(g_ctx, ast, FindBinaryExpression);
        return;
    }
    binExpr = ast;
}

static void FindMainDef(es2panda_AstNode *ast)
{
    if (!g_impl->IsFunctionDeclaration(ast)) {
        g_impl->AstNodeIterateConst(g_ctx, ast, FindMainDef);
        return;
    }
    auto scriptFunc = g_impl->FunctionDeclarationFunction(g_ctx, ast);
    if (scriptFunc == nullptr ||
        std::string("main") != g_impl->IdentifierName(g_ctx, g_impl->ScriptFunctionId(g_ctx, scriptFunc))) {
        return;
    }
    mainScriptFunc = scriptFunc;
}

static void changeParent(es2panda_AstNode *child)
{
    g_impl->AstNodeSetParent(newCtx, child, parNode);
}

static void SetRightParent(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *context = static_cast<es2panda_Context *>(arg);
    newCtx = context;
    parNode = node;
    g_impl->AstNodeIterateConst(context, node, changeParent);
}

static bool SetAndGetBinaryExpressionValue(es2panda_Context *context)
{
    es2panda_AstNode *leftValue = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 8));
    g_impl->BinaryExpressionSetLeft(context, binExpr, leftValue);
    es2panda_AstNode *rightValue = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 7));
    g_impl->BinaryExpressionSetRight(context, binExpr, rightValue);
    es2panda_AstNode *result = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 15));
    g_impl->BinaryExpressionSetResult(context, binExpr, result);
    Es2pandaTokenType operatorValue = Es2pandaTokenType::TOKEN_TYPE_PUNCTUATOR_GREATER_THAN;
    g_impl->BinaryExpressionSetOperator(context, binExpr, operatorValue);
    es2panda_Type *doubleType = g_impl->CreateDoubleType(context);
    g_impl->BinaryExpressionSetOperationType(context, binExpr, doubleType);
    es2panda_AstNode *resultLeftValue = g_impl->BinaryExpressionLeft(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, resultLeftValue), "8") == 0)) {
        return false;
    }
    const es2panda_AstNode *leftConst = g_impl->BinaryExpressionLeftConst(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, const_cast<es2panda_AstNode *>(leftConst)), "8") == 0)) {
        return false;
    }
    es2panda_AstNode *resultRightValue = g_impl->BinaryExpressionRight(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, resultRightValue), "7") == 0)) {
        return false;
    }
    const es2panda_AstNode *rightConst = g_impl->BinaryExpressionRightConst(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, const_cast<es2panda_AstNode *>(rightConst)), "7") == 0)) {
        return false;
    }
    es2panda_AstNode *resultValue = g_impl->BinaryExpressionResult(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, resultValue), "15") == 0)) {
        return false;
    }
    const es2panda_AstNode *resultConst = g_impl->BinaryExpressionResultConst(context, binExpr);
    if (!(strcmp(g_impl->AstNodeDumpEtsSrcConst(context, const_cast<es2panda_AstNode *>(resultConst)), "15") == 0)) {
        return false;
    }
    Es2pandaTokenType operatorType = g_impl->BinaryExpressionOperatorTypeConst(context, binExpr);
    if (operatorType != Es2pandaTokenType::TOKEN_TYPE_PUNCTUATOR_GREATER_THAN) {
        return false;
    }
    es2panda_Type *operationTypeVal = g_impl->BinaryExpressionOperationType(context, binExpr);
    if (operationTypeVal != doubleType) {
        return false;
    }
    const es2panda_Type *operationTypeValConst = g_impl->BinaryExpressionOperationTypeConst(context, binExpr);
    if (operationTypeValConst != doubleType) {
        return false;
    }
    return true;
}

/*
 *  1 + 2
 *  is changed to
 *  12 > 10
 */
static bool BinaryExpressionHandle(es2panda_Context *context, es2panda_AstNode *ast)
{
    es2panda_AstNode *left = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 4));
    es2panda_AstNode *right = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 5));
    Es2pandaTokenType operatorType = Es2pandaTokenType::TOKEN_TYPE_PUNCTUATOR_LESS_THAN;
    es2panda_AstNode *binExpression = g_impl->CreateBinaryExpression(context, left, right, operatorType);
    if (!g_impl->IsBinaryExpression(binExpression)) {
        return false;
    }
    g_impl->AstNodeIterateConst(context, ast, FindBinaryExpression);
    g_impl->AstNodeIterateConst(context, ast, FindMainDef);
    if (mainScriptFunc == nullptr || binExpr == nullptr) {
        return false;
    }
    auto mainFuncBody = g_impl->ScriptFunctionBody(context, mainScriptFunc);
    es2panda_AstNode *exprStatement = g_impl->CreateExpressionStatement(context, binExpression);
    es2panda_AstNode *newMainStatements[1] = {exprStatement};
    g_impl->BlockStatementSetStatements(context, mainFuncBody, newMainStatements, 1U);
    g_impl->AstNodeForEach(ast, SetRightParent, context);
    g_impl->AstNodeIterateConst(context, ast, FindBinaryExpression);
    if (!SetAndGetBinaryExpressionValue(context)) {
        return false;
    }
    Es2pandaTokenType value = static_cast<Es2pandaTokenType>(ark::es2panda::lexer::TokenType::PUNCTUATOR_LOGICAL_AND);
    g_impl->BinaryExpressionSetOperator(context, binExpr, value);
    if (!g_impl->BinaryExpressionIsLogicalConst(context, binExpr) ||
        !g_impl->BinaryExpressionIsLogicalExtendedConst(context, binExpr)) {
        return false;
    }
    Es2pandaTokenType value1 = static_cast<Es2pandaTokenType>(ark::es2panda::lexer::TokenType::PUNCTUATOR_BITWISE_OR);
    g_impl->BinaryExpressionSetOperator(context, binExpr, value1);
    if (!g_impl->BinaryExpressionIsBitwiseConst(context, binExpr) ||
        !g_impl->BinaryExpressionIsArithmeticConst(context, binExpr)) {
        return false;
    }
    es2panda_AstNode *leftUpdate = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 12));
    es2panda_AstNode *rightUpdate = static_cast<es2panda_AstNode *>(g_impl->CreateNumberLiteral(context, 10));
    Es2pandaTokenType operatorUpdate = Es2pandaTokenType::TOKEN_TYPE_PUNCTUATOR_GREATER_THAN;
    es2panda_AstNode *binExpressionUpdate =
        g_impl->UpdateBinaryExpression(context, binExpr, leftUpdate, rightUpdate, operatorUpdate);
    exprStatement = g_impl->CreateExpressionStatement(context, binExpressionUpdate);
    newMainStatements[0] = {exprStatement};
    g_impl->BlockStatementSetStatements(context, mainFuncBody, newMainStatements, 1U);
    g_impl->AstNodeForEach(ast, SetRightParent, context);
    std::string str(g_impl->AstNodeDumpEtsSrcConst(context, ast));
    if (str.find("((12) > (10));") == std::string::npos) {
        std::cout << "Fail to find update expression value." << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return INVALID_ARGC_ERROR_CODE;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }

    g_impl = GetImpl();

    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = g_impl->CreateConfig(argc - 1, args);

    g_ctx = g_impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
    if (g_ctx == nullptr) {
        std::cerr << "Fail to create context." << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    int retCode = Test(g_ctx, g_impl, ES2PANDA_STATE_PARSED, BinaryExpressionHandle);
    if (retCode != 0) {
        g_impl->DestroyConfig(config);
        return retCode;
    }

    g_impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
