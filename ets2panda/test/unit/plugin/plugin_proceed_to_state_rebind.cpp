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
#include "util.h"
#include "public/es2panda_lib.h"

// NOLINTBEGIN

/**
 * Covered C API List:
 *   bool (*IsVariableDeclaration)(es2panda_AstNode *ast);
 *   void (*AstNodeIterateConst)(es2panda_Context *context, es2panda_AstNode *classInstance, NodeTraverser cb);
 *   bool (*IsMethodDefinition)(es2panda_AstNode *ast);
 *   es2panda_AstNode *(*MethodDefinitionFunction)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   char *(*IdentifierName)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   es2panda_AstNode *(*ScriptFunctionId)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   void (*AstNodeSetParent)(es2panda_Context *context, es2panda_AstNode *classInstance, es2panda_AstNode *parent);
 *   char *(*AstNodeDumpJSONConst)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   es2panda_AstNode *(*ScriptFunctionBody)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   es2panda_AstNode *(*CreateIdentifier1)(es2panda_Context *context, char *name);
 *   es2panda_AstNode *(*CreateVariableDeclarator1)(es2panda_Context *context, Es2pandaVariableDeclaratorFlag flag,
 *                                                  es2panda_AstNode *ident, es2panda_AstNode *init);
 *   es2panda_AstNode *(*VariableDeclaratorInit)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   es2panda_AstNode **(*VariableDeclarationDeclaratorsConst)(es2panda_Context *context,
 *                                                             es2panda_AstNode *classInstance, size_t *returnTypeLen);
 *   es2panda_AstNode *(*CreateVariableDeclaration)(es2panda_Context *context, Es2pandaVariableDeclarationKind kind,
 *                                                  es2panda_AstNode **declarators, size_t declaratorsLen);
 *   void (*BlockStatementSetStatements)(es2panda_Context *context, es2panda_AstNode *classInstance,
 *                                       es2panda_AstNode **statementList, size_t statementListLen);
 *   void (*AstNodeForEach)(es2panda_AstNode *ast, void (*func)(es2panda_AstNode *, void *), void *arg);
 *   es2panda_Scope *(*AstNodeRebind)(es2panda_Context *ctx, es2panda_AstNode *node);
 *   void *(*AllocMemory)(es2panda_Context *context, size_t numberOfElements, size_t sizeOfElement);
 *   es2panda_AstNode *(*ProgramAst)(es2panda_Program *program);
 *   es2panda_Program *(*ContextProgram)(es2panda_Context *context);
 *   char *(*AstNodeDumpEtsSrcConst)(es2panda_Context *context, es2panda_AstNode *classInstance);
 *   es2panda_Config *(*CreateConfig)(int argc, char const *const *argv);
 *   es2panda_Context *(*CreateContextFromString)(es2panda_Config *config, const char *source, char const *file_name);
 *   es2panda_Context *(*ProceedToState)(es2panda_Context *context, es2panda_ContextState state);
 *   es2panda_ContextState (*ContextState)(es2panda_Context *context);
 *   void (*DestroyConfig)(es2panda_Config *config);
 *
 */
static es2panda_Impl *impl = nullptr;

static auto source = std::string("function main() { \nlet a = 5;\n }");

static es2panda_AstNode *letStatement = nullptr;
static es2panda_AstNode *mainScriptFunc = nullptr;
static es2panda_Context *ctx = nullptr;

es2panda_AstNode *parNode = nullptr;
es2panda_Context *newCtx = nullptr;

static void FindLet(es2panda_AstNode *ast)
{
    if (!impl->IsVariableDeclaration(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindLet);
        return;
    }
    letStatement = ast;
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

static void changeParent(es2panda_AstNode *child)
{
    impl->AstNodeSetParent(newCtx, child, parNode);
}

static void SetRightParent(es2panda_AstNode *node, void *arg)
{
    es2panda_Context *context = static_cast<es2panda_Context *>(arg);
    newCtx = context;
    parNode = node;
    impl->AstNodeIterateConst(context, node, changeParent);
}

static bool ChangeAst(es2panda_Context *context, es2panda_AstNode *ast)
{
    std::cout << impl->AstNodeDumpJSONConst(context, ast) << std::endl;
    size_t n = 0;
    ctx = context;
    impl->AstNodeIterateConst(context, ast, FindLet);
    impl->AstNodeIterateConst(context, ast, FindMainDef);
    if (mainScriptFunc == nullptr || letStatement == nullptr) {
        return false;
    }
    auto mainFuncBody = impl->ScriptFunctionBody(context, mainScriptFunc);
    std::cout << impl->AstNodeDumpJSONConst(context, mainScriptFunc) << std::endl;
    std::cout << impl->AstNodeDumpJSONConst(context, letStatement) << std::endl;

    std::string className = std::string("b");
    auto *memForName = static_cast<char *>(impl->AllocMemory(context, className.size() + 1, 1));
    std::copy_n(className.c_str(), className.size() + 1, memForName);

    auto varIdent = impl->CreateIdentifier1(context, memForName);
    auto declarator = impl->CreateVariableDeclarator1(
        context, Es2pandaVariableDeclaratorFlag::VARIABLE_DECLARATOR_FLAG_LET, varIdent,
        impl->VariableDeclaratorInit(context, impl->VariableDeclarationDeclaratorsConst(context, letStatement, &n)[0]));
    auto declaration = impl->CreateVariableDeclaration(
        context, Es2pandaVariableDeclarationKind::VARIABLE_DECLARATION_KIND_LET, &declarator, 1);

    es2panda_AstNode *newMainStatements[1] = {declaration};
    impl->BlockStatementSetStatements(context, mainFuncBody, newMainStatements, 1U);
    impl->AstNodeForEach(ast, SetRightParent, context);
    std::cout << impl->AstNodeDumpJSONConst(context, ast) << std::endl;

    impl->AstNodeRebind(context, declaration);

    std::cout << impl->AstNodeDumpEtsSrcConst(context, ast) << std::endl;
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
    impl = GetImpl();
    std::cout << "LOAD SUCCESS" << std::endl;
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = impl->CreateConfig(argc - 1, args);
    auto context = impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
    if (context == nullptr) {
        std::cerr << "FAILED TO CREATE CONTEXT" << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    impl->ProceedToState(context, ES2PANDA_STATE_BOUND);
    CheckForErrors("BOUND", context);

    auto ast = impl->ProgramAst(context, impl->ContextProgram(context));
    if (!ChangeAst(context, ast)) {
        return TEST_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    CheckForErrors("CHECKED", context);

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
    impl->DestroyConfig(config);

    return 0;
}
// NOLINTEND
