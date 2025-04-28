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

#include <cstddef>
#include <cstring>
#include <algorithm>
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *g_impl = nullptr;
static es2panda_Context *g_ctx = nullptr;
static std::string g_source = R"(
interface A {}
class B {
    get x() { return 1; }
}
function C() {
    let a = 1;
}
)";
static int g_count = 6;

void FindFunctionDeclaration(es2panda_AstNode *ast)
{
    if (g_impl->IsFunctionDeclaration(ast)) {
        auto scriptFunc = g_impl->FunctionDeclarationFunction(g_ctx, ast);
        size_t len = 0;
        auto params = g_impl->ScriptFunctionParams(g_ctx, scriptFunc, &len);
        auto typeParams = g_impl->ScriptFunctionTypeParams(g_ctx, scriptFunc);
        auto returnType = g_impl->ScriptFunctionReturnTypeAnnotation(g_ctx, scriptFunc);
        auto signature = g_impl->CreateFunctionSignature(g_ctx, typeParams, params, len, returnType, false);
        auto body = g_impl->ScriptFunctionBody(g_ctx, const_cast<es2panda_AstNode *>(scriptFunc));
        auto newScriptFunc = g_impl->CreateScriptFunction(g_ctx, body, signature, 0, 0);
        auto name = g_impl->CreateIdentifier1(g_ctx, const_cast<char *>("D"));
        g_impl->ScriptFunctionSetIdent(g_ctx, newScriptFunc, name);
        auto funcDeclaration = g_impl->UpdateFunctionDeclaration(g_ctx, ast, newScriptFunc, nullptr, 0, false);
        auto parent = g_impl->AstNodeParent(g_ctx, ast);
        auto statements = g_impl->BlockStatementStatements(g_ctx, parent, &len);
        const size_t position = 2;
        statements[position] = funcDeclaration;
        g_impl->AstNodeSetParent(g_ctx, scriptFunc, body);
        g_impl->AstNodeSetParent(g_ctx, body, newScriptFunc);
        g_impl->AstNodeSetParent(g_ctx, newScriptFunc, funcDeclaration);
        g_impl->AstNodeSetParent(g_ctx, funcDeclaration, parent);
        g_impl->BlockStatementSetStatements(g_ctx, parent, statements, len);
        std::string str(g_impl->AstNodeDumpEtsSrcConst(g_ctx, funcDeclaration));
        if (str.find("function D()") != std::string::npos) {
            g_count--;
        }
    }
}

void FindVariableDeclaration(es2panda_AstNode *ast)
{
    if (g_impl->IsVariableDeclaration(ast)) {
        size_t n = 0;
        auto varIdent = g_impl->CreateIdentifier1(g_ctx, const_cast<char *>("b"));
        auto declarator = g_impl->CreateVariableDeclarator1(
            g_ctx, Es2pandaVariableDeclaratorFlag::VARIABLE_DECLARATOR_FLAG_LET, varIdent,
            g_impl->VariableDeclaratorInit(g_ctx, g_impl->VariableDeclarationDeclaratorsConst(g_ctx, ast, &n)[0]));
        auto stmt = g_impl->UpdateVariableDeclaration(
            g_ctx, ast, Es2pandaVariableDeclarationKind::VARIABLE_DECLARATION_KIND_LET, &declarator, 1);
        auto **stmts = static_cast<es2panda_AstNode **>(g_impl->AllocMemory(g_ctx, 1, sizeof(es2panda_AstNode *)));
        stmts[0] = stmt;
        g_impl->AstNodeSetParent(g_ctx, declarator, stmt);
        g_impl->AstNodeSetParent(g_ctx, varIdent, declarator);
        auto block = g_impl->AstNodeParent(g_ctx, ast);
        if (g_impl->IsBlockStatement(block)) {
            auto newBlock = g_impl->UpdateBlockStatement(g_ctx, block, stmts, 1);
            g_impl->AstNodeSetParent(g_ctx, stmt, newBlock);
            g_impl->ScriptFunctionSetBody(g_ctx, g_impl->AstNodeParent(g_ctx, block), newBlock);
            std::string str(g_impl->AstNodeDumpEtsSrcConst(g_ctx, stmt));
            if (str.find("let b = 1;") != std::string::npos) {
                g_count--;
            }
        }
    }
}

bool Find(es2panda_AstNode *ast)
{
    if (g_impl->IsTSInterfaceDeclaration(ast) && (g_impl->AstNodeModifiers(g_ctx, ast) & MODIFIER_FLAGS_PUBLIC)) {
        g_count--;
    }
    FindFunctionDeclaration(ast);
    FindVariableDeclaration(ast);
    if (g_impl->MethodDefinitionIsGetterConst(g_ctx, ast)) {
        g_count--;
    }
    if (g_impl->IsReturnStatement(ast)) {
        auto arg = g_impl->CreateNumberLiteral(g_ctx, 2);
        auto returnStmt = g_impl->UpdateReturnStatement(g_ctx, ast);
        g_impl->ReturnStatementSetArgument(g_ctx, returnStmt, arg);
        auto **stmts = static_cast<es2panda_AstNode **>(g_impl->AllocMemory(g_ctx, 1, sizeof(es2panda_AstNode *)));
        stmts[0] = returnStmt;
        std::string str(g_impl->AstNodeDumpEtsSrcConst(g_ctx, returnStmt));
        if (g_impl->IsBlockStatement(g_impl->AstNodeParent(g_ctx, ast)) && str.find("return 2;") != std::string::npos) {
            g_impl->BlockStatementSetStatements(g_ctx, g_impl->AstNodeParent(g_ctx, ast), stmts, 1);
            g_count--;
        }
    }
    if (g_impl->IsIdentifier(ast) && strcmp(g_impl->IdentifierName(g_ctx, ast), "A") == 0) {
        auto range = g_impl->AstNodeRangeConst(g_ctx, ast);
        auto start = g_impl->SourceRangeStart(g_ctx, const_cast<es2panda_SourceRange *>(range));
        auto end = g_impl->SourceRangeEnd(g_ctx, const_cast<es2panda_SourceRange *>(range));
        const size_t startIndex = 11;
        const size_t startLine = 1;
        const size_t endIndex = 12;
        const size_t endLine = 1;
        if (startIndex == g_impl->SourcePositionIndex(g_ctx, start) &&
            startLine == g_impl->SourcePositionLine(g_ctx, start) &&
            endIndex == g_impl->SourcePositionIndex(g_ctx, end) && endLine == g_impl->SourcePositionLine(g_ctx, end)) {
            g_count--;
        }
    }
    return g_count == 0;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }
    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    g_impl = GetImpl();
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = g_impl->CreateConfig(argc - 1, args);
    g_ctx = g_impl->CreateContextFromString(config, g_source.data(), argv[argc - 1]);
    if (g_ctx == nullptr) {
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    g_impl->ProceedToState(g_ctx, ES2PANDA_STATE_PARSED);
    if (g_impl->ContextState(g_ctx) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    auto ast = g_impl->ProgramAst(g_ctx, g_impl->ContextProgram(g_ctx));
    if (!g_impl->AstNodeIsAnyChildConst(g_ctx, ast, Find)) {
        return TEST_ERROR_CODE;
    }

    g_impl->ProceedToState(g_ctx, ES2PANDA_STATE_BIN_GENERATED);
    if (g_impl->ContextState(g_ctx) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    g_impl->DestroyContext(g_ctx);
    g_impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
