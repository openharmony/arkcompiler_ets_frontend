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

#include <map>
#include <cstring>
#include <algorithm>
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *g_impl = nullptr;
static es2panda_Context *g_ctx = nullptr;
static bool g_isFound = false;
static std::string g_source = R"(
struct A { };
)";

void CreateStructDeclaration(es2panda_AstNode *program)
{
    size_t sizeOfStatements = 0;
    auto statements = g_impl->BlockStatementStatements(g_ctx, program, &sizeOfStatements);
    es2panda_AstNode **newStatements =
        static_cast<es2panda_AstNode **>(g_impl->AllocMemory(g_ctx, sizeOfStatements + 1, sizeof(es2panda_AstNode *)));
    for (size_t i = 0; i < sizeOfStatements; i++) {
        newStatements[i] = statements[i];
    }
    auto *identifier = g_impl->CreateIdentifier1(g_ctx, const_cast<char *>("B"));
    auto *classDefinition = g_impl->CreateClassDefinition1(
        g_ctx, identifier, nullptr, 0, Es2pandaClassDefinitionModifiers::CLASS_DEFINITION_MODIFIERS_CLASS_DECL,
        Es2pandaModifierFlags::MODIFIER_FLAGS_NONE);
    auto *structDeclaration = g_impl->CreateETSStructDeclaration(g_ctx, classDefinition);
    g_impl->AstNodeSetParent(g_ctx, classDefinition, structDeclaration);
    g_impl->AstNodeSetParent(g_ctx, identifier, classDefinition);
    newStatements[sizeOfStatements] = structDeclaration;
    g_impl->BlockStatementSetStatements(g_ctx, program, newStatements, sizeOfStatements + 1);
    g_impl->AstNodeSetParent(g_ctx, structDeclaration, program);
}

bool UpdateStructDeclaration(es2panda_AstNode *program)
{
    size_t sizeOfStatements = 0;
    auto statements = g_impl->BlockStatementStatements(g_ctx, program, &sizeOfStatements);
    auto original = statements[sizeOfStatements - 1];
    auto *identifier = g_impl->CreateIdentifier1(g_ctx, const_cast<char *>("C"));
    auto *classDefinition = g_impl->CreateClassDefinition1(
        g_ctx, identifier, nullptr, 0, Es2pandaClassDefinitionModifiers::CLASS_DEFINITION_MODIFIERS_CLASS_DECL,
        Es2pandaModifierFlags::MODIFIER_FLAGS_NONE);
    auto *structDeclaration = g_impl->UpdateETSStructDeclaration(g_ctx, original, classDefinition);

    g_impl->AstNodeSetParent(g_ctx, classDefinition, structDeclaration);
    g_impl->AstNodeSetParent(g_ctx, identifier, classDefinition);
    statements[sizeOfStatements - 1] = structDeclaration;
    g_impl->BlockStatementSetStatements(g_ctx, program, statements, sizeOfStatements);

    if (g_impl->AstNodeOriginalNodeConst(g_ctx, structDeclaration) == original) {
        return true;
    }
    return false;
}

static void Find(es2panda_AstNode *ast)
{
    if (!g_isFound && g_impl->IsETSStructDeclaration(ast)) {
        g_isFound = true;
        return;
    }

    g_impl->AstNodeIterateConst(g_ctx, ast, Find);
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
    std::cout << "LOAD SUCCESS" << std::endl;
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

    g_impl->AstNodeIterateConst(g_ctx, ast, Find);

    if (!g_isFound) {
        return TEST_ERROR_CODE;
    }

    CreateStructDeclaration(ast);

    if (!UpdateStructDeclaration(ast)) {
        return TEST_ERROR_CODE;
    }

    if (g_impl->ContextState(g_ctx) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    g_impl->DestroyContext(g_ctx);
    g_impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
