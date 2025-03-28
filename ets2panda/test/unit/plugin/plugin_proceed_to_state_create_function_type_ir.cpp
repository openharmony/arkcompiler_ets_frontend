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

#include <cstring>
#include <algorithm>
#include "util.h"

// NOLINTBEGIN

static std::string g_source = R"(
function main() {}
)";

es2panda_AstNode *CreateFunctionTypeIr(es2panda_Context *context, es2panda_AstNode *program)
{
    auto impl = GetImpl();
    size_t sizeOfStatements = 0;
    auto *statements = impl->BlockStatementStatements(context, program, &sizeOfStatements);
    es2panda_AstNode **newStatements =
        static_cast<es2panda_AstNode **>(impl->AllocMemory(context, sizeOfStatements + 1, sizeof(es2panda_AstNode *)));
    for (size_t i = 0; i < sizeOfStatements; i++) {
        newStatements[i + 1] = statements[i];
    }
    auto signature = impl->CreateFunctionSignature(context, nullptr, nullptr, 0,
                                                   impl->CreateETSPrimitiveType(context, PRIMITIVE_TYPE_INT), false);

    auto *id = impl->CreateIdentifier1(context, const_cast<char *>("foo"));

    auto *functionTypeIr = impl->CreateETSFunctionTypeIr(context, signature, SCRIPT_FUNCTION_FLAGS_NONE);
    auto *typeAliasDeclaration = impl->CreateTSTypeAliasDeclaration(context, id, nullptr, functionTypeIr);
    impl->AstNodeSetParent(context, id, typeAliasDeclaration);
    impl->AstNodeSetParent(context, functionTypeIr, typeAliasDeclaration);
    newStatements[0] = typeAliasDeclaration;
    impl->BlockStatementSetStatements(context, program, newStatements, sizeOfStatements + 1);
    impl->AstNodeSetParent(context, typeAliasDeclaration, program);
    return functionTypeIr;
}

bool UpdateFunctionTypeIr(es2panda_Context *context, es2panda_AstNode *original)
{
    auto impl = GetImpl();
    auto signature = impl->CreateFunctionSignature(context, nullptr, nullptr, 0,
                                                   impl->CreateETSPrimitiveType(context, PRIMITIVE_TYPE_DOUBLE), false);
    auto node = impl->UpdateETSFunctionTypeIr(context, original, signature, SCRIPT_FUNCTION_FLAGS_NONE);
    impl->TSTypeAliasDeclarationSetTsTypeAnnotation(context, impl->AstNodeParent(context, node), node);
    return strcmp(impl->AstNodeDumpEtsSrcConst(context, impl->AstNodeParent(context, node)),
                  "type foo = (()=> double);\n") == 0;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }

    if (GetImpl() == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    auto impl = GetImpl();
    const char **args = const_cast<const char **>(&(argv[1]));
    auto config = impl->CreateConfig(argc - 1, args);
    auto context = impl->CreateContextFromString(config, g_source.data(), argv[argc - 1]);
    if (context == nullptr) {
        return NULLPTR_CONTEXT_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);

    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    auto ast = impl->ProgramAst(context, impl->ContextProgram(context));
    auto original = CreateFunctionTypeIr(context, ast);
    if (!UpdateFunctionTypeIr(context, original)) {
        return TEST_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    impl->AstNodeRecheck(context, ast);

    impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }

    impl->DestroyContext(context);
    impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
