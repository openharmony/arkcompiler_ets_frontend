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
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
#include "macros.h"
#include "util.h"
#include "public/es2panda_lib.h"
#include "ir/ets/etsImportDeclaration.h"
#include "utils/arena_containers.h"

// NOLINTBEGIN

static es2panda_Impl *g_impl = nullptr;

static es2panda_AstNode *CreateImportDecl(es2panda_Context *context, const char *importIdStr,
                                          const char *importAliasStr)
{
    auto *importPath = g_impl->CreateStringLiteral1(context, const_cast<char *>("./export2"));

    std::vector<es2panda_AstNode *> specifiersArray;
    auto *importId = g_impl->CreateIdentifier1(context, const_cast<char *>(importIdStr));
    auto *importAlias = g_impl->CreateIdentifier1(context, const_cast<char *>(importAliasStr));
    ;
    auto *importSpecifier = g_impl->CreateImportSpecifier(context, importId, importAlias);
    g_impl->AstNodeSetParent(context, importId, importSpecifier);
    g_impl->AstNodeSetParent(context, importAlias, importSpecifier);
    specifiersArray.push_back(importSpecifier);

    auto *importDecl = g_impl->ETSParserBuildImportDeclaration(context, Es2pandaImportKinds::IMPORT_KINDS_ALL,
                                                               specifiersArray.data(), 1, importPath);
    return importDecl;
}

void InsertStatementInFunctionBody(es2panda_Context *context, es2panda_AstNode *func)
{
    auto *blockStmt = g_impl->ScriptFunctionBody(context, func);
    size_t newStmtNum = 1;
    auto **statement = g_impl->ETSParserCreateStatements(context, const_cast<char *>("let a0 = A0;"), &newStmtNum);
    PrependStatementToProgram(context, blockStmt, statement[0]);
}

es2panda_AstNode *GetTargetFunc(es2panda_Context *context, es2panda_AstNode *ast)
{
    static constexpr size_t BLK_STMT_IDX = 3;
    static constexpr size_t CLASS_DEF_IDX = 2;
    size_t blockStmtNum = 0;
    auto **blockStmt = g_impl->BlockStatementStatements(context, ast, &blockStmtNum);
    auto *etsGlobal = blockStmt[BLK_STMT_IDX];
    auto *classDef = g_impl->ClassDeclarationDefinition(context, etsGlobal);
    size_t blockStmtNum2 = 0;
    auto *classBody = g_impl->ClassDefinitionBody(context, classDef, &blockStmtNum2);
    auto *fooMethod = classBody[CLASS_DEF_IDX];
    auto *fooFunc = g_impl->MethodDefinitionFunction(context, fooMethod);

    return fooFunc;
}

bool TestInsertImportAfterParse(es2panda_Context *context, es2panda_Config *config, es2panda_Program *program)
{
    size_t externalSourceCnt {0};
    g_impl->ProgramExternalSources(context, g_impl->ContextProgram(context), &externalSourceCnt);
    std::cout << "ExternalProgram Count:" << externalSourceCnt << std::endl;
    auto *importDeclAfterParse = CreateImportDecl(context, "B", "B");

    g_impl->InsertETSImportDeclarationAndParse(context, program, importDeclAfterParse);
    auto *importDeclString = g_impl->AstNodeDumpEtsSrcConst(context, importDeclAfterParse);
    std::cout << importDeclString << std::endl;
    size_t externalSourceCntAfterInsert {0};
    g_impl->ProgramExternalSources(context, g_impl->ContextProgram(context), &externalSourceCntAfterInsert);
    std::cout << "ExternalProgram Count:" << externalSourceCntAfterInsert << std::endl;

    if (externalSourceCntAfterInsert != externalSourceCnt + 1) {
        std::cout << "Insert ETSImportDeclaration Failure." << std::endl;
        g_impl->DestroyContext(context);
        g_impl->DestroyConfig(config);
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

    std::cout << "LOAD SUCCESS" << std::endl;
    const char **args = const_cast<const char **>(std::next(argv));
    auto config = g_impl->CreateConfig(argc - 1, args);
    auto source = std::string("import {A} from \"./export\" ;function foo() {let b:B = new B();let a:A = new A()}");

    auto context = g_impl->CreateContextFromString(config, source.data(), *(std::next(argv, argc - 1)));
    if (context == nullptr) {
        std::cerr << "FAILED TO CREATE CONTEXT" << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }
    g_impl->ProceedToState(context, ES2PANDA_STATE_PARSED);
    CheckForErrors("PARSE", context);

    auto *program = g_impl->ContextProgram(context);
    if (!TestInsertImportAfterParse(context, config, program)) {
        return 1;
    }

    g_impl->ProceedToState(context, ES2PANDA_STATE_BOUND);
    CheckForErrors("BOUND", context);

    g_impl->ProceedToState(context, ES2PANDA_STATE_CHECKED);
    std::cout << g_impl->AstNodeDumpEtsSrcConst(context, g_impl->ProgramAst(context, program)) << std::endl;
    CheckForErrors("CHECKED", context);

    auto *importDeclAfterCheck = CreateImportDecl(context, "A0", "A0");
    g_impl->InsertETSImportDeclarationAndParse(context, program, importDeclAfterCheck);

    std::cout << g_impl->AstNodeDumpEtsSrcConst(context, g_impl->ProgramAst(context, program)) << std::endl;
    auto *tagetFunc = GetTargetFunc(context, g_impl->ProgramAst(context, program));
    InsertStatementInFunctionBody(context, tagetFunc);
    std::cout << g_impl->AstNodeDumpEtsSrcConst(context, g_impl->ProgramAst(context, program)) << std::endl;

    g_impl->AstNodeRecheck(context, g_impl->ProgramAst(context, program));

    g_impl->ProceedToState(context, ES2PANDA_STATE_LOWERED);
    CheckForErrors("LOWERED", context);

    g_impl->ProceedToState(context, ES2PANDA_STATE_ASM_GENERATED);
    CheckForErrors("ASM", context);

    g_impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    CheckForErrors("BIN", context);
    if (g_impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }
    g_impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
