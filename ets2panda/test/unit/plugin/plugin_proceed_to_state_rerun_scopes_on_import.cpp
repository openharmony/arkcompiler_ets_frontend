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

static es2panda_AstNode *letStatement = nullptr;
static std::vector<es2panda_AstNode *> *typeRefs = nullptr;
static es2panda_Context *ctx = nullptr;

es2panda_AstNode *parNode;
es2panda_Context *newCtx;

static void FindLet(es2panda_AstNode *ast)
{
    if (!impl->IsVariableDeclaration(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindLet);
        return;
    }
    letStatement = ast;
}

static void FindEtsTypeReferencesInLet(es2panda_AstNode *ast)
{
    if (!impl->IsETSTypeReferencePart(ast)) {
        impl->AstNodeIterateConst(ctx, ast, FindEtsTypeReferencesInLet);
        return;
    }
    typeRefs->push_back(ast);
    impl->AstNodeIterateConst(ctx, ast, FindEtsTypeReferencesInLet);
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

static bool ChangeAst(es2panda_Context *context)
{
    auto Ast = impl->ProgramAst(context, impl->ContextProgram(context));
    ctx = context;
    impl->AstNodeIterateConst(context, Ast, FindLet);
    if (letStatement == nullptr) {
        return false;
    }
    impl->AstNodeIterateConst(context, letStatement, FindEtsTypeReferencesInLet);
    if (typeRefs == nullptr) {
        return false;
    }

    std::string className = std::string("B");
    auto *memForName = static_cast<char *>(impl->AllocMemory(context, className.size() + 1, 1));
    std::copy_n(className.c_str(), className.size() + 1, memForName);

    for (auto typeRef : *typeRefs) {
        auto identifier = impl->ETSTypeReferencePartGetIdent(context, typeRef);
        impl->IdentifierSetName(context, identifier, memForName);
    }
    impl->AstNodeForEach(Ast, SetRightParent, context);
    impl->AstNodeRecheck(context, Ast);
    return true;
}

int main(int argc, char **argv)
{
    auto recheckTest = [&](es2panda_Context *context) -> bool {
        typeRefs = new std::vector<es2panda_AstNode *>();
        auto testResult = ChangeAst(context);
        delete typeRefs;
        typeRefs = nullptr;
        return testResult;
    };

    std::map<es2panda_ContextState, std::vector<std::function<bool(es2panda_Context *)>>> testFunctions;
    testFunctions[ES2PANDA_STATE_CHECKED] = {recheckTest};
    ProccedToStatePluginTestData data = {argc, argv, &impl, testFunctions, false, ""};
    return RunAllStagesWithTestFunction(data);
}

// NOLINTEND
