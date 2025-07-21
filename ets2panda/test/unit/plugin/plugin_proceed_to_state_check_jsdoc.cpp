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

#include "os/library_loader.h"

#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN

static es2panda_Impl *impl = nullptr;
static es2panda_AstNode *targetClass = nullptr;

static std::string g_source = R"(
/**
 * @param1 {} behindStr
 * @param2 preStr { p }
 * @param3 preStr { p } behindStr
 * @param4 preStr {} behindStr
 * @returns { number }
 */
class A {}
)";

static std::vector<std::string> nameList = {"returns", "param4", "param3", "param2", "param1"};
static std::vector<std::string> paramList = {" number", "", " p", " p", ""};
static std::vector<std::string> commentsList = {"{ number }", "preStr {} behindStr", "preStr { p } behindStr",
                                                "preStr { p }", "{} behindStr"};

static void SetTargetClass(es2panda_AstNode *ast, void *context)
{
    auto ctx = reinterpret_cast<es2panda_Context *>(context);
    if (!impl->IsClassDefinition(ast)) {
        return;
    }
    auto *ident = impl->ClassDefinitionIdent(ctx, ast);
    if (ident == nullptr) {
        return;
    }
    auto name = impl->IdentifierName(ctx, ident);
    if (std::string(name) == "A") {
        targetClass = ast;
    }
}

static bool TestJSDoc(es2panda_Context *context)
{
    auto *program = impl->ContextProgram(context);
    auto *ast = impl->ProgramAst(context, program);
    impl->AstNodeForEach(ast, SetTargetClass, context);
    if (ast == nullptr) {
        std::cerr << "FAILED TO GET AST" << std::endl;
        return false;
    }
    size_t jsDocInfoArrayLen = 0;
    auto **jsDocInfoArray = impl->ClassDefinitionJsDocInformation(context, targetClass, &jsDocInfoArrayLen);
    if (jsDocInfoArray == nullptr || jsDocInfoArrayLen == 0) {
        std::cerr << "FAILED TO GET JsDocInfo" << std::endl;
        return false;
    }
    for (size_t i = 0; i < jsDocInfoArrayLen; ++i) {
        auto *jsDocInfo = jsDocInfoArray[i];
        if (jsDocInfo == nullptr) {
            std::cerr << "FAILED TO GET JsDocInfo" << std::endl;
            return false;
        }
        for (size_t j = 0; j < jsDocInfo->len; ++j) {
            auto *jsDocRecord = jsDocInfo->jsDocRecords[j];
            if (jsDocRecord == nullptr) {
                std::cerr << "FAILED TO GET JsDocRecord" << std::endl;
                return false;
            }
            auto *name = jsDocInfo->strings[j];
            if (name == nullptr) {
                std::cerr << "FAILED TO GET JsDocName" << std::endl;
                return false;
            }

            if (jsDocRecord->name != nameList[j]) {
                std::cerr << "exact: " << jsDocRecord->name << " exp: " << nameList[j] << std::endl;
                return false;
            }

            if (jsDocRecord->param != paramList[j]) {
                std::cerr << "exact: " << jsDocRecord->param << " exp: " << paramList[j] << std::endl;
                return false;
            }

            if (jsDocRecord->comment != commentsList[j]) {
                std::cerr << "exact: " << jsDocRecord->comment << " exp: " << commentsList[j] << std::endl;
                return false;
            }
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    std::vector<char *> newArgv(argv, argv + argc);
    const char *extraArg = "--parse-jsdoc";
    newArgv.push_back(const_cast<char *>(extraArg));
    int newArgc = static_cast<int>(newArgv.size());
    char **newArgvRaw = newArgv.data();

    std::map<es2panda_ContextState, std::vector<std::function<bool(es2panda_Context *)>>> testFunctions;
    testFunctions[ES2PANDA_STATE_PARSED] = {TestJSDoc};
    ProccedToStatePluginTestData data = {newArgc, newArgvRaw, &impl, testFunctions, true, g_source};
    return RunAllStagesWithTestFunction(data);
}

// NOLINTEND