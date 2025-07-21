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

#include "lsp/include/suggestion_diagnostics.h"
#include <gtest/gtest.h>
#include "lsp/include/internal_api.h"
#include "lsp_api_test.h"
#include "public/es2panda_lib.h"
namespace {
using ark::es2panda::lsp::Initializer;

class LspSuggestionTests : public LSPAPITests {};

TEST_F(LspSuggestionTests, isFixablePromiseHandler)
{
    const char *source =
        "function fetchData():Promise<string>{\nreturn Promise.resolve(\"Success\");\n}"
        "\nfetchData().then();";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isFixablePromiseHandler2)
{
    const char *source =
        "function fetchData(name:string):Promise<string>{\nreturn Promise.resolve(\"Success\");\n}"
        "\nfetchData(\"test\").finally();";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isFixablePromiseHandler3)
{
    const char *source =
        "function fetchData():Promise<string>{\n"
        "return Promise.reject(\"Error\");\n}"
        "\nfetchData().catch();";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isFixablePromiseHandler4)
{
    const char *source =
        "function fetchData(name: string,name2:string):Promise<string>{\n"
        "\nreturn Promise.resolve(\"Success\");"
        "\n}\nfetchData(\"test\",\"test2\").finally();";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isReturnStatementWithFixablePromiseHandler)
{
    const char *source =
        "function fetchData(){\nreturn Promise.resolve(\"h\")\n;}\nfunction processData()"
        "{\nreturn fetchData().then();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsReturnStatementWithFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isReturnStatementWithFixablePromiseHandler2)
{
    const char *source =
        "function fetchData(){\nreturn Promise.resolve(\"h\")\n;}\n"
        "\nfunction processData(){\nreturn fetchData().finally();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsReturnStatementWithFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isReturnStatementWithFixablePromiseHandler3)
{
    const char *source =
        "function fetchData(){\nreturn Promise.reject(\"h\")\n;}\nfunction processData(){\n"
        "\nreturn fetchData().catch();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsReturnStatementWithFixablePromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, hasReturnStatementWithPromiseHandler)
{
    const char *source =
        "function fetchData(){\nreturn Promise.reject(\"h\")\n;}\nfunction processData()"
        "{\nreturn fetchData().catch();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::HasReturnStatementWithPromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, hasReturnStatementWithPromiseHandler2)
{
    const char *source =
        "function fetchData(){\nreturn Promise.resolve(\"h\")\n;}\nfunction processData(){\n"
        "\nreturn fetchData().finally();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::HasReturnStatementWithPromiseHandler(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isConvertibleFunction)
{
    const char *source =
        "function fetchData(){\nreturn Promise.resolve(\"h\")\n;}\nfunction processData()"
        "{\nreturn fetchData().finally();\n};\nprocessData();\n";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    EXPECT_TRUE(ark::es2panda::lsp::IsConvertibleFunction(ast, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}

TEST_F(LspSuggestionTests, isFixablePromiseArgument2)
{
    const char *source = "function myFun(x: string): string\n {return x;}\nconsole.log(\"add(1+2)\");";
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("sug-diag.ets", ES2PANDA_STATE_CHECKED, source);
    std::unordered_map<std::string, bool> visitedNestedConvertibleFunctions;
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    auto node = ast->FindChild([](ark::es2panda::ir::AstNode *childNode) {
        return (childNode->Type() == ark::es2panda::ir::AstNodeType::FUNCTION_EXPRESSION);
    });
    EXPECT_TRUE(ark::es2panda::lsp::IsFixablePromiseArgument(node, visitedNestedConvertibleFunctions));
    initializer.DestroyContext(ctx);
}
}  // namespace