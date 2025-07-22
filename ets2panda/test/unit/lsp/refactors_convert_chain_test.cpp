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

#include <gtest/gtest.h>
#include <cstddef>
#include <string>
#include "lsp_api_test.h"
#include "lsp/include/applicable_refactors.h"

const size_t REFACTOR_CHAIN_POSITION_OFFSET = 8;

namespace {
using ark::es2panda::lsp::Initializer;

class LspChainRefTests : public LSPAPITests {
public:
    static constexpr std::string_view TO_NAMED_CHAIN_KIND = "refactor.rewrite.expression.optionalChain";
    static constexpr std::string_view TO_NAMED_CHAIN_NAME = "Convert to optional chain expression";
};

TEST_F(LspChainRefTests, ConvertChainRefactor1)
{
    std::vector<std::string> files = {"ConvertChainRefactor1.ets"};
    std::vector<std::string> texts = {R"(let a = {b: ()=>{return () =>{c:0}}}/*1*/a&&a.b&&a.b()().c/*2*/;)"};

    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    auto pos = texts[0].find("/*1*/");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    ark::es2panda::lsp::RefactorContext refactorContext;
    refactorContext.context = ctx;
    refactorContext.kind = std::string(TO_NAMED_CHAIN_KIND);
    refactorContext.span.pos = pos + REFACTOR_CHAIN_POSITION_OFFSET;
    auto result = GetApplicableRefactorsImpl(&refactorContext);

    initializer.DestroyContext(ctx);
    ASSERT_EQ(1, result.size());
    ASSERT_EQ(std::string(TO_NAMED_CHAIN_NAME), result[0].action.name);
}

TEST_F(LspChainRefTests, ConvertChainRefactor2)
{
    std::vector<std::string> files = {"ConvertChainRefactor2.ets"};
    std::vector<std::string> texts = {R"(interface A { baz?:string | null; }
interface Foo{
bar?: A
}
declare let foo: Foo;
let ccc = /*1*/foo.bar ? foo.bar.baz : "whenFalse";/*2*/
 )"};

    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    auto pos = texts[0].find("/*1*/");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    ark::es2panda::lsp::RefactorContext refactorContext;
    refactorContext.context = ctx;
    refactorContext.kind = std::string(TO_NAMED_CHAIN_KIND);
    refactorContext.span.pos = pos + REFACTOR_CHAIN_POSITION_OFFSET;
    auto result = GetApplicableRefactorsImpl(&refactorContext);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(0, result.size());
}

TEST_F(LspChainRefTests, ConvertChainRefactor3)
{
    std::vector<std::string> files = {"ConvertChainRefactor3.ets"};
    std::vector<std::string> texts = {R"(interface A { baz: string }
interface Foo{
bar?: A
}
declare let foo: Foo;
let ccc = /*1*/foo.bar ? foo.bar.baz: "whenFalse";/*2*/
 )"};

    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    auto pos = texts[0].find("/*1*/");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    ark::es2panda::lsp::RefactorContext refactorContext;
    refactorContext.context = ctx;
    refactorContext.kind = std::string(TO_NAMED_CHAIN_KIND);
    refactorContext.span.pos = pos + REFACTOR_CHAIN_POSITION_OFFSET;
    auto result = GetApplicableRefactorsImpl(&refactorContext);

    initializer.DestroyContext(ctx);
    ASSERT_EQ(1, result.size());
    ASSERT_EQ(std::string(TO_NAMED_CHAIN_NAME), result[0].action.name);
}

}  // namespace