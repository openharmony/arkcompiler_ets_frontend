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

#include "lsp/include/script_element_kind.h"
#include "lsp_api_test.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>

using ark::es2panda::lsp::CompletionEntryKind;
using ark::es2panda::lsp::Initializer;

namespace {

class LspScriptElementKindTests : public LSPAPITests {};

TEST_F(LSPAPITests, GetAliasScriptElementKind_1)
{
    LSPAPI const *lspApi = GetImpl();
    ASSERT_TRUE(lspApi != nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext(
        "script_element_kind.ets", ES2PANDA_STATE_CHECKED,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = "
        "\"foo\";\n");

    ASSERT_EQ(ContextState(context), ES2PANDA_STATE_CHECKED);
    size_t const numberLiteralOffset = 31;  // 31: position of '3' in '1234'
    size_t const stringLiteralOffset = 96;  // 96: position of first 'o' in 'foo'

    auto result = lspApi->getAliasScriptElementKind(context, numberLiteralOffset);
    ASSERT_EQ(result, CompletionEntryKind::VALUE);  // Literal is VALUE
    result = lspApi->getAliasScriptElementKind(context, stringLiteralOffset);
    ASSERT_EQ(result, CompletionEntryKind::VALUE);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetAliasScriptElementKind_2)
{
    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    es2panda_Context *context =
        initializer.CreateContext("script_element_kind.ets", ES2PANDA_STATE_CHECKED,
                                  "    \nfunction f() {\n    let a = 123;\n}\nconst s = \"hello\";\n");

    size_t const startOfFile = 0;            // 0: position of start of file, first space
    size_t const firstleftCurlyBrance = 18;  // 18：position of left curly brance after f()
    size_t const numberLiteralOffset = 33;   // 33: position of '2' in '123'
    size_t const stringLiteralOffset = 50;   // 50: position of 'h' in 'hello'

    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, startOfFile), CompletionEntryKind::TEXT);
    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, firstleftCurlyBrance), CompletionEntryKind::SNIPPET);
    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, numberLiteralOffset), CompletionEntryKind::VALUE);
    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, stringLiteralOffset), CompletionEntryKind::VALUE);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetAliasScriptElementKind_3)
{
    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();

    const char *statement = R"(let empty: null = null;
let notAssigned: undefined = undefined;)";
    es2panda_Context *context = initializer.CreateContext("script_element_kind.ets", ES2PANDA_STATE_CHECKED, statement);

    size_t const nullLiteral = 19;       // 19：position of the second null.
    size_t const etsNullType = 25;       // 25: position of the second let.
    size_t const undefinedLiteral = 54;  // 54: position of the second undefined.

    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, nullLiteral), CompletionEntryKind::VALUE);
    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, etsNullType), CompletionEntryKind::TEXT);
    ASSERT_EQ(lspApi->getAliasScriptElementKind(context, undefinedLiteral), CompletionEntryKind::VALUE);
    initializer.DestroyContext(context);
}

}  // namespace
