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

#include "lsp_api_test.h"

#include <gtest/gtest.h>
#include <cstddef>

#include "ir/astNode.h"
#include "lsp/include/internal_api.h"
#include "public/es2panda_lib.h"

using ark::es2panda::lsp::Initializer;

TEST_F(LSPAPITests, GetPrecedingToken1)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext(

        "precedingtoken_literal.ets", ES2PANDA_STATE_CHECKED,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = "
        "\"foo\";\n");
    ASSERT_EQ(ContextState(context), ES2PANDA_STATE_CHECKED);
    auto ast = GetAstFromContext<AstNode>(context);

    size_t const numberLiteralOffset = 31;  // 31: position of '3' in '1234'
    size_t const stringLiteralOffset = 96;  // 96: position of first 'o' in 'foo'
    auto numberLiteral = ast->FindChild([](AstNode *node) { return node->IsExpressionStatement(); })
                             ->AsExpressionStatement()
                             ->GetExpression()
                             ->AsAssignmentExpression()
                             ->Right()
                             ->AsNumberLiteral();
    auto result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, numberLiteralOffset));
    ASSERT_EQ(result->DumpJSON(), numberLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, numberLiteral->Start().index);
    ASSERT_EQ(result->End().index, numberLiteral->End().index);
    auto stringLiteral = ast->FindChild(
        [](AstNode *node) { return node->IsStringLiteral() && node->AsStringLiteral()->ToString() == "foo"; });
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, stringLiteralOffset));
    ASSERT_EQ(result->DumpJSON(), stringLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, stringLiteral->Start().index);
    ASSERT_EQ(result->End().index, stringLiteral->End().index);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetPrecedingToken2)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext(
        "precedingtoken_function.ets", ES2PANDA_STATE_CHECKED,
        "    \n\n\n\nfunction f() {\n    le\n    let a = 123;\n}\n\n\n\nconst s = \"hello\";\n\n\n");
    auto ast = GetAstFromContext<AstNode>(context);

    size_t const startOfFile = 0;            // 0: position of start of file
    size_t const secondSpaceBeforeLe = 25;   // 25: position of second space before 'le'
    size_t const endOfLe = 29;               // 29: position of the end of 'le' identifier
    size_t const secondSpaceBeforeLet = 32;  // 32: position of second space before 'let'
    size_t const startOfLine10 = 50;         // 50: position of start of line 10
    size_t const startOfLine14 = 72;         // 72: position of start of line 14
    ASSERT_EQ(lspApi->getPrecedingToken(context, startOfFile), nullptr);
    ASSERT_EQ(lspApi->getPrecedingToken(context, secondSpaceBeforeLe), nullptr);
    auto leIdentifier =
        ast->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "le"; });
    auto result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, endOfLe));
    ASSERT_EQ(result->DumpJSON(), leIdentifier->DumpJSON());
    ASSERT_EQ(result->Start().index, leIdentifier->Start().index);
    ASSERT_EQ(result->End().index, leIdentifier->End().index);
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, secondSpaceBeforeLet));
    ASSERT_EQ(result->DumpJSON(), leIdentifier->DumpJSON());
    ASSERT_EQ(result->Start().index, leIdentifier->Start().index);
    ASSERT_EQ(result->End().index, leIdentifier->End().index);
    auto numberLiteral = ast->FindChild(
        [](AstNode *node) { return node->IsNumberLiteral() && node->AsNumberLiteral()->Str() == "123"; });
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, startOfLine10));
    ASSERT_EQ(result->DumpJSON(), numberLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, numberLiteral->Start().index);
    ASSERT_EQ(result->End().index, numberLiteral->End().index);
    auto stringLiteral = ast->FindChild([](AstNode *node) { return node->IsClassProperty(); })
                             ->AsClassProperty()
                             ->Value()
                             ->AsStringLiteral();
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, startOfLine14));
    ASSERT_EQ(result->DumpJSON(), stringLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, stringLiteral->Start().index);
    ASSERT_EQ(result->End().index, stringLiteral->End().index);
    initializer.DestroyContext(context);
}