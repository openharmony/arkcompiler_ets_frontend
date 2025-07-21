/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lsp/include/formatting/formatting_context.h"
#include "lsp_api_test.h"
#include <gtest/gtest.h>
#include "ir/astNode.h"

namespace {

class LSPFormattingContextTests : public LSPAPITests {};

TEST_F(LSPFormattingContextTests, FormattingContextConstructorTest)
{
    const size_t defaultIndentSize = 4U;
    const std::string defaultNewLine = "\n";

    ark::es2panda::lsp::FormatCodeSettings settings;
    settings.SetIndentSize(defaultIndentSize);
    settings.SetNewLineCharacter(defaultNewLine);
    settings.SetConvertTabsToSpaces(true);

    ark::es2panda::lsp::FormattingContext context(ark::es2panda::lsp::FormattingRequestKind::FORMAT_DOCUMENT, settings);

    EXPECT_EQ(context.GetformattingRequestKind(), ark::es2panda::lsp::FormattingRequestKind::FORMAT_DOCUMENT);
    EXPECT_EQ(context.GetFormatCodeSettings().GetIndentSize(), defaultIndentSize);
}

TEST_F(LSPFormattingContextTests, FormattingContextSameLineTest)
{
    const size_t firstLine = 1U;
    const size_t idStart = 4U;
    const size_t numStart = 8U;
    const size_t semiStart = 10U;

    ark::es2panda::lsp::Initializer initializer;
    auto ctx = initializer.CreateContext("sameLineTest.ets", ES2PANDA_STATE_CHECKED, "let x = 10;");
    auto contextPtr = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    auto program = contextPtr->parserProgram;

    ark::es2panda::lsp::FormatCodeSettings settings;
    ark::es2panda::lsp::FormattingContext context(ark::es2panda::lsp::FormattingRequestKind::FORMAT_ON_ENTER, settings);

    ark::es2panda::lexer::SourcePosition pos1(idStart, firstLine, program);
    ark::es2panda::lexer::SourcePosition pos2(numStart, firstLine, program);
    ark::es2panda::lexer::SourcePosition pos3(semiStart, firstLine, program);
    ark::es2panda::lsp::RangeWithKind span1(pos1, pos2, ark::es2panda::ir::AstNodeType::IDENTIFIER);
    ark::es2panda::lsp::RangeWithKind span2(pos2, pos3, ark::es2panda::ir::AstNodeType::NUMBER_LITERAL);

    context.UpdateContext(ctx, span1, span2);

    EXPECT_TRUE(context.TokensAreOnSameLine());

    initializer.DestroyContext(ctx);
}

TEST_F(LSPFormattingContextTests, FormattingContextDifferentLinesTest)
{
    const size_t firstLine = 1U;
    const size_t secondLine = 2U;
    const size_t idStart = 4U;
    const size_t numStart = 8U;

    ark::es2panda::lsp::Initializer initializer;
    auto ctx = initializer.CreateContext("differentLinesTest.ets", ES2PANDA_STATE_CHECKED, "let x = 10;\nlet y = 20;");
    auto contextPtr = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    auto program = contextPtr->parserProgram;

    ark::es2panda::lsp::FormatCodeSettings settings;
    ark::es2panda::lsp::FormattingContext context(ark::es2panda::lsp::FormattingRequestKind::FORMAT_ON_SEMICOLON,
                                                  settings);

    ark::es2panda::lexer::SourcePosition pos1(idStart, firstLine, program);
    ark::es2panda::lexer::SourcePosition pos2(numStart, firstLine, program);
    ark::es2panda::lexer::SourcePosition pos3(idStart, secondLine, program);
    ark::es2panda::lexer::SourcePosition pos4(numStart, secondLine, program);
    ark::es2panda::lsp::RangeWithKind span1(pos1, pos2, ark::es2panda::ir::AstNodeType::IDENTIFIER);
    ark::es2panda::lsp::RangeWithKind span2(pos3, pos4, ark::es2panda::ir::AstNodeType::IDENTIFIER);

    context.UpdateContext(ctx, span1, span2);

    EXPECT_TRUE(context.TokensAreOnSameLine());

    initializer.DestroyContext(ctx);
}

TEST_F(LSPFormattingContextTests, FormattingCodeSettingsTest)
{
    const size_t indentSize = 2U;
    const size_t tabSize = 4U;
    const std::string newlineChar = "\r\n";

    ark::es2panda::lsp::FormatCodeSettings settings;

    settings.SetIndentSize(indentSize);
    settings.SetTabSize(tabSize);
    settings.SetNewLineCharacter(newlineChar);
    settings.SetConvertTabsToSpaces(true);
    settings.SetInsertSpaceAfterCommaDelimiter(true);
    settings.SetInsertSpaceAfterSemicolonInForStatements(true);
    settings.SetInsertSpaceBeforeAndAfterBinaryOperators(true);

    ark::es2panda::lsp::FormattingContext context(ark::es2panda::lsp::FormattingRequestKind::FORMAT_DOCUMENT, settings);

    auto contextSettings = context.GetFormatCodeSettings();
    EXPECT_EQ(contextSettings.GetIndentSize(), indentSize);
    EXPECT_EQ(contextSettings.GetTabSize(), tabSize);
    EXPECT_EQ(contextSettings.GetNewLineCharacter(), newlineChar);
    EXPECT_TRUE(contextSettings.GetConvertTabsToSpaces());
    EXPECT_TRUE(contextSettings.GetInsertSpaceAfterCommaDelimiter());
    EXPECT_TRUE(contextSettings.GetInsertSpaceAfterSemicolonInForStatements());
    EXPECT_TRUE(contextSettings.GetInsertSpaceBeforeAndAfterBinaryOperators());
}

}  // namespace