/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_CORE_ETS_LEXER_H
#define ES2PANDA_PARSER_CORE_ETS_LEXER_H

#include "lexer/lexer.h"
#include "token/letters.h"

namespace ark::es2panda::lexer {
class ETSLexer final : public Lexer {
public:
    explicit ETSLexer(const parser::ParserContext *parserContext) : Lexer(parserContext, false)
    {
        SkipWhiteSpaces();
    }

    NO_COPY_SEMANTIC(ETSLexer);
    NO_MOVE_SEMANTIC(ETSLexer);
    ~ETSLexer() override = default;

    // NOLINTNEXTLINE(google-default-arguments)
    void NextToken(NextTokenFlags flags = NextTokenFlags::NONE) override;
    void ScanHashMark() override;
    bool ScanCharLiteral() override;
    void ScanAsteriskPunctuator() override;

    void ScanNumberLeadingZero() override
    {
        const auto savedLexerPosition = Save();

        bool allowBigint = false;
        if (Iterator().Peek() == LEX_CHAR_LOWERCASE_N) {
            // 0n is the only allowed bigint literal with leading 0
            allowBigint = true;
        }

        if (!ScanNumberLeadingZeroImpl<uint32_t, uint32_t>()) {
            Rewind(savedLexerPosition);
            if (!ScanNumberLeadingZeroImpl<uint64_t, uint64_t>()) {
                ThrowError("Number is too large");
            }
        }

        if ((GetToken().flags_ & TokenFlags::NUMBER_BIGINT) != 0) {
            if (!allowBigint) {
                ThrowError("Invalid BigInt number");
            }
        }
    }

    void CheckNumberLiteralEnd() override;
    void CheckUtf16Compatible(char32_t cp) const;
    void ConvertNumber(const std::string &utf8, NumberFlags flags) override;

protected:
    void ScanEqualsPunctuator() override;
    void ScanExclamationPunctuator() override;
    bool ScanDollarPunctuator() override;
};
}  // namespace ark::es2panda::lexer

#endif
