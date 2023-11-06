/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ETSLexer.h"
#include "generated/keywords.h"

namespace panda::es2panda::lexer {
// NOLINTNEXTLINE(google-default-arguments)
void ETSLexer::NextToken(NextTokenFlags flags)
{
    ETSKeywords kws(this, static_cast<NextTokenFlags>(flags & ~NextTokenFlags::KEYWORD_TO_IDENT));
    Lexer::NextToken(&kws);
}

void ETSLexer::ScanHashMark()
{
    ThrowUnexpectedToken(TokenType::PUNCTUATOR_HASH_MARK);
}

bool ETSLexer::ScanCharLiteral()
{
    //  Note: for character literal on call iterator is pointed to the opening single quote (') character!
    //  Otherwise it's another token.
    if (Iterator().Peek() != LEX_CHAR_SINGLE_QUOTE) {
        return false;
    }

    GetToken().type_ = TokenType::LITERAL_CHAR;

    Iterator().Forward(1);
    char32_t cp = Iterator().PeekCp();

    switch (cp) {
        case LEX_CHAR_SINGLE_QUOTE:
        case util::StringView::Iterator::INVALID_CP: {
            ThrowError("Invalid character literal");
            break;
        }
        case LEX_CHAR_BACKSLASH: {
            GetToken().flags_ |= TokenFlags::HAS_ESCAPE;

            Iterator().Forward(1);
            cp = ScanUnicodeCharacter();
            break;
        }
        default: {
            Iterator().SkipCp();
            break;
        }
    }

    CheckUtf16Compatible(cp);
    GetToken().c16_ = cp;

    if (Iterator().Peek() != LEX_CHAR_SINGLE_QUOTE) {
        ThrowError("Unterminated character literal");
    }

    Iterator().Forward(1);
    return true;
}

void ETSLexer::CheckUtf16Compatible(char32_t cp) const
{
    if (cp >= util::StringView::Constants::CELESTIAL_OFFSET) {
        ThrowError("Unsupported character literal");
    }
}

void ETSLexer::SkipMultiLineComment()
{
    uint32_t depth = 1;

    while (true) {
        switch (Iterator().Next()) {
            case util::StringView::Iterator::INVALID_CP: {
                ThrowError("Unterminated multi-line comment");
                break;
            }
            case LEX_CHAR_LF:
            case LEX_CHAR_CR:
            case LEX_CHAR_LS:
            case LEX_CHAR_PS: {
                Pos().NextTokenLine()++;
                continue;
            }
            case LEX_CHAR_ASTERISK: {
                if (Iterator().Peek() == LEX_CHAR_SLASH) {
                    Iterator().Forward(1);

                    if (--depth == 0) {
                        return;
                    }
                }
                break;
            }
            case LEX_CHAR_SLASH: {
                if (Iterator().Peek() == LEX_CHAR_ASTERISK) {
                    Iterator().Forward(1);
                    depth++;
                }
                break;
            }

            default: {
                break;
            }
        }
    }
}

void ETSLexer::ScanAsteriskPunctuator()
{
    GetToken().type_ = TokenType::PUNCTUATOR_MULTIPLY;

    switch (Iterator().Peek()) {
        case LEX_CHAR_EQUALS: {
            GetToken().type_ = TokenType::PUNCTUATOR_MULTIPLY_EQUAL;
            Iterator().Forward(1);
            break;
        }
        default: {
            break;
        }
    }
}

void ETSLexer::ConvertNumber(const std::string &utf8, NumberFlags flags)
{
    GetToken().number_ = lexer::Number(GetToken().src_, utf8, flags);

    if (GetToken().number_.ConversionError()) {
        ThrowError("Invalid number");
    }
}

void ETSLexer::ScanEqualsPunctuator()
{
    GetToken().type_ = TokenType::PUNCTUATOR_SUBSTITUTION;

    switch (Iterator().Peek()) {
        case LEX_CHAR_EQUALS: {
            GetToken().type_ = TokenType::PUNCTUATOR_EQUAL;
            Iterator().Forward(1);

            if (Iterator().Peek() == LEX_CHAR_EQUALS) {
                GetToken().type_ = TokenType::PUNCTUATOR_STRICT_EQUAL;
                Iterator().Forward(1);
            }
            break;
        }
        case LEX_CHAR_GREATER_THAN: {
            GetToken().type_ = TokenType::PUNCTUATOR_ARROW;
            Iterator().Forward(1);
            break;
        }
        default: {
            break;
        }
    }
}

void ETSLexer::ScanExclamationPunctuator()
{
    GetToken().type_ = TokenType::PUNCTUATOR_EXCLAMATION_MARK;

    switch (Iterator().Peek()) {
        case LEX_CHAR_EQUALS: {
            GetToken().type_ = TokenType::PUNCTUATOR_NOT_EQUAL;
            Iterator().Forward(1);

            if (Iterator().Peek() == LEX_CHAR_EQUALS) {
                GetToken().type_ = TokenType::PUNCTUATOR_NOT_STRICT_EQUAL;
                Iterator().Forward(1);
            }
            break;
        }
        default: {
            break;
        }
    }
}

bool ETSLexer::ScanDollarPunctuator()
{
    if (Iterator().Peek() != LEX_CHAR_DOLLAR_SIGN) {
        return false;
    }

    GetToken().type_ = TokenType::PUNCTUATOR_DOLLAR_DOLLAR;
    Iterator().Forward(1);
    return true;
}
}  // namespace panda::es2panda::lexer
