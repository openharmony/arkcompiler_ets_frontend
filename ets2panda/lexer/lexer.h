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

#ifndef ES2PANDA_PARSER_CORE_LEXER_H
#define ES2PANDA_PARSER_CORE_LEXER_H

#include "lexer/regexp/regexp.h"
#include "lexer/token/letters.h"
#include "lexer/token/token.h"
#include "util/enumbitops.h"

namespace panda::es2panda::parser {
class ParserContext;
}  // namespace panda::es2panda::parser

namespace panda::es2panda::lexer {
class Keywords;

enum class NextTokenFlags : uint32_t {
    NONE = 0U,
    KEYWORD_TO_IDENT = 1U << 0U,
    NUMERIC_SEPARATOR_ALLOWED = 1U << 1U,
    BIGINT_ALLOWED = 1U << 2U,
};

DEFINE_BITOPS(NextTokenFlags)

class LexerPosition {
public:
    explicit LexerPosition(const util::StringView &source);
    DEFAULT_COPY_SEMANTIC(LexerPosition);
    DEFAULT_MOVE_SEMANTIC(LexerPosition);
    ~LexerPosition() = default;

    util::StringView::Iterator &Iterator()
    {
        return iterator_;
    }

    const util::StringView::Iterator &Iterator() const
    {
        return iterator_;
    }

    size_t Line() const
    {
        return line_;
    }

    Token &GetToken()
    {
        return token_;
    }

    const Token &GetToken() const
    {
        return token_;
    }

    size_t &NextTokenLine()
    {
        return next_token_line_;
    }

private:
    friend class Lexer;

    Token token_ {};
    util::StringView::Iterator iterator_;
    size_t line_ {};
    size_t next_token_line_ {};
};

class LexerTemplateString {
public:
    explicit LexerTemplateString(ArenaAllocator *allocator) : str(allocator) {}
    DEFAULT_COPY_SEMANTIC(LexerTemplateString);
    DEFAULT_MOVE_SEMANTIC(LexerTemplateString);
    ~LexerTemplateString() = default;

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    util::UString str;
    size_t end {};
    bool scan_expression {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class TemplateLiteralParserContext;

class Lexer {
public:
    explicit Lexer(const parser::ParserContext *parser_context, bool start_lexer = true);
    NO_COPY_SEMANTIC(Lexer);
    NO_MOVE_SEMANTIC(Lexer);
    virtual ~Lexer() = default;

    // NOLINTNEXTLINE(google-default-arguments)
    virtual void NextToken(NextTokenFlags flags = NextTokenFlags::NONE);
    virtual void ScanAsteriskPunctuator();

    Token &GetToken();
    const Token &GetToken() const;
    size_t Line() const;

    LexerPosition Save() const;
    void Rewind(const LexerPosition &pos);
    void BackwardToken(TokenType type, size_t offset);
    void ForwardToken(TokenType type, size_t offset);

    char32_t Lookahead();
    bool CheckArrow();

    RegExp ScanRegExp();
    template <char32_t END>
    void ScanString();
    void ResetTokenEnd();
    LexerTemplateString ScanTemplateString();
    void ScanTemplateStringEnd();
    void PushTemplateContext(TemplateLiteralParserContext *ctx);
    [[noreturn]] void ThrowUnexpectedStrictModeReservedKeyword() const
    {
        ThrowError("Unexpected strict mode reserved keyword");
    }

    enum class ConversionResult : uint8_t {
        SUCCESS,
        INVALID_ARGUMENT,
        OUT_OF_RANGE,
    };

    template <typename Tret, typename Ret = Tret, typename... Base>
    static Ret StrToNumeric(Tret (*converter)(const char *, char **, Base...), const char *str,
                            ConversionResult &result, Base... base) noexcept
    {
        Ret ret {};
        char *end_ptr;
        // NOLINTBEGIN(cppcoreguidelines-special-member-functions)
        struct SaveErrno {
            explicit SaveErrno() : errno_(errno)
            {
                errno = 0;
            }
            ~SaveErrno()
            {
                if (errno == 0) {
                    errno = errno_;
                }
            }

        private:
            decltype(errno) errno_;
        } const saved_errno;
        // NOLINTEND(cppcoreguidelines-special-member-functions)

        const Tret tmp = converter(str, &end_ptr, base...);

        bool out_of_range = false;
        if constexpr (std::is_same_v<Ret, int>) {
            out_of_range = tmp < static_cast<Tret>(std::numeric_limits<int>::min()) ||
                           tmp > static_cast<Tret>(std::numeric_limits<int>::max());
        }

        if (end_ptr == str) {
            result = ConversionResult::INVALID_ARGUMENT;
        } else if (errno == ERANGE || out_of_range) {
            result = ConversionResult::OUT_OF_RANGE;
        } else {
            result = ConversionResult::SUCCESS;
            ret = tmp;
        }

        return ret;
    }

    util::StringView SourceView(size_t begin, size_t end) const;

protected:
    void NextToken(Keywords *kws);
    ArenaAllocator *Allocator();
    bool IsLineTerminatorOrEos() const;
    void ScanRegExpPattern();
    RegExpFlags ScanRegExpFlags();

    [[noreturn]] void ThrowError(std::string_view message) const;
    [[noreturn]] void ThrowUnexpectedToken(lexer::TokenType token_type) const;

    void SetTokenStart();
    void SetTokenEnd();

    inline util::StringView::Iterator &Iterator()
    {
        return pos_.iterator_;
    }

    inline const util::StringView::Iterator &Iterator() const
    {
        return pos_.iterator_;
    }

    util::StringView SourceView(const util::StringView::Iterator &begin, const util::StringView::Iterator &end) const;

    void SkipWhiteSpaces();
    void SkipSingleLineComment();

    bool ScanPunctuator();
    void ScanQuestionPunctuator();
    void ScanLessThanPunctuator();
    void ScanGreaterThanPunctuator();
    virtual void ScanEqualsPunctuator();
    virtual void ScanExclamationPunctuator();
    void ScanAmpersandPunctuator();
    void ScanVLinePunctuator();
    void ScanCircumflexPunctuator();
    void ScanPlusPunctuator();
    void ScanMinusPunctuator();
    void ScanSlashPunctuator();
    void ScanPercentPunctuator();
    void ScanDotPunctuator();
    void ScanColonPunctuator();

    virtual void SkipMultiLineComment();
    virtual void ScanHashMark();
    virtual void ScanBackTick();

    virtual bool ScanCharLiteral()
    {
        return false;
    }

    char32_t ScanUnicodeEscapeSequence();
    template <int N, bool IN_AS = false>
    char32_t ScanHexEscape();
    char32_t ScanUnicodeCodePointEscape();

    void ScanStringUnicodePart(util::UString *str);
    char32_t ScanUnicodeCharacter();

    void ScanDecimalNumbers();

    virtual void ScanNumberLeadingZero()
    {
        ScanNumberLeadingZeroImpl<double>();
    }

    template <typename RadixType, typename RadixLimit = void *>
    void ScanNumberLeadingZeroImpl();
    template <bool RANGE_CHECK(char32_t), int RADIX, typename RadixType, typename RadixLimit>
    void ScanNumberRadix(bool allow_numeric_separator = true);
    void ScanNumber(bool allow_big_int = true);
    virtual void ConvertNumber(const std::string &utf8, NumberFlags flags);
    void ScanDecimalLiteral();
    void ScanDecimalDigits(bool allow_numeric_separator);
    void CheckNumberLiteralEnd();

    inline static uint32_t HexValue(char32_t ch);
    inline static bool IsDecimalDigit(uint32_t cp);
    inline static bool IsHexDigit(char32_t ch);
    inline static bool IsBinaryDigit(char32_t ch);
    inline static bool IsOctalDigit(char32_t ch);

    friend class KeywordsUtil;
    friend class TemplateLiteralParserContext;

    LexerPosition &Pos();
    const LexerPosition &Pos() const;

private:
    TemplateLiteralParserContext *tl_ctx_ {};
    ArenaAllocator *allocator_;
    Keywords *kws_ {};
    const parser::ParserContext *parser_context_;
    util::StringView source_;
    LexerPosition pos_;
};

class TemplateLiteralParserContext {
public:
    explicit TemplateLiteralParserContext(Lexer *lexer) : lexer_(lexer), prev_(lexer_->tl_ctx_) {}
    NO_MOVE_SEMANTIC(TemplateLiteralParserContext);
    NO_COPY_SEMANTIC(TemplateLiteralParserContext);

    ~TemplateLiteralParserContext()
    {
        lexer_->tl_ctx_ = prev_;
    }

    void ConsumeLeftBrace()
    {
        brace_depth_++;
    }

    bool ConsumeRightBrace()
    {
        brace_depth_--;

        return brace_depth_ == 0;
    }

private:
    Lexer *lexer_;
    TemplateLiteralParserContext *prev_ {};
    size_t brace_depth_ {1};
};

template <char32_t END>
void Lexer::ScanString()
{
    util::UString str(Allocator());
    GetToken().type_ = TokenType::LITERAL_STRING;
    GetToken().keyword_type_ = TokenType::LITERAL_STRING;

    const auto start_pos = Iterator().Index();
    auto escape_end = start_pos;

    do {
        char32_t cp = Iterator().Peek();

        switch (cp) {
            case util::StringView::Iterator::INVALID_CP: {
                ThrowError("Unterminated string");
                break;
            }
            case LEX_CHAR_CR:
            case LEX_CHAR_LF: {
                // NOLINTNEXTLINE(readability-braces-around-statements,bugprone-suspicious-semicolon)
                if constexpr (END != LEX_CHAR_BACK_TICK) {
                    ThrowError("Newline is not allowed in strings");
                }

                GetToken().flags_ |= TokenFlags::HAS_ESCAPE;
                str.Append(SourceView(escape_end, Iterator().Index()));

                if (cp == LEX_CHAR_CR) {
                    Iterator().Forward(1);

                    if (Iterator().Peek() != LEX_CHAR_LF) {
                        Iterator().Backward(1);
                    }
                }

                pos_.line_++;
                str.Append(LEX_CHAR_LF);
                Iterator().Forward(1);
                escape_end = Iterator().Index();
                continue;
            }
            case LEX_CHAR_BACKSLASH: {
                GetToken().flags_ |= TokenFlags::HAS_ESCAPE;
                str.Append(SourceView(escape_end, Iterator().Index()));

                Iterator().Forward(1);
                ScanStringUnicodePart(&str);
                escape_end = Iterator().Index();
                continue;
            }
            case LEX_CHAR_BACK_TICK:
            case LEX_CHAR_SINGLE_QUOTE:
            case LEX_CHAR_DOUBLE_QUOTE: {
                if (END == cp) {
                    break;
                }

                Iterator().Forward(1);
                continue;
            }
            case LEX_CHAR_DOLLAR_SIGN: {
                Iterator().Forward(1);

                // NOLINTNEXTLINE(readability-braces-around-statements,bugprone-suspicious-semicolon)
                if constexpr (END == LEX_CHAR_BACK_TICK) {
                    if (Iterator().Peek() == LEX_CHAR_LEFT_BRACE) {
                        Iterator().Backward(1);
                        break;
                    }
                }

                continue;
            }
            default: {
                Iterator().SkipCp();
                continue;
            }
        }

        if (GetToken().flags_ & TokenFlags::HAS_ESCAPE) {
            str.Append(SourceView(escape_end, Iterator().Index()));
            GetToken().src_ = str.View();
        } else {
            GetToken().src_ = SourceView(start_pos, Iterator().Index());
        }

        break;
    } while (true);

    // NOLINTNEXTLINE(readability-braces-around-statements,bugprone-suspicious-semicolon)
    if constexpr (END != LEX_CHAR_BACK_TICK) {
        Iterator().Forward(1);
    }
}

template <int N, bool IN_AS>
char32_t Lexer::ScanHexEscape()
{
    char32_t code = 0;

    for (size_t i = 0; i < N; ++i) {
        const auto cp = Iterator().Peek();
        if (IN_AS && cp == LEX_CHAR_BACK_TICK) {
            break;
        }

        Iterator().Forward(1);

        if (!IsHexDigit(cp)) {
            ThrowError("Invalid unicode escape sequence");
        }

        constexpr auto MULTIPLIER = 16;
        code = code * MULTIPLIER + HexValue(cp);
    }

    return code;
}

template <typename RadixType, typename RadixLimit>
void Lexer::ScanNumberLeadingZeroImpl()
{
    GetToken().type_ = TokenType::LITERAL_NUMBER;
    GetToken().keyword_type_ = TokenType::LITERAL_NUMBER;

    switch (Iterator().Peek()) {
        case LEX_CHAR_LOWERCASE_X:
        case LEX_CHAR_UPPERCASE_X: {
            Iterator().Forward(1);
            constexpr auto RADIX = 16;
            ScanNumberRadix<IsHexDigit, RADIX, RadixType, RadixLimit>();
            CheckNumberLiteralEnd();
            return;
        }
        case LEX_CHAR_LOWERCASE_B:
        case LEX_CHAR_UPPERCASE_B: {
            Iterator().Forward(1);
            constexpr auto RADIX = 2;
            ScanNumberRadix<IsBinaryDigit, RADIX, RadixType, RadixLimit>();
            CheckNumberLiteralEnd();
            return;
        }
        case LEX_CHAR_LOWERCASE_O:
        case LEX_CHAR_UPPERCASE_O: {
            Iterator().Forward(1);
            constexpr auto RADIX = 8;
            ScanNumberRadix<IsOctalDigit, RADIX, RadixType, RadixLimit>();

            switch (Iterator().Peek()) {
                case LEX_CHAR_8:
                case LEX_CHAR_9: {
                    ThrowError("Invalid octal digit");
                }
                default: {
                    break;
                }
            }

            CheckNumberLiteralEnd();
            return;
        }
        case LEX_CHAR_0:
        case LEX_CHAR_1:
        case LEX_CHAR_2:
        case LEX_CHAR_3:
        case LEX_CHAR_4:
        case LEX_CHAR_5:
        case LEX_CHAR_6:
        case LEX_CHAR_7: {
            ThrowError("Implicit octal literal not allowed");
        }
        case LEX_CHAR_8:
        case LEX_CHAR_9: {
            ThrowError("NonOctalDecimalIntegerLiteral is not enabled in strict mode code");
        }
        case LEX_CHAR_UNDERSCORE: {
            ThrowError("Numeric separator '_' is not allowed in numbers that start with '0'.");
        }
        default: {
            break;
        }
    }

    ScanNumber();
}

template <bool RANGE_CHECK(char32_t), int RADIX, typename RadixType, typename RadixLimit>
void Lexer::ScanNumberRadix(bool allow_numeric_separator)
{
    RadixType number {};

    auto cp = Iterator().Peek();
    if (!RANGE_CHECK(cp)) {
        ThrowError("Invalid digit");
    }

    bool allow_numeric_on_next = true;

    do {
        cp = Iterator().Peek();
        if (RANGE_CHECK(cp)) {
            auto digit = HexValue(cp);

            if constexpr (std::is_arithmetic_v<RadixLimit>) {
                if (number > std::numeric_limits<RadixLimit>::max() / RADIX) {
                    ThrowError("Number is too large");
                }
            }

            number = number * RADIX + digit;
            Iterator().Forward(1);
            allow_numeric_on_next = true;
            continue;
        }

        if (cp == LEX_CHAR_UNDERSCORE) {
            if (!allow_numeric_separator || !allow_numeric_on_next) {
                ThrowError("Invalid numeric separator");
            }

            GetToken().flags_ |= TokenFlags::NUMBER_HAS_UNDERSCORE;
            Iterator().Forward(1);
            allow_numeric_on_next = false;
            continue;
        }

        if (!allow_numeric_on_next) {
            Iterator().Backward(1);
            ThrowError("Numeric separators are not allowed at the end of numeric literals");
        }

        break;
    } while (true);

    GetToken().number_ = lexer::Number(number);
}

inline uint32_t Lexer::HexValue(char32_t ch)
{
    constexpr uint32_t HEX_MASK = 0xF;
    constexpr uint32_t DEC_OFFSET = 10;
    return ch < LEX_CHAR_UPPERCASE_A ? ch - LEX_CHAR_0 : ((ch - LEX_CHAR_UPPERCASE_A + DEC_OFFSET) & HEX_MASK);
}

inline bool Lexer::IsDecimalDigit(uint32_t cp)
{
    return (cp >= LEX_CHAR_0 && cp <= LEX_CHAR_9);
}

inline bool Lexer::IsHexDigit(char32_t ch)
{
    return ch < LEX_ASCII_MAX_BITS && (std::isxdigit(static_cast<unsigned char>(ch)) != 0);
}

inline bool Lexer::IsBinaryDigit(char32_t ch)
{
    return ch == LEX_CHAR_0 || ch == LEX_CHAR_1;
}

inline bool Lexer::IsOctalDigit(char32_t ch)
{
    return (ch >= LEX_CHAR_0 && ch <= LEX_CHAR_7);
}
}  // namespace panda::es2panda::lexer

#endif
