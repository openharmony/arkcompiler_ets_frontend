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

#include "regexp.h"

#include "plugins/ecmascript/es2panda/lexer/token/letters.h"
#include "unicode/uchar.h"

#include <iostream>

namespace panda::es2panda::lexer {
RegExpError::RegExpError(std::string_view m) : message(m) {}

RegExp::RegExp(util::StringView p, util::StringView f, RegExpFlags re_flags)
    : pattern_str(p), flags_str(f), flags(re_flags)
{
}

RegExpParser::RegExpParser(const RegExp &re, ArenaAllocator *allocator)
    : re_(re), allocator_ {allocator}, iter_(re_.pattern_str)
{
}

bool RegExpParser::Unicode() const
{
    return (re_.flags & RegExpFlags::UNICODE) != 0;
}

char32_t RegExpParser::Peek() const
{
    return iter_.Peek();
}

char32_t RegExpParser::Next()
{
    return iter_.Next();
}

static bool IsDecimalDigit(char32_t cp)
{
    return (cp >= LEX_CHAR_0 && cp <= LEX_CHAR_9);
}

static bool IsOctalDigit(char32_t cp)
{
    return (cp >= LEX_CHAR_0 && cp <= LEX_CHAR_7);
}

static bool IsHexDigit(char32_t cp)
{
    return IsDecimalDigit(cp) || (cp >= LEX_CHAR_LOWERCASE_A && cp <= LEX_CHAR_LOWERCASE_F) ||
           (cp >= LEX_CHAR_UPPERCASE_A && cp <= LEX_CHAR_UPPERCASE_F);
}

static uint32_t DigitValue(char32_t cp)
{
    return (cp - LEX_CHAR_0);
}

static uint32_t HexValue(char32_t cp)
{
    if (IsDecimalDigit(cp)) {
        return DigitValue(cp);
    }

    constexpr auto OFFSET = 10;

    if (cp < LEX_CHAR_LOWERCASE_A) {
        return cp - LEX_CHAR_UPPERCASE_A + OFFSET;
    }

    return (cp - LEX_CHAR_LOWERCASE_A + OFFSET);
}

static void ThrowError(std::string_view message)
{
    throw RegExpError(message);
}

void RegExpParser::ParsePattern()
{
    ParseDisjunction();

    if (iter_.HasNext()) {
        ThrowError("Invalid closing parenthesis");
    }

    if (!back_references_.empty() && !group_names_.empty()) {
        for (const auto it : back_references_) {
            auto result = group_names_.find(it);
            if (result == group_names_.end()) {
                ThrowError("Invalid capturing group");
            }
        }
    }
}

void RegExpParser::ParseDisjunction()
{
    while (true) {
        ParseAlternatives();

        if (Peek() != LEX_CHAR_VLINE) {
            break;
        }

        Next();
    };
}

void RegExpParser::ParseAlternative()
{
    switch (Peek()) {
        case LEX_CHAR_BACKSLASH: {
            Next();
            char32_t cp = Peek();
            if (cp == LEX_CHAR_LOWERCASE_B || cp == LEX_CHAR_UPPERCASE_B) {
                /* assertion */
                Next();
                return;
            }

            ParseAtomEscape();
            break;
        }
        case LEX_CHAR_CIRCUMFLEX:
        case LEX_CHAR_DOLLAR_SIGN: {
            /* assertion */
            Next();
            return;
        }
        case LEX_CHAR_LEFT_PAREN: {
            Next();

            if (Peek() != LEX_CHAR_QUESTION) {
                ParseCapturingGroup();
                break;
            }

            Next();  // eat '?'

            char32_t cp = Next();
            if (cp == LEX_CHAR_COLON) {
                ParseNonCapturingGroup();
                break;
            }

            if (cp == LEX_CHAR_EQUALS || cp == LEX_CHAR_EXCLAMATION) {
                ParseAssertion();

                if (Unicode()) {
                    return;
                }

                break;
            }

            if (cp != LEX_CHAR_LESS_THAN) {
                ThrowError("Invalid group");
            }

            cp = Peek();
            if (cp == LEX_CHAR_EQUALS || cp == LEX_CHAR_EXCLAMATION) {
                Next();
                ParseAssertion();
                return;
            }

            ParseNamedCapturingGroup();
            break;
        }
        case LEX_CHAR_LEFT_SQUARE: {
            Next();
            ParseCharacterClass();
            break;
        }
        case LEX_CHAR_DOT: {
            Next();
            break;
        }
        default: {
            if (ParseBracedQuantifier()) {
                ThrowError("Invalid quantifier, nothing to repeat");
            }

            if (!ParsePatternCharacter()) {
                ThrowError("Invalid character");
            }

            break;
        }
    }

    ParseQuantifier();
}

void RegExpParser::ParseAlternatives()
{
    while (true) {
        switch (Peek()) {
            case util::StringView::Iterator::INVALID_CP:
            case LEX_CHAR_RIGHT_PAREN:
            case LEX_CHAR_VLINE: {
                return;
            }
            default: {
                ParseAlternative();
            }
        }
    }
}

void RegExpParser::ParseNonCapturingGroup()
{
    ParseDisjunction();

    if (Peek() != LEX_CHAR_RIGHT_PAREN) {
        ThrowError("Invalid non-capturing group");
    }

    Next();
}

void RegExpParser::ParseNamedCapturingGroup()
{
    util::StringView name = ParseIdent();

    auto result = group_names_.insert(name);
    if (!result.second) {
        ThrowError("Duplicate group name");
    }

    ParseCapturingGroup();
}

void RegExpParser::ParseCapturingGroup()
{
    capturing_group_count_++;

    ParseDisjunction();

    if (Peek() != LEX_CHAR_RIGHT_PAREN) {
        ThrowError("Invalid capturing group");
    }

    Next();
}

void RegExpParser::ParseAssertion()
{
    ParseDisjunction();

    if (Peek() != LEX_CHAR_RIGHT_PAREN) {
        ThrowError("Invalid assertion");
    }

    Next();
}

uint32_t RegExpParser::ParseControlEscape()
{
    char32_t cp = Peek();
    if ((cp < LEX_CHAR_LOWERCASE_A || cp > LEX_CHAR_LOWERCASE_Z) &&
        (cp < LEX_CHAR_UPPERCASE_A || cp > LEX_CHAR_UPPERCASE_Z)) {
        if (Unicode()) {
            ThrowError("Invalid control escape");
        }

        if (cp < LEX_CHAR_0 || cp > LEX_CHAR_9) {
            return LEX_CHAR_LOWERCASE_C;
        }
    }

    Next();
    constexpr auto MODULO = 32;
    return cp % MODULO;
}

char32_t RegExpParser::ParseClassAtom()
{
    char32_t cp = Next();
    if (cp != LEX_CHAR_BACKSLASH) {
        return cp;
    }

    cp = Peek();
    if (cp == LEX_CHAR_0) {
        if (!Unicode()) {
            return ParseDecimalEscape();
        }

        Next();

        if (IsDecimalDigit(Peek())) {
            ThrowError("Invalid class escape");
        }

        return LEX_CHAR_NULL;
    }

    Next();

    switch (cp) {
        case LEX_CHAR_LOWERCASE_C: {
            return ParseControlEscape();
        }
        case LEX_CHAR_LOWERCASE_X: {
            return ParseHexEscape();
        }
        case LEX_CHAR_LOWERCASE_U: {
            if (!Unicode() && Peek() == LEX_CHAR_LEFT_BRACE) {
                return cp;
            }

            return ParseUnicodeEscape();
        }
        case LEX_CHAR_LOWERCASE_P:
        case LEX_CHAR_UPPERCASE_P: {
            if (!Unicode()) {
                return cp;
            }

            ParseUnicodePropertyEscape();
            [[fallthrough]];
        }
        case LEX_CHAR_LOWERCASE_D:
        case LEX_CHAR_UPPERCASE_D:
        case LEX_CHAR_LOWERCASE_S:
        case LEX_CHAR_UPPERCASE_S:
        case LEX_CHAR_LOWERCASE_W:
        case LEX_CHAR_UPPERCASE_W: {
            return std::numeric_limits<uint32_t>::max();
        }
        case LEX_CHAR_LOWERCASE_B: {
            return LEX_CHAR_BS;
        }
        case LEX_CHAR_LOWERCASE_F: {
            return LEX_CHAR_FF;
        }
        case LEX_CHAR_LOWERCASE_N: {
            return LEX_CHAR_LF;
        }
        case LEX_CHAR_LOWERCASE_R: {
            return LEX_CHAR_CR;
        }
        case LEX_CHAR_LOWERCASE_T: {
            return LEX_CHAR_TAB;
        }
        case LEX_CHAR_LOWERCASE_V: {
            return LEX_CHAR_VT;
        }
        case LEX_CHAR_MINUS: {
            return cp;
        }
        default: {
            if (Unicode() && !IsSyntaxCharacter(cp) && cp != LEX_CHAR_SLASH) {
                ThrowError("Invalid escape");
            }

            return cp;
        }
    }

    return cp;
}

static bool IsClassEscape(uint32_t cp)
{
    return cp == std::numeric_limits<uint32_t>::max();
}

void RegExpParser::ParseCharacterClass()
{
    if (Peek() == LEX_CHAR_CIRCUMFLEX) {
        Next();
    }

    while (true) {
        if (Peek() == LEX_CHAR_RIGHT_SQUARE) {
            Next();
            break;
        }

        uint32_t left = ParseClassAtom();

        if (Peek() != LEX_CHAR_MINUS) {
            continue;
        }

        Next();

        if (Peek() == LEX_CHAR_RIGHT_SQUARE) {
            Next();
            break;
        }

        uint32_t right = ParseClassAtom();
        if ((IsClassEscape(left) || IsClassEscape(right))) {
            if (Unicode()) {
                ThrowError("Invalid character class");
            }

            continue;
        }

        if (left > right) {
            ThrowError("Class range out of order");
        }
    }
}

bool RegExpParser::IsSyntaxCharacter(char32_t cp) const
{
    switch (cp) {
        case LEX_CHAR_RIGHT_SQUARE:
        case LEX_CHAR_LEFT_BRACE:
        case LEX_CHAR_RIGHT_BRACE: {
            if (!Unicode()) {
                return false;
            }

            [[fallthrough]];
        }
        case LEX_CHAR_CIRCUMFLEX:
        case LEX_CHAR_DOLLAR_SIGN:
        case LEX_CHAR_BACKSLASH:
        case LEX_CHAR_DOT:
        case LEX_CHAR_ASTERISK:
        case LEX_CHAR_PLUS:
        case LEX_CHAR_QUESTION:
        case LEX_CHAR_LEFT_PAREN:
        case LEX_CHAR_RIGHT_PAREN:
        case LEX_CHAR_LEFT_SQUARE:
        case LEX_CHAR_VLINE: {
            return true;
        }
        default: {
            return false;
        }
    }
}

void RegExpParser::ParseAtomEscape()
{
    char32_t cp = Peek();
    if (IsDecimalDigit(cp)) {
        ParseDecimalEscape();
        return;
    }

    Next();

    switch (cp) {
        case LEX_CHAR_LOWERCASE_X: {
            ParseHexEscape();
            break;
        }
        case LEX_CHAR_LOWERCASE_U: {
            ParseUnicodeEscape();
            break;
        }
        case LEX_CHAR_LOWERCASE_K: {
            ParseNamedBackreference();
            return;
        }
        /* ControlEscape */
        case LEX_CHAR_LOWERCASE_F:
        case LEX_CHAR_LOWERCASE_N:
        case LEX_CHAR_LOWERCASE_R:
        case LEX_CHAR_LOWERCASE_T:
        case LEX_CHAR_LOWERCASE_V:
        /* CharacterClassEscape */
        case LEX_CHAR_LOWERCASE_D:
        case LEX_CHAR_UPPERCASE_D:
        case LEX_CHAR_LOWERCASE_S:
        case LEX_CHAR_UPPERCASE_S:
        case LEX_CHAR_LOWERCASE_W:
        case LEX_CHAR_UPPERCASE_W: {
            return;
        }
        case LEX_CHAR_LOWERCASE_P:
        case LEX_CHAR_UPPERCASE_P: {
            ParseUnicodePropertyEscape();
            return;
        }
        case LEX_CHAR_LOWERCASE_C: {
            cp = Peek();
            if ((cp < LEX_CHAR_LOWERCASE_A || cp > LEX_CHAR_LOWERCASE_Z) &&
                (cp < LEX_CHAR_UPPERCASE_A || cp > LEX_CHAR_UPPERCASE_Z)) {
                ThrowError("Invalid control escape");
            }

            Next();
            return;
        }
        default: {
            /* IdentityEscape */
            if (Unicode() && !IsSyntaxCharacter(cp) && cp != LEX_CHAR_SLASH) {
                ThrowError("Invalid escape");
            }
        }
    }
}

uint32_t RegExpParser::ParseDecimalEscape()
{
    ASSERT(IsDecimalDigit(Peek()));

    auto digit_start = iter_;
    uint32_t decimal_value = DigitValue(Next());
    if (decimal_value == 0) {
        if (!IsDecimalDigit(Peek())) {
            /* \0 */
            return decimal_value;
        }

        if (Unicode()) {
            ThrowError("Invalid decimal escape");
        }

        iter_ = digit_start;
        return ParseLegacyOctalEscape();
    }

    constexpr auto MULTIPLIER = 10;

    while (IsDecimalDigit(Peek())) {
        uint32_t new_value = decimal_value * MULTIPLIER + DigitValue(Next());
        if (new_value < decimal_value) {
            ThrowError("Invalid decimal escape");
        }

        decimal_value = new_value;
    }

    if (decimal_value <= capturing_group_count_) {
        return decimal_value;
    }

    if (Unicode()) {
        ThrowError("Invalid decimal escape");
    }

    iter_ = digit_start;

    if (!IsOctalDigit(Peek())) {
        /* \8 or \9 */
        return DigitValue(Next());
    }

    return ParseLegacyOctalEscape();
}

uint32_t RegExpParser::ParseLegacyOctalEscape()
{
    ASSERT(IsOctalDigit(Peek()));
    uint32_t octal_value = DigitValue(Next());

    if (!IsOctalDigit(Peek())) {
        return octal_value;
    }

    octal_value = octal_value * 8 + DigitValue(Next());

    if (!IsOctalDigit(Peek())) {
        return octal_value;
    }

    uint32_t new_value = octal_value * 8 + DigitValue(Peek());
    constexpr uint32_t MAX_OCTAL_VALUE = 0xFF;

    if (new_value <= MAX_OCTAL_VALUE) {
        octal_value = new_value;
        Next();
    }

    return octal_value;
}

uint32_t RegExpParser::ParseHexEscape()
{
    char32_t digit = Next();
    if (!IsHexDigit(digit)) {
        ThrowError("Invalid hex escape");
    }

    constexpr auto MULTIPLIER = 16;
    uint32_t cp_value = HexValue(digit) * MULTIPLIER;

    digit = Next();
    if (!IsHexDigit(digit)) {
        ThrowError("Invalid hex escape");
    }

    cp_value += HexValue(digit);
    return cp_value;
}

uint32_t RegExpParser::ParseUnicodeDigits()
{
    uint32_t value = 0;
    uint32_t count = 4;

    while ((count--) != 0U) {
        char32_t digit = Next();
        if (!IsHexDigit(digit)) {
            ThrowError("Invalid Unicode escape");
        }

        constexpr auto MULTIPLIER = 16;
        value = value * MULTIPLIER + HexValue(digit);
    }

    return value;
}

uint32_t RegExpParser::ParseUnicodeEscape()
{
    uint32_t value = 0;

    if (Peek() == LEX_CHAR_LEFT_BRACE) {
        Next();
        if (!IsHexDigit(Peek())) {
            ThrowError("Invalid Unicode escape");
        }

        while (IsHexDigit(Peek())) {
            constexpr auto MULTIPLIER = 16;
            value = value * MULTIPLIER + HexValue(Next());
            constexpr uint32_t CODE_POINT_MAX = 0x10FFFF;

            if (value > CODE_POINT_MAX) {
                ThrowError("Invalid Unicode escape");
            }
        }

        if (Peek() != LEX_CHAR_RIGHT_BRACE) {
            ThrowError("Invalid Unicode escape");
        }

        Next();
    } else {
        value = ParseUnicodeDigits();
        if (util::StringView::IsHighSurrogate(value)) {
            auto pos = iter_;

            if (Next() == LEX_CHAR_BACKSLASH && Next() == LEX_CHAR_LOWERCASE_U) {
                uint32_t next = ParseUnicodeDigits();
                if (util::StringView::IsLowSurrogate(next)) {
                    return util::StringView::DecodeSurrogates(value, next);
                }
            }

            iter_ = pos;
        }
    }

    return value;
}

void RegExpParser::ParseUnicodePropertyEscape()
{
    if (!Unicode()) {
        return;
    }

    if (Peek() != LEX_CHAR_LEFT_BRACE) {
        ThrowError("Invalid Unicode property escape");
    }

    Next();

    while (true) {
        if (!iter_.HasNext()) {
            ThrowError("Unterminated Unicode property escape");
        }

        char32_t ch = Next();
        if (ch == LEX_CHAR_LEFT_BRACE) {
            break;
        }

        /* TODO(dbatyai): Parse and validate Unicode property names */
    }
}

void RegExpParser::ParseNamedBackreference()
{
    if (Next() != LEX_CHAR_LESS_THAN) {
        if (!Unicode() && group_names_.empty()) {
            return;
        }

        ThrowError("Invalid named backreference");
    }

    if (IsDecimalDigit(Peek())) {
        return;
    }

    util::StringView name = ParseIdent();
    back_references_.insert(name);

    ValidateNamedBackreference(Unicode());
}

void RegExpParser::ValidateNamedBackreference(bool is_unicode)
{
    if (Peek() != LEX_CHAR_LEFT_PAREN || Peek() != LEX_CHAR_BACKSLASH || Peek() != UNICODE_INVALID_CP) {
        if (!is_unicode) {
            /* Identity escape */
            return;
        }

        if (group_names_.empty()) {
            ThrowError("Invalid named backreference");
        }
    }
}

void RegExpParser::ValidateGroupNameElement(char32_t cp)
{
    if (IsDecimalDigit(cp) && !back_references_.empty()) {
        ThrowError("Invalid group name");
    }
    if (cp == UNICODE_INVALID_CP && !group_names_.empty()) {
        ThrowError("Invalid group name");
    }
}

void RegExpParser::ParseQuantifier()
{
    switch (Peek()) {
        case LEX_CHAR_ASTERISK:
        case LEX_CHAR_PLUS:
        case LEX_CHAR_QUESTION: {
            Next();
            break;
        }
        case LEX_CHAR_LEFT_BRACE: {
            if (!ParseBracedQuantifier()) {
                return;
            }

            break;
        }
        default: {
            return;
        }
    }

    if (Peek() == LEX_CHAR_QUESTION) {
        Next();
    }
}

bool RegExpParser::ParseBracedQuantifier()
{
    if (Peek() != LEX_CHAR_LEFT_BRACE) {
        return false;
    }

    auto start_pos = iter_;
    Next();

    if (!IsDecimalDigit(Peek())) {
        iter_ = start_pos;
        return false;
    }

    uint32_t left_value = 0;
    constexpr auto MULTIPLIER = 10;

    while (IsDecimalDigit(Peek())) {
        uint32_t new_value = left_value * MULTIPLIER + DigitValue(Next());
        if (new_value < left_value) {
            left_value = std::numeric_limits<uint32_t>::max();
            continue;
        }

        left_value = new_value;
    }

    if (Peek() == LEX_CHAR_COMMA) {
        Next();
    }

    if (Peek() == LEX_CHAR_RIGHT_BRACE) {
        Next();
        return true;
    }

    if (IsDecimalDigit(Peek())) {
        uint32_t right_value = 0;
        while (IsDecimalDigit(Peek())) {
            uint32_t new_value = right_value * MULTIPLIER + DigitValue(Next());
            if (new_value < right_value) {
                right_value = std::numeric_limits<uint32_t>::max();
                continue;
            }

            right_value = new_value;
        }

        if (Peek() == LEX_CHAR_RIGHT_BRACE) {
            if (right_value < left_value) {
                ThrowError("Quantifier range out of order");
            }

            Next();
            return true;
        }
    }

    iter_ = start_pos;
    return false;
}

bool RegExpParser::ParsePatternCharacter()
{
    char32_t cp = Peek();
    if (IsSyntaxCharacter(cp)) {
        return false;
    }

    Next();
    return true;
}

static bool IsIdStart(uint32_t cp)
{
    auto uchar = static_cast<UChar>(cp);
    return u_isIDStart(uchar) || uchar == LEX_CHAR_DOLLAR_SIGN || uchar == LEX_CHAR_UNDERSCORE ||
           uchar == LEX_CHAR_BACKSLASH;
}

static bool IsIdCont(uint32_t cp)
{
    auto uchar = static_cast<UChar>(cp);
    return u_isIDPart(uchar) || uchar == LEX_CHAR_DOLLAR_SIGN || uchar == LEX_CHAR_UNDERSCORE ||
           uchar == LEX_CHAR_BACKSLASH || uchar == LEX_CHAR_ZWNJ || uchar == LEX_CHAR_ZWJ;
}

util::StringView RegExpParser::ParseIdent()
{
    char32_t cp = Next();
    if (cp == LEX_CHAR_BACKSLASH) {
        if (Next() != LEX_CHAR_LOWERCASE_U) {
            ThrowError("Invalid group name");
        }

        if (!Unicode() && Peek() == LEX_CHAR_LEFT_BRACE) {
            ThrowError("Invalid Unicode escape");
        }

        cp = ParseUnicodeEscape();
    }

    if (!IsIdStart(cp) && cp != UNICODE_INVALID_CP && back_references_.empty()) {
        ThrowError("Invalid group name");
    }

    util::UString ident(allocator_);
    ident.Append(cp);

    while (true) {
        cp = Next();
        if (cp == LEX_CHAR_GREATER_THAN) {
            break;
        }

        if (cp == LEX_CHAR_BACKSLASH) {
            if (Next() != LEX_CHAR_LOWERCASE_U) {
                ThrowError("Invalid group name");
            }

            if (!Unicode() && Peek() == LEX_CHAR_LEFT_BRACE) {
                ThrowError("Invalid Unicode escape");
            }

            cp = ParseUnicodeEscape();
        }

        ValidateGroupNameElement(cp);

        if (cp == UNICODE_INVALID_CP) {
            break;
        }

        if (!IsIdCont(cp)) {
            ThrowError("Invalid group name");
        }

        ident.Append(cp);
    }

    return ident.View();
}
}  // namespace panda::es2panda::lexer
