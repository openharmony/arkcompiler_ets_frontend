/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_CORE_REGEXP_H
#define ES2PANDA_PARSER_CORE_REGEXP_H

#include "util/enumbitops.h"
#include "util/ustring.h"

#include <unordered_set>

namespace panda::es2panda::lexer {
enum class RegExpFlags : uint32_t {
    EMPTY = 0U,
    GLOBAL = 1U << 0U,
    IGNORE_CASE = 1U << 1U,
    MULTILINE = 1U << 2U,
    DOTALL = 1U << 3U,
    UNICODE = 1U << 4U,
    STICKY = 1U << 5U,
};

DEFINE_BITOPS(RegExpFlags)

class RegExpError : std::exception {
public:
    explicit RegExpError(std::string_view m);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    std::string message;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

struct RegExp {
    RegExp(util::StringView p, util::StringView f, RegExpFlags re_flags);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    util::StringView pattern_str;
    util::StringView flags_str;
    RegExpFlags flags;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class RegExpParser {
public:
    explicit RegExpParser(const RegExp &re, ArenaAllocator *allocator);
    void ParsePattern();

private:
    void ParseDisjunction();
    void ParseAlternatives();
    void ParseAlternative();

    void ParseNonCapturingGroup();
    void ParseNamedCapturingGroup();
    void ParseCapturingGroup();

    void ParseAssertion();
    char32_t ParseClassAtom();
    void ParseCharacterClass();
    void ParseAtomEscape();

    uint32_t ParseControlEscape();
    uint32_t ParseDecimalEscape();
    uint32_t ParseLegacyOctalEscape();
    uint32_t ParseHexEscape();
    uint32_t ParseUnicodeDigits();
    uint32_t ParseUnicodeEscape();

    void ParseUnicodePropertyEscape();
    void ValidateNamedBackreference(bool is_unicode);
    void ValidateGroupNameElement(char32_t cp);
    void ParseNamedBackreference();

    void ParseQuantifier();
    bool ParseBracedQuantifier();

    bool IsSyntaxCharacter(char32_t cp) const;
    bool ParsePatternCharacter();

    util::StringView ParseIdent();

    bool Unicode() const;

    char32_t Peek() const;
    char32_t Next();
    void Advance();
    bool Eos() const;

    RegExp re_;
    ArenaAllocator *allocator_ {};
    util::StringView::Iterator iter_;
    uint32_t capturing_group_count_ {};
    std::unordered_set<util::StringView> group_names_;
    std::unordered_set<util::StringView> back_references_;
};
}  // namespace panda::es2panda::lexer

#endif
