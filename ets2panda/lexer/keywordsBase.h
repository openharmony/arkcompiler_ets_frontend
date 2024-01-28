/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_LEXER_KEYWORDS_BASE_H
#define ES2PANDA_LEXER_KEYWORDS_BASE_H

#include "lexer/keywordString.h"
#include "lexer/keywordsUtil.h"
#include "macros.h"

namespace ark::es2panda::lexer {
class Keywords {
public:
    explicit Keywords(Lexer *lexer, lexer::NextTokenFlags flags) : util_(KeywordsUtil(lexer, flags)) {}
    NO_COPY_SEMANTIC(Keywords);
    NO_MOVE_SEMANTIC(Keywords);
    ~Keywords() = default;

    KeywordsUtil &Util()
    {
        return util_;
    }

    const KeywordsUtil &Util() const
    {
        return util_;
    }

    virtual void ScanKeyword(char32_t cp) = 0;
    virtual void HandlePotentialEscapedKeyword(const KeywordString &kws) const = 0;
    virtual Span<const KeywordString> KeywordMap(char32_t cp) const = 0;

    void SetKeyword(KeywordString kws) const
    {
        if ((util_.Flags() & NextTokenFlags::KEYWORD_TO_IDENT) != 0) {
            util_.SetKeyword({kws.Str(), TokenType::LITERAL_IDENT, kws.GetKeywordType()});
        } else {
            util_.CheckEscapedKeyword();
            util_.SetKeyword(kws);
        }
    }

protected:
    template <KeywordString HANDLER(const KeywordsUtil &, std::string_view, TokenType)>
    void SetKeyword(KeywordString kws) const
    {
        if ((util_.Flags() & NextTokenFlags::KEYWORD_TO_IDENT) != 0) {
            util_.SetKeyword({kws.Str(), TokenType::LITERAL_IDENT, kws.GetKeywordType()});
        } else {
            util_.SetKeyword(HANDLER(util_, kws.Str(), kws.GetTokenType()));
        }
    }

private:
    KeywordsUtil util_;
};
}  // namespace ark::es2panda::lexer
#endif
