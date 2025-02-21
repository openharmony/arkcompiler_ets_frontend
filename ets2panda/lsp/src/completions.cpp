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

#include "completions.h"
#include <algorithm>
#include "generated/tokenType.h"

namespace ark::es2panda::lsp {

std::string ToLowerCase(const std::string &str)
{
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

std::vector<CompletionEntry> AllKeywordsCompletions()
{
    std::vector<CompletionEntry> keywords;
    for (int i = static_cast<int>(lexer::TokenType::FIRST_KEYW); i <= static_cast<int>(lexer::TokenType::KEYW_YIELD);
         i++) {
        keywords.emplace_back(lsp::CompletionEntry(TokenToString(static_cast<lexer::TokenType>(i)),
                                                   CompletionEntryKind::KEYWORD,
                                                   std::string(sort_text::GLOBALS_OR_KEYWORDS)));
    }
    return keywords;
}

std::vector<CompletionEntry> GetKeywordCompletions(const std::string &input)
{
    std::vector<CompletionEntry> allKeywords = AllKeywordsCompletions();
    std::vector<CompletionEntry> completions;

    for (auto entry : allKeywords) {
        if (entry.GetName().find(ToLowerCase(input)) == 0) {
            completions.push_back(entry);
        }
    }
    return completions;
}

Request KeywordCompletionData(const std::string &input)
{
    return {
        CompletionDataKind::KEYWORDS,
        GetKeywordCompletions(input),
    };
}

}  // namespace ark::es2panda::lsp
