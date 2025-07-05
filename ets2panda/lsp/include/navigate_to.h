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

#ifndef NAVIGATE_TO_H
#define NAVIGATE_TO_H

#include <string>
#include <cctype>
#include <string_view>
#include <vector>
#include "es2panda.h"
#include "ir/astNode.h"
#include <regex>

namespace ark::es2panda::lsp {

enum class MatchKind { EXACT, PREFIX, SUBSTRING, CAMELCASE, NONE };

struct TextSpan {
    size_t start;
    size_t length;
};

struct NavigateToItem {
    std::string name;
    std::string_view kind;
    MatchKind matchKind = MatchKind::NONE;
    bool isCaseSensitive = false;
    std::string fileName;
    std::string containerName;
    std::string_view containerKind;
};

class PatternMatcher {
public:
    PatternMatcher(const std::string &pattern, bool isCaseSensitive);

    bool IsPatternValid() const;
    bool MatchesExact(const std::string &candidate) const;
    bool MatchesPrefix(const std::string &candidate) const;
    bool MatchesSubstring(const std::string &candidate) const;

private:
    std::string pattern_;
    std::optional<std::regex> regexPattern_;
    bool isCaseSensitive_;
};

std::vector<NavigateToItem> GetNavigateToItems(es2panda_Context *context,
                                               const std::vector<ark::es2panda::SourceFile> &srcFiles,
                                               size_t maxResultCount, const std::string &searchValue,
                                               bool isCaseSensitive);

ir::AstNode *GetContainerNodes(ir::AstNode *node);
std::vector<NavigateToItem> GetItemsFromNamedDeclaration(const SourceFile &file, const PatternMatcher &matcher);

}  // namespace ark::es2panda::lsp

#endif