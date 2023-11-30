/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_CORE_ETS_NOLINT_PARSER_H
#define ES2PANDA_PARSER_CORE_ETS_NOLINT_PARSER_H

namespace ark::es2panda::parser {

class ETSNolintParser {
public:
    explicit ETSNolintParser(const ParserImpl *mainParser);
    void CollectETSNolints();
    void ApplyETSNolintsToStatements(ArenaVector<ir::Statement *> &statements) const;

private:
    void SetStartPos();
    void NextSymbol();
    void BackwardSymbol();
    void NextSymbol(std::size_t i);
    void BackwardSymbol(std::size_t i);
    void RewindToStart() const;

    char32_t PeekSymbol() const;
    bool TryPeekU32String(const std::u32string &str);
    bool IsEtsNolint();
    bool IsNextLine();
    bool IsBegin();
    bool IsEnd();

    std::set<ETSWarnings> ParseETSNolintArgs();
    bool ValidETSNolintArg(const std::u32string &warningName) const;
    ETSWarnings MapETSNolintArg(const std::u32string &warningName) const;

    void AddToETSNolintLinesCollection(std::size_t line, const std::set<ETSWarnings> &collection);
    bool IsLineWithETSNolint(const std::size_t line) const;
    std::set<ETSWarnings> GetWarningsCollectionByLine(std::size_t line) const;

    void ApplyETSNolintsToNodesRecursively(ir::AstNode *node) const;

    const ParserImpl *parser_;
    std::size_t startPos_ = 0;
    std::size_t posOffset_ = 0;
    std::size_t line_ = 0;
    std::set<ETSWarnings> applyingCollection_;
    std::map<size_t, std::set<ETSWarnings>> linesCollection_;
    std::map<std::u32string, ETSWarnings> warningsMap_;
};
}  // namespace ark::es2panda::parser
#endif
