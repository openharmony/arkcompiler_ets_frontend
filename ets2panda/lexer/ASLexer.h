/*
 * Copyright (c) 2021 - 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_CORE_AS_LEXER_H
#define ES2PANDA_PARSER_CORE_AS_LEXER_H

#include "lexer/lexer.h"

namespace ark::es2panda::lexer {
class ASLexer final : public Lexer {
public:
    explicit ASLexer(const parser::ParserContext *parserContext, util::DiagnosticEngine &diagnosticEngine)
        : Lexer(parserContext, diagnosticEngine, false)
    {
        SkipWhiteSpaces();
    }

    NO_COPY_SEMANTIC(ASLexer);
    NO_MOVE_SEMANTIC(ASLexer);
    ~ASLexer() override = default;
    // NOLINTNEXTLINE(google-default-arguments)
    void NextToken(NextTokenFlags flags = NextTokenFlags::NONE) override;
};
}  // namespace ark::es2panda::lexer

#endif
