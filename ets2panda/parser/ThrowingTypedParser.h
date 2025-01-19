/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_THROWING_TYPED_PARSER_H
#define ES2PANDA_PARSER_THROWING_TYPED_PARSER_H

#include <initializer_list>
#include <string_view>

#include "parser/TypedParser.h"
#include "generated/tokenType.h"

namespace ark::es2panda::parser {

class ThrowingTypedParser : public TypedParser {
public:
    using TypedParser::TypedParser;
    [[noreturn]] void ThrowUnexpectedToken(lexer::TokenType tokenType) const;
    [[noreturn]] void ThrowSyntaxError(std::string_view errorMessage) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list,
                                       const lexer::SourcePosition &pos) const;
    [[noreturn]] void ThrowSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const;
};

}  // namespace ark::es2panda::parser

#endif  // ES2PANDA_PARSER_THROWING_TYPED_PARSER_H
