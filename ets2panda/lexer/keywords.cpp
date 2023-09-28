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

#include "generated/keywords.h"
#include "plugins/ecmascript/es2panda/lexer/keywordsUtil.h"
#include "plugins/ecmascript/es2panda/parser/context/parserContext.h"

namespace panda::es2panda::lexer {

KeywordString JSKeywords::Handle_as([[maybe_unused]] const KeywordsUtil &util, std::string_view src,
                                    TokenType token_type)
{
    return {src, TokenType::LITERAL_IDENT, token_type};
}

KeywordString JSKeywords::Handle_await(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    const auto *parser_context = util.GetParserContext();

    if (!parser_context->IsAsync() && !parser_context->IsModule()) {
        return {src, TokenType::LITERAL_IDENT, token_type};
    }

    util.CheckEscapedKeyword();

    return {src, token_type};
}

KeywordString JSKeywords::Handle_yield(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    const auto *parser_context = util.GetParserContext();

    if (!parser_context->IsGenerator()) {
        util.ThrowUnexpectedStrictModeReservedKeyword();
    }

    util.CheckEscapedKeyword();

    return {src, token_type};
}

KeywordString TSKeywords::Handle_as(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    return JSKeywords::Handle_as(util, src, token_type);
}

KeywordString TSKeywords::Handle_await(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    return JSKeywords::Handle_await(util, src, token_type);
}

KeywordString TSKeywords::Handle_yield(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    return JSKeywords::Handle_yield(util, src, token_type);
}

KeywordString ASKeywords::Handle_as(const KeywordsUtil &util, std::string_view src, TokenType token_type)
{
    return JSKeywords::Handle_as(util, src, token_type);
}

}  // namespace panda::es2panda::lexer
