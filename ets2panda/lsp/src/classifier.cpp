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

#include "classifier.h"
#include "internal_api.h"
#include "ir/astNode.h"
#include "lexer/lexer.h"
#include "lexer/token/tokenType.h"
#include "macros.h"
#include "public/es2panda_lib.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

ClassificationTypeNames GetClassificationType(const lexer::Token &token, ir::AstNode *astNode)
{
    if (token.IsKeyword() || token.KeywordType() >= lexer::TokenType::FIRST_KEYW) {
        return ClassificationTypeNames::KEYWORD;
    }

    if (token.IsPunctuatorToken(token.Type())) {
        return ClassificationTypeNames::PUNCTUATION;
    }

    if (token.Type() == lexer::TokenType::LITERAL_NUMBER) {
        return ClassificationTypeNames::NUMERIC_LITERAL;
    }

    if (token.Type() == lexer::TokenType::LITERAL_STRING || token.Type() == lexer::TokenType::LITERAL_REGEXP) {
        return ClassificationTypeNames::STRING_LITERAL;
    }

    if (token.Type() == lexer::TokenType::LITERAL_TRUE || token.Type() == lexer::TokenType::LITERAL_FALSE) {
        return ClassificationTypeNames::BOOLEAN_LITERAL;
    }

    if (token.Type() == lexer::TokenType::LITERAL_NULL) {
        return ClassificationTypeNames::NULL_LITERAL;
    }

    if (token.Type() == lexer::TokenType::LITERAL_IDENT) {
        if (astNode == nullptr) {
            return ClassificationTypeNames::IDENTIFIER;
        }
        auto parentNode = astNode->Parent();
        switch (parentNode->Type()) {
            case ir::AstNodeType::CLASS_DEFINITION:
                return ClassificationTypeNames::CLASS_NAME;
            case ir::AstNodeType::TS_TYPE_PARAMETER:
                return ClassificationTypeNames::TYPE_PARAMETER_NAME;
            case ir::AstNodeType::TS_INTERFACE_DECLARATION:
                return ClassificationTypeNames::INTERFACE_NAME;
            case ir::AstNodeType::TS_ENUM_DECLARATION:
                return ClassificationTypeNames::ENUM_NAME;
            case ir::AstNodeType::ETS_PARAMETER_EXPRESSION:
                return ClassificationTypeNames::PARAMETER_NAME;
            case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
                return ClassificationTypeNames::TYPE_ALIAS_NAME;
            default:
                return ClassificationTypeNames::IDENTIFIER;
        }
    }

    UNREACHABLE();
}

char const *ClassificationTypeToString(ClassificationTypeNames type)
{
    switch (type) {
        case ClassificationTypeNames::IDENTIFIER:
            return "identifier";
        case ClassificationTypeNames::KEYWORD:
            return "keyword";
        case ClassificationTypeNames::NUMERIC_LITERAL:
            return "number";
        case ClassificationTypeNames::STRING_LITERAL:
            return "string";
        case ClassificationTypeNames::BOOLEAN_LITERAL:
            return "boolean";
        case ClassificationTypeNames::NULL_LITERAL:
            return "null";
        case ClassificationTypeNames::PUNCTUATION:
            return "punctuation";
        case ClassificationTypeNames::CLASS_NAME:
            return "class name";
        case ClassificationTypeNames::ENUM_NAME:
            return "enum name";
        case ClassificationTypeNames::INTERFACE_NAME:
            return "interface name";
        case ClassificationTypeNames::TYPE_PARAMETER_NAME:
            return "type parameter name";
        case ClassificationTypeNames::TYPE_ALIAS_NAME:
            return "type alias name";
        case ClassificationTypeNames::PARAMETER_NAME:
            return "parameter name";
        default:
            return "";
    }
}

ArenaVector<ClassifiedSpan *> GetEncodedSyntacticClassifications(es2panda_Context *context, size_t startPos,
                                                                 size_t length)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto result = ArenaVector<ClassifiedSpan *>(ctx->allocator->Adapter());
    auto parserContext = parser::ParserContext(ctx->parserProgram, parser::ParserStatus::NO_OPTS);
    auto errorLogger = util::ErrorLogger();
    auto lexer = lexer::Lexer(&parserContext, &errorLogger);
    lexer.NextToken();
    while (lexer.GetToken().Type() != lexer::TokenType::EOS) {
        ir::AstNode *currentNode = nullptr;
        auto currentToken = lexer.GetToken();
        if (currentToken.Type() == lexer::TokenType::LITERAL_IDENT) {
            currentNode = GetTouchingToken(context, currentToken.Start().index, false);
        }

        if (currentToken.End().index > startPos + length) {
            break;
        }

        if (currentToken.Start().index >= startPos && currentToken.End().index <= startPos + length) {
            size_t tokenStart = currentToken.Start().index;
            size_t tokenLength = currentToken.End().index - currentToken.Start().index;
            auto classificationType = GetClassificationType(currentToken, currentNode);
            auto name = ClassificationTypeToString(classificationType);
            auto classifiedSpan = ctx->allocator->New<ClassifiedSpan>();
            classifiedSpan->start = tokenStart;
            classifiedSpan->length = tokenLength;
            classifiedSpan->name = name;
            result.push_back(classifiedSpan);
        }
        lexer.NextToken();
    }
    return result;
}

}  // namespace ark::es2panda::lsp