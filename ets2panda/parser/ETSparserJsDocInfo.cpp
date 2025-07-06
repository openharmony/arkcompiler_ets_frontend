/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ETSparser.h"
#include "lexer/lexer.h"
#include "lexer/keywordsUtil.h"
#include "ir/astNode.h"
#include "ir/base/methodDefinition.h"
#include "ir/ets/etsStructDeclaration.h"
#include "ir/statements/classDeclaration.h"
#include <ir/base/classProperty.h>
#include <ir/expressions/arrowFunctionExpression.h>
#include <ir/ets/etsModule.h>
#include <ir/statements/functionDeclaration.h>
#include <ir/statements/variableDeclaration.h>
#include <ir/ts/tsInterfaceDeclaration.h>
#include <ir/ts/tsTypeAliasDeclaration.h>

namespace ark::es2panda::parser {
void ETSParser::ExcludeInvalidStart()
{
    auto cp = Lexer()->Lookahead();
    while (!lexer::KeywordsUtil::IsIdentifierStart(cp) && cp != util::StringView::Iterator::INVALID_CP &&
           cp != lexer::LEX_CHAR_LEFT_BRACE && cp != lexer::LEX_CHAR_ASTERISK) {
        Lexer()->ForwardToken(Lexer()->GetToken().Type());
        cp = Lexer()->Lookahead();
    }
}

std::string ETSParser::ParseJsDocInfoItemParam()
{
    ExcludeInvalidStart();
    Lexer()->NextToken();
    auto token = Lexer()->GetToken();
    std::string jsDocInfoParamStr {};
    bool needAppendToken = token.Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE;
    bool needBackwardBlank = lexer::KeywordsUtil::IsIdentifierStart(Lexer()->Lookahead());
    size_t leftBraceCount = 1;
    while (token.Type() != lexer::TokenType::EOS && token.Type() != lexer::TokenType::JS_DOC_END) {
        if (needAppendToken) {
            jsDocInfoParamStr += token.ToString();
        }

        if (needBackwardBlank) {
            jsDocInfoParamStr += " ";
        }

        auto cp = Lexer()->Lookahead();
        if (lexer::KeywordsUtil::IsIdentifierStart(cp) || cp == lexer::LEX_CHAR_ASTERISK) {
            Lexer()->NextToken();
            token = Lexer()->GetToken();
            needAppendToken = lexer::KeywordsUtil::IsIdentifierStart(cp);
            needBackwardBlank = lexer::KeywordsUtil::IsIdentifierStart(Lexer()->Lookahead());
            continue;
        }

        if (cp == lexer::LEX_CHAR_RIGHT_BRACE) {
            --leftBraceCount;
            if (leftBraceCount == 0) {
                Lexer()->NextToken();
                break;
            }
        }

        if (cp == lexer::LEX_CHAR_LEFT_BRACE) {
            ++leftBraceCount;
        }

        if (cp == util::StringView::Iterator::INVALID_CP) {
            break;
        }

        jsDocInfoParamStr += std::string(1, cp);
        needAppendToken = false;
        needBackwardBlank = false;
        Lexer()->ForwardToken(token.Type());
    }

    return jsDocInfoParamStr;
}

static void RegularCommentStr(std::string &str)
{
    if (str.empty()) {
        return;
    }

    auto backChar = static_cast<char32_t>(static_cast<unsigned char>(str.back()));
    while (backChar == lexer::LEX_CHAR_CR || backChar == lexer::LEX_CHAR_LF || backChar == lexer::LEX_CHAR_ASTERISK ||
           backChar == lexer::LEX_CHAR_NBSP || backChar == lexer::LEX_CHAR_SP) {
        str.pop_back();
        if (str.empty()) {
            return;
        }
        backChar = static_cast<char32_t>(static_cast<unsigned char>(str.back()));
    }
}

std::tuple<util::StringView, util::StringView> ETSParser::ParseJsDocInfoItemValue()
{
    ExcludeInvalidStart();
    util::UString jsDocInfoItemCommentStr(Allocator());
    std::string jsDocInfoParamStr {};
    if (Lexer()->GetToken().Type() == lexer::TokenType::JS_DOC_END) {
        util::UString jsDocInfoItemParam {jsDocInfoParamStr, Allocator()};
        return std::make_tuple(jsDocInfoItemParam.View(), jsDocInfoItemCommentStr.View());
    }

    const auto startIdx = Lexer()->GetIndex();
    auto escapeEnd = startIdx;
    do {
        const char32_t cp = Lexer()->Lookahead();
        switch (cp) {
            case lexer::LEX_CHAR_LEFT_BRACE: {
                jsDocInfoParamStr = ParseJsDocInfoItemParam();
                continue;
            }
            case util::StringView::Iterator::INVALID_CP: {
                break;
            }
            case lexer::LEX_CHAR_CR:
            case lexer::LEX_CHAR_LF: {
                Lexer()->HandleNewlineHelper(&jsDocInfoItemCommentStr, &escapeEnd);
                continue;
            }
            case lexer::LEX_CHAR_AT:
            case lexer::LEX_CHAR_ASTERISK: {
                auto saved = Lexer()->Save();
                Lexer()->NextToken();
                auto nextType = Lexer()->GetToken().Type();
                Lexer()->Rewind(saved);
                if (nextType == lexer::TokenType::JS_DOC_END || nextType == lexer::TokenType::PUNCTUATOR_AT) {
                    break;
                }
                [[fallthrough]];
            }
            default: {
                Lexer()->SkipCp();
                continue;
            }
        }
        Lexer()->FinalizeJsDocInfoHelper(&jsDocInfoItemCommentStr, startIdx, escapeEnd);
        break;
    } while (true);

    std::string commentStr = std::string(jsDocInfoItemCommentStr.View());
    RegularCommentStr(commentStr);
    util::UString jsDocInfoItemParam {jsDocInfoParamStr, Allocator()};
    util::UString jsDocInfoCommentStr {commentStr, Allocator()};
    return std::make_tuple(jsDocInfoItemParam.View(), jsDocInfoCommentStr.View());
}

ir::JsDocInfo ETSParser::ParseJsDocInfo()
{
    ir::JsDocInfo jsDocInfo(Allocator()->Adapter());
    auto tokenType = Lexer()->GetToken().Type();
    while (tokenType != lexer::TokenType::EOS && tokenType != lexer::TokenType::JS_DOC_END) {
        if (tokenType != lexer::TokenType::PUNCTUATOR_AT) {
            auto cp = Lexer()->Lookahead();
            if (cp == lexer::LEX_CHAR_ASTERISK || cp == lexer::LEX_CHAR_AT) {
                Lexer()->NextToken();
                tokenType = Lexer()->GetToken().Type();
                continue;
            }

            if (Lexer()->Lookahead() == util::StringView::Iterator::INVALID_CP) {
                break;
            }

            Lexer()->ForwardToken(tokenType, 1);
            continue;
        }
        Lexer()->NextToken();
        auto const &token = Lexer()->GetToken();
        util::UString jsDocInfoItemKey {token.Ident(), Allocator()};
        auto [jsDocInfoItemParam, jsDocInfoItemComment] = ParseJsDocInfoItemValue();
        jsDocInfo.emplace(jsDocInfoItemKey.View(),
                          ir::JsDocRecord(jsDocInfoItemKey.View(), jsDocInfoItemParam, jsDocInfoItemComment));
        tokenType = Lexer()->GetToken().Type();
    }

    Lexer()->NextToken();
    return jsDocInfo;
}

ArenaVector<ir::JsDocInfo> ETSParser::ParseJsDocInfos()
{
    ArenaVector<ir::JsDocInfo> result(Allocator()->Adapter());
    bool hasMoreJsDocInfos = true;
    while (hasMoreJsDocInfos) {
        auto jsDocInfo = ParseJsDocInfo();
        if (!jsDocInfo.empty()) {
            result.emplace_back(jsDocInfo);
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::JS_DOC_START) {
            hasMoreJsDocInfos = false;
        }
    }
    return result;
}

static bool ApplyJsDocInfoToNamespace(ir::ETSModule *ns, ArenaVector<ir::JsDocInfo> &jsDocInformation)
{
    if (ns->IsNamespaceChainLastNode()) {
        ns->SetJsDocInformation(std::move(jsDocInformation));
        return true;
    }

    for (auto *node : ns->Statements()) {
        if (node->IsETSModule()) {
            if (ApplyJsDocInfoToNamespace(node->AsETSModule(), jsDocInformation)) {
                return true;
            }
        }
    }
    return false;
}

// CC-OFFNXT(huge_method,huge_cyclomatic_complexity,G.FUN.01-CPP) big switch-case, solid logic
void ETSParser::ApplyJsDocInfoToSpecificNodeType(ir::AstNode *node, ArenaVector<ir::JsDocInfo> &&jsDocInformation)
{
    if (jsDocInformation.empty()) {
        return;
    }

    switch (node->Type()) {
        case ir::AstNodeType::METHOD_DEFINITION: {
            auto *func = node->AsMethodDefinition()->Function();
            ES2PANDA_ASSERT(func != nullptr);
            func->SetJsDocInformation(std::move(jsDocInformation));
            break;
        }
        case ir::AstNodeType::CLASS_DECLARATION:
            node->AsClassDeclaration()->Definition()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::STRUCT_DECLARATION:
            node->AsETSStructDeclaration()->Definition()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::FUNCTION_DECLARATION:
            node->AsFunctionDeclaration()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::TS_INTERFACE_DECLARATION:
            node->AsTSInterfaceDeclaration()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::CLASS_PROPERTY:
            node->AsClassProperty()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::VARIABLE_DECLARATION:
            node->AsVariableDeclaration()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
            node->AsTSTypeAliasDeclaration()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::ARROW_FUNCTION_EXPRESSION:
            node->AsArrowFunctionExpression()->SetJsDocInformation(std::move(jsDocInformation));
            break;
        case ir::AstNodeType::ETS_MODULE:
            ApplyJsDocInfoToNamespace(node->AsETSModule(), jsDocInformation);
            break;
        default: {
        }
    }
}
}  // namespace ark::es2panda::parser
