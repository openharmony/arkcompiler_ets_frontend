/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FORMATTING_CONTEXT_H
#define FORMATTING_CONTEXT_H

#include "ir/astNode.h"
#include "formatting_settings.h"

namespace ark::es2panda::lsp {

enum class FormattingRequestKind {
    FORMAT_DOCUMENT,
    FORMAT_SELECTION,
    FORMAT_ON_ENTER,
    FORMAT_ON_SEMICOLON,
    FORMAT_ON_OPENING_CURLY_BRACE,
    FORMAT_ON_CLOSING_CURLY_BRACE,
};

struct RangeWithKind : lexer::SourceRange {
private:
    ir::AstNodeType kind_;

public:
    explicit RangeWithKind(lexer::SourcePosition startPos = lexer::SourcePosition(),
                           lexer::SourcePosition endPos = lexer::SourcePosition(),
                           ir::AstNodeType nodeKind = ir::AstNodeType::DUMMYNODE)
        : lexer::SourceRange(startPos, endPos), kind_(nodeKind)
    {
    }

    const ir::AstNodeType &GetKind()
    {
        return kind_;
    }
};

struct FormattingContext {
public:
    explicit FormattingContext(FormattingRequestKind requestKind, FormatCodeSettings &formatSettings);

    void UpdateContext(es2panda_Context *context, RangeWithKind &currentToken, RangeWithKind &nextToken);

    bool ContextNodeAllOnSameLine() const;
    bool NextNodeAllOnSameLine() const;
    bool TokensAreOnSameLine() const;
    bool ContextNodeBlockIsOnOneLine() const;
    bool NextNodeBlockIsOnOneLine() const;

    const RangeWithKind &GetCurrentTokenSpan() const
    {
        return currentTokenSpan_;
    }
    const RangeWithKind &GetNextTokenSpan() const
    {
        return nextTokenSpan_;
    }

    ir::AstNode *GetContextNode() const
    {
        return contextNode_;
    }
    ir::AstNode *GetCurrentTokenParent() const
    {
        return currentTokenParent_;
    }
    ir::AstNode *GetNextTokenParent() const
    {
        return nextTokenParent_;
    }

    FormatCodeSettings GetFormatCodeSettings()
    {
        return formatCodeSettings_;
    }

    FormattingRequestKind GetformattingRequestKind()
    {
        return formattingRequestKind_;
    }

private:
    bool NodeIsOnOneLine(ir::AstNode *node) const;
    bool BlockIsOnOneLine(ir::AstNode *node) const;

    bool contextNodeAllOnSameLine_ = false;
    bool nextNodeAllOnSameLine_ = false;
    bool tokensAreOnSameLine_ = false;
    bool contextNodeBlockIsOnOneLine_ = false;
    bool nextNodeBlockIsOnOneLine_ = false;

    RangeWithKind currentTokenSpan_;
    RangeWithKind nextTokenSpan_;
    ir::AstNode *contextNode_ = nullptr;
    ir::AstNode *currentTokenParent_ = nullptr;
    ir::AstNode *nextTokenParent_ = nullptr;

    FormatCodeSettings formatCodeSettings_;
    FormattingRequestKind formattingRequestKind_;
};

}  // namespace ark::es2panda::lsp

#endif