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

#include "formatting/formatting_context.h"
#include "brace_matching.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

FormattingContext::FormattingContext(FormattingRequestKind requestKind, FormatCodeSettings &formatSettings)
{
    formatCodeSettings_ = formatSettings;
    formattingRequestKind_ = requestKind;
}

void FormattingContext::UpdateContext(es2panda_Context *context, RangeWithKind &currentToken, RangeWithKind &nextToken)
{
    currentTokenSpan_ = currentToken;
    nextTokenSpan_ = nextToken;

    if (context == nullptr) {
        return;
    }

    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return;
    }

    contextNode_ = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());

    auto current = GetTouchingToken(context, currentTokenSpan_.start.index, false);
    if (current == nullptr) {
        return;
    }
    currentTokenParent_ = current->Parent();

    nextTokenParent_ = GetTouchingToken(context, nextToken.start.index, false)->Parent();

    contextNodeAllOnSameLine_ = NodeIsOnOneLine(contextNode_);
    nextNodeAllOnSameLine_ = NodeIsOnOneLine(nextTokenParent_);
    tokensAreOnSameLine_ = currentTokenSpan_.start.ToLocation().line == nextTokenSpan_.start.ToLocation().line;
    contextNodeBlockIsOnOneLine_ = BlockIsOnOneLine(contextNode_);
    nextNodeBlockIsOnOneLine_ = BlockIsOnOneLine(nextTokenParent_);
}

bool FormattingContext::ContextNodeAllOnSameLine() const
{
    return contextNodeAllOnSameLine_;
}

bool FormattingContext::NextNodeAllOnSameLine() const
{
    return nextNodeAllOnSameLine_;
}

bool FormattingContext::TokensAreOnSameLine() const
{
    return tokensAreOnSameLine_;
}

bool FormattingContext::ContextNodeBlockIsOnOneLine() const
{
    return contextNodeBlockIsOnOneLine_;
}

bool FormattingContext::NextNodeBlockIsOnOneLine() const
{
    return nextNodeBlockIsOnOneLine_;
}

bool FormattingContext::NodeIsOnOneLine(ir::AstNode *node) const
{
    if (node == nullptr) {
        return false;
    }

    return node->Start().line == node->End().line;
}

bool FormattingContext::BlockIsOnOneLine(ir::AstNode *node) const
{
    if (node == nullptr) {
        return false;
    }

    auto nodeChild = node->FindChild([](ir::AstNode *astnode) { return CheckNodeKindForBraceMatching(astnode); });

    return NodeIsOnOneLine(nodeChild);
}

}  // namespace ark::es2panda::lsp