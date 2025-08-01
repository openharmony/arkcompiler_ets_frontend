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

#include <cstddef>
#include "checker/types/signature.h"
#include "compiler/lowering/util.h"
#include "get_signature.h"
#include "internal_api.h"
#include "ir/astNode.h"
#include "public/es2panda_lib.h"
#include "public/public.h"
namespace ark::es2panda::lsp {

size_t FindFirstNonSpaceLeft(const std::string &str, size_t pos)
{
    if (str.empty()) {
        return std::string::npos;
    }

    if (pos >= str.size()) {
        pos = str.size() - 1;
    }

    for (size_t i = pos;; --i) {
        if (std::isspace(static_cast<unsigned char>(str[i])) == 0) {
            return i;
        }

        if (i == 0) {
            break;
        }
    }

    return std::string::npos;
}

SignatureHelpItems MakeSignatureHelpItem(ir::AstNode *callExpressionNode, ir::AstNode *node, ir::AstNode *declNode,
                                         checker::Signature *signature, size_t position)
{
    SignatureHelpItems res;
    res.SetApplicableSpan(node->End().index + 1, position - node->End().index - 1);
    res.SetArgumentIndex(callExpressionNode->AsCallExpression()->Arguments().size());
    auto params = signature->GetSignatureInfo()->params;
    auto returnType = signature->ReturnType();
    res.SetArgumentCount(params.size());

    SignatureHelpItem item;
    auto methodName = std::string(declNode->AsMethodDefinition()->Id()->Name());
    item.SetPrefixDisplayParts(SymbolDisplayPart(methodName, "functionName"));
    item.SetPrefixDisplayParts(SymbolDisplayPart("(", "punctuation"));

    item.SetSeparatorDisplayParts(SymbolDisplayPart(",", "punctuation"));
    item.SetSeparatorDisplayParts(SymbolDisplayPart(" ", "space"));

    item.SetSuffixDisplayParts(SymbolDisplayPart(")", "punctuation"));
    item.SetSuffixDisplayParts(SymbolDisplayPart(" ", "space"));
    item.SetSuffixDisplayParts(SymbolDisplayPart("=>", "punctuation"));
    item.SetSuffixDisplayParts(SymbolDisplayPart(" ", "space"));
    item.SetSuffixDisplayParts(SymbolDisplayPart(returnType->ToString(), "keyword"));

    for (auto param : params) {
        SignatureHelpParameter paramItem;
        auto paramName = std::string(param->Name());
        auto paramType = param->TsType()->ToString();
        paramItem.SetName(paramName);
        paramItem.SetDisplayParts(SymbolDisplayPart(paramName, "parameterNmae"));
        paramItem.SetDisplayParts(SymbolDisplayPart(":", "punctuation"));
        paramItem.SetDisplayParts(SymbolDisplayPart(" ", "space"));
        paramItem.SetDisplayParts(SymbolDisplayPart(paramType, "keyword"));
        item.SetParameters(paramItem);
    }

    res.SetItems(item);
    return res;
}

SignatureHelpItems GetSignature(es2panda_Context *context, size_t position)
{
    SignatureHelpItems res;
    if (context == nullptr) {
        return res;
    }

    auto callExpressionNode = GetTouchingToken(context, position, false);
    if (callExpressionNode == nullptr || !callExpressionNode->IsCallExpression()) {
        return res;
    }

    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto sourceCode = ctx->parserProgram->SourceCode();
    if (position >= sourceCode.Length()) {
        return res;
    }

    auto foundPos = std::string(sourceCode).rfind('(', position);
    auto targetPos = FindFirstNonSpaceLeft(std::string(sourceCode), foundPos);
    auto node = GetTouchingToken(context, targetPos - 1, false);
    if (node == nullptr || !node->IsIdentifier()) {
        return res;
    }

    auto declNode = compiler::DeclarationFromIdentifier(node->AsIdentifier());
    if (declNode == nullptr || !declNode->IsMethodDefinition()) {
        return res;
    }

    auto function = declNode->AsMethodDefinition()->Function();
    if (function == nullptr) {
        return res;
    }

    auto signature = function->Signature();
    if (signature == nullptr) {
        return res;
    }
    res = MakeSignatureHelpItem(callExpressionNode, node, declNode, signature, position);
    return res;
}
}  // namespace ark::es2panda::lsp