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
#include <string>
#include <utility>
#include <vector>
#include "compiler/lowering/util.h"
#include "get_safe_delete_info.h"
#include "ir/astNode.h"
#include "internal_api.h"
#include "public/public.h"
#include "references.h"

namespace ark::es2panda::lsp {
bool NodeIsEligibleForSafeDelete(ir::AstNode *astNode)
{
    if (astNode == nullptr) {
        return false;
    }
    switch (astNode->Type()) {
        case ir::AstNodeType::THIS_EXPRESSION:
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE:
        case ir::AstNodeType::IDENTIFIER:
            return true;
        default:
            return false;
    }
}

DeclInfo GetDeclInfoCur(es2panda_Context *context, size_t position)
{
    DeclInfo result;
    if (context == nullptr) {
        return result;
    }
    auto astNode = GetTouchingToken(context, position, false);
    auto declInfo = GetDeclInfoImpl(astNode);
    result.fileName = std::get<0>(declInfo);
    result.fileText = std::get<1>(declInfo);
    return result;
}

// This function judge whether type is standard library file defined type.
bool IsLibrayFile(ir::AstNode *node, const std::string &path)
{
    auto declInfo = GetDeclInfoImpl(node);
    auto fileName = std::get<0>(declInfo);
    if (fileName.empty()) {
        return false;
    }
    if (fileName.find("ets1.2") != std::string::npos) {
        return fileName.find(path) != std::string::npos;
    }
    return true;
}

bool IsAllowToDeleteDeclaration(ir::AstNode *node, const std::string &path)
{
    return (node->IsETSModule() && node->AsETSModule()->IsNamespace()) || node->IsTSTypeParameterDeclaration() ||
           (node->Type() == ir::AstNodeType::IDENTIFIER && node->Parent()->IsTSModuleDeclaration()) ||
           IsLibrayFile(node, path) || node->IsArrowFunctionExpression() || node->IsETSStringLiteralType();
}

bool GetSafeDeleteInfoForNode(es2panda_Context *context, size_t position, const std::string &path)
{
    auto declInfoData = GetDeclInfoCur(context, position);
    DeclInfoType declInfo = {declInfoData.fileName, declInfoData.fileText};
    std::vector<ir::AstNode *> nodes;

    auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return false;
    }
    auto astNode = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    astNode->IterateRecursively([declInfo, &nodes](ir::AstNode *child) {
        auto info = GetDeclInfoImpl(child);
        if (info == declInfo) {
            nodes.push_back(child);
        }
    });
    std::vector<ir::AstNode *> filterNodes;
    std::for_each(nodes.begin(), nodes.end(), [&filterNodes, path](ir::AstNode *node) {
        if (IsAllowToDeleteDeclaration(node, path)) {
            filterNodes.push_back(node);
        }
    });

    return !filterNodes.empty();
}

bool GetSafeDeleteInfoImpl(es2panda_Context *context, size_t position, const std::string &path)
{
    auto astNode = GetTouchingToken(context, position, false);
    if (NodeIsEligibleForSafeDelete(astNode)) {
        return GetSafeDeleteInfoForNode(context, position, path);
    }
    return false;
}
}  // namespace ark::es2panda::lsp
