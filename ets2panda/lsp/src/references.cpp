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

#include "references.h"
#include <cstddef>
#include <string>
#include "api.h"
#include "ir/astNode.h"
#include "public/es2panda_lib.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

bool IsValidReference(ir::AstNode *astNode)
{
    switch (astNode->Type()) {
        case ark::es2panda::ir::AstNodeType::IDENTIFIER:
            return true;
        default:
            return false;
    }
}

std::tuple<std::string, size_t, size_t> GetDeclInfo(ir::AstNode *astNode)
{
    if (astNode == nullptr || !IsValidReference(astNode) || astNode->Variable() == nullptr ||
        astNode->Variable()->Declaration() == nullptr) {
        return {};
    }
    auto decl = astNode->Variable()->Declaration();
    auto declName = decl->Name();
    auto declStart = decl->Node()->Start().index;
    auto declEnd = decl->Node()->End().index;
    return std::make_tuple(std::string(declName), declStart, declEnd);
}

void GetReferencesAtPositionImpl(es2panda_Context *context, const std::tuple<std::string, size_t, size_t> &declInfo,
                                 References *result)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto astNode = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    astNode->IterateRecursively([ctx, declInfo, result](ir::AstNode *child) {
        auto info = GetDeclInfo(child);
        if (info == declInfo) {
            size_t startPos = child->Start().index;
            size_t endPos = child->End().index;
            result->referenceInfos.emplace_back(ctx->sourceFileName, startPos, endPos - startPos);
        }
    });
}

}  // namespace ark::es2panda::lsp