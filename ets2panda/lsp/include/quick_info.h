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

#ifndef ES2PANDA_LSP_INCLUDE_QUICK_INFO_H
#define ES2PANDA_LSP_INCLUDE_QUICK_INFO_H

#include "ir/astNode.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {

bool IsIncludedToken(const ir::AstNode *node);
ir::AstNode *GetTokenForQuickInfo(es2panda_Context *context, size_t position);
bool IsObjectLiteralElement(ir::AstNode *node);
ir::AstNode *GetContainingObjectLiteralNode(ir::AstNode *node);
ir::AstNode *GetContextualTypeNode(ir::AstNode *node);
ir::AstNode *GetPropertyNodeFromContextualType(ir::AstNode *node, ir::AstNode *contextualTypeNode);
ir::AstNode *GetNodeAtLocationForQuickInfo(ir::AstNode *node);

}  // namespace ark::es2panda::lsp

#endif