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

#ifndef ES2PANDA_LSP_INCLUDE_CLASSHIERARCHY_H
#define ES2PANDA_LSP_INCLUDE_CLASSHIERARCHY_H

#include <tuple>
#include <vector>
#include "api.h"
#include "ir/astNode.h"
#include "line_column_offset.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {
ir::AstNode *GetTargetDeclarationNodeByPosition(es2panda_Context *context, size_t pos);
// NOLINTBEGIN(misc-non-private-member-variables-in-classes)
const ir::AstNode *GetEffectiveBaseTypeNode(const ir::AstNode *node);
// NOLINTEND(misc-non-private-member-variables-in-classes)
void GetSuperTypeHierarchies(const ir::AstNode *node, TypeHierarchies &typeHierarchies,
                             std::set<TypeHierarchies> &superLists);
TypeHierarchiesInfo GetTypeHierarchiesImpl(es2panda_Context *context, size_t pos,
                                           const ir::AstNode *declaration = nullptr);
}  // namespace ark::es2panda::lsp
#endif