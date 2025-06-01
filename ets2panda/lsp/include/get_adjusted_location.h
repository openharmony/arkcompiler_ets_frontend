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

#ifndef ES2PANDA_LSP_GET_ADJUSTED_LOCATION_H
#define ES2PANDA_LSP_GET_ADJUSTED_LOCATION_H

#include <optional>
#include <string>
#include <vector>
#include "ir/astNode.h"
#include "ir/astNodeFlags.h"
#include "es2panda.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {

// Main location adjustment functions
std::optional<ir::AstNode *> GetAdjustedLocation(ir::AstNode *node, bool forRename, ArenaAllocator *allocator);
std::optional<ir::AstNode *> GetAdjustedLocationForClass(ir::AstNode *node, ArenaAllocator *allocator);
std::optional<ir::AstNode *> GetAdjustedLocationForFunction(ir::AstNode *node, ArenaAllocator *allocator);
std::optional<ir::AstNode *> GetAdjustedLocationForDeclaration(ir::AstNode *node, bool forRename,
                                                               const ArenaVector<ir::AstNode *> &children,
                                                               ArenaAllocator *allocator);
std::optional<ir::AstNode *> GetAdjustedLocationForImportDeclaration(ir::AstNode *node, bool forRename,
                                                                     const ArenaVector<ir::AstNode *> &children);
std::optional<ir::AstNode *> GetAdjustedLocationForExportDeclaration(ir::AstNode *node, bool forRename,
                                                                     const ArenaVector<ir::AstNode *> &children);
std::optional<ir::AstNode *> GetAdjustedLocationForHeritageClause(ir::AstNode *node);
ir::AstNode *GetTouchingPropertyName(es2panda_Context *context, size_t pos);
// Expression handlers
std::optional<ir::AstNode *> HandleBasicExpressions(ir::AstNode *node, ir::AstNode *parent,
                                                    const ArenaVector<ir::AstNode *> &parentChildren);
std::optional<ir::AstNode *> HandleBinaryExpressions(ir::AstNode *node, ir::AstNode *parent,
                                                     const ArenaVector<ir::AstNode *> &parentChildren);
std::optional<ir::AstNode *> HandleForStatements(ir::AstNode *node, ir::AstNode *parent,
                                                 const ArenaVector<ir::AstNode *> &parentChildren);
std::optional<ir::AstNode *> HandleNonRenameExpressions(ir::AstNode *node, ir::AstNode *parent,
                                                        const ArenaVector<ir::AstNode *> &parentChildren,
                                                        bool forRename);

// Node type handlers
inline std::optional<ir::AstNode *> HandleTSAsExpression(ir::AstNode *node, ir::AstNode *parent,
                                                         const ArenaVector<ir::AstNode *> &parentChildren);
inline std::optional<ir::AstNode *> HandleImportDeclaration(ir::AstNode *node, ir::AstNode *parent,
                                                            const ArenaVector<ir::AstNode *> &parentChildren,
                                                            bool forRename);
inline std::optional<ir::AstNode *> HandleTSImportType(ir::AstNode *node, ir::AstNode *parent,
                                                       const ArenaVector<ir::AstNode *> &parentChildren, bool forRename,
                                                       ArenaAllocator *allocator);

// Node finding functions
ir::AstNode *FindFirstIdentifier(ir::AstNode *node, bool skipModifiers, const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindFirstExpression(ir::AstNode *node, const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindFirstExpressionAfter(ir::AstNode *node, ir::AstNode *after,
                                      const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindNodeOfType(ir::AstNode *node, ir::AstNodeType type, const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindTypeReference(ir::AstNode *node, const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindTypeParameter(ir::AstNode *node, const ArenaVector<ir::AstNode *> &children);
ir::AstNode *FindArrayType(ir::AstNode *node, const ArenaVector<ir::AstNode *> &children);

// Node property checkers
bool IsModifier(const ir::AstNode *node);
bool CanHaveModifiers(const ir::AstNode &node);
bool IsOuterExpression(const ir::AstNode *node);
bool IsDeclarationOrModifier(ir::AstNode *node, ir::AstNode *parent, bool forRename);

// Node manipulation functions
ir::AstNode *SkipOuterExpressions(ir::AstNode *node);

// Child node functions
ArenaVector<ir::AstNode *> GetChildren(ir::AstNode *node, ArenaAllocator *allocator);

}  // namespace ark::es2panda::lsp

#endif  // ES2PANDA_LSP_GET_ADJUSTED_LOCATION_H
