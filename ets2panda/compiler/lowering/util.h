/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_LOWERING_UTIL_H
#define ES2PANDA_COMPILER_LOWERING_UTIL_H

#include "ir/astNode.h"

namespace ark::es2panda::compiler {

varbinder::Scope *NearestScope(const ir::AstNode *ast);
ir::Identifier *Gensym(ArenaAllocator *allocator);
util::UString GenName(ArenaAllocator *allocator);
void ClearTypesAndVariables(ir::AstNode *node) noexcept;

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_LOWERING_UTIL_H
