/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "util.h"

#include "ir/expressions/identifier.h"

namespace panda::es2panda::compiler {

binder::Scope *NearestScope(const ir::AstNode *ast)
{
    while (!ast->IsScopeBearer()) {
        ast = ast->Parent();
        ASSERT(ast != nullptr);
    }

    return ast->Scope();
}

static size_t GENSYM_COUNTER = 0;

ir::Identifier *Gensym(ArenaAllocator *allocator)
{
    std::stringstream ss;
    ss << "gensym$" << (GENSYM_COUNTER++);
    const ArenaString s {allocator->Adapter()};
    const auto str = ss.str();
    auto *arena_pointer = allocator->Alloc(str.size() + 1);
    memmove(arena_pointer, reinterpret_cast<const void *>(str.c_str()), str.size() + 1);
    return allocator->New<ir::Identifier>(util::StringView(reinterpret_cast<const char *>(arena_pointer)), allocator);
}

}  // namespace panda::es2panda::compiler
