/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

namespace ark::es2panda::compiler {

varbinder::Scope *NearestScope(const ir::AstNode *ast)
{
    while (ast != nullptr && !ast->IsScopeBearer()) {
        ast = ast->Parent();
    }

    return ast == nullptr ? nullptr : ast->Scope();
}

ir::Identifier *Gensym(ArenaAllocator *const allocator)
{
    util::UString const s = GenName(allocator);
    return allocator->New<ir::Identifier>(s.View(), allocator);
}

util::UString GenName(ArenaAllocator *const allocator)
{
    static std::string const GENSYM_CORE = "gensym$_";
    static std::size_t gensymCounter = 0U;

    return util::UString {GENSYM_CORE + std::to_string(++gensymCounter), allocator};
}

// Function to clear expression node types and identifier node variables (for correct re-binding and re-checking)
void ClearTypesAndVariables(ir::AstNode *node) noexcept
{
    node->Iterate([](ir::AstNode *child) -> void {
        if (child->IsExpression()) {
            auto *expression = child->AsExpression();
            if (!expression->IsTypeNode()) {
                expression->SetTsType(nullptr);
            }
            if (expression->IsIdentifier()) {
                expression->AsIdentifier()->SetVariable(nullptr);
                return;
            }
        }
        ClearTypesAndVariables(child);
    });
}
}  // namespace ark::es2panda::compiler
