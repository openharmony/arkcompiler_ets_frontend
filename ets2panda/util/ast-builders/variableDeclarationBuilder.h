/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_INCLUDE_VARIABLE_DECLARATION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_VARIABLE_DECLARATION_BUILDER

#include "ir/statements/variableDeclaration.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class VariableDeclarationBuilder : public AstBuilder {
public:
    explicit VariableDeclarationBuilder(ark::ArenaAllocator *allocator)
        : AstBuilder(allocator), declarators_(allocator->Adapter())
    {
    }

    VariableDeclarationBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    VariableDeclarationBuilder &SetKind(VariableDeclaration::VariableDeclarationKind kind)
    {
        kind_ = kind;
        return *this;
    }

    VariableDeclarationBuilder &SetDeclare(bool decl)
    {
        declare_ = decl;
        return *this;
    }

    VariableDeclarationBuilder &SetDeclarators(ArenaVector<VariableDeclarator *> &&declarators)
    {
        declarators_ = std::move(declarators);
        return *this;
    }

    VariableDeclarationBuilder &AddDeclarator(VariableDeclarator *declarator)
    {
        declarators_.emplace_back(declarator);
        return *this;
    }

    VariableDeclaration *Build()
    {
        auto *etsTypeReference =
            AllocNode<ir::VariableDeclaration>(kind_, Allocator(), std::move(declarators_), declare_);
        return etsTypeReference;
    }

private:
    AstNode *parent_ {};
    VariableDeclaration::VariableDeclarationKind kind_ = VariableDeclaration::VariableDeclarationKind::LET;
    ArenaVector<VariableDeclarator *> declarators_;
    bool declare_ = true;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_VARIABLE_DECLARATION_BUILDER