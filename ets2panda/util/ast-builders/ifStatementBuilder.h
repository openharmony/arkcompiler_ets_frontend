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

#ifndef ES2PANDA_UTIL_INCLUDE_IF_STATEMENT_BUILDER
#define ES2PANDA_UTIL_INCLUDE_IF_STATEMENT_BUILDER

#include "ir/statements/ifStatement.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class IfStatementBuilder : public AstBuilder {
public:
    explicit IfStatementBuilder(ark::ArenaAllocator *allocator) : AstBuilder(allocator) {}

    IfStatementBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    IfStatementBuilder &SetTest(Expression *test)
    {
        test_ = test;
        return *this;
    }

    IfStatementBuilder &SetConsequent(Statement *conseq)
    {
        consequent_ = conseq;
        return *this;
    }

    IfStatementBuilder &SetAlternate(Statement *alternate)
    {
        alternate_ = alternate;
        return *this;
    }

    IfStatement *Build()
    {
        auto *node = AllocNode<ir::IfStatement>(test_, consequent_, alternate_);
        return node;
    }

private:
    AstNode *parent_ {};
    Expression *test_ {};
    Statement *consequent_ {};
    Statement *alternate_ {};
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_IF_STATEMENT_BUILDER