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

#ifndef ES2PANDA_UTIL_INCLUDE_BLOCK_STATEMENT_BUILDER
#define ES2PANDA_UTIL_INCLUDE_BLOCK_STATEMENT_BUILDER

#include "ir/statements/blockStatement.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class BlockStatementBuilder : public AstBuilder {
public:
    explicit BlockStatementBuilder(ark::ArenaAllocator *allocator)
        : AstBuilder(allocator), statementList_(allocator->Adapter())
    {
    }

    BlockStatementBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    BlockStatementBuilder &SetStatements(ArenaVector<Statement *> statements)
    {
        statementList_ = std::move(statements);
        return *this;
    }

    BlockStatementBuilder &AddStatement(Statement *statement)
    {
        statementList_.emplace_back(statement);
        return *this;
    }

    BlockStatement *Build()
    {
        auto node = AllocNode<ir::BlockStatement>(Allocator(), std::move(statementList_));
        if (parent_ != nullptr) {
            node->SetParent(parent_);
        }
        return node;
    }

private:
    AstNode *parent_ {};
    ArenaVector<Statement *> statementList_;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_BLOCK_STATEMENT_BUILDER