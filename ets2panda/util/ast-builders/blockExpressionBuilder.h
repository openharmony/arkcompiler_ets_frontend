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

#ifndef ES2PANDA_UTIL_INCLUDE_BLOCK_EXPRESSION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_BLOCK_EXPRESSION_BUILDER

#include "ir/expressions/blockExpression.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class BlockExpressionBuilder : public AstBuilder {
public:
    explicit BlockExpressionBuilder(ark::ArenaAllocator *allocator)
        : AstBuilder(allocator), statements_(allocator->Adapter())
    {
    }

    BlockExpressionBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    BlockExpressionBuilder &SetStatements(ArenaVector<Statement *> statements)
    {
        statements_ = std::move(statements);
        return *this;
    }

    BlockExpressionBuilder &AddStatement(Statement *statement)
    {
        statements_.emplace_back(statement);
        return *this;
    }

    BlockExpression *Build()
    {
        auto *node = AllocNode<ir::BlockExpression>(std::move(statements_));
        return node;
    }

private:
    AstNode *parent_ {};
    ArenaVector<ir::Statement *> statements_;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_BLOCK_EXPRESSION_BUILDER