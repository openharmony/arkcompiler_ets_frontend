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

#ifndef ES2PANDA_UTIL_INCLUDE_UNARY_EXPRESSION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_UNARY_EXPRESSION_BUILDER

#include "mem/arena_allocator.h"
#include "astBuilder.h"
#include "ir/expressions/unaryExpression.h"

namespace ark::es2panda::ir {

class UnaryExpressionBuilder : public AstBuilder {
public:
    explicit UnaryExpressionBuilder(ark::ArenaAllocator *allocator) : AstBuilder(allocator) {}

    UnaryExpressionBuilder &SetOperator(lexer::TokenType op)
    {
        operator_ = op;
        return *this;
    }

    UnaryExpressionBuilder &SetArgument(Expression *arg)
    {
        argument_ = arg;
        return *this;
    }

    UnaryExpressionBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    UnaryExpression *Build()
    {
        auto *node = AllocNode<ir::UnaryExpression>(argument_, operator_);
        node->SetParent(parent_);
        return node;
    }

private:
    Expression *argument_ {};
    lexer::TokenType operator_ = lexer::TokenType::PUNCTUATOR_PLUS_PLUS;
    AstNode *parent_ {};
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_UNARY_EXPRESSION_BUILDER