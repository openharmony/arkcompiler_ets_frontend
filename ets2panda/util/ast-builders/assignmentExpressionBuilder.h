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

#ifndef ES2PANDA_UTIL_INCLUDE_ASSIGNMENT_EXPRESSION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_ASSIGNMENT_EXPRESSION_BUILDER

#include "mem/arena_allocator.h"
#include "astBuilder.h"
#include "ir/expressions/assignmentExpression.h"

namespace ark::es2panda::ir {

class AssignmentExpressionBuilder : public AstBuilder<ir::AssignmentExpression> {
public:
    explicit AssignmentExpressionBuilder(ark::ArenaAllocator *allocator) : AstBuilder(allocator) {}

    AssignmentExpressionBuilder &SetOperator(lexer::TokenType op)
    {
        operator_ = op;
        return *this;
    }

    AssignmentExpressionBuilder &SetLeft(Expression *left)
    {
        left_ = left;
        return *this;
    }

    AssignmentExpressionBuilder &SetRight(Expression *right)
    {
        right_ = right;
        return *this;
    }

    AssignmentExpression *Build()
    {
        auto *node = AllocNode(left_, right_, operator_);
        return node;
    }

private:
    Expression *left_ = nullptr;
    Expression *right_ = nullptr;
    lexer::TokenType operator_ = lexer::TokenType::PUNCTUATOR_SUBSTITUTION;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_ASSIGNMENT_EXPRESSION_BUILDER