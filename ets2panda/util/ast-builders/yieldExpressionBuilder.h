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

#ifndef ES2PANDA_UTIL_INCLUDE_YIELD_EXPRESSION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_YIELD_EXPRESSION_BUILDER

#include "ir/expressions/yieldExpression.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class YieldExpressionBuilder : public AstBuilder {
public:
    YieldExpressionBuilder(ark::ArenaAllocator *allocator) : AstBuilder(allocator) {}

    YieldExpressionBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    YieldExpressionBuilder &SetArgument(Expression *argument)
    {
        argument_ = argument;
        return *this;
    }

    YieldExpressionBuilder &SetIsDelegate(bool isDelegate)
    {
        delegate_ = isDelegate;
        return *this;
    }

    YieldExpression *Build()
    {
        auto etsTypeReference = AllocNode<ir::YieldExpression>(argument_, delegate_);
        return etsTypeReference;
    }

private:
    AstNode *parent_ {};
    Expression *argument_;
    bool delegate_;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_YIELD_EXPRESSION_BUILDER