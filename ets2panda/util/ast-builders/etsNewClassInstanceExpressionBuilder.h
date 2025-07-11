/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_INCLUDE_ETS_NEW_CLASS_INSTANCE_EXPRESSION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_ETS_NEW_CLASS_INSTANCE_EXPRESSION_BUILDER

#include "ir/ets/etsNewClassInstanceExpression.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class ETSNewClassInstanceExpressionBuilder : public AstBuilder<ir::ETSNewClassInstanceExpression> {
public:
    explicit ETSNewClassInstanceExpressionBuilder(ark::ArenaAllocator *allocator)
        : AstBuilder(allocator), arguments_(Allocator()->Adapter())
    {
    }

    ETSNewClassInstanceExpressionBuilder &SetTypeReference(ir::Expression *typeRef)
    {
        typeReference_ = typeRef;
        return *this;
    }

    ETSNewClassInstanceExpressionBuilder &AddArgument(ir::Expression *argument)
    {
        arguments_.emplace_back(argument);
        return *this;
    }

    ETSNewClassInstanceExpression *Build()
    {
        auto *node = AllocNode(typeReference_, std::move(arguments_));
        return node;
    }

private:
    ir::Expression *typeReference_ = nullptr;
    ArenaVector<ir::Expression *> arguments_;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_ETS_NEW_CLASS_INSTANCE_EXPRESSION_BUILDER