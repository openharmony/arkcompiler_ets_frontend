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

#ifndef ES2PANDA_UTIL_INCLUDE_LABELLED_STATEMENT_BUILDER
#define ES2PANDA_UTIL_INCLUDE_LABELLED_STATEMENT_BUILDER

#include "ir/statements/labelledStatement.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class LabelledStatementBuilder : public AstBuilder<ir::LabelledStatement> {
public:
    explicit LabelledStatementBuilder(ark::ArenaAllocator *allocator) : AstBuilder(allocator) {}

    LabelledStatementBuilder &SetIdent(Identifier *ident)
    {
        ident_ = ident;
        return *this;
    }

    LabelledStatementBuilder &SetBody(Statement *body)
    {
        body_ = body;
        return *this;
    }

    LabelledStatement *Build()
    {
        auto node = AllocNode(ident_, body_);
        return node;
    }

private:
    Identifier *ident_ {};
    Statement *body_ {};
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_LABELLED_STATEMENT_BUILDER