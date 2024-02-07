/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#ifndef ARK_DYNAMICCALLINFO_H
#define ARK_DYNAMICCALLINFO_H

#include <optional>

#include "varbinder/ETSBinder.h"
#include "ir/expression.h"

namespace ark::es2panda::checker {

class DynamicCall {
    using NameHolder = ArenaVector<util::StringView>;

public:
    struct Result {
        const ir::AstNode *obj;
        const NameHolder name;  // NOLINT(readability-identifier-naming)
    };

    /**
     * Resolve callee
     * @param varbinder
     * @param callee expression used to call method
     * @return callee and name from which should be used to produce call
     */
    static Result ResolveCall(const varbinder::ETSBinder *varbinder, const ir::Expression *callee);
    static bool IsByValue(const varbinder::ETSBinder *varbinder, const ir::Expression *callee)
    {
        return ResolveCall(varbinder, callee).name.empty();
    }

    /**
     * Example: A[0].C.D => return: A[0], name: ".C.D"
     * @param expr member expression
     * @param name to store result
     * @return object with remaining member expression
     */
    static Result SqueezeExpr(ArenaAllocator *allocator, const ir::MemberExpression *expr);

private:
    static const ir::Expression *SqueezeExpr(const ir::MemberExpression *expr, NameHolder &name);
};

}  // namespace ark::es2panda::checker
#endif  // ARK_DYNAMICCALLINFO_H
