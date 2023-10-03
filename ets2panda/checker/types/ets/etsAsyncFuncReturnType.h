/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ASYNC_FUNC_RETURN_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ASYNC_FUNC_RETURN_TYPE_H

#include "checker/types/ets/etsObjectType.h"

namespace panda::es2panda::checker {
class GlobalTypesHolder;

class ETSAsyncFuncReturnType : public ETSObjectType {
public:
    ETSAsyncFuncReturnType(ArenaAllocator *allocator, ETSObjectType *promise_type)
        : ETSObjectType(allocator, ETSObjectFlags::ASYNC_FUNC_RETURN_TYPE), promise_type_(promise_type)
    {
        ASSERT(promise_type->TypeArguments().size() == 1);
        SetAssemblerName(compiler::Signatures::BUILTIN_OBJECT);
    }

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;

private:
    const Type *GetPromiseTypeArg() const
    {
        return promise_type_->TypeArguments()[0];
    }

    Type *GetPromiseTypeArg()
    {
        return promise_type_->TypeArguments()[0];
    }

    ETSObjectType *promise_type_;
};
}  // namespace panda::es2panda::checker

#endif /* ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ASYNC_FUNC_RETURN_TYPE_H \
# */
