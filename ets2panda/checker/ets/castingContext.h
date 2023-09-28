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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_CASTING_CONTEXT_H
#define ES2PANDA_COMPILER_CHECKER_ETS_CASTING_CONTEXT_H

#include "plugins/ecmascript/es2panda/checker/types/typeRelation.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"

namespace panda::es2panda::checker {
class CastingContext {
public:
    CastingContext(TypeRelation *relation, ir::Expression *node, Type *source, Type *target,
                   const lexer::SourcePosition &pos, std::initializer_list<TypeErrorMessageElement> list,
                   TypeRelationFlag extra_flags = TypeRelationFlag::NONE);

    [[nodiscard]] bool UncheckedCast() const noexcept;

private:
    TypeRelationFlag flags_ {TypeRelationFlag::CASTING_CONTEXT | TypeRelationFlag::IN_CASTING_CONTEXT};
    bool unchecked_cast_ {true};
};

}  // namespace panda::es2panda::checker

#endif
