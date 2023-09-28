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

#include "castingContext.h"

namespace panda::es2panda::checker {
CastingContext::CastingContext(TypeRelation *relation, ir::Expression *node, Type *source, Type *target,
                               const lexer::SourcePosition &pos, std::initializer_list<TypeErrorMessageElement> list,
                               TypeRelationFlag extra_flags)
{
    flags_ |= extra_flags;

    const SavedTypeRelationFlagsContext saved_type_relation_flags(relation, flags_);
    relation->SetNode(node);
    relation->Result(false);

    relation->IsCastableTo(source, target);
    if (!relation->IsTrue() && (flags_ & TypeRelationFlag::NO_THROW) == 0) {
        relation->RaiseError(list, pos);
    }

    unchecked_cast_ = relation->UncheckedCast();
    relation->SetNode(nullptr);
}

bool CastingContext::UncheckedCast() const noexcept
{
    return unchecked_cast_;
}
}  // namespace panda::es2panda::checker
