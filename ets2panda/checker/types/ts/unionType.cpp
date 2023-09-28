/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "unionType.h"
#include <algorithm>

#include "plugins/ecmascript/es2panda/checker/types/globalTypesHolder.h"

namespace panda::es2panda::checker {
void UnionType::ToString(std::stringstream &ss) const
{
    for (auto it = constituent_types_.begin(); it != constituent_types_.end(); it++) {
        (*it)->ToString(ss);
        if (std::next(it) != constituent_types_.end()) {
            ss << " | ";
        }
    }
}

bool UnionType::EachTypeRelatedToSomeType(TypeRelation *relation, UnionType *source, UnionType *target)
{
    return std::all_of(source->constituent_types_.begin(), source->constituent_types_.end(),
                       [relation, target](auto *s) { return TypeRelatedToSomeType(relation, s, target); });
}

bool UnionType::TypeRelatedToSomeType(TypeRelation *relation, Type *source, UnionType *target)
{
    return std::any_of(target->constituent_types_.begin(), target->constituent_types_.end(),
                       [relation, source](auto *t) { return relation->IsIdenticalTo(source, t); });
}

void UnionType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsUnionType()) {
        if (EachTypeRelatedToSomeType(relation, this, other->AsUnionType()) &&
            EachTypeRelatedToSomeType(relation, other->AsUnionType(), this)) {
            relation->Result(true);
            return;
        }
    }

    relation->Result(false);
}

bool UnionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    for (auto *it : constituent_types_) {
        if (!relation->IsAssignableTo(it, target)) {
            return false;
        }
    }

    relation->Result(true);
    return true;
}

void UnionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    for (auto *it : constituent_types_) {
        if (relation->IsAssignableTo(source, it)) {
            return;
        }
    }
}

TypeFacts UnionType::GetTypeFacts() const
{
    TypeFacts facts = TypeFacts::NONE;

    for (auto *it : constituent_types_) {
        facts |= it->GetTypeFacts();
    }

    return facts;
}

void UnionType::RemoveDuplicatedTypes(TypeRelation *relation, ArenaVector<Type *> &constituent_types)
{
    auto compare = constituent_types.begin();

    while (compare != constituent_types.end()) {
        auto it = compare + 1;

        while (it != constituent_types.end()) {
            relation->Result(false);

            (*compare)->Identical(relation, *it);

            if (relation->IsTrue()) {
                it = constituent_types.erase(it);
            } else {
                it++;
            }
        }

        compare++;
    }
}

Type *UnionType::HandleUnionType(UnionType *union_type, GlobalTypesHolder *global_types_holder)
{
    if (union_type->HasConstituentFlag(TypeFlag::ANY)) {
        return global_types_holder->GlobalAnyType();
    }

    if (union_type->HasConstituentFlag(TypeFlag::UNKNOWN)) {
        return global_types_holder->GlobalUnknownType();
    }

    RemoveRedundantLiteralTypesFromUnion(union_type);

    if (union_type->ConstituentTypes().size() == 1) {
        return union_type->ConstituentTypes()[0];
    }

    return union_type;
}

void UnionType::RemoveRedundantLiteralTypesFromUnion(UnionType *type)
{
    bool remove_number_literals = false;
    bool remove_string_literals = false;
    bool remove_bigint_literals = false;
    bool remove_boolean_literals = false;

    if (type->HasConstituentFlag(TypeFlag::NUMBER) && type->HasConstituentFlag(TypeFlag::NUMBER_LITERAL)) {
        remove_number_literals = true;
    }

    if (type->HasConstituentFlag(TypeFlag::STRING) && type->HasConstituentFlag(TypeFlag::STRING_LITERAL)) {
        remove_string_literals = true;
    }

    if (type->HasConstituentFlag(TypeFlag::BIGINT) && type->HasConstituentFlag(TypeFlag::BIGINT_LITERAL)) {
        remove_bigint_literals = true;
    }

    if (type->HasConstituentFlag(TypeFlag::BOOLEAN) && type->HasConstituentFlag(TypeFlag::BOOLEAN_LITERAL)) {
        remove_boolean_literals = true;
    }

    auto &constituent_types = type->ConstituentTypes();
    /* TODO(dbatyai): use std::erase_if */
    auto it = constituent_types.begin();
    while (it != constituent_types.end()) {
        if ((remove_number_literals && (*it)->IsNumberLiteralType()) ||
            (remove_string_literals && (*it)->IsStringLiteralType()) ||
            (remove_bigint_literals && (*it)->IsBigintLiteralType()) ||
            (remove_boolean_literals && (*it)->IsBooleanLiteralType())) {
            type->RemoveConstituentFlag((*it)->TypeFlags());
            it = constituent_types.erase(it);
            continue;
        }

        it++;
    }
}

Type *UnionType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ArenaVector<Type *> copied_constituents(constituent_types_.size(), allocator->Adapter());

    for (auto *it : constituent_types_) {
        copied_constituents.push_back(it->Instantiate(allocator, relation, global_types));
    }

    RemoveDuplicatedTypes(relation, copied_constituents);

    if (copied_constituents.size() == 1) {
        return copied_constituents[0];
    }

    Type *new_union_type = allocator->New<UnionType>(allocator, std::move(copied_constituents));

    return HandleUnionType(new_union_type->AsUnionType(), global_types);
}
}  // namespace panda::es2panda::checker
