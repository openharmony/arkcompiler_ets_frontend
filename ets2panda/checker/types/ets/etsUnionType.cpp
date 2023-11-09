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

#include <algorithm>

#include "etsUnionType.h"
#include "checker/ets/conversion.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::checker {
void ETSUnionType::ToString(std::stringstream &ss) const
{
    for (auto it = constituent_types_.begin(); it != constituent_types_.end(); it++) {
        (*it)->ToString(ss);
        if (std::next(it) != constituent_types_.end()) {
            ss << " | ";
        }
    }
}

bool ETSUnionType::EachTypeRelatedToSomeType(TypeRelation *relation, ETSUnionType *source, ETSUnionType *target)
{
    return std::all_of(source->constituent_types_.begin(), source->constituent_types_.end(),
                       [relation, target](auto *s) { return TypeRelatedToSomeType(relation, s, target); });
}

bool ETSUnionType::TypeRelatedToSomeType(TypeRelation *relation, Type *source, ETSUnionType *target)
{
    return std::any_of(target->constituent_types_.begin(), target->constituent_types_.end(),
                       [relation, source](auto *t) { return relation->IsIdenticalTo(source, t); });
}

Type *ETSUnionType::GetLeastUpperBoundType(ETSChecker *checker)
{
    ASSERT(constituent_types_.size() > 1);
    if (lub_type_ == nullptr) {
        lub_type_ = constituent_types_.front();
        for (auto *t : constituent_types_) {
            if (!t->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                lub_type_ = checker->GetGlobalTypesHolder()->GlobalETSObjectType();
                return lub_type_;
            }
            lub_type_ = checker->FindLeastUpperBound(lub_type_, t);
        }
    }
    return lub_type_;
}

void ETSUnionType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsETSUnionType()) {
        if (EachTypeRelatedToSomeType(relation, this, other->AsETSUnionType()) &&
            EachTypeRelatedToSomeType(relation, other->AsETSUnionType(), this)) {
            relation->Result(true);
            return;
        }
    }

    relation->Result(false);
}

bool ETSUnionType::AssignmentSource(TypeRelation *relation, Type *target)
{
    for (auto *it : constituent_types_) {
        if (!relation->IsAssignableTo(it, target)) {
            return false;
        }
    }

    relation->Result(true);
    return true;
}

void ETSUnionType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    // For an unsorted constituent_types_, a less suitable type may first come across than it could be
    // if the entire array of constituent types was analyzed.
    for (auto *it : constituent_types_) {
        if (!source->IsETSObjectType() && (source->HasTypeFlag(it->TypeFlags()) || it == source)) {
            relation->IsAssignableTo(source, it);
            return;
        }
    }
    for (auto *it : constituent_types_) {
        if (relation->IsAssignableTo(source, it)) {
            return;
        }
    }
}

Type *ETSUnionType::HandleUnionType(ETSUnionType *union_type)
{
    if (union_type->ConstituentTypes().size() == 1) {
        return union_type->ConstituentTypes()[0];
    }

    return union_type;
}

Type *ETSUnionType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ArenaVector<Type *> copied_constituents(constituent_types_.size(), allocator->Adapter());

    for (auto *it : constituent_types_) {
        copied_constituents.push_back(it->Instantiate(allocator, relation, global_types));
    }

    if (copied_constituents.size() == 1) {
        return copied_constituents[0];
    }

    Type *new_union_type = allocator->New<ETSUnionType>(std::move(copied_constituents));

    lub_type_ = global_types->GlobalETSObjectType();
    return HandleUnionType(new_union_type->AsETSUnionType());
}

void ETSUnionType::Cast(TypeRelation *relation, Type *target)
{
    bool is_cast_to_obj = target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT);
    for (auto *source : constituent_types_) {
        relation->IsCastableTo(source, target);
        if (relation->IsTrue()) {
            if (is_cast_to_obj && source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                GetLeastUpperBoundType(relation->GetChecker()->AsETSChecker())->Cast(relation, target);
                return;
            }
            if (!is_cast_to_obj) {
                source->Cast(relation, target);
                return;
            }
        }
    }

    conversion::Forbidden(relation);
}

void ETSUnionType::CastToThis(TypeRelation *relation, Type *source)
{
    Type *target_type = FindTypeIsCastableToThis(relation->GetNode(), relation, source);
    if (target_type != nullptr) {
        source->Cast(relation, target_type);
        return;
    }

    conversion::Forbidden(relation);
}

Type *ETSUnionType::FindTypeIsCastableToThis(ir::Expression *node, TypeRelation *relation, Type *source) const
{
    ASSERT(node);
    bool node_was_set = false;
    if (relation->GetNode() == nullptr) {
        node_was_set = true;
        relation->SetNode(node);
    }
    // Prioritize object to object conversion
    auto it = std::find_if(constituent_types_.begin(), constituent_types_.end(), [relation, source](Type *target) {
        relation->IsCastableTo(source, target);
        return relation->IsTrue() && source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) &&
               target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT);
    });
    if (it != constituent_types_.end()) {
        if (node_was_set) {
            relation->SetNode(nullptr);
        }
        return *it;
    }
    it = std::find_if(constituent_types_.begin(), constituent_types_.end(), [relation, source](Type *target) {
        relation->IsCastableTo(source, target);
        return relation->IsTrue();
    });
    if (node_was_set) {
        relation->SetNode(nullptr);
    }
    if (it != constituent_types_.end()) {
        return *it;
    }
    return nullptr;
}

Type *ETSUnionType::FindTypeIsCastableToSomeType(ir::Expression *node, TypeRelation *relation, Type *target) const
{
    ASSERT(node);
    bool node_was_set = false;
    if (relation->GetNode() == nullptr) {
        node_was_set = true;
        relation->SetNode(node);
        relation->SetFlags(TypeRelationFlag::CASTING_CONTEXT);
    }
    auto is_castable_pred = [](TypeRelation *r, Type *source_type, Type *target_type) {
        if (target_type->IsETSUnionType()) {
            auto *found_target_type =
                target_type->AsETSUnionType()->FindTypeIsCastableToThis(r->GetNode(), r, source_type);
            r->Result(found_target_type != nullptr);
        } else {
            r->IsCastableTo(source_type, target_type);
        }
        return r->IsTrue();
    };
    // Prioritize object to object conversion
    auto it = std::find_if(
        constituent_types_.begin(), constituent_types_.end(), [relation, target, &is_castable_pred](Type *source) {
            return is_castable_pred(relation, source, target) && source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) &&
                   target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT);
        });
    if (it != constituent_types_.end()) {
        if (node_was_set) {
            relation->SetNode(nullptr);
            relation->RemoveFlags(TypeRelationFlag::CASTING_CONTEXT);
        }
        return *it;
    }
    it = std::find_if(
        constituent_types_.begin(), constituent_types_.end(),
        [relation, target, &is_castable_pred](Type *source) { return is_castable_pred(relation, source, target); });
    if (node_was_set) {
        relation->SetNode(nullptr);
        relation->RemoveFlags(TypeRelationFlag::CASTING_CONTEXT);
    }
    if (it != constituent_types_.end()) {
        return *it;
    }
    return nullptr;
}

}  // namespace panda::es2panda::checker
