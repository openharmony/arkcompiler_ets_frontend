/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
#include "ir/astNode.h"

namespace panda::es2panda::checker {
void ETSUnionType::ToString(std::stringstream &ss) const
{
    for (auto it = constituent_types_.begin(); it != constituent_types_.end(); it++) {
        (*it)->ToString(ss);
        if (std::next(it) != constituent_types_.end()) {
            ss << "|";
        }
    }
}

void ETSUnionType::ToAssemblerType(std::stringstream &ss) const
{
    ss << compiler::Signatures::BUILTIN_OBJECT;
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

void ETSUnionType::SetLeastUpperBoundType(ETSChecker *checker)
{
    ASSERT(constituent_types_.size() > 1);
    if (lub_type_ == nullptr) {
        lub_type_ = constituent_types_.front();
        for (auto *t : constituent_types_) {
            if (!t->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                lub_type_ = checker->GetGlobalTypesHolder()->GlobalETSObjectType();
                return;
            }
            lub_type_ = checker->FindLeastUpperBound(lub_type_, t);
        }
    }
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
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const ref_source =
        source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) ? checker->PrimitiveTypeAsETSBuiltinType(source) : source;
    auto exact_type = std::find_if(
        constituent_types_.begin(), constituent_types_.end(), [checker, relation, source, ref_source](Type *ct) {
            if (ct == ref_source && source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && ct->IsETSObjectType() &&
                ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
                relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(ct));
                return relation->IsAssignableTo(ref_source, ct);
            }
            return false;
        });
    if (exact_type != constituent_types_.end()) {
        return;
    }
    for (auto *it : constituent_types_) {
        if (relation->IsAssignableTo(ref_source, it)) {
            if (ref_source != source) {
                relation->IsAssignableTo(source, it);
                ASSERT(relation->IsTrue());
            }
            return;
        }
        bool assign_primitive = it->IsETSObjectType() &&
                                it->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE) &&
                                source->HasTypeFlag(TypeFlag::ETS_PRIMITIVE);
        if (assign_primitive && relation->IsAssignableTo(source, checker->ETSBuiltinTypeAsPrimitiveType(it))) {
            Type *unboxed_it = checker->ETSBuiltinTypeAsPrimitiveType(it);
            if (unboxed_it != source) {
                relation->GetNode()->SetBoxingUnboxingFlags(checker->GetBoxingFlag(it));
                source->Cast(relation, unboxed_it);
                ASSERT(relation->IsTrue());
            }
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
        copied_constituents.push_back(it->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)
                                          ? relation->GetChecker()->AsETSChecker()->PrimitiveTypeAsETSBuiltinType(it)
                                          : it->Instantiate(allocator, relation, global_types));
    }

    if (copied_constituents.size() == 1) {
        return copied_constituents[0];
    }

    auto *new_union_type = allocator->New<ETSUnionType>(std::move(copied_constituents));

    new_union_type->SetLeastUpperBoundType(relation->GetChecker()->AsETSChecker());
    return HandleUnionType(new_union_type);
}

void ETSUnionType::Cast(TypeRelation *relation, Type *target)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const ref_target =
        target->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) ? checker->PrimitiveTypeAsETSBuiltinType(target) : target;
    auto exact_type = std::find_if(constituent_types_.begin(), constituent_types_.end(),
                                   [this, checker, relation, ref_target](Type *src) {
                                       if (src == ref_target && relation->IsCastableTo(src, ref_target)) {
                                           GetLeastUpperBoundType(checker)->Cast(relation, ref_target);
                                           ASSERT(relation->IsTrue());
                                           return true;
                                       }
                                       return false;
                                   });
    if (exact_type != constituent_types_.end()) {
        return;
    }
    for (auto *source : constituent_types_) {
        if (relation->IsCastableTo(source, ref_target)) {
            GetLeastUpperBoundType(checker)->Cast(relation, ref_target);
            ASSERT(relation->IsTrue());
            if (ref_target != target) {
                source->Cast(relation, target);
                ASSERT(relation->IsTrue());
                ASSERT(relation->GetNode()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE);
            }
            return;
        }
        bool cast_primitive = source->IsETSObjectType() &&
                              source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE) &&
                              target->HasTypeFlag(TypeFlag::ETS_PRIMITIVE);
        if (cast_primitive && relation->IsCastableTo(checker->ETSBuiltinTypeAsPrimitiveType(source), target)) {
            ASSERT(relation->IsTrue());
            return;
        }
    }

    conversion::Forbidden(relation);
}

void ETSUnionType::CastTarget(TypeRelation *relation, Type *source)
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

Type *ETSUnionType::FindUnboxableType() const
{
    auto it = std::find_if(constituent_types_.begin(), constituent_types_.end(),
                           [](Type *t) { return t->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE); });
    if (it != constituent_types_.end()) {
        return *it;
    }
    return nullptr;
}

bool ETSUnionType::HasObjectType(ETSObjectFlags flag) const
{
    auto it = std::find_if(constituent_types_.begin(), constituent_types_.end(),
                           [flag](Type *t) { return t->AsETSObjectType()->HasObjectFlag(flag); });
    return it != constituent_types_.end();
}

Type *ETSUnionType::FindExactOrBoxedType(ETSChecker *checker, Type *const type) const
{
    auto it = std::find_if(constituent_types_.begin(), constituent_types_.end(), [checker, type](Type *ct) {
        if (ct->IsETSObjectType() && ct->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
            auto *const unboxed_ct = checker->ETSBuiltinTypeAsPrimitiveType(ct);
            return unboxed_ct == type;
        }
        return ct == type;
    });
    if (it != constituent_types_.end()) {
        return *it;
    }
    return nullptr;
}

}  // namespace panda::es2panda::checker
