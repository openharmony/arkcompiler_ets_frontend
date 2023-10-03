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

#include "tupleType.h"

#include "checker/TSchecker.h"

namespace panda::es2panda::checker {
Type *TupleType::ConvertToArrayType(TSChecker *checker)
{
    ArenaVector<Type *> union_types(checker->Allocator()->Adapter());

    for (const auto *it : desc_->properties) {
        union_types.push_back(it->TsType());
    }

    Type *array_type = checker->CreateUnionType(std::move(union_types));
    return checker->Allocator()->New<ArrayType>(array_type);
}

void TupleType::ToString(std::stringstream &ss) const
{
    if (readonly_) {
        ss << "readonly ";
    }
    ss << "[";

    if (named_members_.empty()) {
        for (auto it = desc_->properties.begin(); it != desc_->properties.end(); it++) {
            (*it)->TsType()->ToString(ss);
            if ((*it)->HasFlag(binder::VariableFlags::OPTIONAL)) {
                ss << "?";
            }

            if (std::next(it) != desc_->properties.end()) {
                ss << ", ";
            }
        }
    } else {
        for (auto it = desc_->properties.begin(); it != desc_->properties.end(); it++) {
            const util::StringView &member_name = FindNamedMemberName(*it);
            ss << member_name;

            if ((*it)->HasFlag(binder::VariableFlags::OPTIONAL)) {
                ss << "?";
            }

            ss << ": ";
            (*it)->TsType()->ToString(ss);
            if (std::next(it) != desc_->properties.end()) {
                ss << ", ";
            }
        }
    }

    ss << "]";
}

void TupleType::Identical(TypeRelation *relation, Type *other)
{
    if (other->IsObjectType() && other->AsObjectType()->IsTupleType()) {
        TupleType *other_tuple = other->AsObjectType()->AsTupleType();
        if (kind_ == other_tuple->Kind() && desc_->properties.size() == other_tuple->Properties().size()) {
            for (size_t i = 0; i < desc_->properties.size(); i++) {
                binder::LocalVariable *target_prop = desc_->properties[i];
                binder::LocalVariable *source_prop = other_tuple->Properties()[i];

                if (target_prop->Flags() != source_prop->Flags()) {
                    relation->Result(false);
                    return;
                }

                relation->IsIdenticalTo(target_prop->TsType(), source_prop->TsType());

                if (!relation->IsTrue()) {
                    return;
                }
            }
            relation->Result(true);
        }
    }
}

void TupleType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (!source->IsObjectType() || !source->AsObjectType()->IsTupleType()) {
        relation->Result(false);
        return;
    }

    TupleType *source_tuple = source->AsObjectType()->AsTupleType();
    if (FixedLength() < source_tuple->MinLength()) {
        relation->Result(false);
        return;
    }

    relation->Result(true);

    const auto &source_properties = source_tuple->Properties();
    for (size_t i = 0; i < desc_->properties.size(); i++) {
        auto *target_prop = desc_->properties[i];

        if (i < source_properties.size()) {
            if (!target_prop->HasFlag(binder::VariableFlags::OPTIONAL) &&
                source_properties[i]->HasFlag(binder::VariableFlags::OPTIONAL)) {
                relation->Result(false);
                return;
            }

            Type *target_prop_type = target_prop->TsType();
            Type *source_prop_type = source_properties[i]->TsType();
            if (!relation->IsAssignableTo(source_prop_type, target_prop_type)) {
                return;
            }

            continue;
        }

        if (!target_prop->HasFlag(binder::VariableFlags::OPTIONAL)) {
            relation->Result(false);
            return;
        }
    }

    if (relation->IsTrue()) {
        AssignIndexInfo(relation, source_tuple);
    }
}

TypeFacts TupleType::GetTypeFacts() const
{
    if (desc_->properties.empty()) {
        return TypeFacts::EMPTY_OBJECT_FACTS;
    }

    return TypeFacts::OBJECT_FACTS;
}

Type *TupleType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ObjectDescriptor *copied_desc = allocator->New<ObjectDescriptor>(allocator);

    desc_->Copy(allocator, copied_desc, relation, global_types);

    NamedTupleMemberPool copied_named_member_pool = named_members_;
    ArenaVector<ElementFlags> copied_element_flags(allocator->Adapter());

    for (auto it : element_flags_) {
        copied_element_flags.push_back(it);
    }

    return allocator->New<TupleType>(copied_desc, std::move(copied_element_flags), combined_flags_, min_length_,
                                     fixed_length_, readonly_, std::move(copied_named_member_pool));
}
}  // namespace panda::es2panda::checker
