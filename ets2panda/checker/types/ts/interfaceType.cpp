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

#include "interfaceType.h"

#include "binder/variable.h"
#include "checker/checker.h"
#include "checker/types/ts/typeParameter.h"

#include <algorithm>
#include <utility>

namespace panda::es2panda::checker {
void InterfaceType::ToString(std::stringstream &ss) const
{
    ss << name_;

    if (!type_param_types_.empty()) {
        ss << "<";

        for (auto it = type_param_types_.begin(); it != type_param_types_.end(); it++) {
            (*it)->ToString(ss);

            if (std::next(it) != type_param_types_.end()) {
                ss << ", ";
            }
        }

        ss << ">";
    }
}

void InterfaceType::Identical(TypeRelation *relation, Type *other)
{
    if (!other->IsObjectType() || !other->AsObjectType()->IsInterfaceType()) {
        return;
    }

    InterfaceType *other_interface = other->AsObjectType()->AsInterfaceType();

    const ArenaVector<binder::LocalVariable *> &target_properties = Properties();
    const ArenaVector<binder::LocalVariable *> &source_properties = other_interface->Properties();

    if (target_properties.size() != source_properties.size()) {
        relation->Result(false);
        return;
    }

    for (auto *target_prop : target_properties) {
        bool found_prop =
            std::any_of(source_properties.begin(), source_properties.end(),
                        [target_prop, relation](binder::LocalVariable *source_prop) {
                            if (target_prop->Name() == source_prop->Name()) {
                                Type *target_type = relation->GetChecker()->GetTypeOfVariable(target_prop);
                                Type *source_type = relation->GetChecker()->GetTypeOfVariable(source_prop);
                                return relation->IsIdenticalTo(target_type, source_type);
                            }

                            return false;
                        });
        if (!found_prop) {
            relation->Result(false);
            return;
        }
    }

    const ArenaVector<Signature *> &target_call_signatures = CallSignatures();
    const ArenaVector<Signature *> &source_call_signatures = other_interface->CallSignatures();
    if (target_call_signatures.size() != source_call_signatures.size()) {
        relation->Result(false);
        return;
    }

    if (!EachSignatureRelatedToSomeSignature(relation, target_call_signatures, source_call_signatures) ||
        !EachSignatureRelatedToSomeSignature(relation, source_call_signatures, target_call_signatures)) {
        return;
    }

    const ArenaVector<Signature *> &target_construct_signatures = ConstructSignatures();
    const ArenaVector<Signature *> &source_construct_signatures = other_interface->ConstructSignatures();

    if (target_construct_signatures.size() != source_construct_signatures.size()) {
        relation->Result(false);
        return;
    }

    if (!EachSignatureRelatedToSomeSignature(relation, target_construct_signatures, source_construct_signatures) ||
        !EachSignatureRelatedToSomeSignature(relation, source_construct_signatures, target_construct_signatures)) {
        return;
    }

    IndexInfo *target_number_info = NumberIndexInfo();
    IndexInfo *source_number_info = other_interface->NumberIndexInfo();

    if ((target_number_info != nullptr && source_number_info == nullptr) ||
        (target_number_info == nullptr && source_number_info != nullptr)) {
        relation->Result(false);
        return;
    }

    relation->IsIdenticalTo(target_number_info, source_number_info);

    if (relation->IsTrue()) {
        IndexInfo *target_string_info = StringIndexInfo();
        IndexInfo *source_string_info = other_interface->StringIndexInfo();

        if ((target_string_info != nullptr && source_string_info == nullptr) ||
            (target_string_info == nullptr && source_string_info != nullptr)) {
            relation->Result(false);
            return;
        }

        relation->IsIdenticalTo(target_string_info, source_string_info);
    }
}

Type *InterfaceType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ObjectDescriptor *copied_desc = allocator->New<ObjectDescriptor>(allocator);

    desc_->Copy(allocator, copied_desc, relation, global_types);

    Type *new_interface_type = allocator->New<InterfaceType>(allocator, name_, copied_desc);

    for (auto *it : bases_) {
        new_interface_type->AsObjectType()->AsInterfaceType()->AddBase(
            it->Instantiate(allocator, relation, global_types)->AsObjectType());
    }

    return new_interface_type;
}

void InterfaceType::CollectSignatures(ArenaVector<Signature *> *collected_signatures,
                                      bool collect_call_signatures) const
{
    if (collect_call_signatures) {
        for (auto *it : desc_->call_signatures) {
            collected_signatures->push_back(it);
        }
    } else {
        for (auto *it : desc_->construct_signatures) {
            collected_signatures->push_back(it);
        }
    }

    for (auto *it : bases_) {
        it->AsInterfaceType()->CollectSignatures(collected_signatures, collect_call_signatures);
    }
}

void InterfaceType::CollectProperties(ArenaVector<binder::LocalVariable *> *collected_properties) const
{
    for (auto *current_prop : desc_->properties) {
        bool prop_already_collected = false;
        for (auto *collected_prop : *collected_properties) {
            if (current_prop->Name() == collected_prop->Name()) {
                prop_already_collected = true;
                break;
            }
        }

        if (prop_already_collected) {
            continue;
        }

        collected_properties->push_back(current_prop);
    }

    for (auto *it : bases_) {
        it->AsInterfaceType()->CollectProperties(collected_properties);
    }
}

const IndexInfo *InterfaceType::FindIndexInfo(bool find_number_info) const
{
    const IndexInfo *found_info = nullptr;

    if (find_number_info && desc_->number_index_info != nullptr) {
        found_info = desc_->number_index_info;
    } else if (!find_number_info && desc_->string_index_info != nullptr) {
        found_info = desc_->string_index_info;
    }

    for (auto it = bases_.begin(); it != bases_.end() && found_info == nullptr; it++) {
        found_info = (*it)->AsInterfaceType()->FindIndexInfo(find_number_info);
    }

    return found_info;
}

IndexInfo *InterfaceType::FindIndexInfo(bool find_number_info)
{
    IndexInfo *found_info = nullptr;

    if (find_number_info && desc_->number_index_info != nullptr) {
        found_info = desc_->number_index_info;
    } else if (!find_number_info && desc_->string_index_info != nullptr) {
        found_info = desc_->string_index_info;
    }

    for (auto it = bases_.begin(); it != bases_.end() && found_info == nullptr; it++) {
        found_info = (*it)->AsInterfaceType()->FindIndexInfo(find_number_info);
    }

    return found_info;
}

TypeFacts InterfaceType::GetTypeFacts() const
{
    if (desc_->properties.empty() && desc_->call_signatures.empty() && desc_->construct_signatures.empty() &&
        desc_->string_index_info == nullptr && desc_->number_index_info == nullptr) {
        if (bases_.empty()) {
            return TypeFacts::EMPTY_OBJECT_FACTS;
        }

        bool is_empty = true;
        for (auto it = bases_.begin(); is_empty && it != bases_.end(); it++) {
            if (!(*it)->Properties().empty() || !(*it)->CallSignatures().empty() ||
                !(*it)->ConstructSignatures().empty() || (*it)->StringIndexInfo() != nullptr ||
                (*it)->NumberIndexInfo() != nullptr) {
                is_empty = false;
            }
        }

        if (is_empty) {
            return TypeFacts::EMPTY_OBJECT_FACTS;
        }
    }

    return TypeFacts::OBJECT_FACTS;
}
}  // namespace panda::es2panda::checker
