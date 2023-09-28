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

#include "objectType.h"

#include "plugins/ecmascript/es2panda/checker/types/ts/indexInfo.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/interfaceType.h"
#include "plugins/ecmascript/es2panda/checker/types/signature.h"
#include "plugins/ecmascript/es2panda/checker/checker.h"

namespace panda::es2panda::checker {
bool ObjectType::EachSignatureRelatedToSomeSignature(TypeRelation *relation,
                                                     const ArenaVector<Signature *> &source_signatures,
                                                     const ArenaVector<Signature *> &target_signatures)
{
    ArenaVector<Signature *> target_copy = target_signatures;

    return std::all_of(source_signatures.begin(), source_signatures.end(), [relation, &target_copy](Signature *source) {
        return SignatureRelatedToSomeSignature(relation, source, &target_copy);
    });
}

bool ObjectType::SignatureRelatedToSomeSignature(TypeRelation *relation, Signature *source_signature,
                                                 ArenaVector<Signature *> *target_signatures)
{
    for (auto it = target_signatures->begin(); it != target_signatures->end();) {
        if (relation->IsIdenticalTo(source_signature, *it)) {
            target_signatures->erase(it);
            return true;
        }

        it++;
    }

    return false;
}

void ObjectType::Identical(TypeRelation *relation, Type *other)
{
    if (!other->IsObjectType() || kind_ != other->AsObjectType()->Kind()) {
        return;
    }

    ObjectType *other_obj = other->AsObjectType();

    if (desc_->properties.size() != other_obj->Properties().size() ||
        CallSignatures().size() != other_obj->CallSignatures().size() ||
        ConstructSignatures().size() != other_obj->ConstructSignatures().size() ||
        (desc_->number_index_info != nullptr && other_obj->NumberIndexInfo() == nullptr) ||
        (desc_->number_index_info == nullptr && other_obj->NumberIndexInfo() != nullptr) ||
        (desc_->string_index_info != nullptr && other_obj->StringIndexInfo() == nullptr) ||
        (desc_->string_index_info == nullptr && other_obj->StringIndexInfo() != nullptr)) {
        relation->Result(false);
        return;
    }

    for (auto *it : desc_->properties) {
        binder::LocalVariable *found = other_obj->Desc()->FindProperty(it->Name());
        if (found == nullptr) {
            relation->Result(false);
            return;
        }

        relation->IsIdenticalTo(it->TsType(), found->TsType());

        if (!relation->IsTrue()) {
            return;
        }

        if (it->Flags() != found->Flags()) {
            relation->Result(false);
            return;
        }
    }

    if (!EachSignatureRelatedToSomeSignature(relation, CallSignatures(), other_obj->CallSignatures()) ||
        !EachSignatureRelatedToSomeSignature(relation, other_obj->CallSignatures(), CallSignatures())) {
        return;
    }

    if (!EachSignatureRelatedToSomeSignature(relation, ConstructSignatures(), other_obj->ConstructSignatures()) ||
        !EachSignatureRelatedToSomeSignature(relation, other_obj->ConstructSignatures(), ConstructSignatures())) {
        return;
    }

    if (desc_->number_index_info != nullptr) {
        relation->IsIdenticalTo(desc_->number_index_info, other_obj->NumberIndexInfo());
        if (!relation->IsTrue()) {
            return;
        }
    }

    if (desc_->string_index_info != nullptr) {
        relation->IsIdenticalTo(desc_->string_index_info, other_obj->StringIndexInfo());
        if (!relation->IsTrue()) {
            return;
        }
    }
}

void ObjectType::AssignProperties(TypeRelation *relation, ObjectType *source)
{
    const ArenaVector<binder::LocalVariable *> &target_properties = Properties();
    IndexInfo *number_info = NumberIndexInfo();
    IndexInfo *string_info = StringIndexInfo();

    for (auto *it : target_properties) {
        binder::LocalVariable *found = source->GetProperty(it->Name(), true);
        Type *target_type = relation->GetChecker()->GetTypeOfVariable(it);

        if (found != nullptr) {
            Type *source_type = relation->GetChecker()->GetTypeOfVariable(found);

            if (!relation->IsAssignableTo(source_type, target_type)) {
                return;
            }

            if (found->HasFlag(binder::VariableFlags::OPTIONAL) && !it->HasFlag(binder::VariableFlags::OPTIONAL)) {
                relation->Result(false);
                return;
            }

            continue;
        }

        if (number_info != nullptr && it->HasFlag(binder::VariableFlags::NUMERIC_NAME) &&
            !relation->IsAssignableTo(number_info->GetType(), target_type)) {
            return;
        }

        if (string_info != nullptr && !relation->IsAssignableTo(string_info->GetType(), target_type)) {
            return;
        }

        if (!it->HasFlag(binder::VariableFlags::OPTIONAL)) {
            relation->Result(false);
            return;
        }
    }
}

void ObjectType::AssignSignatures(TypeRelation *relation, ObjectType *source, bool assign_call_signatures)
{
    ArenaVector<Signature *> target_signatures = assign_call_signatures ? CallSignatures() : ConstructSignatures();
    ArenaVector<Signature *> source_signatures =
        assign_call_signatures ? source->CallSignatures() : source->ConstructSignatures();

    for (auto *target_signature : target_signatures) {
        bool found_compatible = false;
        for (auto *source_signature : source_signatures) {
            target_signature->AssignmentTarget(relation, source_signature);

            if (relation->IsTrue()) {
                found_compatible = true;
                break;
            }
        }

        if (!found_compatible) {
            relation->Result(false);
            return;
        }
    }
}

void ObjectType::AssignIndexInfo([[maybe_unused]] TypeRelation *relation, ObjectType *source, bool assign_number_info)
{
    IndexInfo *target_info = assign_number_info ? NumberIndexInfo() : StringIndexInfo();
    IndexInfo *source_info = assign_number_info ? source->NumberIndexInfo() : source->StringIndexInfo();

    if (target_info != nullptr) {
        if (source_info != nullptr) {
            target_info->AssignmentTarget(relation, source_info);
            return;
        }

        for (auto *it : source->Properties()) {
            if (assign_number_info && !it->HasFlag(binder::VariableFlags::NUMERIC_NAME)) {
                continue;
            }

            if (!relation->IsAssignableTo(relation->GetChecker()->GetTypeOfVariable(it), target_info->GetType())) {
                return;
            }
        }
    }
}

void ObjectType::CheckExcessProperties(TypeRelation *relation, ObjectType *source)
{
    for (auto *it : source->Properties()) {
        auto *found = GetProperty(it->Name(), true);

        if (found != nullptr || (it->HasFlag(binder::VariableFlags::NUMERIC_NAME) && NumberIndexInfo() != nullptr) ||
            StringIndexInfo() != nullptr) {
            continue;
        }

        relation->Result(false);
        return;
    }
}

void ObjectType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (!source->IsObjectType()) {
        relation->Result(false);
        return;
    }

    relation->Result(true);

    ObjectType *source_obj = source->AsObjectType();

    if (source_obj->HasObjectFlag(ObjectFlags::CHECK_EXCESS_PROPS)) {
        CheckExcessProperties(relation, source_obj);
    }

    if (relation->IsTrue()) {
        AssignProperties(relation, source_obj);

        if (relation->IsTrue()) {
            AssignSignatures(relation, source_obj);

            if (relation->IsTrue()) {
                AssignSignatures(relation, source_obj, false);

                if (relation->IsTrue()) {
                    AssignIndexInfo(relation, source_obj);

                    if (relation->IsTrue()) {
                        AssignIndexInfo(relation, source_obj, false);
                    }
                }
            }
        }
    }
}
}  // namespace panda::es2panda::checker
