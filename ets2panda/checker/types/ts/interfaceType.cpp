/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "varbinder/variable.h"
#include "checker/checker.h"
#include "checker/types/ts/typeParameter.h"

#include <algorithm>
#include <utility>

namespace ark::es2panda::checker {
void InterfaceType::ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const
{
    ss << name_;

    if (!typeParamTypes_.empty()) {
        ss << "<";

        for (auto it = typeParamTypes_.begin(); it != typeParamTypes_.end(); it++) {
            (*it)->ToString(ss);

            if (std::next(it) != typeParamTypes_.end()) {
                ss << ", ";
            }
        }

        ss << ">";
    }
}

bool InterfaceType::CheckVarType(TypeRelation *relation,
                                 const ArenaVector<varbinder::LocalVariable *> &targetProperties,
                                 const ArenaVector<varbinder::LocalVariable *> &sourceProperties)
{
    for (auto *targetProp : targetProperties) {
        bool foundProp = std::any_of(sourceProperties.begin(), sourceProperties.end(),
                                     [targetProp, relation](varbinder::LocalVariable *sourceProp) {
                                         if (targetProp->Name() == sourceProp->Name()) {
                                             Type *targetType = relation->GetChecker()->GetTypeOfVariable(targetProp);
                                             Type *sourceType = relation->GetChecker()->GetTypeOfVariable(sourceProp);
                                             return relation->IsIdenticalTo(targetType, sourceType);
                                         }

                                         return false;  // CC-OFF(G.FMT.02) project code style
                                     });
        if (!foundProp) {
            relation->Result(false);
            return true;
        }
    }
    return false;
}

void InterfaceType::Identical(TypeRelation *relation, Type *other)
{
    if (!other->IsObjectType() || !other->AsObjectType()->IsInterfaceType()) {
        return;
    }

    InterfaceType *otherInterface = other->AsObjectType()->AsInterfaceType();

    const ArenaVector<varbinder::LocalVariable *> &targetProperties = Properties();
    const ArenaVector<varbinder::LocalVariable *> &sourceProperties = otherInterface->Properties();

    if (targetProperties.size() != sourceProperties.size()) {
        relation->Result(false);
        return;
    }

    if (CheckVarType(relation, targetProperties, sourceProperties)) {
        return;
    }

    const ArenaVector<Signature *> &targetCallSignatures = CallSignatures();
    const ArenaVector<Signature *> &sourceCallSignatures = otherInterface->CallSignatures();
    if (targetCallSignatures.size() != sourceCallSignatures.size()) {
        relation->Result(false);
        return;
    }

    if (!EachSignatureRelatedToSomeSignature(relation, targetCallSignatures, sourceCallSignatures) ||
        !EachSignatureRelatedToSomeSignature(relation, sourceCallSignatures, targetCallSignatures)) {
        return;
    }

    const ArenaVector<Signature *> &targetConstructSignatures = ConstructSignatures();
    const ArenaVector<Signature *> &sourceConstructSignatures = otherInterface->ConstructSignatures();

    if (targetConstructSignatures.size() != sourceConstructSignatures.size()) {
        relation->Result(false);
        return;
    }

    if (!EachSignatureRelatedToSomeSignature(relation, targetConstructSignatures, sourceConstructSignatures) ||
        !EachSignatureRelatedToSomeSignature(relation, sourceConstructSignatures, targetConstructSignatures)) {
        return;
    }

    IndexInfo *targetNumberInfo = NumberIndexInfo();
    IndexInfo *sourceNumberInfo = otherInterface->NumberIndexInfo();

    if ((targetNumberInfo != nullptr && sourceNumberInfo == nullptr) ||
        (targetNumberInfo == nullptr && sourceNumberInfo != nullptr)) {
        relation->Result(false);
        return;
    }

    relation->IsIdenticalTo(targetNumberInfo, sourceNumberInfo);

    CheckStringInfo(relation, otherInterface);
}

void InterfaceType::CheckStringInfo(TypeRelation *relation, InterfaceType *otherInterface)
{
    if (relation->IsTrue()) {
        IndexInfo *targetStringInfo = StringIndexInfo();
        IndexInfo *sourceStringInfo = otherInterface->StringIndexInfo();

        if ((targetStringInfo != nullptr && sourceStringInfo == nullptr) ||
            (targetStringInfo == nullptr && sourceStringInfo != nullptr)) {
            relation->Result(false);
            return;
        }

        relation->IsIdenticalTo(targetStringInfo, sourceStringInfo);
    }
}

Type *InterfaceType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    ObjectDescriptor *copiedDesc = allocator->New<ObjectDescriptor>(allocator);

    desc_->Copy(allocator, copiedDesc, relation, globalTypes);

    Type *newInterfaceType = allocator->New<InterfaceType>(allocator, name_, copiedDesc);

    ES2PANDA_ASSERT(newInterfaceType != nullptr);
    for (auto *it : bases_) {
        newInterfaceType->AsObjectType()->AsInterfaceType()->AddBase(
            it->Instantiate(allocator, relation, globalTypes)->AsObjectType());
    }

    return newInterfaceType;
}

void InterfaceType::CollectSignatures(ArenaVector<Signature *> *collectedSignatures, bool collectCallSignatures) const
{
    if (collectCallSignatures) {
        for (auto *it : desc_->callSignatures) {
            collectedSignatures->push_back(it);
        }
    } else {
        for (auto *it : desc_->constructSignatures) {
            collectedSignatures->push_back(it);
        }
    }

    for (auto *it : bases_) {
        it->AsInterfaceType()->CollectSignatures(collectedSignatures, collectCallSignatures);
    }
}

void InterfaceType::CollectProperties(ArenaVector<varbinder::LocalVariable *> *collectedProperties) const
{
    for (auto *currentProp : desc_->properties) {
        bool propAlreadyCollected = false;
        for (auto *collectedProp : *collectedProperties) {
            if (currentProp->Name() == collectedProp->Name()) {
                propAlreadyCollected = true;
                break;
            }
        }

        if (propAlreadyCollected) {
            continue;
        }

        collectedProperties->push_back(currentProp);
    }

    for (auto *it : bases_) {
        it->AsInterfaceType()->CollectProperties(collectedProperties);
    }
}

const IndexInfo *InterfaceType::FindIndexInfo(bool findNumberInfo) const
{
    const IndexInfo *foundInfo = nullptr;

    if (findNumberInfo && desc_->numberIndexInfo != nullptr) {
        foundInfo = desc_->numberIndexInfo;
    } else if (!findNumberInfo && desc_->stringIndexInfo != nullptr) {
        foundInfo = desc_->stringIndexInfo;
    }

    for (auto it = bases_.begin(); it != bases_.end() && foundInfo == nullptr; it++) {
        foundInfo = (*it)->AsInterfaceType()->FindIndexInfo(findNumberInfo);
    }

    return foundInfo;
}

IndexInfo *InterfaceType::FindIndexInfo(bool findNumberInfo)
{
    IndexInfo *foundInfo = nullptr;

    if (findNumberInfo && desc_->numberIndexInfo != nullptr) {
        foundInfo = desc_->numberIndexInfo;
    } else if (!findNumberInfo && desc_->stringIndexInfo != nullptr) {
        foundInfo = desc_->stringIndexInfo;
    }

    for (auto it = bases_.begin(); it != bases_.end() && foundInfo == nullptr; it++) {
        foundInfo = (*it)->AsInterfaceType()->FindIndexInfo(findNumberInfo);
    }

    return foundInfo;
}

TypeFacts InterfaceType::GetTypeFacts() const
{
    if (desc_->properties.empty() && desc_->callSignatures.empty() && desc_->constructSignatures.empty() &&
        desc_->stringIndexInfo == nullptr && desc_->numberIndexInfo == nullptr) {
        if (bases_.empty()) {
            return TypeFacts::EMPTY_OBJECT_FACTS;
        }

        bool isEmpty = true;
        for (auto it = bases_.begin(); isEmpty && it != bases_.end(); it++) {
            if (!(*it)->Properties().empty() || !(*it)->CallSignatures().empty() ||
                !(*it)->ConstructSignatures().empty() || (*it)->StringIndexInfo() != nullptr ||
                (*it)->NumberIndexInfo() != nullptr) {
                isEmpty = false;
            }
        }

        if (isEmpty) {
            return TypeFacts::EMPTY_OBJECT_FACTS;
        }
    }

    return TypeFacts::OBJECT_FACTS;
}
}  // namespace ark::es2panda::checker
