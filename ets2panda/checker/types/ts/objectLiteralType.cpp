/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "objectLiteralType.h"

#include "varbinder/variable.h"
#include "checker/types/ts/indexInfo.h"
#include "checker/types/signature.h"

namespace ark::es2panda::checker {
class TSChecker;

void ObjectLiteralType::ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const
{
    ss << "{ ";

    if (desc_->stringIndexInfo != nullptr) {
        desc_->stringIndexInfo->ToString(ss, false);
        ss << "; ";
    }

    if (desc_->numberIndexInfo != nullptr) {
        desc_->numberIndexInfo->ToString(ss, true);
        ss << "; ";
    }

    for (auto *it : desc_->callSignatures) {
        it->ToString(ss, nullptr, true);
        ss << "; ";
    }

    for (auto *it : desc_->constructSignatures) {
        ss << "new ";
        it->ToString(ss, nullptr, true);
        ss << "; ";
    }

    for (auto *it : desc_->properties) {
        if (it->HasFlag(varbinder::VariableFlags::READONLY)) {
            ss << "readonly ";
        }
        ss << it->Name();

        if (it->HasFlag(varbinder::VariableFlags::OPTIONAL)) {
            ss << "?";
        }
        if (it->HasFlag(varbinder::VariableFlags::PROPERTY)) {
            ss << ": ";
        }

        if (it->TsType() != nullptr) {
            it->TsType()->ToString(ss);
        } else {
            ss << "any";
        }

        ss << "; ";
    }

    ss << "}";
}

TypeFacts ObjectLiteralType::GetTypeFacts() const
{
    if (desc_->properties.empty() && desc_->callSignatures.empty() && desc_->constructSignatures.empty() &&
        desc_->numberIndexInfo == nullptr && desc_->stringIndexInfo == nullptr) {
        return TypeFacts::EMPTY_OBJECT_FACTS;
    }

    return TypeFacts::OBJECT_FACTS;
}

Type *ObjectLiteralType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    ObjectDescriptor *copiedDesc = allocator->New<ObjectDescriptor>(allocator);
    desc_->Copy(allocator, copiedDesc, relation, globalTypes);
    return allocator->New<ObjectLiteralType>(copiedDesc);
}
}  // namespace ark::es2panda::checker
