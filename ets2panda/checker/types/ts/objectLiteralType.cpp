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

#include "objectLiteralType.h"

#include "binder/variable.h"
#include "checker/types/ts/indexInfo.h"
#include "checker/types/signature.h"

namespace panda::es2panda::checker {
class TSChecker;

void ObjectLiteralType::ToString(std::stringstream &ss) const
{
    ss << "{ ";

    if (desc_->string_index_info != nullptr) {
        desc_->string_index_info->ToString(ss, false);
        ss << "; ";
    }

    if (desc_->number_index_info != nullptr) {
        desc_->number_index_info->ToString(ss, true);
        ss << "; ";
    }

    for (auto *it : desc_->call_signatures) {
        it->ToString(ss, nullptr, true);
        ss << "; ";
    }

    for (auto *it : desc_->construct_signatures) {
        ss << "new ";
        it->ToString(ss, nullptr, true);
        ss << "; ";
    }

    for (auto *it : desc_->properties) {
        if (it->HasFlag(binder::VariableFlags::READONLY)) {
            ss << "readonly ";
        }
        ss << it->Name();

        if (it->HasFlag(binder::VariableFlags::OPTIONAL)) {
            ss << "?";
        }
        if (it->HasFlag(binder::VariableFlags::PROPERTY)) {
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
    if (desc_->properties.empty() && desc_->call_signatures.empty() && desc_->construct_signatures.empty() &&
        desc_->number_index_info == nullptr && desc_->string_index_info == nullptr) {
        return TypeFacts::EMPTY_OBJECT_FACTS;
    }

    return TypeFacts::OBJECT_FACTS;
}

Type *ObjectLiteralType::Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ObjectDescriptor *copied_desc = allocator->New<ObjectDescriptor>(allocator);
    desc_->Copy(allocator, copied_desc, relation, global_types);
    return allocator->New<ObjectLiteralType>(copied_desc);
}
}  // namespace panda::es2panda::checker
