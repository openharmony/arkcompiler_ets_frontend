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

#include "objectDescriptor.h"

#include "binder/variable.h"
#include "checker/types/ts/indexInfo.h"
#include "checker/types/signature.h"

namespace panda::es2panda::checker {
binder::LocalVariable *ObjectDescriptor::FindProperty(const util::StringView &name) const
{
    for (auto *it : properties) {
        if (it->Name() == name) {
            return it;
        }
    }

    return nullptr;
}

void ObjectDescriptor::Copy(ArenaAllocator *allocator, ObjectDescriptor *copied_desc, TypeRelation *relation,
                            GlobalTypesHolder *global_types)
{
    // copy by hand
    for (auto *it : properties) {
        auto *copied_prop = it->Copy(allocator, it->Declaration());
        copied_prop->SetTsType(it->TsType()->Instantiate(allocator, relation, global_types));
        copied_desc->properties.push_back(copied_prop);
    }

    for (auto *it : call_signatures) {
        copied_desc->call_signatures.push_back(it->Copy(allocator, relation, global_types));
    }

    for (auto *it : construct_signatures) {
        copied_desc->construct_signatures.push_back(it->Copy(allocator, relation, global_types));
    }

    if (number_index_info != nullptr) {
        copied_desc->number_index_info = number_index_info->Copy(allocator, relation, global_types);
    }

    if (string_index_info != nullptr) {
        copied_desc->string_index_info = string_index_info->Copy(allocator, relation, global_types);
    }
}
}  // namespace panda::es2panda::checker
