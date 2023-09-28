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

#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/indexInfo.h"

namespace panda::es2panda::checker {
Type *TSChecker::CreateNumberLiteralType(double value)
{
    auto search = number_literal_map_.find(value);
    if (search != number_literal_map_.end()) {
        return search->second;
    }

    auto *new_num_literal_type = Allocator()->New<NumberLiteralType>(value);
    number_literal_map_.insert({value, new_num_literal_type});
    return new_num_literal_type;
}

Type *TSChecker::CreateBigintLiteralType(const util::StringView &str, bool negative)
{
    auto search = bigint_literal_map_.find(str);
    if (search != bigint_literal_map_.end()) {
        return search->second;
    }

    auto *new_bigint_literal_type = Allocator()->New<BigintLiteralType>(str, negative);
    bigint_literal_map_.insert({str, new_bigint_literal_type});
    return new_bigint_literal_type;
}

Type *TSChecker::CreateStringLiteralType(const util::StringView &str)
{
    auto search = string_literal_map_.find(str);
    if (search != string_literal_map_.end()) {
        return search->second;
    }

    auto *new_str_literal_type = Allocator()->New<StringLiteralType>(str);
    string_literal_map_.insert({str, new_str_literal_type});
    return new_str_literal_type;
}

Type *TSChecker::CreateUnionType(std::initializer_list<Type *> constituent_types)
{
    ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

    for (auto *it : constituent_types) {
        new_constituent_types.push_back(it);
    }

    return CreateUnionType(std::move(new_constituent_types));
}

Type *TSChecker::CreateUnionType(ArenaVector<Type *> &constituent_types)
{
    ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

    for (auto *it : constituent_types) {
        if (it->IsUnionType()) {
            for (auto *type : it->AsUnionType()->ConstituentTypes()) {
                new_constituent_types.push_back(type);
            }

            continue;
        }

        new_constituent_types.push_back(it);
    }

    UnionType::RemoveDuplicatedTypes(Relation(), new_constituent_types);

    if (new_constituent_types.size() == 1) {
        return new_constituent_types[0];
    }

    auto *new_union_type = Allocator()->New<UnionType>(Allocator(), new_constituent_types);

    return UnionType::HandleUnionType(new_union_type, GetGlobalTypesHolder());
}

Type *TSChecker::CreateUnionType(ArenaVector<Type *> &&constituent_types)
{
    if (constituent_types.empty()) {
        return nullptr;
    }

    ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

    for (auto *it : constituent_types) {
        if (it->IsUnionType()) {
            for (auto *type : it->AsUnionType()->ConstituentTypes()) {
                new_constituent_types.push_back(type);
            }

            continue;
        }

        new_constituent_types.push_back(it);
    }

    UnionType::RemoveDuplicatedTypes(Relation(), new_constituent_types);

    if (new_constituent_types.size() == 1) {
        return new_constituent_types[0];
    }

    auto *new_union_type = Allocator()->New<UnionType>(Allocator(), std::move(new_constituent_types));

    return UnionType::HandleUnionType(new_union_type, GetGlobalTypesHolder());
}

Type *TSChecker::CreateObjectTypeWithCallSignature(Signature *call_signature)
{
    auto *obj_type = Allocator()->New<ObjectLiteralType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    obj_type->AddCallSignature(call_signature);
    return obj_type;
}

Type *TSChecker::CreateObjectTypeWithConstructSignature(Signature *construct_signature)
{
    auto *obj_type = Allocator()->New<ObjectLiteralType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    obj_type->AddConstructSignature(construct_signature);
    return obj_type;
}

Type *TSChecker::CreateFunctionTypeWithSignature(Signature *call_signature)
{
    auto *func_obj_type = Allocator()->New<FunctionType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    func_obj_type->AddCallSignature(call_signature);
    return func_obj_type;
}

Type *TSChecker::CreateConstructorTypeWithSignature(Signature *construct_signature)
{
    auto *construct_obj_type = Allocator()->New<ConstructorType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    construct_obj_type->AddConstructSignature(construct_signature);
    return construct_obj_type;
}

Type *TSChecker::CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&element_flags,
                                 ElementFlags combined_flags, uint32_t min_length, uint32_t fixed_length, bool readonly)
{
    desc->string_index_info = Allocator()->New<IndexInfo>(GlobalAnyType(), "x", readonly);
    checker::NamedTupleMemberPool named_members(Allocator()->Adapter());
    return Allocator()->New<TupleType>(desc, std::move(element_flags), combined_flags, min_length, fixed_length,
                                       readonly, std::move(named_members));
}

Type *TSChecker::CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&element_flags,
                                 ElementFlags combined_flags, uint32_t min_length, uint32_t fixed_length, bool readonly,
                                 NamedTupleMemberPool &&named_members)
{
    desc->string_index_info = Allocator()->New<IndexInfo>(GlobalAnyType(), "x", readonly);

    return Allocator()->New<TupleType>(desc, std::move(element_flags), combined_flags, min_length, fixed_length,
                                       readonly, std::move(named_members));
}
}  // namespace panda::es2panda::checker
