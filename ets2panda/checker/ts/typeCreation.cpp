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

#include "checker/TSchecker.h"
#include "checker/types/ts/indexInfo.h"

namespace ark::es2panda::checker {
Type *TSChecker::CreateNumberLiteralType(double value)
{
    auto search = numberLiteralMap_.find(value);
    if (search != numberLiteralMap_.end()) {
        return search->second;
    }

    auto *newNumLiteralType = Allocator()->New<NumberLiteralType>(value);
    numberLiteralMap_.insert({value, newNumLiteralType});
    return newNumLiteralType;
}

Type *TSChecker::CreateBigintLiteralType(const util::StringView &str, bool negative)
{
    auto search = bigintLiteralMap_.find(str);
    if (search != bigintLiteralMap_.end()) {
        return search->second;
    }

    auto *newBigintLiteralType = Allocator()->New<BigintLiteralType>(str, negative);
    bigintLiteralMap_.insert({str, newBigintLiteralType});
    return newBigintLiteralType;
}

Type *TSChecker::CreateStringLiteralType(const util::StringView &str)
{
    auto search = stringLiteralMap_.find(str);
    if (search != stringLiteralMap_.end()) {
        return search->second;
    }

    auto *newStrLiteralType = Allocator()->New<StringLiteralType>(str);
    stringLiteralMap_.insert({str, newStrLiteralType});
    return newStrLiteralType;
}

Type *TSChecker::CreateUnionType(std::initializer_list<Type *> constituentTypes)
{
    ArenaVector<Type *> newConstituentTypes(Allocator()->Adapter());

    for (auto *it : constituentTypes) {
        newConstituentTypes.push_back(it);
    }

    return CreateUnionType(std::move(newConstituentTypes));
}

Type *TSChecker::CreateUnionType(ArenaVector<Type *> &constituentTypes)
{
    ArenaVector<Type *> newConstituentTypes(Allocator()->Adapter());

    for (auto *it : constituentTypes) {
        if (it->IsUnionType()) {
            for (auto *type : it->AsUnionType()->ConstituentTypes()) {
                newConstituentTypes.push_back(type);
            }

            continue;
        }

        newConstituentTypes.push_back(it);
    }

    UnionType::RemoveDuplicatedTypes(Relation(), newConstituentTypes);

    if (newConstituentTypes.size() == 1) {
        return newConstituentTypes[0];
    }

    auto *newUnionType = Allocator()->New<UnionType>(Allocator(), newConstituentTypes);

    return UnionType::HandleUnionType(newUnionType, GetGlobalTypesHolder());
}

Type *TSChecker::CreateUnionType(ArenaVector<Type *> &&constituentTypes)
{
    if (constituentTypes.empty()) {
        return nullptr;
    }

    ArenaVector<Type *> newConstituentTypes(Allocator()->Adapter());

    for (auto *it : constituentTypes) {
        if (it->IsUnionType()) {
            for (auto *type : it->AsUnionType()->ConstituentTypes()) {
                newConstituentTypes.push_back(type);
            }

            continue;
        }

        newConstituentTypes.push_back(it);
    }

    UnionType::RemoveDuplicatedTypes(Relation(), newConstituentTypes);

    if (newConstituentTypes.size() == 1) {
        return newConstituentTypes[0];
    }

    auto *newUnionType = Allocator()->New<UnionType>(Allocator(), std::move(newConstituentTypes));

    return UnionType::HandleUnionType(newUnionType, GetGlobalTypesHolder());
}

Type *TSChecker::CreateObjectTypeWithCallSignature(Signature *callSignature)
{
    auto *objType = Allocator()->New<ObjectLiteralType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    objType->AddCallSignature(callSignature);
    return objType;
}

Type *TSChecker::CreateObjectTypeWithConstructSignature(Signature *constructSignature)
{
    auto *objType = Allocator()->New<ObjectLiteralType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    objType->AddConstructSignature(constructSignature);
    return objType;
}

Type *TSChecker::CreateFunctionTypeWithSignature(Signature *callSignature)
{
    auto *funcObjType = Allocator()->New<FunctionType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    funcObjType->AddCallSignature(callSignature);
    return funcObjType;
}

Type *TSChecker::CreateConstructorTypeWithSignature(Signature *constructSignature)
{
    auto *constructObjType = Allocator()->New<ConstructorType>(Allocator()->New<ObjectDescriptor>(Allocator()));
    constructObjType->AddConstructSignature(constructSignature);
    return constructObjType;
}

Type *TSChecker::CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&elementFlags,
                                 ElementFlags combinedFlags, uint32_t minLength, uint32_t fixedLength, bool readonly)
{
    desc->stringIndexInfo = Allocator()->New<IndexInfo>(GlobalAnyType(), "x", readonly);
    checker::NamedTupleMemberPool namedMembers(Allocator()->Adapter());
    return Allocator()->New<TupleType>(desc, std::move(elementFlags), combinedFlags, minLength, fixedLength, readonly,
                                       std::move(namedMembers));
}

Type *TSChecker::CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&elementFlags,
                                 ElementFlags combinedFlags, uint32_t minLength, uint32_t fixedLength, bool readonly,
                                 NamedTupleMemberPool &&namedMembers)
{
    desc->stringIndexInfo = Allocator()->New<IndexInfo>(GlobalAnyType(), "x", readonly);

    return Allocator()->New<TupleType>(desc, std::move(elementFlags), combinedFlags, minLength, fixedLength, readonly,
                                       std::move(namedMembers));
}
}  // namespace ark::es2panda::checker
