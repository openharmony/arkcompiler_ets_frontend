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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_TUPLE_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_TUPLE_TYPE_H

#include "util/es2pandaMacros.h"

#include "varbinder/variable.h"
#include "checker/types/ts/elementFlags.h"
#include "checker/types/ts/objectType.h"

namespace ark::es2panda::checker {
using NamedTupleMemberPool = ArenaUnorderedMap<varbinder::LocalVariable *, util::StringView>;

class TupleType : public ObjectType {
public:
    explicit TupleType(ArenaAllocator *allocator)
        : ObjectType(ObjectTypeKind::TUPLE), elementFlags_(allocator->Adapter()), namedMembers_(allocator->Adapter())
    {
    }

    TupleType(
        std::tuple<ObjectDescriptor *, ArenaVector<ElementFlags> &&, ElementFlags, NamedTupleMemberPool &&> contents,
        uint32_t minLength, uint32_t fixedLength, bool readonly)
        : ObjectType(ObjectType::ObjectTypeKind::TUPLE, std::get<ObjectDescriptor *>(contents)),
          elementFlags_(std::move(std::get<ArenaVector<ElementFlags> &&>(contents))),
          combinedFlags_(std::get<ElementFlags>(contents)),
          minLength_(minLength),
          fixedLength_(fixedLength),
          namedMembers_(std::move(std::get<NamedTupleMemberPool &&>(contents))),
          readonly_(readonly)
    {
        if (readonly_) {
            for (auto *it : Properties()) {
                it->AddFlag(varbinder::VariableFlags::READONLY);
            }
        }
    }

    ElementFlags CombinedFlags() const
    {
        return combinedFlags_;
    }

    uint32_t MinLength() const
    {
        return minLength_;
    }

    uint32_t FixedLength() const
    {
        return fixedLength_;
    }

    bool HasCombinedFlag(ElementFlags combinedFlag) const
    {
        return (combinedFlags_ & combinedFlag) != 0;
    }

    bool IsReadOnly() const
    {
        return readonly_;
    }

    const NamedTupleMemberPool &NamedMembers() const
    {
        return namedMembers_;
    }

    const util::StringView &FindNamedMemberName(varbinder::LocalVariable *member) const
    {
        auto res = namedMembers_.find(member);
        return res->second;
    }

    Type *ConvertToArrayType(TSChecker *checker);

    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    TypeFacts GetTypeFacts() const override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;

private:
    ArenaVector<ElementFlags> elementFlags_;
    ElementFlags combinedFlags_ {};
    uint32_t minLength_ {};
    uint32_t fixedLength_ {};
    NamedTupleMemberPool namedMembers_;
    bool readonly_ {};
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_TUPLE_TYPE_H */
