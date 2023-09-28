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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_TUPLE_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_TUPLE_TYPE_H

#include "macros.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/elementFlags.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/objectType.h"

namespace panda::es2panda::checker {
using NamedTupleMemberPool = ArenaUnorderedMap<binder::LocalVariable *, util::StringView>;

class TupleType : public ObjectType {
public:
    explicit TupleType(ArenaAllocator *allocator)
        : ObjectType(ObjectTypeKind::TUPLE), element_flags_(allocator->Adapter()), named_members_(allocator->Adapter())
    {
    }

    TupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&element_flags, ElementFlags combined_flags,
              uint32_t min_length, uint32_t fixed_length, bool readonly, NamedTupleMemberPool &&named_members)
        : ObjectType(ObjectType::ObjectTypeKind::TUPLE, desc),
          element_flags_(std::move(element_flags)),
          combined_flags_(combined_flags),
          min_length_(min_length),
          fixed_length_(fixed_length),
          named_members_(std::move(named_members)),
          readonly_(readonly)
    {
        if (readonly_) {
            for (auto *it : Properties()) {
                it->AddFlag(binder::VariableFlags::READONLY);
            }
        }
    }

    ElementFlags CombinedFlags() const
    {
        return combined_flags_;
    }

    uint32_t MinLength() const
    {
        return min_length_;
    }

    uint32_t FixedLength() const
    {
        return fixed_length_;
    }

    bool HasCombinedFlag(ElementFlags combined_flag) const
    {
        return (combined_flags_ & combined_flag) != 0;
    }

    bool IsReadOnly() const
    {
        return readonly_;
    }

    const NamedTupleMemberPool &NamedMembers() const
    {
        return named_members_;
    }

    const util::StringView &FindNamedMemberName(binder::LocalVariable *member) const
    {
        auto res = named_members_.find(member);
        return res->second;
    }

    Type *ConvertToArrayType(TSChecker *checker);

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    TypeFacts GetTypeFacts() const override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

private:
    ArenaVector<ElementFlags> element_flags_;
    ElementFlags combined_flags_ {};
    uint32_t min_length_ {};
    uint32_t fixed_length_ {};
    NamedTupleMemberPool named_members_;
    bool readonly_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_TUPLE_TYPE_H */
