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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_OBJECT_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_OBJECT_TYPE_H

#include "plugins/ecmascript/es2panda/checker/types/type.h"

#include "plugins/ecmascript/es2panda/checker/types/ts/objectDescriptor.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"
#include "plugins/ecmascript/es2panda/util/enumbitops.h"

namespace panda::es2panda::checker {
class Signature;
class IndexInfo;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_OBJECT_TYPENAMES(objectKind, typeName) class typeName;
OBJECT_TYPE_MAPPING(DECLARE_OBJECT_TYPENAMES)
#undef DECLARE_OBJECT_TYPENAMES

enum class ObjectFlags : uint32_t {
    NO_OPTS = 0U,
    CHECK_EXCESS_PROPS = 1U << 0U,
    RESOLVED_MEMBERS = 1U << 1U,
    RESOLVED_BASE_TYPES = 1U << 2U,
    RESOLVED_DECLARED_MEMBERS = 1U << 3U,
};

DEFINE_BITOPS(ObjectFlags)

class ObjectType : public Type {
public:
    enum class ObjectTypeKind {
        LITERAL,
        CLASS,
        INTERFACE,
        TUPLE,
        FUNCTION,
    };

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define OBJECT_TYPE_IS_CHECKS(object_kind, type_name) \
    bool Is##type_name() const                        \
    {                                                 \
        return kind_ == object_kind;                  \
    }
    OBJECT_TYPE_MAPPING(OBJECT_TYPE_IS_CHECKS)
#undef OBJECT_TYPE_IS_CHECKS

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define OBJECT_TYPE_AS_CASTS(objectKind, typeName)       \
    typeName *As##typeName()                             \
    {                                                    \
        ASSERT(Is##typeName());                          \
        return reinterpret_cast<typeName *>(this);       \
    }                                                    \
    const typeName *As##typeName() const                 \
    {                                                    \
        ASSERT(Is##typeName());                          \
        return reinterpret_cast<const typeName *>(this); \
    }
    OBJECT_TYPE_MAPPING(OBJECT_TYPE_AS_CASTS)
#undef OBJECT_TYPE_AS_CASTS

    explicit ObjectType(ObjectType::ObjectTypeKind kind)
        : Type(TypeFlag::OBJECT), kind_(kind), obj_flag_(ObjectFlags::NO_OPTS)
    {
    }

    ObjectType(ObjectType::ObjectTypeKind kind, ObjectDescriptor *desc)
        : Type(TypeFlag::OBJECT), kind_(kind), desc_(desc), obj_flag_(ObjectFlags::NO_OPTS)
    {
    }

    ObjectType::ObjectTypeKind Kind() const
    {
        return kind_;
    }

    virtual ArenaVector<Signature *> CallSignatures()
    {
        return desc_->call_signatures;
    }

    virtual ArenaVector<Signature *> ConstructSignatures()
    {
        return desc_->construct_signatures;
    }

    virtual const IndexInfo *StringIndexInfo() const
    {
        return desc_->string_index_info;
    }

    virtual const IndexInfo *NumberIndexInfo() const
    {
        return desc_->number_index_info;
    }

    virtual IndexInfo *StringIndexInfo()
    {
        return desc_->string_index_info;
    }

    virtual IndexInfo *NumberIndexInfo()
    {
        return desc_->number_index_info;
    }

    virtual ArenaVector<binder::LocalVariable *> Properties()
    {
        return desc_->properties;
    }

    ObjectDescriptor *Desc()
    {
        return desc_;
    }

    const ObjectDescriptor *Desc() const
    {
        return desc_;
    }

    void AddProperty(binder::LocalVariable *prop)
    {
        desc_->properties.push_back(prop);
    }

    virtual binder::LocalVariable *GetProperty(const util::StringView &name, [[maybe_unused]] bool search_in_base) const
    {
        for (auto *it : desc_->properties) {
            if (name == it->Name()) {
                return it;
            }
        }

        return nullptr;
    }

    void AddCallSignature(Signature *signature)
    {
        desc_->call_signatures.push_back(signature);
    }

    void AddConstructSignature(Signature *signature)
    {
        desc_->construct_signatures.push_back(signature);
    }

    void AddObjectFlag(ObjectFlags flag)
    {
        obj_flag_ |= flag;
    }

    void RemoveObjectFlag(ObjectFlags flag)
    {
        flag &= ~flag;
    }

    bool HasObjectFlag(ObjectFlags flag) const
    {
        return (obj_flag_ & flag) != 0;
    }

    static bool SignatureRelatedToSomeSignature(TypeRelation *relation, Signature *source_signature,
                                                ArenaVector<Signature *> *target_signatures);

    static bool EachSignatureRelatedToSomeSignature(TypeRelation *relation,
                                                    const ArenaVector<Signature *> &source_signatures,
                                                    const ArenaVector<Signature *> &target_signatures);

    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;

    void CheckExcessProperties(TypeRelation *relation, ObjectType *source);
    void AssignProperties(TypeRelation *relation, ObjectType *source);
    void AssignSignatures(TypeRelation *relation, ObjectType *source, bool assign_call_signatures = true);
    void AssignIndexInfo(TypeRelation *relation, ObjectType *source, bool assign_number_info = true);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ObjectTypeKind kind_;
    ObjectDescriptor *desc_ {};
    ObjectFlags obj_flag_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_OBJECT_TYPE_H */
