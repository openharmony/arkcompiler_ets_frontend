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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_OBJECT_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_OBJECT_TYPE_H

#include "checker/types/type.h"

#include "checker/types/ts/objectDescriptor.h"
#include "varbinder/variable.h"
#include "util/ustring.h"
#include "util/enumbitops.h"

namespace ark::es2panda::checker {
class Signature;
class IndexInfo;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_OBJECT_TYPENAMES(objectKind, typeName) class typeName;
OBJECT_TYPE_MAPPING(DECLARE_OBJECT_TYPENAMES)
#undef DECLARE_OBJECT_TYPENAMES

using ENUMBITOPS_OPERATORS;

enum class ObjectFlags : uint32_t {
    NO_OPTS = 0U,
    CHECK_EXCESS_PROPS = 1U << 0U,
    RESOLVED_MEMBERS = 1U << 1U,
    RESOLVED_BASE_TYPES = 1U << 2U,
    RESOLVED_DECLARED_MEMBERS = 1U << 3U,
};

}  // namespace ark::es2panda::checker

template <>
struct enumbitops::IsAllowedType<ark::es2panda::checker::ObjectFlags> : std::true_type {
};

namespace ark::es2panda::checker {

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
        return kind_ == (object_kind);                \
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
        : Type(TypeFlag::OBJECT), kind_(kind), objFlag_(ObjectFlags::NO_OPTS)
    {
    }

    ObjectType(ObjectType::ObjectTypeKind kind, ObjectDescriptor *desc)
        : Type(TypeFlag::OBJECT), kind_(kind), desc_(desc), objFlag_(ObjectFlags::NO_OPTS)
    {
    }

    ObjectType::ObjectTypeKind Kind() const
    {
        return kind_;
    }

    virtual ArenaVector<Signature *> CallSignatures()
    {
        return desc_->callSignatures;
    }

    virtual ArenaVector<Signature *> ConstructSignatures()
    {
        return desc_->constructSignatures;
    }

    virtual const IndexInfo *StringIndexInfo() const
    {
        return desc_->stringIndexInfo;
    }

    virtual const IndexInfo *NumberIndexInfo() const
    {
        return desc_->numberIndexInfo;
    }

    virtual IndexInfo *StringIndexInfo()
    {
        return desc_->stringIndexInfo;
    }

    virtual IndexInfo *NumberIndexInfo()
    {
        return desc_->numberIndexInfo;
    }

    virtual ArenaVector<varbinder::LocalVariable *> Properties()
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

    void AddProperty(varbinder::LocalVariable *prop)
    {
        desc_->properties.push_back(prop);
    }

    virtual varbinder::LocalVariable *GetProperty(const util::StringView &name,
                                                  [[maybe_unused]] bool searchInBase) const
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
        desc_->callSignatures.push_back(signature);
    }

    void AddConstructSignature(Signature *signature)
    {
        desc_->constructSignatures.push_back(signature);
    }

    void AddObjectFlag(ObjectFlags flag)
    {
        objFlag_ |= flag;
    }

    void RemoveObjectFlag(ObjectFlags flag)
    {
        flag &= ~flag;
    }

    bool HasObjectFlag(ObjectFlags flag) const
    {
        return (objFlag_ & flag) != 0;
    }

    static bool SignatureRelatedToSomeSignature(TypeRelation *relation, Signature *sourceSignature,
                                                ArenaVector<Signature *> *targetSignatures);

    static bool EachSignatureRelatedToSomeSignature(TypeRelation *relation,
                                                    const ArenaVector<Signature *> &sourceSignatures,
                                                    const ArenaVector<Signature *> &targetSignatures);

    bool FindPropertyAndCheckIdentical(TypeRelation *relation, ObjectType *otherObj);
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;

    void CheckExcessProperties(TypeRelation *relation, ObjectType *source);
    void AssignProperties(TypeRelation *relation, ObjectType *source);
    void AssignSignatures(TypeRelation *relation, ObjectType *source, bool assignCallSignatures = true);
    void AssignIndexInfo(TypeRelation *relation, ObjectType *source, bool assignNumberInfo = true);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ObjectTypeKind kind_;
    ObjectDescriptor *desc_ {};
    ObjectFlags objFlag_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_OBJECT_TYPE_H */
