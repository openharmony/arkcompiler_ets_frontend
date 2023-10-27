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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TYPE_H

#include "generated/signatures.h"
#include "checker/types/typeMapping.h"
#include "checker/types/typeRelation.h"
#include "checker/types/typeFacts.h"

#include "macros.h"
#include <sstream>
#include <variant>

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
class ObjectDescriptor;
class GlobalTypesHolder;
class ETSDynamicType;
class ETSAsyncFuncReturnType;
class ETSChecker;
class ETSDynamicFunctionType;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_TYPENAMES(typeFlag, typeName) class typeName;
TYPE_MAPPING(DECLARE_TYPENAMES)
#undef DECLARE_TYPENAMES
class ETSStringType;

using Substitution = ArenaMap<Type *, Type *>;

class Type {
public:
    explicit Type(TypeFlag flag) : type_flags_(flag)
    {
        static uint64_t type_id = 0;
        id_ = ++type_id;
    }

    NO_COPY_SEMANTIC(Type);
    NO_MOVE_SEMANTIC(Type);

    virtual ~Type() = default;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_IS_CHECKS(typeFlag, typeName) \
    bool Is##typeName() const              \
    {                                      \
        return HasTypeFlag(typeFlag);      \
    }
    TYPE_MAPPING(TYPE_IS_CHECKS)
#undef DECLARE_IS_CHECKS

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_AS_CASTS(typeFlag, typeName)                \
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
    TYPE_MAPPING(TYPE_AS_CASTS)
#undef TYPE_AS_CASTS

    bool IsETSStringType() const;
    bool IsETSNullType() const;
    bool IsETSAsyncFuncReturnType() const;
    bool IsNullableType() const;

    ETSStringType *AsETSStringType()
    {
        ASSERT(IsETSObjectType());
        return reinterpret_cast<ETSStringType *>(this);
    }

    const ETSStringType *AsETSStringType() const
    {
        ASSERT(IsETSObjectType());
        return reinterpret_cast<const ETSStringType *>(this);
    }

    bool IsETSDynamicType() const
    {
        return IsETSObjectType() && HasTypeFlag(TypeFlag::ETS_DYNAMIC_FLAG);
    }

    ETSDynamicType *AsETSDynamicType()
    {
        ASSERT(IsETSDynamicType());
        return reinterpret_cast<ETSDynamicType *>(this);
    }

    const ETSDynamicType *AsETSDynamicType() const
    {
        ASSERT(IsETSDynamicType());
        return reinterpret_cast<const ETSDynamicType *>(this);
    }

    ETSAsyncFuncReturnType *AsETSAsyncFuncReturnType()
    {
        ASSERT(IsETSAsyncFuncReturnType());
        return reinterpret_cast<ETSAsyncFuncReturnType *>(this);
    }

    const ETSAsyncFuncReturnType *AsETSAsyncFuncReturnType() const
    {
        ASSERT(IsETSAsyncFuncReturnType());
        return reinterpret_cast<const ETSAsyncFuncReturnType *>(this);
    }

    bool IsETSDynamicFunctionType() const
    {
        return TypeFlags() == TypeFlag::ETS_DYNAMIC_FUNCTION_TYPE;
    }

    ETSDynamicFunctionType *AsETSDynamicFunctionType()
    {
        ASSERT(IsETSDynamicFunctionType());
        return reinterpret_cast<ETSDynamicFunctionType *>(this);
    }

    const ETSDynamicFunctionType *AsETSDynamicFunctionType() const
    {
        ASSERT(IsETSDynamicFunctionType());
        return reinterpret_cast<const ETSDynamicFunctionType *>(this);
    }

    bool IsConditionalExprType() const
    {
        return HasTypeFlag(TypeFlag::CONDITION_EXPRESSION_TYPE);
    }

    bool IsConstantType() const
    {
        return HasTypeFlag(checker::TypeFlag::CONSTANT);
    }

    TypeFlag TypeFlags() const
    {
        return type_flags_;
    }

    bool HasTypeFlag(TypeFlag type_flag) const
    {
        return (type_flags_ & type_flag) != 0;
    }

    void AddTypeFlag(TypeFlag type_flag)
    {
        type_flags_ |= type_flag;
    }

    void RemoveTypeFlag(TypeFlag type_flag)
    {
        type_flags_ &= ~type_flag;
    }

    uint64_t Id() const
    {
        return id_;
    }

    void SetVariable(binder::Variable *variable)
    {
        variable_ = variable;
    }

    binder::Variable *Variable()
    {
        return variable_;
    }

    const binder::Variable *Variable() const
    {
        return variable_;
    }

    util::StringView ToAssemblerTypeView(ArenaAllocator *allocator) const
    {
        std::stringstream ss;
        ToAssemblerType(ss);
        return util::UString(ss.str(), allocator).View();
    }

    bool IsLambdaObject() const;
    virtual void ToString(std::stringstream &ss) const = 0;
    virtual void ToStringAsSrc(std::stringstream &ss) const;
    virtual TypeFacts GetTypeFacts() const;
    virtual void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const {};
    virtual void ToDebugInfoType([[maybe_unused]] std::stringstream &ss) const {};
    virtual void ToAssemblerTypeWithRank([[maybe_unused]] std::stringstream &ss) const
    {
        ToAssemblerType(ss);
    };

    virtual uint32_t Rank() const
    {
        return 0;
    }

    virtual std::tuple<bool, bool> ResolveConditionExpr() const
    {
        UNREACHABLE();
    };

    virtual void Identical(TypeRelation *relation, Type *other);
    virtual void AssignmentTarget(TypeRelation *relation, Type *source) = 0;
    virtual bool AssignmentSource(TypeRelation *relation, Type *target);
    virtual void Compare(TypeRelation *relation, Type *other);
    virtual void Cast(TypeRelation *relation, Type *target);
    virtual void IsSupertypeOf(TypeRelation *relation, Type *source);
    virtual Type *AsSuper(Checker *checker, binder::Variable *source_var);

    virtual Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types);
    virtual Type *Substitute(TypeRelation *relation, const Substitution *substitution);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    TypeFlag type_flags_;
    binder::Variable *variable_ {};  // Variable associated with the type if any
    uint64_t id_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_TYPE_H */
