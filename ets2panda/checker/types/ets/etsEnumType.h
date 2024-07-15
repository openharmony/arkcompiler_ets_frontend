/*
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ENUM_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_ENUM_TYPE_H

#include "checker/types/type.h"
#include "ir/base/property.h"
#include "ir/ts/tsEnumDeclaration.h"

template <typename>
// NOLINTNEXTLINE(readability-identifier-naming)
inline constexpr bool dependent_false_v = false;

namespace ark::es2panda::varbinder {
class LocalVariable;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::checker {
template <typename T>
struct ETSEnumValueType {
    using ValueType = T;
};

class ETSEnumType : public Type {
public:
    using UType = std::int32_t;

    explicit ETSEnumType(const ir::TSEnumDeclaration *enumDecl, UType ordinal, const ir::TSEnumMember *member,
                         TypeFlag typeFlag);

    NO_COPY_SEMANTIC(ETSEnumType);
    NO_MOVE_SEMANTIC(ETSEnumType);

    ETSEnumType() = delete;
    ~ETSEnumType() override = default;

    [[nodiscard]] bool AssignmentSource(TypeRelation *relation, Type *target) override;

    void AssignmentTarget(TypeRelation *relation, Type *source) override;

    void Cast(TypeRelation *relation, Type *target) override;

    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;

    void Identical(TypeRelation *relation, Type *other) override;

    void ToAssemblerType(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;

    void ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const override;

    [[nodiscard]] const ir::TSEnumDeclaration *GetDecl() const noexcept;

    [[nodiscard]] const ArenaVector<ir::AstNode *> &GetMembers() const noexcept;

    [[nodiscard]] varbinder::LocalVariable *GetMemberVar() const noexcept;

    [[nodiscard]] util::StringView GetName() const noexcept;

    [[nodiscard]] UType GetOrdinal() const noexcept;

    [[nodiscard]] ETSEnumType *LookupConstant(ETSChecker *checker, const ir::Expression *expression,
                                              const ir::Identifier *prop) const;

    [[nodiscard]] ETSFunctionType *LookupMethod(ETSChecker *checker, const ir::Expression *expression,
                                                const ir::Identifier *prop) const;

    [[nodiscard]] bool IsLiteralType() const noexcept;

    [[nodiscard]] bool IsSameEnumType(const ETSEnumType *const other) const noexcept;

    [[nodiscard]] bool IsSameEnumLiteralType(const ETSEnumType *const other) const noexcept;

    [[nodiscard]] bool IsEnumInstanceExpression(const ir::Expression *expression) const noexcept;

    [[nodiscard]] bool IsEnumLiteralExpression(const ir::Expression *expression) const noexcept;

    [[nodiscard]] bool IsEnumTypeExpression(const ir::Expression *expression) const noexcept;

    static constexpr std::string_view const TO_STRING_METHOD_NAME {"toString"};
    static constexpr std::string_view const VALUE_OF_METHOD_NAME {"valueOf"};
    static constexpr std::string_view const GET_NAME_METHOD_NAME {"getName"};
    static constexpr std::string_view const GET_VALUE_OF_METHOD_NAME {"getValueOf"};
    static constexpr std::string_view const VALUES_METHOD_NAME {"values"};
    static constexpr std::string_view const FROM_INT_METHOD_NAME {"fromInt"};
    static constexpr std::string_view const BOXED_FROM_INT_METHOD_NAME {"boxedfromInt"};
    static constexpr std::string_view const UNBOX_METHOD_NAME {"unbox"};

    struct Method {
        Signature *globalSignature;
        ETSFunctionType *memberProxyType;
    };

    [[nodiscard]] Method ToStringMethod() const noexcept;
    void SetToStringMethod(Method const &method) noexcept
    {
        toStringMethod_ = method;
    }

    [[nodiscard]] Method ValueOfMethod() const noexcept;
    void SetValueOfMethod(Method const &method) noexcept
    {
        valueOfMethod_ = method;
    }

    [[nodiscard]] Method GetNameMethod() const noexcept;
    void SetGetNameMethod(Method const &method) noexcept
    {
        getNameMethod_ = method;
    }

    [[nodiscard]] Method GetValueOfMethod() const noexcept;
    void SetGetValueOfMethod(Method const &method) noexcept
    {
        getValueOfMethod_ = method;
    }

    [[nodiscard]] Method ValuesMethod() const noexcept;
    void SetValuesMethod(Method const &method) noexcept
    {
        valuesMethod_ = method;
    }

    [[nodiscard]] Method FromIntMethod() const noexcept;
    void SetFromIntMethod(Method const &method) noexcept
    {
        fromIntMethod_ = method;
    }

    [[nodiscard]] Method BoxedFromIntMethod() const noexcept;
    void SetBoxedFromIntMethod(Method const &method) noexcept
    {
        boxedFromIntMethod_ = method;
    }

    [[nodiscard]] Method UnboxMethod() const noexcept;
    void SetUnboxMethod(Method const &method) noexcept
    {
        unboxMethod_ = method;
    }

    std::tuple<bool, bool> ResolveConditionExpr() const override
    {
        return {false, false};  // NOTE (psiket) It should be true, int value != 0 | string value !empty()
    }

private:
    const ir::TSEnumDeclaration *decl_;
    const UType ordinal_;
    const ir::TSEnumMember *member_;

    Method toStringMethod_ {};
    Method valueOfMethod_ {};
    Method getNameMethod_ {};
    Method getValueOfMethod_ {};
    Method valuesMethod_ {};
    Method fromIntMethod_ {};
    Method boxedFromIntMethod_ {};
    Method unboxMethod_ {};

    [[nodiscard]] ir::TSEnumMember *FindMember(const util::StringView &name) const noexcept;

    [[nodiscard]] ETSFunctionType *LookupConstantMethod(ETSChecker *checker, const ir::Identifier *prop) const;

    [[nodiscard]] ETSFunctionType *LookupTypeMethod(ETSChecker *checker, const ir::Identifier *prop) const;

    template <typename T>
    void ToAssemblerTypeImpl(std::stringstream &ss) const noexcept
    {
        if constexpr (std::is_same_v<T, int64_t>) {
            ss << compiler::Signatures::PRIMITIVE_LONG;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            ss << compiler::Signatures::PRIMITIVE_INT;
        } else {
            static_assert(dependent_false_v<T>, "Invalid underlying type for enumeration.");
        }
    }

    template <typename T>
    void ToDebugInfoTypeImpl(std::stringstream &ss) const noexcept
    {
        if constexpr (std::is_same_v<T, int64_t>) {
            ss << compiler::Signatures::TYPE_DESCRIPTOR_LONG;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            ss << compiler::Signatures::TYPE_DESCRIPTOR_INT;
        } else {
            static_assert(dependent_false_v<T>, "Invalid underlying type for enumeration.");
        }
    }
};

class ETSIntEnumType : public ETSEnumType, public ETSEnumValueType<std::int32_t> {
public:
    explicit ETSIntEnumType(const ir::TSEnumDeclaration *enumDecl, UType ordinal,
                            const ir::TSEnumMember *member = nullptr)
        : ETSEnumType(enumDecl, ordinal, member, TypeFlag::ETS_INT_ENUM)
    {
    }

    NO_COPY_SEMANTIC(ETSIntEnumType);
    NO_MOVE_SEMANTIC(ETSIntEnumType);

    ETSIntEnumType() = delete;
    ~ETSIntEnumType() override = default;
};

class ETSStringEnumType : public ETSEnumType, public ETSEnumValueType<std::string> {
public:
    explicit ETSStringEnumType(const ir::TSEnumDeclaration *enumDecl, UType ordinal,
                               const ir::TSEnumMember *member = nullptr)
        : ETSEnumType(enumDecl, ordinal, member, TypeFlag::ETS_STRING_ENUM)
    {
    }

    NO_COPY_SEMANTIC(ETSStringEnumType);
    NO_MOVE_SEMANTIC(ETSStringEnumType);

    ETSStringEnumType() = delete;
    ~ETSStringEnumType() override = default;
};
}  // namespace ark::es2panda::checker

#endif
