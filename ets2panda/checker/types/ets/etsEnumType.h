/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

namespace panda::es2panda::binder {
class LocalVariable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
template <typename T>
struct ETSEnumValueType {
    using ValueType = T;
};

class ETSEnumInterface : public Type {
public:
    using UType = std::int32_t;

    explicit ETSEnumInterface(const ir::TSEnumDeclaration *enum_decl, UType ordinal, const ir::TSEnumMember *member,
                              TypeFlag type_flag);

    NO_COPY_SEMANTIC(ETSEnumInterface);
    NO_MOVE_SEMANTIC(ETSEnumInterface);

    ETSEnumInterface() = delete;
    ~ETSEnumInterface() override = default;

    [[nodiscard]] bool AssignmentSource(TypeRelation *relation, Type *target) override;

    void AssignmentTarget(TypeRelation *relation, Type *source) override;

    void Cast(TypeRelation *relation, Type *target) override;

    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

    void Identical(TypeRelation *relation, Type *other) override;

    void ToAssemblerType(std::stringstream &ss) const override;
    void ToDebugInfoType(std::stringstream &ss) const override;

    void ToString(std::stringstream &ss) const override;

    [[nodiscard]] const ir::TSEnumDeclaration *GetDecl() const noexcept;

    [[nodiscard]] const ArenaVector<ir::AstNode *> &GetMembers() const noexcept;

    [[nodiscard]] binder::LocalVariable *GetMemberVar() const noexcept;

    [[nodiscard]] util::StringView GetName() const noexcept;

    [[nodiscard]] UType GetOrdinal() const noexcept;

    [[nodiscard]] ETSEnumInterface *LookupConstant(ETSChecker *checker, const ir::Expression *expression,
                                                   const ir::Identifier *prop) const;

    [[nodiscard]] ETSFunctionType *LookupMethod(ETSChecker *checker, const ir::Expression *expression,
                                                const ir::Identifier *prop) const;

    [[nodiscard]] bool IsLiteralType() const noexcept;

    [[nodiscard]] bool IsSameEnumType(const ETSEnumInterface *other) const noexcept;

    [[nodiscard]] bool IsSameEnumLiteralType(const ETSEnumInterface *other) const noexcept;

    [[nodiscard]] bool IsEnumInstanceExpression(const ir::Expression *expression) const noexcept;

    [[nodiscard]] bool IsEnumLiteralExpression(const ir::Expression *expression) const noexcept;

    [[nodiscard]] bool IsEnumTypeExpression(const ir::Expression *expression) const noexcept;

    static constexpr std::string_view const TO_STRING_METHOD_NAME {"toString"};
    static constexpr std::string_view const GET_VALUE_METHOD_NAME {"getValue"};
    static constexpr std::string_view const GET_NAME_METHOD_NAME {"getName"};
    static constexpr std::string_view const VALUE_OF_METHOD_NAME {"valueOf"};
    static constexpr std::string_view const VALUES_METHOD_NAME {"values"};
    static constexpr std::string_view const FROM_INT_METHOD_NAME {"fromInt"};

    struct Method {
        Signature *global_signature;
        ETSFunctionType *member_proxy_type;
    };

    [[nodiscard]] Method ToStringMethod() const noexcept;
    void SetToStringMethod(Method const &method) noexcept
    {
        to_string_method_ = method;
    }

    [[nodiscard]] Method GetValueMethod() const noexcept;
    void SetGetValueMethod(Method const &method) noexcept
    {
        get_value_method_ = method;
    }

    [[nodiscard]] Method GetNameMethod() const noexcept;
    void SetGetNameMethod(Method const &method) noexcept
    {
        get_name_method_ = method;
    }

    [[nodiscard]] Method ValueOfMethod() const noexcept;
    void SetValueOfMethod(Method const &method) noexcept
    {
        value_of_method_ = method;
    }

    [[nodiscard]] Method ValuesMethod() const noexcept;
    void SetValuesMethod(Method const &method) noexcept
    {
        values_method_ = method;
    }

    [[nodiscard]] Method FromIntMethod() const noexcept;
    void SetFromIntMethod(Method const &method) noexcept
    {
        from_int_method_ = method;
    }

private:
    const ir::TSEnumDeclaration *decl_;
    const UType ordinal_;
    const ir::TSEnumMember *member_;

    Method to_string_method_ {};
    Method get_value_method_ {};
    Method get_name_method_ {};
    Method value_of_method_ {};
    Method values_method_ {};
    Method from_int_method_ {};

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

class ETSEnumType : public ETSEnumInterface, public ETSEnumValueType<std::int32_t> {
public:
    explicit ETSEnumType(const ir::TSEnumDeclaration *enum_decl, UType ordinal,
                         const ir::TSEnumMember *member = nullptr)
        : ETSEnumInterface(enum_decl, ordinal, member, TypeFlag::ETS_ENUM)
    {
    }

    NO_COPY_SEMANTIC(ETSEnumType);
    NO_MOVE_SEMANTIC(ETSEnumType);

    ETSEnumType() = delete;
    ~ETSEnumType() override = default;
};

class ETSStringEnumType : public ETSEnumInterface, public ETSEnumValueType<std::string> {
public:
    explicit ETSStringEnumType(const ir::TSEnumDeclaration *enum_decl, UType ordinal,
                               const ir::TSEnumMember *member = nullptr)
        : ETSEnumInterface(enum_decl, ordinal, member, TypeFlag::ETS_STRING_ENUM)
    {
    }

    NO_COPY_SEMANTIC(ETSStringEnumType);
    NO_MOVE_SEMANTIC(ETSStringEnumType);

    ETSStringEnumType() = delete;
    ~ETSStringEnumType() override = default;
};
}  // namespace panda::es2panda::checker

#endif
