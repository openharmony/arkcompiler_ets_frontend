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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_SIGNATURE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_SIGNATURE_H

#include "type.h"
#include "ets/etsObjectType.h"

#include "varbinder/variable.h"

namespace ark::es2panda::public_lib {
struct Context;
}  // namespace ark::es2panda::public_lib

namespace ark::es2panda::checker {

class SignatureInfo final {
public:
    explicit SignatureInfo(ArenaAllocator *allocator) : typeParams {allocator->Adapter()}, params {allocator->Adapter()}
    {
    }

    SignatureInfo(const SignatureInfo *other, ArenaAllocator *allocator)
        : typeParams(allocator->Adapter()), params(allocator->Adapter())
    {
        for (auto *it : other->typeParams) {
            typeParams.push_back(it);
        }
        for (auto *it : other->params) {
            params.push_back(it->Copy(allocator, it->Declaration()));
            params.back()->SetTsType(it->TsType());
        }

        minArgCount = other->minArgCount;

        if (other->restVar != nullptr) {
            restVar = other->restVar->Copy(allocator, other->restVar->Declaration());
            restVar->SetTsType(other->restVar->TsType());
        }
    }

    SignatureInfo() = delete;
    ~SignatureInfo() = default;
    NO_COPY_SEMANTIC(SignatureInfo);
    NO_MOVE_SEMANTIC(SignatureInfo);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<Type *> typeParams;
    uint32_t minArgCount {};
    varbinder::LocalVariable *restVar {};
    ArenaVector<varbinder::LocalVariable *> params;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

using ENUMBITOPS_OPERATORS;

enum class SignatureFlags : uint32_t {
    NO_OPTS = 0U,
    VIRTUAL = 1U << 0U,
    ABSTRACT = 1U << 1U,
    CALL = 1U << 2U,
    CONSTRUCT = 1U << 3U,
    PUBLIC = 1U << 4U,
    PROTECTED = 1U << 5U,
    PRIVATE = 1U << 6U,
    STATIC = 1U << 7U,
    FINAL = 1U << 8U,
    CONSTRUCTOR = 1U << 9U,
    TYPE = 1U << 10U,
    PROXY = 1U << 11U,
    INTERNAL = 1U << 12U,
    NEED_RETURN_TYPE = 1U << 13U,
    INFERRED_RETURN_TYPE = 1U << 14U,
    THIS_RETURN_TYPE = 1U << 15U,
    GETTER = 1U << 16U,
    SETTER = 1U << 17U,
    THROWS = 1U << 18U,
    RETHROWS = 1U << 19U,
    EXTENSION_FUNCTION_RETURN_THIS = 1U << 20U,

    INTERNAL_PROTECTED = INTERNAL | PROTECTED,
    GETTER_OR_SETTER = GETTER | SETTER,
    THROWING = THROWS | RETHROWS,
    FUNCTIONAL_INTERFACE_SIGNATURE = VIRTUAL | ABSTRACT | CALL | PUBLIC | TYPE
};

}  // namespace ark::es2panda::checker

template <>
struct enumbitops::IsAllowedType<ark::es2panda::checker::SignatureFlags> : std::true_type {
};

namespace ark::es2panda::checker {

class Signature final {
public:
    Signature(SignatureInfo *signatureInfo, Type *returnType) : signatureInfo_(signatureInfo), returnType_(returnType)
    {
    }

    Signature(SignatureInfo *signatureInfo, Type *returnType, util::StringView internalName)
        : signatureInfo_(signatureInfo), returnType_(returnType), internalName_(internalName)
    {
    }

    Signature(SignatureInfo *signatureInfo, Type *returnType, ir::ScriptFunction *func)
        : signatureInfo_(signatureInfo), returnType_(returnType), func_(func)
    {
    }

    Signature() = delete;
    ~Signature() = default;
    NO_COPY_SEMANTIC(Signature);
    NO_MOVE_SEMANTIC(Signature);

    [[nodiscard]] const SignatureInfo *GetSignatureInfo() const noexcept
    {
        return signatureInfo_;
    }

    [[nodiscard]] SignatureInfo *GetSignatureInfo() noexcept
    {
        return signatureInfo_;
    }

    [[nodiscard]] const ArenaVector<Type *> &TypeParams() const noexcept
    {
        return signatureInfo_->typeParams;
    }

    [[nodiscard]] ArenaVector<Type *> &TypeParams() noexcept
    {
        return signatureInfo_->typeParams;
    }

    [[nodiscard]] const ArenaVector<varbinder::LocalVariable *> &Params() const noexcept
    {
        return signatureInfo_->params;
    }

    [[nodiscard]] ArenaVector<varbinder::LocalVariable *> &Params() noexcept
    {
        return signatureInfo_->params;
    }

    [[nodiscard]] const Type *ReturnType() const noexcept
    {
        return returnType_;
    }

    [[nodiscard]] Type *ReturnType() noexcept
    {
        return returnType_;
    }

    [[nodiscard]] uint32_t MinArgCount() const noexcept
    {
        return signatureInfo_->minArgCount;
    }

    void MinArgCount(uint32_t count) noexcept
    {
        signatureInfo_->minArgCount = count;
    }

    [[nodiscard]] uint32_t OptionalArgCount() const noexcept
    {
        return signatureInfo_->params.size() - signatureInfo_->minArgCount;
    }

    void SetReturnType(Type *type) noexcept
    {
        returnType_ = type;
    }

    void SetOwner(ETSObjectType *owner) noexcept
    {
        ownerObj_ = owner;
    }

    void SetOwnerVar(varbinder::Variable *owner) noexcept
    {
        ownerVar_ = owner;
    }

    void SetFunction(ir::ScriptFunction *const function) noexcept
    {
        func_ = function;
    }

    [[nodiscard]] ir::ScriptFunction *Function() noexcept
    {
        return func_;
    }

    [[nodiscard]] ETSObjectType *Owner() noexcept
    {
        return ownerObj_;
    }

    [[nodiscard]] const ETSObjectType *Owner() const noexcept
    {
        return ownerObj_;
    }

    [[nodiscard]] varbinder::Variable *OwnerVar() noexcept
    {
        return ownerVar_;
    }

    [[nodiscard]] const ir::ScriptFunction *Function() const noexcept
    {
        return func_;
    }

    [[nodiscard]] const varbinder::LocalVariable *RestVar() const noexcept
    {
        return signatureInfo_->restVar;
    }

    [[nodiscard]] uint8_t ProtectionFlag() const noexcept
    {
        if ((flags_ & SignatureFlags::PRIVATE) != 0) {
            return 2U;
        }

        if ((flags_ & SignatureFlags::PROTECTED) != 0) {
            return 1U;
        }

        return 0;
    }

    [[nodiscard]] SignatureFlags Flags() const noexcept
    {
        return flags_;
    }

    void AddSignatureFlag(SignatureFlags const flag) noexcept
    {
        flags_ |= flag;
    }

    void RemoveSignatureFlag(SignatureFlags const flag) noexcept
    {
        flags_ &= ~flag;
    }

    [[nodiscard]] bool HasSignatureFlag(SignatureFlags const flag) const noexcept
    {
        return (flags_ & flag) != 0U;
    }

    [[nodiscard]] bool HasRestParameter() const noexcept
    {
        return signatureInfo_->restVar != nullptr;
    }

    [[nodiscard]] bool IsFinal() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::FINAL);
    }

    [[nodiscard]] bool IsTypeAnnotation() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::TYPE);
    }

    [[nodiscard]] bool Throws() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::THROWS);
    }

    [[nodiscard]] bool Rethrows() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::RETHROWS);
    }

    [[nodiscard]] bool Throwing() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::THROWING);
    }

    void ToAssemblerType(std::stringstream &ss) const;

    [[nodiscard]] util::StringView InternalName() const;

    [[nodiscard]] Signature *Copy(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes);
    [[nodiscard]] Signature *Substitute(TypeRelation *relation, const Substitution *substitution);
    [[nodiscard]] Signature *Clone(ETSChecker *checker);

    void ToString(std::stringstream &ss, const varbinder::Variable *variable, bool printAsMethod = false,
                  bool precise = false) const;
    [[nodiscard]] std::string ToString() const;

    void Compatible(TypeRelation *relation, Signature *other);
    void AssignmentTarget(TypeRelation *relation, Signature *source);
    [[nodiscard]] Signature *BoxPrimitives(ETSChecker *checker);
    friend class ETSExtensionFuncHelperType;

private:
    [[nodiscard]] bool CheckGeneralData(TypeRelation *relation, Signature *other) const noexcept;
    [[nodiscard]] bool CheckParameter(TypeRelation *relation, Type const *type1, Type const *type2) const noexcept;
    [[nodiscard]] bool CheckReturnType(TypeRelation *relation, Type const *other) const noexcept;

    checker::SignatureInfo *signatureInfo_;
    Type *returnType_;
    ir::ScriptFunction *func_ {};
    SignatureFlags flags_ {SignatureFlags::NO_OPTS};
    util::StringView internalName_ {};
    ETSObjectType *ownerObj_ {};
    varbinder::Variable *ownerVar_ {};
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_SIGNATURE_H */
