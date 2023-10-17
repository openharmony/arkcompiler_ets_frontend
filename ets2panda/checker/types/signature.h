/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "binder/variable.h"
#include "compiler/core/compilerContext.h"

namespace panda::es2panda::checker {
// For use in Signature::ToAssemblerType
Type const *MaybeBoxedType(Checker *checker, binder::Variable const *var);

class SignatureInfo {
public:
    explicit SignatureInfo(ArenaAllocator *allocator)
        : type_params {allocator->Adapter()}, params {allocator->Adapter()}
    {
    }

    SignatureInfo(const SignatureInfo *other, ArenaAllocator *allocator)
        : type_params(allocator->Adapter()), params(allocator->Adapter())
    {
        for (auto *it : other->type_params) {
            type_params.push_back(it);
        }
        for (auto *it : other->params) {
            params.push_back(it->Copy(allocator, it->Declaration()));
        }

        min_arg_count = other->min_arg_count;

        if (other->rest_var != nullptr) {
            rest_var = other->rest_var->Copy(allocator, other->rest_var->Declaration());
        }
    }

    ~SignatureInfo() = default;
    NO_COPY_SEMANTIC(SignatureInfo);
    NO_MOVE_SEMANTIC(SignatureInfo);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<Type *> type_params;
    uint32_t min_arg_count {};
    binder::LocalVariable *rest_var {};
    ArenaVector<binder::LocalVariable *> params;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

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

    INTERNAL_PROTECTED = INTERNAL | PROTECTED,
    FUNCTIONAL_INTERFACE_SIGNATURE = VIRTUAL | ABSTRACT | CALL | PUBLIC | TYPE
};

DEFINE_BITOPS(SignatureFlags)

class Signature {
public:
    Signature(SignatureInfo *signature_info, Type *return_type)
        : signature_info_(signature_info), return_type_(return_type)
    {
    }

    Signature(SignatureInfo *signature_info, Type *return_type, util::StringView internal_name)
        : signature_info_(signature_info), return_type_(return_type), internal_name_(internal_name)
    {
    }

    Signature(SignatureInfo *signature_info, Type *return_type, ir::ScriptFunction *func)
        : signature_info_(signature_info), return_type_(return_type), func_(func)
    {
    }

    ~Signature() = default;
    NO_COPY_SEMANTIC(Signature);
    NO_MOVE_SEMANTIC(Signature);

    const SignatureInfo *GetSignatureInfo() const
    {
        return signature_info_;
    }

    SignatureInfo *GetSignatureInfo()
    {
        return signature_info_;
    }

    const ArenaVector<binder::LocalVariable *> &Params() const
    {
        return signature_info_->params;
    }

    ArenaVector<binder::LocalVariable *> &Params()
    {
        return signature_info_->params;
    }

    const Type *ReturnType() const
    {
        return return_type_;
    }

    Type *ReturnType()
    {
        return return_type_;
    }

    uint32_t MinArgCount() const
    {
        return signature_info_->min_arg_count;
    }

    uint32_t OptionalArgCount() const
    {
        return signature_info_->params.size() - signature_info_->min_arg_count;
    }

    void SetReturnType(Type *type)
    {
        return_type_ = type;
    }

    void SetOwner(ETSObjectType *owner)
    {
        owner_obj_ = owner;
    }

    void SetOwnerVar(binder::Variable *owner)
    {
        owner_var_ = owner;
    }

    void SetFunction(ir::ScriptFunction *const function) noexcept
    {
        func_ = function;
    }

    ir::ScriptFunction *Function()
    {
        return func_;
    }

    ETSObjectType *Owner()
    {
        return owner_obj_;
    }

    binder::Variable *OwnerVar()
    {
        return owner_var_;
    }

    const ir::ScriptFunction *Function() const
    {
        return func_;
    }

    const binder::LocalVariable *RestVar() const
    {
        return signature_info_->rest_var;
    }

    uint8_t ProtectionFlag() const
    {
        if ((flags_ & SignatureFlags::PRIVATE) != 0) {
            return 2;
        }

        if ((flags_ & SignatureFlags::PROTECTED) != 0) {
            return 1;
        }

        return 0;
    }

    void AddSignatureFlag(SignatureFlags const flag) noexcept
    {
        flags_ |= flag;
    }

    void RemoveSignatureFlag(SignatureFlags const flag) noexcept
    {
        flags_ &= ~flag;
    }

    bool HasSignatureFlag(SignatureFlags const flag) const noexcept
    {
        return (flags_ & flag) != 0U;
    }

    bool IsFinal() const noexcept
    {
        return HasSignatureFlag(SignatureFlags::FINAL);
    }

    void ToAssemblerType(compiler::CompilerContext *context, std::stringstream &ss) const
    {
        ss << compiler::Signatures::MANGLE_BEGIN;

        for (const auto *param : signature_info_->params) {
            MaybeBoxedType(context->Checker(), param)->ToAssemblerTypeWithRank(ss);
            ss << compiler::Signatures::MANGLE_SEPARATOR;
        }

        return_type_->ToAssemblerTypeWithRank(ss);
        ss << compiler::Signatures::MANGLE_SEPARATOR;
    }

    util::StringView InternalName() const;

    Signature *Copy(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types);
    Signature *Substitute(TypeRelation *relation, const Substitution *substitution);

    void ToString(std::stringstream &ss, const binder::Variable *variable, bool print_as_method = false) const;
    void Identical(TypeRelation *relation, Signature *other);
    bool CheckFunctionalInterfaces(TypeRelation *relation, Type *source, Type *target);
    void AssignmentTarget(TypeRelation *relation, Signature *source);

private:
    checker::SignatureInfo *signature_info_;
    Type *return_type_;
    ir::ScriptFunction *func_ {};
    SignatureFlags flags_ {SignatureFlags::NO_OPTS};
    util::StringView internal_name_ {};
    ETSObjectType *owner_obj_ {};
    binder::Variable *owner_var_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_SIGNATURE_H */
