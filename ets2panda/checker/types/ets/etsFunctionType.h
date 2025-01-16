/*
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H

#include "checker/types/type.h"
#include "checker/types/signature.h"
#include "ir/base/scriptFunction.h"

namespace ark::es2panda::checker {

class ETSFunctionType : public Type {
public:
    explicit ETSFunctionType(ETSChecker *checker, util::StringView const &name, ArenaVector<Signature *> &&signatures);
    explicit ETSFunctionType(ETSChecker *checker, util::StringView const &name, Signature *signature);
    explicit ETSFunctionType(util::StringView const &name, ArenaAllocator *allocator);
    explicit ETSFunctionType(ETSChecker *checker, util::StringView const &name, Signature *signature,
                             ETSObjectType *interface);

    ETSFunctionType() = delete;
    ~ETSFunctionType() override = default;
    NO_COPY_SEMANTIC(ETSFunctionType);
    NO_MOVE_SEMANTIC(ETSFunctionType);

    [[nodiscard]] Signature *CallSignature() const
    {
        ASSERT(!callSignatures_.empty());
        return callSignatures_[0U];
    }

    [[nodiscard]] ArenaVector<Signature *> &CallSignatures() noexcept
    {
        return callSignatures_;
    }

    [[nodiscard]] const ArenaVector<Signature *> &CallSignatures() const noexcept
    {
        return callSignatures_;
    }

    [[nodiscard]] util::StringView const &Name() const noexcept
    {
        return name_;
    }

    [[nodiscard]] bool HasFunctionalInterface() const noexcept
    {
        return funcInterface_ != nullptr;
    }

    [[nodiscard]] Type *FunctionalInterface() const noexcept
    {
        ASSERT(HasFunctionalInterface());
        return funcInterface_;
    }

    void AddCallSignature(Signature *signature);

    template <class UnaryPredicate>
    Signature *FindSpecificSignature(UnaryPredicate predicate) const noexcept
    {
        auto const it = std::find_if(callSignatures_.cbegin(), callSignatures_.cend(), predicate);
        return it != callSignatures_.cend() ? *it : nullptr;
    }

    [[nodiscard]] Signature *FindSignature(const ir::ScriptFunction *func) const noexcept
    {
        return FindSpecificSignature([func](auto const *const sig) -> bool { return sig->Function() == func; });
    }

    [[nodiscard]] Signature *FindGetter() const noexcept
    {
        return FindSpecificSignature([](auto const *const sig) -> bool { return sig->Function()->IsGetter(); });
    }

    [[nodiscard]] Signature *FindSetter() const noexcept
    {
        return FindSpecificSignature([](auto const *const sig) -> bool { return sig->Function()->IsSetter(); });
    }

    [[nodiscard]] Signature *FirstAbstractSignature() const noexcept
    {
        return FindSpecificSignature(
            [](auto const *const sig) -> bool { return sig->HasSignatureFlag(SignatureFlags::ABSTRACT); });
    }

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        funcInterface_->ToAssemblerType(ss);
    }

    void ToDebugInfoType([[maybe_unused]] std::stringstream &ss) const override
    {
        UNREACHABLE();
    }

    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void CastTarget(TypeRelation *relation, Type *source) override;

    ETSFunctionType *Instantiate(ArenaAllocator *allocator, TypeRelation *relation,
                                 GlobalTypesHolder *globalTypes) override;
    ETSFunctionType *Substitute(TypeRelation *relation, const Substitution *substitution) override;

    checker::RelationResult CastFunctionParams(TypeRelation *relation, Signature *targetInvokeSig) const noexcept;
    ETSFunctionType *BoxPrimitives(ETSChecker *checker) const;

private:
    ArenaVector<Signature *> callSignatures_;
    util::StringView name_;
    Type *const funcInterface_;
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
