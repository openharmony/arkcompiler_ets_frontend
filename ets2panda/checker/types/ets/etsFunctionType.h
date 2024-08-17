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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H

#include "checker/types/type.h"
#include "checker/types/signature.h"
#include "ir/base/scriptFunction.h"

namespace ark::es2panda::checker {

class ETSFunctionType : public Type {
public:
    explicit ETSFunctionType(ETSChecker *checker, util::StringView name, ArenaVector<Signature *> &&signatures);

    explicit ETSFunctionType(util::StringView name, Signature *signature, ArenaAllocator *allocator)
        : Type(TypeFlag::FUNCTION), callSignatures_(allocator->Adapter()), name_(name), funcInterface_(nullptr)
    {
        callSignatures_.push_back(signature);
    }
    explicit ETSFunctionType(util::StringView name, ArenaAllocator *allocator)
        : Type(TypeFlag::FUNCTION), callSignatures_(allocator->Adapter()), name_(name), funcInterface_(nullptr)
    {
    }

    ArenaVector<Signature *> &CallSignatures()
    {
        return callSignatures_;
    }

    const ArenaVector<Signature *> &CallSignatures() const
    {
        return callSignatures_;
    }

    util::StringView Name() const
    {
        return name_;
    }

    Type *FunctionalInterface() const
    {
        return funcInterface_;
    }

    void AddCallSignature(Signature *signature)
    {
        if (signature->Function()->IsGetter()) {
            AddTypeFlag(TypeFlag::GETTER);
        } else if (signature->Function()->IsSetter()) {
            AddTypeFlag(TypeFlag::SETTER);
        }
        callSignatures_.push_back(signature);
    }

    void SetReferencedSignature(Signature *refSignature)
    {
        refSignature_ = refSignature;
    }

    Signature *GetReferencedSignature() const
    {
        return refSignature_;
    }

    Signature *FindSignature(const ir::ScriptFunction *func) const
    {
        for (auto *it : callSignatures_) {
            if (it->Function() == func) {
                return it;
            }
        }

        return nullptr;
    }

    Signature *FindGetter() const
    {
        for (auto *sig : callSignatures_) {
            if (sig->Function()->IsGetter()) {
                return sig;
            }
        }
        return nullptr;
    }

    Signature *FindSetter() const
    {
        for (auto *sig : callSignatures_) {
            if (sig->Function()->IsSetter()) {
                return sig;
            }
        }
        return nullptr;
    }

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        funcInterface_->ToAssemblerType(ss);
    }

    void ToDebugInfoType([[maybe_unused]] std::stringstream &ss) const override
    {
        UNREACHABLE();
    }

    Signature *FirstAbstractSignature();
    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    ETSFunctionType *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    void Cast(TypeRelation *relation, Type *target) override;
    checker::RelationResult CastFunctionParams(TypeRelation *relation, Signature *targetInvokeSig);
    ETSFunctionType *BoxPrimitives(ETSChecker *checker);

private:
    ArenaVector<Signature *> callSignatures_;
    util::StringView name_;
    Signature *refSignature_ {};
    Type *const funcInterface_;
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
