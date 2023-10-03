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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_FUNCTION_TYPE_H

#include "checker/types/type.h"
#include "checker/types/signature.h"

namespace panda::es2panda::checker {

class ETSFunctionType : public Type {
public:
    explicit ETSFunctionType(util::StringView name, Signature *signature, ArenaAllocator *allocator)
        : Type(TypeFlag::FUNCTION), call_signatures_(allocator->Adapter()), name_(name)
    {
        call_signatures_.push_back(signature);
    }

    explicit ETSFunctionType(util::StringView name, ArenaAllocator *allocator)
        : Type(TypeFlag::FUNCTION), call_signatures_(allocator->Adapter()), name_(name)
    {
    }

    ArenaVector<Signature *> &CallSignatures()
    {
        return call_signatures_;
    }

    const ArenaVector<Signature *> &CallSignatures() const
    {
        return call_signatures_;
    }

    util::StringView Name() const
    {
        return name_;
    }

    void AddCallSignature(Signature *signature)
    {
        call_signatures_.push_back(signature);
    }

    void SetReferencedSignature(Signature *ref_signature)
    {
        ref_signature_ = ref_signature;
    }

    Signature *GetReferencedSignature() const
    {
        return ref_signature_;
    }

    Signature *FindSignature(const ir::ScriptFunction *func) const
    {
        for (auto *it : call_signatures_) {
            if (it->Function() == func) {
                return it;
            }
        }

        return nullptr;
    }

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        ss << "ets.lang.Object";
    }

    void ToDebugInfoType(std::stringstream &ss) const override
    {
        ss << "ets.lang.Object";
    }

    Signature *FirstAbstractSignature();
    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;
    ETSFunctionType *Substitute(TypeRelation *relation, const Substitution *substitution) override;

private:
    ArenaVector<Signature *> call_signatures_;
    util::StringView name_;
    Signature *ref_signature_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
