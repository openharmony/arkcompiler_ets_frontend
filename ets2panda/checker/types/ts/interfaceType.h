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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_INTERFACE_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_INTERFACE_TYPE_H

#include "objectType.h"

namespace panda::es2panda::checker {
class InterfaceType : public ObjectType {
public:
    InterfaceType(ArenaAllocator *allocator, util::StringView name, ObjectDescriptor *desc)
        : ObjectType(ObjectType::ObjectTypeKind::INTERFACE, desc),
          name_(name),
          bases_(allocator->Adapter()),
          allocator_(allocator)
    {
    }

    void AddBase(ObjectType *base)
    {
        bases_.push_back(base);
    }

    ArenaVector<ObjectType *> &Bases()
    {
        return bases_;
    }

    const util::StringView &Name() const
    {
        return name_;
    }

    void SetMergedTypeParams(std::pair<std::vector<binder::Variable *>, size_t> &&merged_type_params)
    {
        merged_type_params_ = std::move(merged_type_params);
    }

    const std::pair<std::vector<binder::Variable *>, size_t> &GetMergedTypeParams() const
    {
        return merged_type_params_;
    }

    void SetTypeParamTypes(std::vector<Type *> &&type_param_types)
    {
        type_param_types_ = std::move(type_param_types);
    }

    const std::vector<Type *> &GetTypeParamTypes() const
    {
        return type_param_types_;
    }

    binder::LocalVariable *GetProperty(const util::StringView &name,
                                       [[maybe_unused]] bool search_in_base) const override
    {
        binder::LocalVariable *result_prop = ObjectType::GetProperty(name, false);

        if (result_prop != nullptr) {
            return result_prop;
        }

        if (!search_in_base) {
            return nullptr;
        }

        for (auto *base : bases_) {
            result_prop = base->GetProperty(name, true);
            if (result_prop != nullptr) {
                return result_prop;
            }
        }

        return nullptr;
    }

    ArenaVector<Signature *> CallSignatures() override
    {
        ArenaVector<Signature *> signatures(allocator_->Adapter());
        CollectSignatures(&signatures, true);
        return signatures;
    }

    ArenaVector<Signature *> ConstructSignatures() override
    {
        ArenaVector<Signature *> signatures(allocator_->Adapter());
        CollectSignatures(&signatures, false);
        return signatures;
    }

    const IndexInfo *StringIndexInfo() const override
    {
        return FindIndexInfo(false);
    }

    const IndexInfo *NumberIndexInfo() const override
    {
        return FindIndexInfo(true);
    }

    IndexInfo *StringIndexInfo() override
    {
        return FindIndexInfo(false);
    }

    IndexInfo *NumberIndexInfo() override
    {
        return FindIndexInfo(true);
    }

    ArenaVector<binder::LocalVariable *> Properties() override
    {
        ArenaVector<binder::LocalVariable *> properties(allocator_->Adapter());
        CollectProperties(&properties);
        return properties;
    }

    void ToString(std::stringstream &ss) const override;
    TypeFacts GetTypeFacts() const override;
    void Identical(TypeRelation *relation, Type *other) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;

    void CollectSignatures(ArenaVector<Signature *> *collected_signatures, bool collect_call_signatures) const;
    void CollectProperties(ArenaVector<binder::LocalVariable *> *collected_properties) const;
    const IndexInfo *FindIndexInfo(bool find_number_info) const;
    IndexInfo *FindIndexInfo(bool find_number_info);

private:
    util::StringView name_;
    ArenaVector<ObjectType *> bases_;
    ArenaAllocator *allocator_;
    std::pair<std::vector<binder::Variable *>, size_t> merged_type_params_ {};
    std::vector<Type *> type_param_types_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_INTERFACE_TYPE_H */
