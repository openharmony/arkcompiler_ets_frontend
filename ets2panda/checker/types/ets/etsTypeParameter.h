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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TYPE_PARAMETER_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_TYPE_PARAMETER_TYPE_H

#include "checker/types/type.h"

namespace panda::es2panda::checker {
class ETSTypeParameter : public Type {
public:
    explicit ETSTypeParameter() : Type(TypeFlag::ETS_TYPE_PARAMETER) {}
    explicit ETSTypeParameter(Type *assembler_type)
        : Type(TypeFlag::ETS_TYPE_PARAMETER), assembler_type_(assembler_type)
    {
    }

    void SetType(Type *type)
    {
        type_ = type;
    }

    Type *GetType()
    {
        return type_;
    }

    Type *GetAssemblerType()
    {
        return assembler_type_;
    }

    Type **GetTypeRef()
    {
        return &type_;
    }

    Type **GetAssemblerTypeRef()
    {
        return &assembler_type_;
    }

    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;

private:
    Type *type_ {};
    Type *assembler_type_ {};
};
}  // namespace panda::es2panda::checker

#endif
