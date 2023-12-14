/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_SCRIPT_FUNCTION_SIGNATURE_H
#define ES2PANDA_COMPILER_CORE_SCRIPT_FUNCTION_SIGNATURE_H

#include "ir/astNode.h"

namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;
class TypeNode;

class FunctionSignature {
public:
    using FunctionParams = ArenaVector<Expression *>;

    FunctionSignature(TSTypeParameterDeclaration *type_params, FunctionParams &&params,
                      TypeNode *return_type_annotation)
        : type_params_(type_params), params_(std::move(params)), return_type_annotation_(return_type_annotation)
    {
    }

    const FunctionParams &Params() const
    {
        return params_;
    }

    FunctionParams &Params()
    {
        return params_;
    }

    TSTypeParameterDeclaration *TypeParams()
    {
        return type_params_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    TypeNode *ReturnType()
    {
        return return_type_annotation_;
    }

    void SetReturnType(TypeNode *type)
    {
        return_type_annotation_ = type;
    }

    const TypeNode *ReturnType() const
    {
        return return_type_annotation_;
    }

    void Iterate(const NodeTraverser &cb) const;

    void TransformChildren(const NodeTransformer &cb);

private:
    TSTypeParameterDeclaration *type_params_;
    ArenaVector<Expression *> params_;
    TypeNode *return_type_annotation_;
};

}  // namespace panda::es2panda::ir

#endif
