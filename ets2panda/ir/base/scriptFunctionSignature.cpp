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

#include "ir/base/scriptFunctionSignature.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/typeNode.h"

namespace ark::es2panda::ir {

void FunctionSignature::Iterate(const NodeTraverser &cb) const
{
    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    for (auto *it : Params()) {
        cb(it);
    }

    if (returnTypeAnnotation_ != nullptr) {
        cb(returnTypeAnnotation_);
    }
}

void FunctionSignature::TransformChildren(const NodeTransformer &cb)
{
    if (typeParams_ != nullptr) {
        typeParams_ = cb(typeParams_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    if (returnTypeAnnotation_ != nullptr) {
        returnTypeAnnotation_ = static_cast<TypeNode *>(cb(returnTypeAnnotation_));
    }
}
}  // namespace ark::es2panda::ir
