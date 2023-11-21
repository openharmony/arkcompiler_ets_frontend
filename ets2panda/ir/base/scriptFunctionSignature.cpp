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

namespace panda::es2panda::ir {

void FunctionSignature::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : Params()) {
        cb(it);
    }

    if (return_type_annotation_ != nullptr) {
        cb(return_type_annotation_);
    }
}

void FunctionSignature::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    if (return_type_annotation_ != nullptr) {
        return_type_annotation_ = static_cast<TypeNode *>(cb(return_type_annotation_));
    }
}
}  // namespace panda::es2panda::ir
