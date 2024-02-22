/**
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

#include "typeNode.h"
#include "astNode.h"
#include "opaqueTypeNode.h"
#include "es2panda.h"

namespace ark::es2panda::ir {

TypeNode *TypeNode::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const type = TsType(); type != nullptr) {
        if (auto *const clone = allocator->New<OpaqueTypeNode>(type); clone != nullptr) {
            if (parent != nullptr) {
                clone->SetParent(parent);
            }
            return clone;
        }
        throw Error(ErrorType::GENERIC, "", "Unsuccessful allocation during cloning.");
    }

    return this;
}

}  // namespace ark::es2panda::ir
