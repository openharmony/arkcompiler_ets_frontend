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

#include "TypedBinder.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsConstructorType.h"
#include "ir/ets/etsFunctionType.h"

namespace panda::es2panda::binder {

void TypedBinder::BuildSignatureDeclarationBaseParams(ir::AstNode *type_node)
{
    if (type_node == nullptr) {
        return;
    }

    Scope *scope = nullptr;

    switch (type_node->Type()) {
        case ir::AstNodeType::ETS_FUNCTION_TYPE: {
            scope = type_node->AsETSFunctionType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_FUNCTION_TYPE: {
            scope = type_node->AsTSFunctionType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE: {
            scope = type_node->AsTSConstructorType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_SIGNATURE_DECLARATION: {
            scope = type_node->AsTSSignatureDeclaration()->Scope();
            break;
        }
        case ir::AstNodeType::TS_METHOD_SIGNATURE: {
            scope = type_node->AsTSMethodSignature()->Scope();
            break;
        }
        default: {
            ResolveReference(type_node);
            return;
        }
    }

    ASSERT(scope && scope->IsFunctionParamScope());

    auto scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, scope->AsFunctionParamScope(), false);
    ResolveReferences(type_node);
}

void TypedBinder::HandleCustomNodes(ir::AstNode *child_node)
{
    switch (child_node->Type()) {
        case ir::AstNodeType::TS_FUNCTION_TYPE:
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE:
        case ir::AstNodeType::TS_METHOD_SIGNATURE:
        case ir::AstNodeType::TS_SIGNATURE_DECLARATION: {
            BuildSignatureDeclarationBaseParams(child_node);
            break;
        }
        default: {
            ResolveReferences(child_node);
            break;
        }
    }
}
}  // namespace panda::es2panda::binder
