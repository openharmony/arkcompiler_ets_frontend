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

#include "TypedBinder.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsConstructorType.h"
#include "ir/ets/etsFunctionType.h"

namespace ark::es2panda::varbinder {

void TypedBinder::BuildSignatureDeclarationBaseParams(ir::AstNode *typeNode)
{
    if (typeNode == nullptr) {
        return;
    }

    Scope *scope = nullptr;

    switch (typeNode->Type()) {
        case ir::AstNodeType::ETS_FUNCTION_TYPE: {
            scope = typeNode->AsETSFunctionType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_FUNCTION_TYPE: {
            scope = typeNode->AsTSFunctionType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE: {
            scope = typeNode->AsTSConstructorType()->Scope();
            break;
        }
        case ir::AstNodeType::TS_SIGNATURE_DECLARATION: {
            scope = typeNode->AsTSSignatureDeclaration()->Scope();
            break;
        }
        case ir::AstNodeType::TS_METHOD_SIGNATURE: {
            scope = typeNode->AsTSMethodSignature()->Scope();
            break;
        }
        default: {
            ResolveReference(typeNode);
            return;
        }
    }

    ES2PANDA_ASSERT(scope && scope->IsFunctionParamScope());

    auto scopeCtx = LexicalScope<FunctionParamScope>::Enter(this, scope->AsFunctionParamScope(), false);
    ResolveReferences(typeNode);
}

void TypedBinder::HandleCustomNodes(ir::AstNode *childNode)
{
    switch (childNode->Type()) {
        case ir::AstNodeType::TS_FUNCTION_TYPE:
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE:
        case ir::AstNodeType::TS_METHOD_SIGNATURE:
        case ir::AstNodeType::TS_SIGNATURE_DECLARATION: {
            BuildSignatureDeclarationBaseParams(childNode);
            break;
        }
        default: {
            ResolveReferences(childNode);
            break;
        }
    }
}
}  // namespace ark::es2panda::varbinder
