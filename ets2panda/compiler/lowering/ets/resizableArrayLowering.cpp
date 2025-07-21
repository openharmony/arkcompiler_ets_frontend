/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "resizableArrayLowering.h"
#include <utility>
#include "compiler/lowering/util.h"
#include "ir/ets/etsUnionType.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

static ir::AstNode *ConvertToResizableArrayType(ir::TSArrayType *node, public_lib::Context *ctx)
{
    auto *parser = ctx->parser->AsETSParser();
    ir::TypeNode *typeAnnotation =
        parser->CreateFormattedTypeAnnotation("Array<" + node->ElementType()->DumpEtsSrc() + ">");
    ES2PANDA_ASSERT(typeAnnotation != nullptr);
    typeAnnotation->SetAnnotations(std::move(node->Annotations()));
    typeAnnotation->SetParent(node->Parent());
    typeAnnotation->SetRange(node->Range());
    RefineSourceRanges(node);
    typeAnnotation->AddModifier(node->Modifiers());
    return typeAnnotation;
}

bool ResizableArrayConvert::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    program->Ast()->TransformChildrenRecursivelyPreorder(
        [ctx](ir::AstNode *node) -> AstNodePtr {
            if (node->IsTSArrayType()) {
                return ConvertToResizableArrayType(node->AsTSArrayType(), ctx);
            }
            return node;
        },
        Name());

    return true;
}
}  // namespace ark::es2panda::compiler
