/*
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

#include "expressionLambdaLowering.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::compiler {
static ir::AstNode *ConvertExpression(checker::ETSChecker *const checker, ir::ArrowFunctionExpression *const arrow)
{
    auto *const function = arrow->Function();
    auto *const scope = function->Scope();
    auto *const expr = function->Body()->AsExpression();

    ArenaVector<ir::Statement *> statements(checker->Allocator()->Adapter());

    if ((function->ReturnTypeAnnotation() != nullptr && function->ReturnTypeAnnotation()->IsETSPrimitiveType() &&
         function->ReturnTypeAnnotation()->AsETSPrimitiveType()->GetPrimitiveType() == ir::PrimitiveType::VOID)) {
        statements.emplace_back(checker->AllocNode<ir::ExpressionStatement>(expr));
    } else {
        statements.emplace_back(checker->AllocNode<ir::ReturnStatement>(expr));
        function->AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);
    }

    auto *const block = checker->AllocNode<ir::BlockStatement>(checker->Allocator(), std::move(statements));

    block->SetScope(scope);
    block->SetParent(function);

    function->SetBody(block);

    return arrow;
}

using AstNodePtr = ir::AstNode *;

bool ExpressionLambdaConstructionPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [checker](ir::AstNode *const node) -> AstNodePtr {
            if (node->IsArrowFunctionExpression() &&
                node->AsArrowFunctionExpression()->Function()->Body()->IsExpression()) {
                return ConvertExpression(checker, node->AsArrowFunctionExpression());
            }

            return node;
        },
        Name());

    return true;
}

bool ExpressionLambdaConstructionPhase::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *node) {
        return node->IsArrowFunctionExpression() &&
               node->AsArrowFunctionExpression()->Function()->Body()->IsExpression();
    });
}

}  // namespace ark::es2panda::compiler
