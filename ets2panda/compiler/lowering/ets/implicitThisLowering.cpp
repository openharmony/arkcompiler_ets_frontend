/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "implicitThisLowering.h"
#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

static ir::AstNode *HandleImplicitThisLowering(public_lib::Context *ctx, ir::ArrowFunctionExpression *lambda)
{
    auto *checker = ctx->checker->AsETSChecker();

    lambda->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [checker](ir::AstNode *ast) -> AstNodePtr {
            // Handling implicit this calls in lambda with receiver body.
            // implicit this Identifier -> MemberExpression (this.id)
            if (!ast->IsIdentifier() || !ast->AsIdentifier()->IsImplicitThis()) {
                return ast;
            }

            auto *ident = ast->AsIdentifier();
            if (ident->TsType() != nullptr && ident->TsType()->IsTypeError()) {
                return ast;
            }

            auto thisid = checker->Allocator()->New<ir::Identifier>(varbinder::TypedBinder::MANDATORY_PARAM_THIS,
                                                                    checker->Allocator());
            auto mem =
                checker->AllocNode<ir::MemberExpression>(thisid, ident->Clone(checker->Allocator(), nullptr),
                                                         ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            mem->SetParent(ast->Parent());
            return mem;
        },
        "ImplicitThisLoweringPhase");

    Recheck(checker->VarBinder()->AsETSBinder(), checker, lambda);
    return lambda;
}

bool ImplicitThisLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [ctx](ir::AstNode *ast) -> AstNodePtr {
            if (ast->IsArrowFunctionExpression() && ast->AsArrowFunctionExpression()->Function()->IsExtensionMethod()) {
                return HandleImplicitThisLowering(ctx, ast->AsArrowFunctionExpression());
            }
            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
