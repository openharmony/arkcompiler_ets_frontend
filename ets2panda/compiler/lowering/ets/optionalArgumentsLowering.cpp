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

#include "optionalArgumentsLowering.h"
#include "compiler/lowering/util.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::compiler {

static void TransformArguments(public_lib::Context *ctx, ir::Expression *callLike, checker::Signature *signature,
                               ArenaVector<ir::Expression *> &arguments)
{
    if (signature->ArgCount() < arguments.size()) {
        ES2PANDA_ASSERT(signature->HasRestParameter());
        return;
    }
    ES2PANDA_ASSERT(signature->ArgCount() >= signature->MinArgCount());
    if (arguments.size() < signature->MinArgCount()) {  // #22952: workaround for dynamic types
        auto callee = callLike->IsCallExpression() ? callLike->AsCallExpression()->Callee()
                                                   : callLike->AsETSNewClassInstanceExpression()->GetTypeRef();
        if (callee->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG)) {
            return;
        }
    }
    ES2PANDA_ASSERT(arguments.size() >= signature->MinArgCount());

    auto const checker = ctx->checker->AsETSChecker();
    auto const allocator = ctx->allocator;

    size_t missing = signature->ArgCount() - arguments.size();
    for (size_t i = 0; i < missing; ++i) {
        auto undefArg = allocator->New<ir::UndefinedLiteral>();
        undefArg->SetTsType(checker->GlobalETSUndefinedType());
        arguments.push_back(undefArg);
        undefArg->SetParent(callLike);
    }
}

bool OptionalArgumentsLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    program->Ast()->TransformChildrenRecursivelyPreorder(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [ctx](ir::AstNode *const node) -> ir::AstNode * {
            if (node->IsCallExpression()) {
                auto callExpr = node->AsCallExpression();
                TransformArguments(ctx, callExpr, callExpr->Signature(), callExpr->Arguments());
            } else if (node->IsETSNewClassInstanceExpression()) {
                auto newExpr = node->AsETSNewClassInstanceExpression();
                TransformArguments(ctx, newExpr, newExpr->GetSignature(), newExpr->GetArguments());
            }
            return node;
        },
        Name());

    return true;
}

bool OptionalArgumentsLowering::PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                                       parser::Program const *program)
{
    return !program->Ast()->IsAnyChild([](ir::AstNode const *node) {
        if (!node->IsScriptFunction()) {
            return false;
        }
        for (auto p : node->AsScriptFunction()->Params()) {
            if (p->AsETSParameterExpression()->Initializer() != nullptr) {
                return true;
            }
        }
        return false;
    });
}

}  // namespace ark::es2panda::compiler
