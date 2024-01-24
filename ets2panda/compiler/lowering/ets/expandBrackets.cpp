/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "expandBrackets.h"

#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/statements/blockStatement.h"
#include "ir/expressions/memberExpression.h"
#include "parser/ETSparser.h"
#include "varbinder/ETSBinder.h"

namespace panda::es2panda::compiler {

bool ExpandBracketsPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    auto *const checker = ctx->checker->AsETSChecker();
    auto *const allocator = checker->Allocator();
    auto *const parser = ctx->parser->AsETSParser();

    program->Ast()->TransformChildrenRecursively([ctx, parser, checker, allocator](ir::AstNode *ast) -> ir::AstNode * {
        if (!ast->IsETSNewArrayInstanceExpression()) {
            return ast;
        }
        auto *newExpression = ast->AsETSNewArrayInstanceExpression();
        auto *dimension = newExpression->Dimension();
        auto *dimType = dimension->TsType();
        if (auto *unboxed = checker->ETSBuiltinTypeAsPrimitiveType(dimType); unboxed != nullptr) {
            dimType = unboxed;
        }
        if (!dimType->HasTypeFlag(checker::TypeFlag::ETS_FLOATING_POINT)) {
            return ast;
        }

        auto *castedDimension =
            parser->CreateFormattedExpression("@@E1 as int", parser::DEFAULT_SOURCE_FILE, dimension);
        castedDimension->Check(checker);
        castedDimension->SetParent(dimension->Parent());
        newExpression->SetDimension(castedDimension);

        auto *const scope = NearestScope(newExpression);
        auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
        auto *ident = Gensym(allocator);
        auto *exprType = checker->AllocNode<ir::OpaqueTypeNode>(dimType);
        auto *sequenceExpr = parser->CreateFormattedExpression(
            "let @@I1 = (@@E2) as @@T3;"
            "if (!isSafeInteger(@@I4)) {"
            "  throw new TypeError(\"Index fractional part should not be different from 0.0\");"
            "};"
            "(@@E5);",
            parser::DEFAULT_SOURCE_FILE, ident, dimension, exprType, ident->Clone(allocator), newExpression);
        sequenceExpr->SetParent(newExpression->Parent());
        InitScopesPhaseETS::RunExternalNode(sequenceExpr, ctx->compilerContext->VarBinder());
        checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(sequenceExpr, scope);
        sequenceExpr->Check(checker);

        return sequenceExpr;
    });
    return true;
}

}  // namespace panda::es2panda::compiler
