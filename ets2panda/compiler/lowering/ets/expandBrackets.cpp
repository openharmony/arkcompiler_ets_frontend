/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

namespace ark::es2panda::compiler {

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const FORMAT_NEW_MULTI_DIM_ARRAY_EXPRESSION[] =
    "let @@I1: @@T2 = (@@E3);"
    "if (!isSafeInteger(@@I4)) {"
    "  throw new TypeError(\"Fractional part of index expression should be zero.\");"
    "};";
static constexpr char const FORMAT_NEW_ARRAY_EXPRESSION[] =
    "let @@I1: @@T2 = (@@E3);"
    "if (!isSafeInteger(@@I4)) {"
    "  throw new TypeError(\"Fractional part of index expression should be zero.\");"
    "};"
    "(@@E5);";
static constexpr char const CAST_NEW_DIMENSION_EXPRESSION[] = "@@I1 as int";
static constexpr char const CAST_OLD_DIMENSION_EXPRESSION[] = "(@@E1) as int";
// NOLINTEND(modernize-avoid-c-arrays)

ir::Expression *ExpandBracketsPhase::ProcessNewArrayInstanceExpression(
    parser::ETSParser *parser, checker::ETSChecker *checker,
    ir::ETSNewArrayInstanceExpression *newInstanceExpression) const
{
    auto *dimension = newInstanceExpression->Dimension();
    auto *dimType = dimension->TsType();
    if (auto *unboxed = checker->MaybeUnboxInRelation(dimType); unboxed != nullptr) {
        dimType = unboxed;
    }
    if (dimType == nullptr || !dimType->HasTypeFlag(checker::TypeFlag::ETS_FLOATING_POINT)) {
        return newInstanceExpression;
    }

    auto *scope = NearestScope(newInstanceExpression);
    if (scope == nullptr) {
        scope = checker->VarBinder()->VarScope() != nullptr ? checker->VarBinder()->VarScope()
                                                            : checker->VarBinder()->TopScope();
    }
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);

    auto const identName = GenName(checker->Allocator());
    auto *exprType = checker->AllocNode<ir::OpaqueTypeNode>(dimType, checker->Allocator());
    auto *const newInstanceParent = newInstanceExpression->Parent();

    auto *blockExpression = parser->CreateFormattedExpression(FORMAT_NEW_ARRAY_EXPRESSION, identName, exprType,
                                                              dimension, identName, newInstanceExpression);
    blockExpression->SetParent(newInstanceParent);

    auto *castedDimension = parser->CreateFormattedExpression(CAST_NEW_DIMENSION_EXPRESSION, identName);
    newInstanceExpression->SetDimension(castedDimension);

    newInstanceExpression->SetTsType(nullptr);
    InitScopesPhaseETS::RunExternalNode(blockExpression, checker->VarBinder());
    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(blockExpression, NearestScope(blockExpression));
    blockExpression->Check(checker);

    return blockExpression;
}

ir::Expression *ExpandBracketsPhase::ProcessNewMultiDimArrayInstanceExpression(
    parser::ETSParser *parser, checker::ETSChecker *checker,
    ir::ETSNewMultiDimArrayInstanceExpression *newInstanceExpression) const
{
    ir::BlockExpression *returnExpression = nullptr;

    auto *scope = NearestScope(newInstanceExpression);
    if (scope == nullptr) {
        scope = checker->VarBinder()->VarScope() != nullptr ? checker->VarBinder()->VarScope()
                                                            : checker->VarBinder()->TopScope();
    }
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);

    for (std::size_t i = 0U; i < newInstanceExpression->Dimensions().size(); ++i) {
        auto *dimension = newInstanceExpression->Dimensions()[i];
        auto *dimType = dimension->TsType();
        if (auto *unboxed = checker->MaybeUnboxInRelation(dimType); unboxed != nullptr) {
            dimType = unboxed;
        }
        if (dimType == nullptr || !dimType->HasTypeFlag(checker::TypeFlag::ETS_FLOATING_POINT)) {
            continue;
        }

        if (dimension->IsNumberLiteral()) {
            auto *castedDimension = parser->CreateFormattedExpression(CAST_OLD_DIMENSION_EXPRESSION, dimension);
            castedDimension->SetParent(newInstanceExpression);
            newInstanceExpression->Dimensions()[i] = castedDimension;
        } else {
            auto const identName = GenName(checker->Allocator());
            auto *exprType = checker->AllocNode<ir::OpaqueTypeNode>(dimType, checker->Allocator());

            auto *blockExpression = parser
                                        ->CreateFormattedExpression(FORMAT_NEW_MULTI_DIM_ARRAY_EXPRESSION, identName,
                                                                    exprType, dimension, identName)
                                        ->AsBlockExpression();

            if (returnExpression == nullptr) {
                returnExpression = blockExpression;
            } else {
                returnExpression->AddStatements(blockExpression->Statements());
            }

            auto *castedDimension = parser->CreateFormattedExpression(CAST_NEW_DIMENSION_EXPRESSION, identName);
            castedDimension->SetParent(newInstanceExpression);
            newInstanceExpression->Dimensions()[i] = castedDimension;
        }
    }

    if (returnExpression != nullptr) {
        return CreateNewMultiDimArrayInstanceExpression(checker, newInstanceExpression, returnExpression);
    }

    return newInstanceExpression;
}

//  NOTE: Just to reduce the size of 'ProcessNewMultiDimArrayInstanceExpression' method
ir::Expression *ExpandBracketsPhase::CreateNewMultiDimArrayInstanceExpression(
    checker::ETSChecker *checker, ir::ETSNewMultiDimArrayInstanceExpression *newInstanceExpression,
    ir::BlockExpression *blockExpression) const
{
    blockExpression->SetParent(newInstanceExpression->Parent());
    newInstanceExpression->SetTsType(nullptr);
    blockExpression->AddStatement(checker->AllocNode<ir::ExpressionStatement>(newInstanceExpression));

    InitScopesPhaseETS::RunExternalNode(blockExpression, checker->VarBinder());
    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(blockExpression, NearestScope(blockExpression));
    blockExpression->Check(checker);

    return blockExpression;
}

bool ExpandBracketsPhase::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    auto *const parser = ctx->parser->AsETSParser();
    ES2PANDA_ASSERT(parser != nullptr);
    auto *const checker = ctx->checker->AsETSChecker();
    ES2PANDA_ASSERT(checker != nullptr);

    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, parser, checker](ir::AstNode *const ast) -> ir::AstNode * {
            if (ast->IsETSNewArrayInstanceExpression()) {
                return ProcessNewArrayInstanceExpression(parser, checker, ast->AsETSNewArrayInstanceExpression());
            }

            if (ast->IsETSNewMultiDimArrayInstanceExpression()) {
                return ProcessNewMultiDimArrayInstanceExpression(parser, checker,
                                                                 ast->AsETSNewMultiDimArrayInstanceExpression());
            }

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
