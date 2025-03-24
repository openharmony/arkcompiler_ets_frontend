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

//
//  desc:   For-of-loop syntax is translated to the while-loop syntax by calling of special method
//          providing predefined 'iterator' interface:
//  for (let x of c) {    // c is an object of 'iterable' class
//    <body>
//  }
//  ...
//  let_ci_=_c.$_iterator()
//  let_it_=_ci.next()
//  while_(!it.done)_{
//    x_=_it.value!
//    <body>
//    it_=_ci.next()
//  }
//

#include "objectIterator.h"

#include "parser/ETSparser.h"
#include "compiler/lowering/util.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "checker/ETSchecker.h"
#include "util/options.h"

namespace ark::es2panda::compiler {

static constexpr std::size_t const WHILE_LOOP_POSITION = 2U;
static constexpr std::size_t const WHILE_LOOP_SIZE = 2U;

std::string_view ObjectIteratorLowering::Name() const
{
    static std::string const NAME = "ObjectIteratorLowering";
    return NAME;
}

void ObjectIteratorLowering::TransferForOfLoopBody(ir::Statement *const forBody, ir::BlockStatement *const whileBody,
                                                   bool const needCleaning) const noexcept
{
    ES2PANDA_ASSERT(forBody != nullptr && whileBody != nullptr);
    auto &whileStatements = whileBody->Statements();

    //  Currently while loop body consists of 2 statements: 'x = it.value!' and 'it = ci.next()'
    //  We need to insert the body of original for-of-loop between them, change their parent and
    //  probably clean types for expressions and variables for identifier for subsequent re-check.
    if (forBody->IsBlockStatement()) {
        auto &forStatements = forBody->AsBlockStatement()->Statements();
        std::size_t const forSize = forStatements.size();

        whileStatements.resize(WHILE_LOOP_SIZE + forSize);
        whileStatements[WHILE_LOOP_SIZE + forSize - 1U] = whileStatements[WHILE_LOOP_SIZE - 1U];

        for (std::size_t i = 0U; i < forSize; ++i) {
            auto &statement = forStatements[i];
            statement->SetParent(whileBody);
            if (needCleaning) {
                // Note: we don't need to clean top-level statement itself because it doesn't have type.
                ClearTypesVariablesAndScopes(statement);
            }
            whileStatements[WHILE_LOOP_SIZE + i - 1U] = statement;
        }
    } else {
        whileStatements.resize(WHILE_LOOP_SIZE + 1U);
        whileStatements[WHILE_LOOP_SIZE] = whileStatements[WHILE_LOOP_SIZE - 1U];

        forBody->SetParent(whileBody);
        if (needCleaning) {
            ClearTypesVariablesAndScopes(forBody);
        }
        whileStatements[WHILE_LOOP_SIZE - 1U] = forBody;
    }
}

ir::Statement *ObjectIteratorLowering::ProcessObjectIterator(parser::ETSParser *parser, checker::ETSChecker *checker,
                                                             varbinder::ETSBinder *varbinder,
                                                             ir::ForOfStatement *forOfStatement) const
{
    //  Note! We assume that parser, varbinder and checker phases have been already passed correctly, thus the
    //  class has required accessible iterator method and all the types and scopes are properly resolved.

    auto *const allocator = checker->Allocator();
    auto statementScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder, NearestScope(forOfStatement));

    ir::Identifier *const iterIdent = Gensym(allocator);
    ir::Identifier *const nextIdent = Gensym(allocator);
    bool declared = true;
    ir::Identifier *loopVariableIdent = nullptr;

    //  Replace the for-of loop with the while loop using the provided iterator interface
    std::string whileStatement = "let @@I1 = (@@E2)." + std::string {compiler::Signatures::ITERATOR_METHOD} + "(); ";
    whileStatement += "let @@I3 = @@I4.next(); ";
    whileStatement += "while (!@@I5.done) { ";

    if (auto *const left = forOfStatement->Left(); left->IsVariableDeclaration()) {
        auto *const declaration = left->AsVariableDeclaration();
        whileStatement +=
            declaration->Kind() != ir::VariableDeclaration::VariableDeclarationKind::CONST ? "let " : "const ";
        loopVariableIdent = declaration->Declarators().at(0U)->Id()->AsIdentifier()->Clone(allocator, nullptr);
    } else if (left->IsIdentifier()) {
        declared = false;
        loopVariableIdent = left->AsIdentifier()->Clone(allocator, nullptr);
    } else {
        ES2PANDA_UNREACHABLE();
    }

    whileStatement += "@@I6 = @@I7.value!; ";
    //  later on here we will insert the current for-of-loop body.
    whileStatement += "@@I8 = @@I9.next(); }";

    // Parse ArkTS code string and create corresponding AST nodes
    auto *const loweringResult = parser->CreateFormattedStatement(
        whileStatement, iterIdent, forOfStatement->Right(), nextIdent, iterIdent->Clone(allocator, nullptr),
        nextIdent->Clone(allocator, nullptr), loopVariableIdent, nextIdent->Clone(allocator, nullptr),
        nextIdent->Clone(allocator, nullptr), iterIdent->Clone(allocator, nullptr));
    loweringResult->SetParent(forOfStatement->Parent());

    TransferForOfLoopBody(forOfStatement->Body(),
                          loweringResult->AsBlockStatement()
                              ->Statements()[WHILE_LOOP_POSITION]
                              ->AsWhileStatement()
                              ->Body()
                              ->AsBlockStatement(),
                          declared);

    CheckLoweredNode(varbinder, checker, loweringResult);
    return loweringResult;
}

bool ObjectIteratorLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    auto *const parser = ctx->parser->AsETSParser();
    ES2PANDA_ASSERT(parser != nullptr);
    auto *const checker = ctx->checker->AsETSChecker();
    ES2PANDA_ASSERT(checker != nullptr);
    auto *const varbinder = ctx->checker->VarBinder()->AsETSBinder();
    ES2PANDA_ASSERT(varbinder != nullptr);

    auto hasIterator = [](checker::Type const *const exprType) -> bool {
        return exprType != nullptr &&
               ((exprType->IsETSObjectType() && !exprType->IsETSStringType()) || exprType->IsETSTypeParameter());
    };

    program->Ast()->TransformChildrenRecursively(
        // clang-format off
        [this, parser, checker, varbinder, &hasIterator](ir::AstNode *ast) -> ir::AstNode* {
            // clang-format on
            if (ast->IsForOfStatement()) {
                if (auto const *const exprType = ast->AsForOfStatement()->Right()->TsType();
                    hasIterator(exprType) || (exprType != nullptr && exprType->IsETSUnionType() &&
                                              exprType->AsETSUnionType()->AllOfConstituentTypes(hasIterator))) {
                    return ProcessObjectIterator(parser, checker, varbinder, ast->AsForOfStatement());
                }
            }
            return ast;
        },
        Name());

    return true;
}
}  // namespace ark::es2panda::compiler
