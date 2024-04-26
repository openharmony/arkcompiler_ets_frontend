/**
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

#include "tupleLowering.h"

#include "checker/ETSchecker.h"
#include "checker/types/ets/etsTupleType.h"
#include "compiler/core/ASTVerifier.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsAsExpression.h"

namespace ark::es2panda::compiler {
static ir::Expression *ConvertTupleUpdate(checker::ETSChecker *const checker, ir::UpdateExpression *const update)
{
    // Converts `tuple[n]++` to
    // ```
    // let gensym = tuple[n] as <tuple type at index n>;                            // line 1
    // let gensym2 = (gensym)++;                                                    // line 2
    // tuple[n] = (gensym as <tuple type at index n>) as <tuple element_type>;      // line 3
    // gensym2 as <tuple type at index n>;                                          // line 4
    // ```
    // Notes:
    // ---
    // Because we can modify only 1 expression in the lowering (we don't want to add statements to the enclosing block),
    // the expressions will be in a wrapper SequenceExpression
    // ---
    // At line 3 the double as expression is needed. If we simply write `gensym as <tuple type at index n>`, then a
    // boxing flag may be put on the `gensym` identifier node. It'll be boxed in 'line 2' instead of 'line 3', which
    // cause error. If we put another as expression inside (which won't do any conversion, because the type of `gensym`
    // is already <tuple type at index n>), the boxing flag will be on the as expression, instead of the identifier, so
    // the identifier node won't be unboxed at 'line 2'.

    // Check if argument of update expression is tuple
    auto *const argument = update->Argument();
    const bool isArgumentMemberExpression = argument->IsMemberExpression();
    auto *const argumentType =
        isArgumentMemberExpression ? argument->AsMemberExpression()->Object()->TsType() : nullptr;

    if ((argumentType == nullptr) || (!argumentType->IsETSTupleType())) {
        return update;
    }
    // --------------

    // Set tuple type to Object (because we'll need implicit boxing)
    auto *const savedType = argument->TsType();
    argument->SetTsType(argumentType->AsETSTupleType()->ElementType());
    // --------------

    // Compute necessary types and OpaqueTypeNodes
    auto *const tupleTypeAtIdx = argumentType->AsETSTupleType()->GetTypeAtIndex(checker->GetTupleElementAccessValue(
        argument->AsMemberExpression()->Property()->TsType(), argument->AsMemberExpression()->Property()->Start()));

    auto *const tupleElementTypeNode =
        checker->AllocNode<ir::OpaqueTypeNode>(argumentType->AsETSTupleType()->ElementType());
    auto *const tupleTypeAtIdxNode = checker->AllocNode<ir::OpaqueTypeNode>(tupleTypeAtIdx);
    // --------------

    // Clone argument of update expression (conversion flag might be added to it, so we need to duplicate it to not make
    // conversions on 'line 3', that belongs to 'line 1' )
    auto *const memberExpr = argument->AsMemberExpression();
    auto *const argumentClone = memberExpr->Clone(checker->Allocator(), memberExpr->Parent());
    argumentClone->Object()->SetTsType(memberExpr->Object()->TsType());
    if (argumentClone->Object()->IsIdentifier()) {
        argumentClone->Object()->AsIdentifier()->SetVariable(memberExpr->Object()->AsIdentifier()->Variable());
    }
    argumentClone->Property()->SetTsType(memberExpr->Property()->TsType());
    if (argumentClone->Property()->IsIdentifier()) {
        argumentClone->Property()->AsIdentifier()->SetVariable(memberExpr->Property()->AsIdentifier()->Variable());
    }
    argumentClone->SetTsType(memberExpr->TsType());
    // --------------

    // Generate temporary symbols
    auto *gensym = Gensym(checker->Allocator());
    auto *const tmpVar = NearestScope(update)->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(
        checker->Allocator(), gensym->Name(), varbinder::VariableFlags::LOCAL);
    tmpVar->SetTsType(tupleTypeAtIdx);
    gensym->SetVariable(tmpVar);
    gensym->SetTsType(tmpVar->TsType());

    auto *gensym2 = Gensym(checker->Allocator());
    auto *const tmpVar2 = NearestScope(update)->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(
        checker->Allocator(), gensym2->Name(), varbinder::VariableFlags::LOCAL);
    tmpVar2->SetTsType(tupleTypeAtIdx);
    gensym2->SetVariable(tmpVar2);
    gensym2->SetTsType(tmpVar2->TsType());
    // --------------

    // make node: let gensym = tuple[n] as <tuple type at index n>;
    auto *const gensymTsAs = checker->AllocNode<ir::TSAsExpression>(argumentClone, tupleTypeAtIdxNode, false);
    auto *const tupleAsType =
        checker->AllocNode<ir::AssignmentExpression>(gensym, gensymTsAs, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: let gensym2 = (gensym)++;
    auto *identClone = gensym->Clone(checker->Allocator(), nullptr);
    identClone->SetTsType(tmpVar->TsType());
    auto *gensymUpdate =
        checker->AllocNode<ir::UpdateExpression>(identClone, update->OperatorType(), update->IsPrefix());
    auto *const gensym2Assignment =
        checker->AllocNode<ir::AssignmentExpression>(gensym2, gensymUpdate, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: tuple[n] = (gensym as <tuple type at index n>) as <tuple element_type>;
    identClone = gensym->Clone(checker->Allocator(), nullptr);
    identClone->SetTsType(tmpVar->TsType());
    auto *gensymAs = checker->AllocNode<ir::TSAsExpression>(
        identClone, tupleTypeAtIdxNode->Clone(checker->Allocator(), nullptr), false);
    auto *gensymAsTupleTypeAtIdx = checker->AllocNode<ir::TSAsExpression>(gensymAs, tupleElementTypeNode, false);
    auto *const tupleAssignment = checker->AllocNode<ir::AssignmentExpression>(
        argument, gensymAsTupleTypeAtIdx, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: gensym2 as <tuple type at index n>;
    identClone = gensym2->Clone(checker->Allocator(), nullptr);
    identClone->SetTsType(tmpVar2->TsType());
    auto *const finalTupleNode = checker->AllocNode<ir::TSAsExpression>(
        identClone, tupleTypeAtIdxNode->Clone(checker->Allocator(), nullptr), false);
    // --------------

    // Construct sequence expression order
    ArenaVector<ir::Expression *> expressionList(checker->Allocator()->Adapter());
    expressionList.push_back(tupleAsType);
    expressionList.push_back(gensym2Assignment);
    expressionList.push_back(tupleAssignment);
    expressionList.push_back(finalTupleNode);
    // --------------

    // Check the new sequence expression
    auto *const sequenceExpr = checker->AllocNode<ir::SequenceExpression>(std::move(expressionList));
    sequenceExpr->SetParent(update->Parent());
    sequenceExpr->Check(checker);
    // --------------

    // Set back TsType of argument (not necessarily needed now, but there can be a phase later, that need to get the
    // right type of it)
    argument->SetTsType(savedType);
    // --------------

    return sequenceExpr;
}

static ir::AssignmentExpression *ConvertTupleAssignment(checker::ETSChecker *const checker,
                                                        ir::AssignmentExpression *const assignment)
{
    // Converts `tuple[n] = variable;` to
    // `tuple[n] = ((variable as <tuple type at index n>) as <tuple element_type>)`
    // This lowering is necessary to handle `an unboxing conversion followed by a widening primitive
    // conversion`, eg. when `tuple[n]` has type of `int`, and assignment::right_ has type of `Short`. Because every
    // type is stored as the LUB type in the tuple (which can be Object), then the following conversions need to be done
    // for this case: Short->short->int->Int->Object which can't be made implicitly, hence lowering is needed

    // Check if the left side of an assignment expression is a tuple element access
    auto *const left = assignment->Left();
    auto *const leftObjectType = left->AsMemberExpression()->Object()->TsType();

    if ((leftObjectType == nullptr) || (!leftObjectType->IsETSTupleType())) {
        return assignment;
    }
    // --------------

    // Set tuple type to <tuple element_type> (because we may need implicit boxing)
    auto *const savedLeftType = left->TsType();
    left->SetTsType(leftObjectType->AsETSTupleType()->ElementType());
    // --------------

    // Compute necessary types and OpaqueTypeNodes
    auto *const elementTypeTypeNode =
        checker->AllocNode<ir::OpaqueTypeNode>(leftObjectType->AsETSTupleType()->ElementType());
    auto *const tupleTypeAtIdxTypeNode = checker->AllocNode<ir::OpaqueTypeNode>(savedLeftType);
    // --------------

    // make node: tuple[n] = ((variable as <tuple type at index n>) as <tuple element_type>)
    auto *const tsAsExpressionLeft =
        checker->AllocNode<ir::TSAsExpression>(assignment->Right(), tupleTypeAtIdxTypeNode, false);

    auto *const tsAsExpression = checker->AllocNode<ir::TSAsExpression>(tsAsExpressionLeft, elementTypeTypeNode, false);
    auto *const newAssignment =
        checker->AllocNode<ir::AssignmentExpression>(left, tsAsExpression, assignment->OperatorType());
    // --------------

    // Check the new assignment
    newAssignment->SetParent(assignment->Parent());
    newAssignment->Check(checker);
    left->SetTsType(savedLeftType);
    // --------------

    return newAssignment;
}

bool TupleLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [checker](ir::AstNode *const ast) -> ir::AstNode * {
            // Check if node is an 'assignment expression', with a member expression on the left (potentially tuple)
            if (ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->Left()->IsMemberExpression()) {
                return ConvertTupleAssignment(checker, ast->AsAssignmentExpression());
            }

            // Check if node is an 'update expression', with a member expression as an argument (potentially tuple)
            if (ast->IsUpdateExpression() && ast->AsUpdateExpression()->Argument()->IsMemberExpression()) {
                return ConvertTupleUpdate(checker, ast->AsUpdateExpression());
            }

            return ast;
        },
        Name());

    return true;
}

bool TupleLowering::Postcondition(public_lib::Context *const ctx, const parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (const auto *const extProg : ext_programs) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *const ast) {
        const bool isLeftMemberExpr =
            ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->Left()->IsMemberExpression();
        const bool isLeftTuple =
            isLeftMemberExpr
                ? (ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType() != nullptr) &&
                      ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType()->IsETSTupleType()
                : false;
        // Check if there is an 'assignment expression' with a 'member expression' on it's left, which is a tuple. If
        // yes, then the right hand side must be a type of the element type.
        return isLeftMemberExpr && isLeftTuple &&
               (ast->AsAssignmentExpression()->Right()->TsType() ==
                ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType()->AsETSTupleType()->ElementType());
    });
}

}  // namespace ark::es2panda::compiler
