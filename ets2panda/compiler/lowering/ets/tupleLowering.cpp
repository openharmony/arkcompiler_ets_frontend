/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "checker/checker.h"
#include "checker/types/type.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsAsExpression.h"

namespace panda::es2panda::compiler {

std::string_view TupleLowering::Name()
{
    return "tuple-lowering";
}

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
    const bool is_argument_member_expression = argument->IsMemberExpression();
    auto *const argument_type =
        is_argument_member_expression ? argument->AsMemberExpression()->Object()->TsType() : nullptr;

    if ((argument_type == nullptr) || (!argument_type->IsETSTupleType())) {
        return update;
    }
    // --------------

    // Set tuple type to Object (because we'll need implicit boxing)
    auto *const saved_type = argument->TsType();
    argument->SetTsType(argument_type->AsETSTupleType()->ElementType());
    // --------------

    // Compute necessary types and OpaqueTypeNodes
    auto *const tuple_type_at_idx = argument_type->AsETSTupleType()->GetTypeAtIndex(
        checker->GetTupleElementAccessValue(argument->AsMemberExpression()->Property()->TsType()));

    auto *const tuple_element_type_node =
        checker->AllocNode<ir::OpaqueTypeNode>(argument_type->AsETSTupleType()->ElementType());
    auto *const tuple_type_at_idx_node = checker->AllocNode<ir::OpaqueTypeNode>(tuple_type_at_idx);
    // --------------

    // Clone argument of update expression (conversion flag might be added to it, so we need to duplicate it to not make
    // conversions on 'line 3', that belongs to 'line 1' )
    auto *const member_expr = argument->AsMemberExpression();
    auto *const argument_clone =
        checker->AllocNode<ir::MemberExpression>(member_expr->Object(), member_expr->Property(), member_expr->Kind(),
                                                 member_expr->IsComputed(), member_expr->IsOptional());
    argument_clone->SetPropVar(member_expr->PropVar());
    argument_clone->SetParent(member_expr->Parent());
    argument_clone->SetTsType(member_expr->TsType());
    argument_clone->SetObjectType(member_expr->ObjType());
    // --------------

    // Generate temporary symbols
    auto *gensym = Gensym(checker->Allocator());
    auto *const tmp_var = NearestScope(update)->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(
        checker->Allocator(), gensym->Name(), varbinder::VariableFlags::LOCAL);
    tmp_var->SetTsType(tuple_type_at_idx);
    gensym->SetVariable(tmp_var);
    gensym->SetTsType(tmp_var->TsType());

    auto *gensym_2 = Gensym(checker->Allocator());
    auto *const tmp_var_2 = NearestScope(update)->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(
        checker->Allocator(), gensym_2->Name(), varbinder::VariableFlags::LOCAL);
    tmp_var_2->SetTsType(tuple_type_at_idx);
    gensym_2->SetVariable(tmp_var_2);
    gensym_2->SetTsType(tmp_var_2->TsType());
    // --------------

    // make node: let gensym = tuple[n] as <tuple type at index n>;
    auto *const gensym_ts_as = checker->AllocNode<ir::TSAsExpression>(argument_clone, tuple_type_at_idx_node, false);
    auto *const tuple_as_type =
        checker->AllocNode<ir::AssignmentExpression>(gensym, gensym_ts_as, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: let gensym2 = (gensym)++;
    auto *gensym_update = checker->AllocNode<ir::UpdateExpression>(gensym, update->OperatorType(), update->IsPrefix());
    auto *const gensym_2_assignment = checker->AllocNode<ir::AssignmentExpression>(
        gensym_2, gensym_update, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: tuple[n] = (gensym as <tuple type at index n>) as <tuple element_type>;
    auto *gensym_as = checker->AllocNode<ir::TSAsExpression>(gensym, tuple_type_at_idx_node, false);
    auto *gensym_as_tuple_type_at_idx =
        checker->AllocNode<ir::TSAsExpression>(gensym_as, tuple_element_type_node, false);
    auto *const tuple_assignment = checker->AllocNode<ir::AssignmentExpression>(
        argument, gensym_as_tuple_type_at_idx, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // --------------

    // make node: gensym2 as <tuple type at index n>;
    auto *const final_tuple_node = checker->AllocNode<ir::TSAsExpression>(gensym_2, tuple_type_at_idx_node, false);
    // --------------

    // Construct sequence expression order
    ArenaVector<ir::Expression *> expression_list(checker->Allocator()->Adapter());
    expression_list.push_back(tuple_as_type);
    expression_list.push_back(gensym_2_assignment);
    expression_list.push_back(tuple_assignment);
    expression_list.push_back(final_tuple_node);
    // --------------

    // Check the new sequence expression
    auto *const sequence_expr = checker->AllocNode<ir::SequenceExpression>(std::move(expression_list));
    sequence_expr->SetParent(update->Parent());
    sequence_expr->Check(checker);
    // --------------

    // Set back TsType of argument (not necessarily needed now, but there can be a phase later, that need to get the
    // right type of it)
    argument->SetTsType(saved_type);
    // --------------

    return sequence_expr;
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
    auto *const left_object_type = left->AsMemberExpression()->Object()->TsType();

    if ((left_object_type == nullptr) || (!left_object_type->IsETSTupleType())) {
        return assignment;
    }
    // --------------

    // Set tuple type to <tuple element_type> (because we may need implicit boxing)
    auto *const saved_left_type = left->TsType();
    left->SetTsType(left_object_type->AsETSTupleType()->ElementType());
    // --------------

    // Compute necessary types and OpaqueTypeNodes
    auto *const element_type_type_node =
        checker->AllocNode<ir::OpaqueTypeNode>(left_object_type->AsETSTupleType()->ElementType());
    auto *const tuple_type_at_idx_type_node = checker->AllocNode<ir::OpaqueTypeNode>(saved_left_type);
    // --------------

    // make node: tuple[n] = ((variable as <tuple type at index n>) as <tuple element_type>)
    auto *const ts_as_expression_left =
        checker->AllocNode<ir::TSAsExpression>(assignment->Right(), tuple_type_at_idx_type_node, false);

    auto *const ts_as_expression =
        checker->AllocNode<ir::TSAsExpression>(ts_as_expression_left, element_type_type_node, false);
    auto *const new_assignment =
        checker->AllocNode<ir::AssignmentExpression>(left, ts_as_expression, assignment->OperatorType());
    // --------------

    // Check the new assignment
    new_assignment->SetParent(assignment->Parent());
    new_assignment->Check(checker);
    left->SetTsType(saved_left_type);
    // --------------

    return new_assignment;
}

bool TupleLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const ext_prog : ext_programs) {
            Perform(ctx, ext_prog);
        }
    }

    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([checker](ir::AstNode *const ast) -> ir::AstNode * {
        // Check if node is an 'assignment expression', with a member expression on the left (potentially tuple)
        if (ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->Left()->IsMemberExpression()) {
            return ConvertTupleAssignment(checker, ast->AsAssignmentExpression());
        }

        // Check if node is an 'update expression', with a member expression as an argument (potentially tuple)
        if (ast->IsUpdateExpression() && ast->AsUpdateExpression()->Argument()->IsMemberExpression()) {
            return ConvertTupleUpdate(checker, ast->AsUpdateExpression());
        }

        return ast;
    });

    return true;
}

bool TupleLowering::Postcondition(public_lib::Context *const ctx, const parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (const auto *const ext_prog : ext_programs) {
            if (!Postcondition(ctx, ext_prog)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *const ast) {
        const bool is_left_member_expr =
            ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->Left()->IsMemberExpression();
        const bool is_left_tuple =
            is_left_member_expr
                ? (ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType() != nullptr) &&
                      ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType()->IsETSTupleType()
                : false;
        // Check if there is an 'assignment expression' with a 'member expression' on it's left, which is a tuple. If
        // yes, then the right hand side must be a type of the element type.
        return is_left_member_expr && is_left_tuple &&
               (ast->AsAssignmentExpression()->Right()->TsType() ==
                ast->AsAssignmentExpression()->Left()->AsMemberExpression()->TsType()->AsETSTupleType()->ElementType());
    });
}

}  // namespace panda::es2panda::compiler
