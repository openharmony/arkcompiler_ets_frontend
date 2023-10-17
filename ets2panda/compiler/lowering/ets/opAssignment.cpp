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

/**
 * This is a sample lowering, of little value by itself.
 * TODO(gogabr):
 *   - temporary variables are inserted into the current scope without any accompanying definition
 *     construction; most likely, a proper AST checker would complain.
 *
 * desc: A compound assignment expression of the form E1 op= E2 is equivalent to E1 =
 *   	 ((E1) op (E2)) as T, where T is the type of E1, except that E1 is evaluated only
 *   	 once.
 */

#include "opAssignment.h"
#include "checker/types/typeFlag.h"
#include "binder/variableFlags.h"
#include "checker/ETSchecker.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsAsExpression.h"
#include "lexer/token/tokenType.h"

namespace panda::es2panda::compiler {

util::StringView OpAssignmentLowering::Name()
{
    return "op-assignment";
}

struct Conversion {
    lexer::TokenType from;
    lexer::TokenType to;
};

// NOLINTNEXTLINE(readability-magic-numbers)
static constexpr std::array<Conversion, 16> OP_TRANSLATION {
    {{lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_LEFT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_PLUS_EQUAL, lexer::TokenType::PUNCTUATOR_PLUS},
     {lexer::TokenType::PUNCTUATOR_MINUS_EQUAL, lexer::TokenType::PUNCTUATOR_MINUS},
     {lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL, lexer::TokenType::PUNCTUATOR_MULTIPLY},
     {lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL, lexer::TokenType::PUNCTUATOR_DIVIDE},
     {lexer::TokenType::PUNCTUATOR_MOD_EQUAL, lexer::TokenType::PUNCTUATOR_MOD},
     {lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_AND},
     {lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_OR},
     {lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_XOR},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_AND_EQUAL, lexer::TokenType::PUNCTUATOR_LOGICAL_AND},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_OR_EQUAL, lexer::TokenType::PUNCTUATOR_LOGICAL_OR},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL, lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING},
     {lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL, lexer::TokenType::PUNCTUATOR_EXPONENTIATION}}};

static lexer::TokenType OpEqualToOp(const lexer::TokenType op_equal)
{
    for (const auto &conv : OP_TRANSLATION) {
        if (conv.from == op_equal) {
            return conv.to;
        }
    }
    UNREACHABLE();
}

// This should probably be a virtual method of AstNode
static ir::AstNode *CloneNode(checker::ETSChecker *checker, ir::AstNode *ast)
{
    if (ast->IsIdentifier()) {
        const auto *id = ast->AsIdentifier();
        auto *res = checker->AllocNode<ir::Identifier>(id->Name(), id->TypeAnnotation(), checker->Allocator());
        res->SetVariable(id->Variable());
        res->SetOptional(id->IsOptional());
        res->SetReference(id->IsReference());

        if (id->IsTdz()) {
            res->SetTdz();
        }

        if (id->IsAccessor()) {
            res->SetAccessor();
        }

        if (id->IsMutator()) {
            res->SetMutator();
        }

        res->SetPrivate(id->IsPrivate());
        if (id->IsIgnoreBox()) {
            res->SetIgnoreBox();
        }

        return res;
    }

    ASSERT(ast->IsMemberExpression());

    auto *me = ast->AsMemberExpression();
    auto *object = CloneNode(checker, me->Object())->AsExpression();
    auto *property = CloneNode(checker, me->Property())->AsExpression();

    auto *res =
        checker->AllocNode<ir::MemberExpression>(object, property, me->Kind(), me->IsComputed(), me->IsOptional());
    res->SetPropVar(me->PropVar());
    if (me->IsIgnoreBox()) {
        res->SetIgnoreBox();
    }

    return res;
}

void AdjustBoxingUnboxingFlags(ir::Expression *new_expr, const ir::Expression *old_expr)
{
    // TODO(gogabr): make sure that the checker never puts both a boxing and an unboxing flag on the same node.
    // Then this function will become unnecessary.
    const ir::BoxingUnboxingFlags old_boxing_flag {old_expr->GetBoxingUnboxingFlags() &
                                                   ir::BoxingUnboxingFlags::BOXING_FLAG};
    const ir::BoxingUnboxingFlags old_unboxing_flag {old_expr->GetBoxingUnboxingFlags() &
                                                     ir::BoxingUnboxingFlags::UNBOXING_FLAG};

    if (new_expr->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) &&
        old_boxing_flag != ir::BoxingUnboxingFlags::NONE) {
        new_expr->SetBoxingUnboxingFlags(old_boxing_flag);
    } else if (new_expr->TsType()->IsETSObjectType() && old_unboxing_flag != ir::BoxingUnboxingFlags::NONE) {
        new_expr->SetBoxingUnboxingFlags(old_unboxing_flag);
    }
}

ir::Expression *HandleOpAssignment(checker::ETSChecker *checker, ir::AssignmentExpression *assignment)
{
    if (assignment->TsType() == nullptr) {  // hasn't been throiugh checker
        return assignment;
    }

    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY};

    ir::Expression *tmp_assignment_for_obj = nullptr;
    ir::Expression *tmp_assignment_for_prop = nullptr;
    ir::Expression *left_adjusted = nullptr;

    auto *left = assignment->Left();
    auto *right = assignment->Right();

    const auto op_equal = assignment->OperatorType();
    ASSERT(op_equal != lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    if (left->IsIdentifier() || (left->IsMemberExpression() && left->AsMemberExpression()->Object()->IsIdentifier() &&
                                 left->AsMemberExpression()->Property()->IsIdentifier())) {
        left_adjusted = left->AsExpression();
    } else {
        ASSERT(left->IsMemberExpression());

        auto *left_memb = left->AsMemberExpression();
        auto *scope = NearestScope(assignment);

        auto *tmp_obj_var_id = Gensym(checker->Allocator());
        auto *tmp_obj_var = scope->AddDecl<binder::LetDecl, binder::LocalVariable>(
            checker->Allocator(), tmp_obj_var_id->Name(), binder::VariableFlags::LOCAL);
        tmp_obj_var->SetTsType(left_memb->Object()->TsType());
        tmp_obj_var_id->SetVariable(tmp_obj_var);
        tmp_obj_var_id->SetTsType(tmp_obj_var->TsType());
        tmp_assignment_for_obj = checker->AllocNode<ir::AssignmentExpression>(
            tmp_obj_var_id, left_memb->Object(), lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

        tmp_assignment_for_obj->SetTsType(tmp_obj_var->TsType());

        auto *property = left_memb->Property();
        if (!property->IsIdentifier()) {
            auto *tmp_prop_var_id = Gensym(checker->Allocator());
            auto *tmp_prop_var = scope->AddDecl<binder::LetDecl, binder::LocalVariable>(
                checker->Allocator(), tmp_prop_var_id->Name(), binder::VariableFlags::LOCAL);
            tmp_prop_var->SetTsType(left_memb->Property()->TsType());
            tmp_prop_var_id->SetVariable(tmp_prop_var);
            tmp_prop_var_id->SetTsType(tmp_prop_var->TsType());

            tmp_assignment_for_prop = checker->AllocNode<ir::AssignmentExpression>(
                tmp_prop_var_id, left_memb->Property(), lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            tmp_assignment_for_prop->SetTsType(tmp_prop_var->TsType());
            property = tmp_prop_var_id;
        }

        left_adjusted = checker->AllocNode<ir::MemberExpression>(tmp_obj_var_id, property, left_memb->Kind(),
                                                                 left_memb->IsComputed(), left_memb->IsOptional());
        left_adjusted->AsMemberExpression()->SetPropVar(left_memb->PropVar());
        left_adjusted->AsMemberExpression()->SetObjectType(left_memb->ObjType());
        left_adjusted->SetTsType(left->TsType());

        if (left_memb->IsIgnoreBox()) {
            left_adjusted->AsMemberExpression()->SetIgnoreBox();
        }
    }

    left_adjusted->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);  // to be recomputed
    auto *left_cloned = CloneNode(checker, left_adjusted)->AsExpression();
    auto *new_right = checker->AllocNode<ir::BinaryExpression>(left_cloned, right, OpEqualToOp(op_equal));

    auto *lc_type = left_cloned->Check(checker);

    if (auto *lc_type_as_primitive = checker->ETSBuiltinTypeAsPrimitiveType(lc_type); lc_type_as_primitive != nullptr) {
        lc_type = lc_type_as_primitive;
    }

    auto *lc_type_node = checker->AllocNode<ir::OpaqueTypeNode>(lc_type);
    auto *new_right_converted = checker->AllocNode<ir::TSAsExpression>(new_right, lc_type_node, false);
    auto *new_assignment = checker->AllocNode<ir::AssignmentExpression>(left_adjusted, new_right_converted,
                                                                        lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    ir::Expression *res = new_assignment;
    if (tmp_assignment_for_obj != nullptr) {
        ArenaVector<ir::Expression *> seq_exprs {checker->Allocator()->Adapter()};
        seq_exprs.push_back(tmp_assignment_for_obj);

        if (tmp_assignment_for_prop != nullptr) {
            seq_exprs.push_back(tmp_assignment_for_prop);
        }

        seq_exprs.push_back(new_assignment);
        auto *seq = checker->AllocNode<ir::SequenceExpression>(std::move(seq_exprs));
        res = seq;
    }

    res->SetParent(assignment->Parent());
    new_assignment->Check(checker);
    AdjustBoxingUnboxingFlags(new_assignment, assignment);

    return res;
}

void OpAssignmentLowering::Perform(CompilerContext *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            Perform(ctx, ext_prog);
        }
    }

    checker::ETSChecker *checker = ctx->Checker()->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([checker](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsAssignmentExpression() &&
            ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            return HandleOpAssignment(checker, ast->AsAssignmentExpression());
        }

        return ast;
    });
}

bool OpAssignmentLowering::Postcondition(CompilerContext *ctx, const parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            if (!Postcondition(ctx, ext_prog)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->TsType() != nullptr &&
               ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION;
    });
}

}  // namespace panda::es2panda::compiler
