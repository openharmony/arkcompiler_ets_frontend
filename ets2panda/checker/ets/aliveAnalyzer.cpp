/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "aliveAnalyzer.h"
#include <cstddef>

#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/switchCaseStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsStructDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "binder/variable.h"
#include "binder/scope.h"
#include "binder/declaration.h"
#include "checker/ETSchecker.h"
#include "ir/base/catchClause.h"

namespace panda::es2panda::checker {

void AliveAnalyzer::AnalyzeNodes(const ir::AstNode *node)
{
    node->Iterate([this](auto *child_node) { AnalyzeNode(child_node); });
}

void AliveAnalyzer::AnalyzeNode(const ir::AstNode *node)
{
    if (node == nullptr) {
        return;
    }

    switch (node->Type()) {
        case ir::AstNodeType::EXPRESSION_STATEMENT: {
            AnalyzeNode(node->AsExpressionStatement()->GetExpression());
            break;
        }
        case ir::AstNodeType::STRUCT_DECLARATION: {
            AnalyzeStructDecl(node->AsETSStructDeclaration());
            break;
        }
        case ir::AstNodeType::CLASS_DECLARATION: {
            AnalyzeClassDecl(node->AsClassDeclaration());
            break;
        }
        case ir::AstNodeType::CLASS_DEFINITION: {
            AnalyzeClassDef(node->AsClassDefinition());
            break;
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            AnalyzeMethodDef(node->AsMethodDefinition());
            break;
        }
        case ir::AstNodeType::VARIABLE_DECLARATION: {
            AnalyzeVarDef(node->AsVariableDeclaration());
            break;
        }
        case ir::AstNodeType::BLOCK_STATEMENT: {
            AnalyzeStats(node->AsBlockStatement()->Statements());
            break;
        }
        case ir::AstNodeType::DO_WHILE_STATEMENT: {
            AnalyzeDoLoop(node->AsDoWhileStatement());
            break;
        }
        case ir::AstNodeType::WHILE_STATEMENT: {
            AnalyzeWhileLoop(node->AsWhileStatement());
            break;
        }
        case ir::AstNodeType::FOR_UPDATE_STATEMENT: {
            AnalyzeForLoop(node->AsForUpdateStatement());
            break;
        }
        case ir::AstNodeType::FOR_OF_STATEMENT: {
            AnalyzeForOfLoop(node->AsForOfStatement());
            break;
        }
        case ir::AstNodeType::IF_STATEMENT: {
            AnalyzeIf(node->AsIfStatement());
            break;
        }
        case ir::AstNodeType::LABELLED_STATEMENT: {
            AnalyzeLabelled(node->AsLabelledStatement());
            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            AnalyzeNewClass(node->AsETSNewClassInstanceExpression());
            break;
        }
        case ir::AstNodeType::CALL_EXPRESSION: {
            AnalyzeCall(node->AsCallExpression());
            break;
        }
        case ir::AstNodeType::THROW_STATEMENT: {
            AnalyzeThrow(node->AsThrowStatement());
            break;
        }
        case ir::AstNodeType::SWITCH_STATEMENT: {
            AnalyzeSwitch(node->AsSwitchStatement());
            break;
        }
        case ir::AstNodeType::TRY_STATEMENT: {
            AnalyzeTry(node->AsTryStatement());
            break;
        }
        case ir::AstNodeType::BREAK_STATEMENT: {
            AnalyzeBreak(node->AsBreakStatement());
            break;
        }
        case ir::AstNodeType::CONTINUE_STATEMENT: {
            AnalyzeContinue(node->AsContinueStatement());
            break;
        }
        case ir::AstNodeType::RETURN_STATEMENT: {
            AnalyzeReturn(node->AsReturnStatement());
            break;
        }
        default: {
            break;
        }
    }
}

void AliveAnalyzer::AnalyzeDef(const ir::AstNode *node)
{
    AnalyzeStat(node);
    if (node != nullptr && node->IsClassStaticBlock() && status_ == LivenessStatus::DEAD) {
        checker_->ThrowTypeError("Initializer must be able to complete normally.", node->Start());
    }
}

void AliveAnalyzer::AnalyzeStat(const ir::AstNode *node)
{
    if (node == nullptr) {
        return;
    }

    if (status_ == LivenessStatus::DEAD) {
        checker_->ThrowTypeError("Unreachable statement.", node->Start());
    }

    if (node->IsClassStaticBlock()) {
        AnalyzeNodes(node);
        return;
    }

    AnalyzeNode(node);
}

void AliveAnalyzer::AnalyzeStats(const ArenaVector<ir::Statement *> &stats)
{
    for (const auto *it : stats) {
        AnalyzeStat(it);
    }
}

static bool IsStaticMember(const ir::AstNode *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::CLASS_PROPERTY: {
            return node->IsStatic();
        }
        case ir::AstNodeType::STRUCT_DECLARATION: {
            return node->AsETSStructDeclaration()->Definition()->IsStatic();
        }
        case ir::AstNodeType::CLASS_DECLARATION: {
            return node->AsClassDeclaration()->Definition()->IsStatic();
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return node->IsStatic();
        }
        default: {
            return false;
        }
    }
}

void AliveAnalyzer::AnalyzeStructDecl(const ir::ETSStructDeclaration *struct_decl)
{
    for (const auto *it : struct_decl->Definition()->Body()) {
        AnalyzeNode(it);
    }
}

void AliveAnalyzer::AnalyzeClassDecl(const ir::ClassDeclaration *class_decl)
{
    for (const auto *it : class_decl->Definition()->Body()) {
        AnalyzeNode(it);
    }
}

void AliveAnalyzer::AnalyzeClassDef(const ir::ClassDefinition *class_def)
{
    if (class_def->Variable() == nullptr) {
        return;
    }

    LivenessStatus prev_status = status_;
    SetOldPendingExits(PendingExits());

    for (const auto *it : class_def->Body()) {
        if (!it->IsMethodDefinition() && IsStaticMember(it)) {
            AnalyzeDef(it);
            ClearPendingExits();
        }
    }

    for (const auto *it : class_def->Body()) {
        if (!it->IsMethodDefinition() && !IsStaticMember(it)) {
            AnalyzeDef(it);
            ClearPendingExits();
        }
    }

    for (const auto *it : class_def->Body()) {
        if (it->IsClassStaticBlock()) {
            AnalyzeDef(it);
            break;
        }
    }

    for (const auto *it : class_def->Body()) {
        if (it->IsMethodDefinition()) {
            AnalyzeNode(it);
        }
    }

    SetPendingExits(OldPendingExits());
    status_ = prev_status;
}

void AliveAnalyzer::AnalyzeMethodDef(const ir::MethodDefinition *method_def)
{
    auto *func = method_def->Function();

    if (func->Body() == nullptr || func->IsProxy()) {
        return;
    }

    status_ = LivenessStatus::ALIVE;
    AnalyzeStat(func->Body());
    ASSERT(method_def->TsType() && method_def->TsType()->IsETSFunctionType());

    if (status_ == LivenessStatus::ALIVE &&
        (!method_def->TsType()->AsETSFunctionType()->FindSignature(func)->ReturnType()->IsETSVoidType() &&
         method_def->TsType()->AsETSFunctionType()->FindSignature(func)->ReturnType() !=
             checker_->GlobalBuiltinVoidType())) {
        checker_->ThrowTypeError("Function with a non void return type must return a value.", func->Id()->Start());
    }

    ClearPendingExits();
}

void AliveAnalyzer::AnalyzeVarDef(const ir::VariableDeclaration *var_def)
{
    for (auto *it : var_def->Declarators()) {
        if (it->Init() == nullptr) {
            continue;
        }

        AnalyzeNode(it->Init());
    }
}

void AliveAnalyzer::AnalyzeDoLoop(const ir::DoWhileStatement *do_while)
{
    SetOldPendingExits(PendingExits());
    AnalyzeStat(do_while->Body());
    status_ = Or(status_, ResolveContinues(do_while));
    AnalyzeNode(do_while->Test());
    ASSERT(do_while->Test()->TsType() && do_while->Test()->TsType()->IsETSBooleanType());
    auto *cond_type = do_while->Test()->TsType()->AsETSBooleanType();
    status_ = And(status_,
                  static_cast<LivenessStatus>(!(cond_type->HasTypeFlag(TypeFlag::CONSTANT) && cond_type->GetValue())));
    status_ = Or(status_, ResolveBreaks(do_while));
}

void AliveAnalyzer::AnalyzeWhileLoop(const ir::WhileStatement *while_stmt)
{
    SetOldPendingExits(PendingExits());
    AnalyzeNode(while_stmt->Test());
    ASSERT(while_stmt->Test()->TsType() && while_stmt->Test()->TsType()->IsETSBooleanType());
    auto *cond_type = while_stmt->Test()->TsType()->AsETSBooleanType();
    status_ = And(status_,
                  static_cast<LivenessStatus>(!(cond_type->HasTypeFlag(TypeFlag::CONSTANT) && !cond_type->GetValue())));
    AnalyzeStat(while_stmt->Body());
    status_ = Or(status_, ResolveContinues(while_stmt));
    status_ =
        Or(ResolveBreaks(while_stmt), From(!(cond_type->HasTypeFlag(TypeFlag::CONSTANT) && cond_type->GetValue())));
}

void AliveAnalyzer::AnalyzeForLoop(const ir::ForUpdateStatement *for_stmt)
{
    AnalyzeNode(for_stmt->Init());
    SetOldPendingExits(PendingExits());
    const ETSBooleanType *cond_type {};
    if (for_stmt->Test() != nullptr) {
        AnalyzeNode(for_stmt->Test());
        ASSERT(for_stmt->Test()->TsType() && for_stmt->Test()->TsType()->IsETSBooleanType());
        cond_type = for_stmt->Test()->TsType()->AsETSBooleanType();
        status_ = From(!(cond_type->HasTypeFlag(TypeFlag::CONSTANT) && !cond_type->GetValue()));
    } else {
        status_ = LivenessStatus::ALIVE;
    }

    AnalyzeStat(for_stmt->Body());
    status_ = Or(status_, ResolveContinues(for_stmt));
    AnalyzeNode(for_stmt->Update());
    status_ = Or(ResolveBreaks(for_stmt),
                 From(cond_type != nullptr && !(cond_type->HasTypeFlag(TypeFlag::CONSTANT) && cond_type->GetValue())));
}

void AliveAnalyzer::AnalyzeForOfLoop(const ir::ForOfStatement *for_of_stmt)
{
    //  Note: iterator definition can be a reference to variable defined in outer scope!
    if (for_of_stmt->Left()->IsVariableDeclaration()) {
        AnalyzeVarDef(for_of_stmt->Left()->AsVariableDeclaration());
    } else {
        AnalyzeNode(for_of_stmt->Left());
    }
    AnalyzeNode(for_of_stmt->Right());
    SetOldPendingExits(PendingExits());

    AnalyzeStat(for_of_stmt->Body());
    status_ = Or(status_, ResolveContinues(for_of_stmt));
    ResolveBreaks(for_of_stmt);
    status_ = LivenessStatus::ALIVE;
}

void AliveAnalyzer::AnalyzeIf(const ir::IfStatement *if_stmt)
{
    AnalyzeNode(if_stmt->Test());
    AnalyzeStat(if_stmt->Consequent());
    if (if_stmt->Alternate() != nullptr) {
        LivenessStatus prev_status = status_;
        status_ = LivenessStatus::ALIVE;
        AnalyzeStat(if_stmt->Alternate());
        status_ = Or(status_, prev_status);
    } else {
        status_ = LivenessStatus::ALIVE;
    }
}

void AliveAnalyzer::AnalyzeLabelled(const ir::LabelledStatement *labelled_stmt)
{
    SetOldPendingExits(PendingExits());
    AnalyzeStat(labelled_stmt->Body());
    status_ = Or(status_, ResolveBreaks(labelled_stmt));
}

void AliveAnalyzer::AnalyzeNewClass(const ir::ETSNewClassInstanceExpression *new_class)
{
    for (const auto *it : new_class->GetArguments()) {
        AnalyzeNode(it);
    }

    if (new_class->ClassDefinition() != nullptr) {
        AnalyzeNode(new_class->ClassDefinition());
    }
}

void AliveAnalyzer::AnalyzeCall(const ir::CallExpression *call_expr)
{
    AnalyzeNode(call_expr->Callee());
    for (const auto *it : call_expr->Arguments()) {
        AnalyzeNode(it);
    }
}

void AliveAnalyzer::AnalyzeThrow(const ir::ThrowStatement *throw_stmt)
{
    AnalyzeNode(throw_stmt->Argument());
    MarkDead();
}

void AliveAnalyzer::AnalyzeSwitch([[maybe_unused]] const ir::SwitchStatement *switch_stmt)
{
    // TODO(aszilagyi): fix analysis to be correct
    /*
    PendingExitsVector oldPendingExits = std::move(pendingExits_);
    AnalyzeNode(switchStmt->Discriminant());

    std::vector<binder::LocalVariable *> constants;
    for (const auto *it : switchStmt->Cases()) {
        status_ = LivenessStatus::ALIVE;
        AnalyzeNode(it->Test());
        AnalyzeStats(it->Consequent());
    }

    status_ = Or(status_, ResolveBreaks(switchStmt, oldPendingExits));
    */
}

void AliveAnalyzer::AnalyzeBreak(const ir::BreakStatement *break_stmt)
{
    RecordExit(PendingExit(break_stmt));
}

void AliveAnalyzer::AnalyzeContinue(const ir::ContinueStatement *cont_stmt)
{
    RecordExit(PendingExit(cont_stmt));
}

void AliveAnalyzer::AnalyzeReturn(const ir::ReturnStatement *ret_stmt)
{
    AnalyzeNode(ret_stmt->Argument());
    RecordExit(PendingExit(ret_stmt));
}

void AliveAnalyzer::AnalyzeTry(const ir::TryStatement *try_stmt)
{
    status_ = LivenessStatus::ALIVE;
    bool is_alive = false;
    AnalyzeStats(try_stmt->Block()->Statements());

    if (status_ != LivenessStatus::DEAD) {
        is_alive = true;
    }

    for (const auto &it : try_stmt->CatchClauses()) {
        status_ = LivenessStatus::ALIVE;
        AnalyzeStats(it->Body()->Statements());
        if (status_ == LivenessStatus::ALIVE) {
            is_alive = true;
        }
    }

    if (try_stmt->FinallyBlock() != nullptr) {
        status_ = LivenessStatus::ALIVE;
        AnalyzeStats(try_stmt->FinallyBlock()->Statements());
        if (status_ == LivenessStatus::DEAD) {
            is_alive = false;
        }
    }

    status_ = is_alive ? LivenessStatus::ALIVE : LivenessStatus::DEAD;
}
}  // namespace panda::es2panda::checker
