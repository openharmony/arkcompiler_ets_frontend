/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#include "compiler/lowering/ets/topLevelStmts/globalClassHandler.h"

#include "ir/statements/classDeclaration.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/classExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/blockStatement.h"
#include "compiler/lowering/ets/topLevelStmts/globalDeclTransformer.h"
#include "util/helpers.h"

namespace ark::es2panda::compiler {

using util::NodeAllocator;

static bool MainFunctionExists(const ArenaVector<ir::Statement *> &statements)
{
    for (auto stmt : statements) {
        if (stmt->IsFunctionDeclaration() &&
            stmt->AsFunctionDeclaration()->Function()->Id()->Name().Is(compiler::Signatures::MAIN)) {
            return true;
        }
    }
    return false;
}

void GlobalClassHandler::InitGlobalClass(const ArenaVector<parser::Program *> &programs)
{
    if (programs.empty()) {
        return;
    }
    auto globalDecl = CreateGlobalClass();
    auto globalClass = globalDecl->Definition();

    auto addCCtor = [this](ir::AstNode *node) {
        if (node->IsClassDefinition()) {
            auto classDef = node->AsClassDefinition();
            bool allowEmpty = false;
            auto staticBlock = CreateCCtor(classDef->Body(), classDef->Start(), allowEmpty);
            if (staticBlock != nullptr) {
                classDef->Body().emplace_back(staticBlock);
                staticBlock->SetParent(classDef);
            }
        }
    };

    ArenaVector<GlobalStmts> statements(allocator_->Adapter());
    bool mainExists = false;
    bool topLevelStatementsExist = false;
    for (auto program : programs) {
        program->Ast()->IterateRecursively(addCCtor);
        if (program->IsEntryPoint() && !mainExists && MainFunctionExists(program->Ast()->Statements())) {
            mainExists = true;
        }

        // NOTE(rsipka): unclear naming, OmitModuleName() used to determine the entry point without --ets-module option
        auto stmts = MakeGlobalStatements(program->Ast(), globalClass, program->OmitModuleName());
        if (!topLevelStatementsExist && !stmts.empty()) {
            topLevelStatementsExist = true;
        }
        statements.emplace_back(GlobalStmts {program, std::move(stmts)});
        program->SetGlobalClass(globalClass);
    }
    InitCallToCCTOR(programs.front(), statements, mainExists, topLevelStatementsExist);
}

static ir::MethodDefinition *CreateAndFillTopLevelMethod(
    const ArenaVector<GlobalClassHandler::GlobalStmts> &initStatements, ArenaAllocator *allocator,
    const std::string_view name)
{
    const auto functionFlags = ir::ScriptFunctionFlags::NONE;
    const auto functionModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;
    auto *ident = NodeAllocator::Alloc<ir::Identifier>(allocator, name, allocator);

    ArenaVector<ir::Expression *> params(allocator->Adapter());

    ArenaVector<ir::Statement *> statements(allocator->Adapter());
    auto *body = NodeAllocator::Alloc<ir::BlockStatement>(allocator, allocator, std::move(statements));

    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);

    auto *func = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {
            body, std::move(funcSignature), functionFlags, {}, false, Language(Language::Id::ETS)});

    func->SetIdent(ident);
    func->AddModifier(functionModifiers);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator, func);
    auto methodDef = NodeAllocator::Alloc<ir::MethodDefinition>(allocator, ir::MethodDefinitionKind::METHOD,
                                                                ident->Clone(allocator, nullptr)->AsExpression(),
                                                                funcExpr, functionModifiers, allocator, false);

    for (const auto &stmts : initStatements) {
        for (auto stmt : stmts.statements) {
            methodDef->Function()->Body()->AsBlockStatement()->Statements().emplace_back(stmt);
            stmt->SetParent(methodDef->Function()->Body());
        }
    }
    return methodDef;
}

void GlobalClassHandler::AddInitCall(ir::ClassDefinition *globalClass, ir::MethodDefinition *initMethod)
{
    ASSERT(initMethod != nullptr);

    auto &globalBody = globalClass->Body();
    auto maybeStaticBlock = std::find_if(globalBody.begin(), globalBody.end(),
                                         [](ir::AstNode *cctor) { return cctor->IsClassStaticBlock(); });
    ASSERT(maybeStaticBlock != globalBody.end());

    auto *staticBlock = (*maybeStaticBlock)->AsClassStaticBlock();
    auto *callee = RefIdent(initMethod->Id()->Name());

    auto *const callExpr = NodeAllocator::Alloc<ir::CallExpression>(
        allocator_, callee, ArenaVector<ir::Expression *>(allocator_->Adapter()), nullptr, false, false);

    auto *blockBody = staticBlock->Function()->Body()->AsBlockStatement();
    auto exprStmt = NodeAllocator::Alloc<ir::ExpressionStatement>(allocator_, callExpr);
    exprStmt->SetParent(blockBody);
    blockBody->Statements().emplace_back(exprStmt);
}

ir::Identifier *GlobalClassHandler::RefIdent(const util::StringView &name)
{
    auto *const callee = NodeAllocator::Alloc<ir::Identifier>(allocator_, name, allocator_);
    callee->SetReference();
    return callee;
}

ir::ClassStaticBlock *GlobalClassHandler::CreateCCtor(const ArenaVector<ir::AstNode *> &properties,
                                                      const lexer::SourcePosition &loc, bool allowEmptyCctor)
{
    bool hasStaticField = false;
    for (const auto *prop : properties) {
        if (prop->IsClassStaticBlock()) {
            return nullptr;
        }

        if (!prop->IsClassProperty()) {
            continue;
        }

        const auto *field = prop->AsClassProperty();

        if (field->IsStatic()) {
            hasStaticField = true;
        }
    }

    if (!hasStaticField && !allowEmptyCctor) {
        return nullptr;
    }

    ArenaVector<ir::Expression *> params(allocator_->Adapter());

    auto *id = NodeAllocator::Alloc<ir::Identifier>(allocator_, compiler::Signatures::CCTOR, allocator_);

    ArenaVector<ir::Statement *> statements(allocator_->Adapter());

    auto *body = NodeAllocator::Alloc<ir::BlockStatement>(allocator_, allocator_, std::move(statements));
    auto *func = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator_, allocator_,
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::HIDDEN,
                                                ir::ModifierFlags::STATIC, false, Language(Language::Id::ETS)});

    func->SetIdent(id);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, func);
    auto *staticBlock = NodeAllocator::Alloc<ir::ClassStaticBlock>(allocator_, funcExpr, allocator_);
    staticBlock->AddModifier(ir::ModifierFlags::STATIC);
    staticBlock->SetRange({loc, loc});
    return staticBlock;
}

ArenaVector<ir::Statement *> GlobalClassHandler::MakeGlobalStatements(ir::BlockStatement *globalStmts,
                                                                      ir::ClassDefinition *classDef,
                                                                      bool addInitializer)
{
    auto globalDecl = GlobalDeclTransformer(allocator_);
    auto statements = globalDecl.TransformStatements(globalStmts->Statements(), addInitializer);
    classDef->AddProperties(util::Helpers::ConvertVector<ir::AstNode>(statements.classProperties));
    globalDecl.FilterDeclarations(globalStmts->Statements());
    return std::move(statements.initStatements);
}

void GlobalClassHandler::InitGlobalClass(ir::ClassDefinition *classDef, parser::ScriptKind scriptKind)
{
    auto &globalProperties = classDef->Body();
    auto staticBlock = CreateCCtor(globalProperties, classDef->Start(), scriptKind != parser::ScriptKind::STDLIB);
    if (staticBlock != nullptr) {
        staticBlock->SetParent(classDef);
        globalProperties.emplace_back(staticBlock);
    }
    classDef->SetGlobalInitialized();
}

ir::ClassDeclaration *GlobalClassHandler::CreateGlobalClass()
{
    auto *ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, compiler::Signatures::ETS_GLOBAL, allocator_);

    auto *classDef =
        NodeAllocator::Alloc<ir::ClassDefinition>(allocator_, allocator_, ident, ir::ClassDefinitionModifiers::GLOBAL,
                                                  ir::ModifierFlags::ABSTRACT, Language(Language::Id::ETS));
    auto *classDecl = NodeAllocator::Alloc<ir::ClassDeclaration>(allocator_, classDef, allocator_);
    return classDecl;
}

void GlobalClassHandler::InitCallToCCTOR(parser::Program *program, const ArenaVector<GlobalStmts> &initStatements,
                                         bool mainExists, bool topLevelStatementsExist)
{
    auto globalClass = program->GlobalClass();
    auto globalDecl = globalClass->Parent()->AsClassDeclaration();
    program->Ast()->Statements().emplace_back(globalDecl);
    globalDecl->SetParent(program->Ast());
    InitGlobalClass(globalClass, program->Kind());
    auto &globalBody = globalClass->Body();
    // NOTE(rsipka): unclear call, OmitModuleName() used to determine the entry points without --ets-module option
    if (program->OmitModuleName() && program->Kind() != parser::ScriptKind::STDLIB) {
        ir::MethodDefinition *initMethod = CreateAndFillTopLevelMethod(initStatements, allocator_, INIT_NAME);
        ir::MethodDefinition *mainMethod = nullptr;
        if (!mainExists && topLevelStatementsExist) {
            const ArenaVector<GlobalStmts> emptyStatements(allocator_->Adapter());
            mainMethod = CreateAndFillTopLevelMethod(emptyStatements, allocator_, compiler::Signatures::MAIN);
        }
        if (initMethod != nullptr) {
            initMethod->SetParent(program->GlobalClass());
            globalBody.insert(globalBody.begin(), initMethod);
            if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
                AddInitCall(program->GlobalClass(), initMethod);
            }
        }
        if (mainMethod != nullptr) {
            mainMethod->SetParent(program->GlobalClass());
            globalBody.insert(globalBody.begin(), mainMethod);
        }
    }
}

}  // namespace ark::es2panda::compiler
