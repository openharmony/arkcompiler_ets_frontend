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
    for (auto program : programs) {
        program->Ast()->IterateRecursively(addCCtor);
        auto stmts = MakeGlobalStatements(program->Ast(), globalClass, !program->GetPackageName().Empty());
        statements.emplace_back(GlobalStmts {program, std::move(stmts)});
        program->SetGlobalClass(globalClass);
    }
    InitCallToCCTOR(programs.front(), statements);
}

ir::MethodDefinition *GlobalClassHandler::CreateAndFillInitMethod(const ArenaVector<GlobalStmts> &initStatements)
{
    auto initMethod = CreateInitMethod();

    for (const auto &stmts : initStatements) {
        for (auto stmt : stmts.statements) {
            initMethod->Function()->Body()->AsBlockStatement()->Statements().emplace_back(stmt);
            stmt->SetParent(initMethod->Function()->Body());
        }
    }
    return initMethod;
}

ir::MethodDefinition *GlobalClassHandler::CreateInitMethod()
{
    const auto functionFlags = ir::ScriptFunctionFlags::NONE;
    const auto functionModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;
    auto *initIdent = NodeAllocator::Alloc<ir::Identifier>(allocator_, INIT_NAME, allocator_);

    ArenaVector<ir::Expression *> params(allocator_->Adapter());

    ArenaVector<ir::Statement *> statements(allocator_->Adapter());
    auto *initBody = NodeAllocator::Alloc<ir::BlockStatement>(allocator_, allocator_, std::move(statements));

    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);

    auto *initFunc = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator_, allocator_,
        ir::ScriptFunction::ScriptFunctionData {
            initBody, std::move(funcSignature), functionFlags, {}, false, Language(Language::Id::ETS)});

    initFunc->SetIdent(initIdent);
    initFunc->AddModifier(functionModifiers);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, initFunc);
    auto methodDef = NodeAllocator::Alloc<ir::MethodDefinition>(allocator_, ir::MethodDefinitionKind::METHOD,
                                                                initIdent->Clone(allocator_, nullptr)->AsExpression(),
                                                                funcExpr, functionModifiers, allocator_, false);
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
                                                                      ir::ClassDefinition *classDef, bool isPackage)
{
    auto globalDecl = GlobalDeclTransformer(allocator_);
    auto statements = globalDecl.TransformStatements(globalStmts->Statements(), isPackage);
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

void GlobalClassHandler::InitCallToCCTOR(parser::Program *program, const ArenaVector<GlobalStmts> &initStatements)
{
    auto globalClass = program->GlobalClass();
    auto globalDecl = globalClass->Parent()->AsClassDeclaration();
    program->Ast()->Statements().emplace_back(globalDecl);
    globalDecl->SetParent(program->Ast());
    InitGlobalClass(globalClass, program->Kind());
    auto &globalBody = globalClass->Body();
    if (program->GetPackageName().Empty() && program->Kind() != parser::ScriptKind::STDLIB) {
        ir::MethodDefinition *initMethod = CreateAndFillInitMethod(initStatements);
        if (initMethod != nullptr) {
            initMethod->SetParent(program->GlobalClass());
            globalBody.insert(globalBody.begin(), initMethod);
            if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
                AddInitCall(program->GlobalClass(), initMethod);
            }
        }
    }
}

}  // namespace ark::es2panda::compiler