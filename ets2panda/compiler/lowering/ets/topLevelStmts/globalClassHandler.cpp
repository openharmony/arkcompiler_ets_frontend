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
#include "util/ustring.h"

namespace ark::es2panda::compiler {

using util::NodeAllocator;

static bool FunctionExists(const ArenaVector<ir::Statement *> &statements, const std::string_view name)
{
    for (auto stmt : statements) {
        if (stmt->IsFunctionDeclaration() && stmt->AsFunctionDeclaration()->Function()->Id()->Name().Is(name)) {
            return true;
        }
    }
    return false;
}

void GlobalClassHandler::InitGlobalClass(const ArenaVector<parser::Program *> &programs,
                                         const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms)
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
    bool triggeringCCtorMethodExists = false;

    bool isEntrypoint = programs.size() == 1 ? programs.front()->IsEntryPoint() : false;
    for (auto program : programs) {
        program->Ast()->IterateRecursively(addCCtor);
        if (program->IsEntryPoint() && !mainExists &&
            FunctionExists(program->Ast()->Statements(), compiler::Signatures::MAIN)) {
            mainExists = true;
        }
        if (!triggeringCCtorMethodExists && FunctionExists(program->Ast()->Statements(), TRIGGER_CCTOR)) {
            triggeringCCtorMethodExists = true;
        }

        auto stmts = MakeGlobalStatements(program->Ast(), globalClass, isEntrypoint);
        if (!topLevelStatementsExist && !stmts.empty()) {
            topLevelStatementsExist = true;
        }
        statements.emplace_back(GlobalStmts {program, std::move(stmts)});
        program->SetGlobalClass(globalClass);
    }
    InitCallToCCTOR(programs.front(), triggeringCCtorMethodsAndPrograms, statements, mainExists,
                    topLevelStatementsExist, triggeringCCtorMethodExists);
}

ir::MethodDefinition *GlobalClassHandler::CreateAndFillTopLevelMethod(
    parser::Program *program,
    const GlobalClassHandler::TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms,
    const ArenaVector<GlobalClassHandler::GlobalStmts> &initStatements, const std::string_view name,
    bool exportFunction)
{
    const auto functionFlags = ir::ScriptFunctionFlags::NONE;
    auto functionModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;
    if (exportFunction) {
        functionModifiers |= ir::ModifierFlags::EXPORT;
    }
    auto *ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, name, allocator_);

    ArenaVector<ir::Expression *> params(allocator_->Adapter());

    ArenaVector<ir::Statement *> statements(allocator_->Adapter());

    auto *body = NodeAllocator::Alloc<ir::BlockStatement>(allocator_, allocator_, std::move(statements));
    if (!util::Helpers::IsStdLib(program) && util::StringView(name).Is(INIT_NAME)) {
        AddTriggerCctrMethodsToInit(body, triggeringCCtorMethodsAndPrograms);
    }

    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);

    auto *func = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator_, allocator_,
        ir::ScriptFunction::ScriptFunctionData {
            body, std::move(funcSignature), functionFlags, {}, false, Language(Language::Id::ETS)});

    func->SetIdent(ident);
    func->AddModifier(functionModifiers);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, func);
    auto *methodDef = NodeAllocator::Alloc<ir::MethodDefinition>(allocator_, ir::MethodDefinitionKind::METHOD,
                                                                 ident->Clone(allocator_, nullptr)->AsExpression(),
                                                                 funcExpr, functionModifiers, allocator_, false);

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

util::UString GlobalClassHandler::ReplaceSpecialCharacters(util::UString *word) const
/*
 * This function replaces special characters that might occur in a a filename but should not be in a method name.
 *
 * `$` is an exception: it is replaced so that it would not crash with the naming in `FormTriggeringCCtorMethodName`.
 */
{
    std::unordered_map<char, std::string> replacements = {
        {'.', "$DOT$"},
        {':', "$COLON$"},
        {';', "$SEMICOLON$"},
        {',', "$COMMA$"},
        {'/', "$SLASH$"},
        {'\\', "$BACKSLASH$"},
        {'|', "$PIPE$"},
        {'!', "$EXCL_MARK$"},
        {'?', "$QUESTION_MARK$"},
        {'~', "$TILDE$"},
        {'@', "$AT_SIGN$"},
        {'&', "$AND_SIGN$"},
        {'#', "$HASHMARK$"},
        {'$', "$DOLLAR_SIGN$"},
        {'^', "$CARET$"},
        {'*', "$ASTERISK$"},
        {'=', "$EQUAL_SIGN$"},
        {'(', "$OPEN_PARENTHESIS$"},
        {')', "$CLOSE_PARENTHESIS$"},
        {'{', "$OPEN_CURLY_BRACE$"},
        {'}', "$CLOSE_CURLY_BRACE$"},
        {'[', "$OPEN_BRACKET$"},
        {']', "$CLOSE_BRACKET$"},
        {'<', "$OPEN_ANGULAR_BRACKET$"},
        {'>', "$CLOSE_ANGULAR_BRACKET$"},
        {'\'', "$APOSTROPHE$"},
        {'"', "$DOUBLE_QUOTATION_MARK$"},
        {' ', "$SPACE$"},
    };

    size_t pos = 0;

    auto text = word->View().Mutf8();
    while (pos < text.size()) {
        char currentChar = text[pos];

        if (replacements.find(currentChar) != replacements.end()) {
            const auto replacement = replacements.at(currentChar);
            text.replace(pos, 1, replacement);

            pos += replacement.size();
        } else {
            ++pos;
        }
    }

    return util::UString(text, allocator_);
}

util::StringView GlobalClassHandler::FormTriggeringCCtorMethodName(util::StringView importPath) const
{
    auto path = util::UString(importPath.Mutf8(), allocator_);
    auto modifiedPath = ReplaceSpecialCharacters(&path);
    util::UString name = util::UString(util::StringView(TRIGGER_CCTOR).Mutf8(), allocator_);
    name.Append(util::StringView("for_"));
    name.Append(modifiedPath.View());
    name.Append(util::StringView("$_"));

    return name.View();
}

void GlobalClassHandler::AddTriggerCctrMethodsToInit(
    ir::BlockStatement *blockBody, const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms)
{
    if (triggeringCCtorMethodsAndPrograms == nullptr) {
        return;
    }
    ArenaSet<util::StringView> calledTriggeringCCtors {allocator_->Adapter()};
    for (auto &[packageName, triggeringCCtorProgramPairs] : *triggeringCCtorMethodsAndPrograms) {
        for (auto [triggeringCCtorName, extProg] : triggeringCCtorProgramPairs) {
            if (util::Helpers::IsStdLib(extProg)) {
                continue;
            }
            auto &extGlobalBody = extProg->GlobalClass()->Body();
            auto triggeringCCtorNode = std::find_if(extGlobalBody.begin(), extGlobalBody.end(), [](ir::AstNode *node) {
                return node->IsMethodDefinition() &&
                       node->AsMethodDefinition()->Key()->AsIdentifier()->Name().Is(TRIGGER_CCTOR);
            });
            if (triggeringCCtorNode == extGlobalBody.end()) {
                continue;
            }
            if (!calledTriggeringCCtors.insert(triggeringCCtorName).second) {
                continue;
            }
            auto *callee = RefIdent(triggeringCCtorName);
            auto *const callExpr = NodeAllocator::Alloc<ir::CallExpression>(
                allocator_, callee, ArenaVector<ir::Expression *>(allocator_->Adapter()), nullptr, false, false);

            auto exprStmt = NodeAllocator::Alloc<ir::ExpressionStatement>(allocator_, callExpr);
            exprStmt->SetParent(blockBody);
            blockBody->Statements().push_back(exprStmt);
            if (extProg->IsPackageModule()) {
                break;
            }
        }
    }
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

void GlobalClassHandler::InitCallToCCTOR(parser::Program *program,
                                         const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms,
                                         const ArenaVector<GlobalStmts> &initStatements, bool mainExists,
                                         bool topLevelStatementsExist, bool triggeringCCtorMethodExists)
{
    auto globalClass = program->GlobalClass();
    auto globalDecl = globalClass->Parent()->AsClassDeclaration();
    program->Ast()->Statements().emplace_back(globalDecl);
    globalDecl->SetParent(program->Ast());
    InitGlobalClass(globalClass, program->Kind());
    auto &globalBody = globalClass->Body();

    if (program->Kind() == parser::ScriptKind::STDLIB || util::Helpers::IsStdLib(program)) {
        return;
    }
    if (!program->IsDeclarationModule()) {
        ir::MethodDefinition *initMethod = nullptr;
        initMethod = CreateAndFillTopLevelMethod(program, triggeringCCtorMethodsAndPrograms, initStatements, INIT_NAME);
        if (initMethod != nullptr) {
            initMethod->SetParent(program->GlobalClass());
            globalBody.insert(globalBody.begin(), initMethod);
            if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
                AddInitCall(program->GlobalClass(), initMethod);
            }
        }
    }

    // NOTE(rsipka): unclear call, OmitModuleName() used to determine the entry points without --ets-module option
    if (program->OmitModuleName()) {
        ir::MethodDefinition *mainMethod = nullptr;
        if (!mainExists && topLevelStatementsExist) {
            const ArenaVector<GlobalStmts> emptyStatements(allocator_->Adapter());
            mainMethod = CreateAndFillTopLevelMethod(program, nullptr, emptyStatements, compiler::Signatures::MAIN);
        }
        if (mainMethod != nullptr) {
            mainMethod->SetParent(program->GlobalClass());
            globalBody.insert(globalBody.begin(), mainMethod);
        }
    }

    if (!triggeringCCtorMethodExists && !program->IsDeclarationModule()) {
        const ArenaVector<GlobalStmts> emptyStatements(allocator_->Adapter());
        ir::MethodDefinition *cctrTriggerMethod =
            CreateAndFillTopLevelMethod(program, nullptr, emptyStatements, TRIGGER_CCTOR, true);
        cctrTriggerMethod->SetParent(program->GlobalClass());
        globalBody.insert(globalBody.end(), cctrTriggerMethod);
    }
}

}  // namespace ark::es2panda::compiler
