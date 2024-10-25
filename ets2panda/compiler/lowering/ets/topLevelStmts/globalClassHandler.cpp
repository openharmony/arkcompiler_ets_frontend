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
#include "compiler/lowering/ets/topLevelStmts/globalDeclTransformer.h"
#include "compiler/lowering/util.h"

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

void GlobalClassHandler::SetupGlobalClass(const ArenaVector<parser::Program *> &programs,
                                          const ModuleDependencies *moduleDependencies)
{
    if (programs.empty()) {
        return;
    }
    ir::ClassDeclaration *const globalDecl = CreateGlobalClass();
    ir::ClassDefinition *const globalClass = globalDecl->Definition();

    auto addStaticBlock = [this](ir::AstNode *node) {
        if (node->IsClassDefinition()) {
            auto classDef = node->AsClassDefinition();
            if (auto staticBlock = CreateStaticBlock(classDef); staticBlock != nullptr) {
                classDef->Body().emplace_back(staticBlock);  // NOTE(vpukhov): inserted to end for some reason
                staticBlock->SetParent(classDef);
            }
        }
    };

    ArenaVector<GlobalStmts> statements(allocator_->Adapter());
    bool mainExists = false;
    bool topLevelStatementsExist = false;
    parser::Program *const globalProgram = programs.front();

    bool isEntrypoint = programs.size() == 1 ? globalProgram->IsEntryPoint() : false;
    for (auto program : programs) {
        program->Ast()->IterateRecursively(addStaticBlock);
        if (program->IsEntryPoint() && !mainExists &&
            FunctionExists(program->Ast()->Statements(), compiler::Signatures::MAIN)) {
            mainExists = true;
        }
        auto stmts = CollectProgramGlobalStatements(program, globalClass, isEntrypoint);
        if (!topLevelStatementsExist && !stmts.empty()) {
            topLevelStatementsExist = true;
        }
        statements.emplace_back(GlobalStmts {program, std::move(stmts)});
        program->SetGlobalClass(globalClass);
    }

    globalProgram->Ast()->Statements().emplace_back(globalDecl);
    globalDecl->SetParent(globalProgram->Ast());
    globalClass->SetGlobalInitialized();

    // NOTE(vpukhov): stdlib checks are to be removed - do not extend the existing logic
    if (globalProgram->Kind() != parser::ScriptKind::STDLIB) {
        addStaticBlock(globalClass);
        if (!util::Helpers::IsStdLib(globalProgram)) {
            auto initStatements = FormInitMethodStatements(globalProgram, moduleDependencies, std::move(statements));
            SetupGlobalMethods(globalProgram, std::move(initStatements), mainExists, topLevelStatementsExist);
        }
    }
}

ir::MethodDefinition *GlobalClassHandler::CreateGlobalMethod(const std::string_view name,
                                                             ArenaVector<ir::Statement *> &&statements)
{
    const auto functionFlags = ir::ScriptFunctionFlags::NONE;
    auto functionModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;
    auto ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, name, allocator_);
    auto body = NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator_, allocator_, std::move(statements));
    auto funcSignature = ir::FunctionSignature(nullptr, ArenaVector<ir::Expression *>(allocator_->Adapter()), nullptr);

    auto *func = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator_, allocator_,
        ir::ScriptFunction::ScriptFunctionData {
            body, std::move(funcSignature), functionFlags, {}, false, Language(Language::Id::ETS)});

    func->SetIdent(ident);
    func->AddModifier(functionModifiers);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, func);
    return NodeAllocator::Alloc<ir::MethodDefinition>(allocator_, ir::MethodDefinitionKind::METHOD,
                                                      ident->Clone(allocator_, nullptr)->AsExpression(), funcExpr,
                                                      functionModifiers, allocator_, false);
}

void GlobalClassHandler::AddInitCallFromStaticBlock(ir::ClassDefinition *globalClass, ir::MethodDefinition *initMethod)
{
    ASSERT(initMethod != nullptr);

    auto &globalBody = globalClass->Body();
    auto maybeStaticBlock = std::find_if(globalBody.begin(), globalBody.end(),
                                         [](ir::AstNode *node) { return node->IsClassStaticBlock(); });
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

ArenaVector<ir::Statement *> GlobalClassHandler::FormInitMethodStatements(parser::Program *program,
                                                                          const ModuleDependencies *moduleDependencies,
                                                                          ArenaVector<GlobalStmts> &&initStatements)
{
    ArenaVector<ir::Statement *> statements(allocator_->Adapter());
    if (!util::Helpers::IsStdLib(program) && moduleDependencies != nullptr) {
        FormDependentInitTriggers(statements, moduleDependencies);
    }
    for (const auto &[p, ps] : initStatements) {
        statements.insert(statements.end(), ps.begin(), ps.end());
    }
    for (auto st : statements) {
        st->SetParent(nullptr);
    }
    return statements;
}

void GlobalClassHandler::FormDependentInitTriggers(ArenaVector<ir::Statement *> &statements,
                                                   const ModuleDependencies *moduleDependencies)
{
    auto const sequence = [&statements](ir::Statement *stmt) { statements.push_back(stmt); };

    auto triggerInitOf = [this, sequence, initialized = false](parser::Program *prog) mutable {
        if (!initialized) {
            initialized = true;
            sequence(parser_->CreateFormattedStatement("const __linker = Class.ofCaller().getLinker();"));
        }
        std::string name = (prog->OmitModuleName() ? "" : std::string(prog->ModuleName()) + ".") + "ETSGLOBAL";
        sequence(parser_->CreateFormattedStatement("__linker.loadClass(\"" + name + "\", true);"));
    };

    for (auto depProg : *moduleDependencies) {
        if (util::Helpers::IsStdLib(depProg)) {
            continue;
        }
        triggerInitOf(depProg);
    }
}

ir::ClassStaticBlock *GlobalClassHandler::CreateStaticBlock(ir::ClassDefinition *classDef)
{
    bool hasStaticField = false;
    for (const auto *prop : classDef->Body()) {
        if (prop->IsClassStaticBlock()) {
            return nullptr;
        }
        if (prop->IsClassProperty() && prop->AsClassProperty()->IsStatic()) {
            hasStaticField = true;
        }
    }

    if (!hasStaticField && !classDef->IsGlobal()) {
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
    staticBlock->SetRange({classDef->Start(), classDef->Start()});
    return staticBlock;
}

ArenaVector<ir::Statement *> GlobalClassHandler::CollectProgramGlobalStatements(parser::Program *program,
                                                                                ir::ClassDefinition *classDef,
                                                                                bool addInitializer)
{
    auto ast = program->Ast();
    auto globalDecl = GlobalDeclTransformer(allocator_);
    auto statements = globalDecl.TransformStatements(ast->Statements(), addInitializer);
    classDef->AddProperties(util::Helpers::ConvertVector<ir::AstNode>(statements.classProperties));
    globalDecl.FilterDeclarations(ast->Statements());
    return std::move(statements.initStatements);
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

void GlobalClassHandler::SetupGlobalMethods(parser::Program *program, ArenaVector<ir::Statement *> &&initStatements,
                                            bool mainExists, bool topLevelStatementsExist)
{
    ir::ClassDefinition *const globalClass = program->GlobalClass();

    auto const insertInGlobal = [globalClass](ir::AstNode *node) {
        // NOTE(vpukhov): inserted to begin for some reason
        globalClass->Body().insert(globalClass->Body().begin(), node);
        node->SetParent(globalClass);
    };

    if (!program->IsDeclarationModule()) {
        ir::MethodDefinition *initMethod =
            CreateGlobalMethod(compiler::Signatures::INIT_METHOD, std::move(initStatements));
        insertInGlobal(initMethod);
        if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
            AddInitCallFromStaticBlock(globalClass, initMethod);
        }
    }

    // NOTE(rsipka): unclear call, OmitModuleName() used to determine the entry points without --ets-module option
    if (program->OmitModuleName()) {
        if (!mainExists && topLevelStatementsExist) {
            ir::MethodDefinition *mainMethod =
                CreateGlobalMethod(compiler::Signatures::MAIN, ArenaVector<ir::Statement *>(allocator_->Adapter()));
            insertInGlobal(mainMethod);
        }
    }
}

}  // namespace ark::es2panda::compiler
