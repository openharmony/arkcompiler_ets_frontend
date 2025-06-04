/*
 * Copyright (c) 2023 - 2025 Huawei Device Co., Ltd.
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
#include "utils/arena_containers.h"
#include "generated/diagnostic.h"

namespace ark::es2panda::compiler {

using util::NodeAllocator;

void GlobalClassHandler::AddStaticBlockToClass(ir::AstNode *node)
{
    if (node->IsClassDefinition() && !node->AsClassDefinition()->IsDeclare()) {
        auto classDef = node->AsClassDefinition();
        if (auto staticBlock = CreateStaticBlock(classDef); staticBlock != nullptr) {
            classDef->Body().emplace_back(staticBlock);  // NOTE(vpukhov): inserted to end for some reason
            staticBlock->SetParent(classDef);
        }
    }
}

std::string AddToNamespaceChain(std::string chain, std::string name)
{
    if (chain.empty()) {
        return name;
    }
    if (name.empty()) {
        return chain;
    }
    return chain + "." + name;
}

void GlobalClassHandler::CollectNamespaceExportedClasses(ir::ClassDefinition *classDef)
{
    CollectExportedClasses(classDef, classDef->Body());
}

template <class Node>
void GlobalClassHandler::CollectExportedClasses(ir::ClassDefinition *classDef, const ArenaVector<Node *> &statements)
{
    for (const auto *statement : statements) {
        if (!statement->IsExported()) {
            continue;
        }
        if (statement->IsClassDeclaration()) {
            classDef->AddToExportedClasses(statement->AsClassDeclaration());
        }
    }
}

ir::ClassDeclaration *GlobalClassHandler::CreateTransformedClass(ir::ETSModule *ns)
{
    auto className = ns->Ident()->Name();
    auto *ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, className, allocator_);
    ident->SetRange(ns->Ident()->Range());

    auto *classDef = NodeAllocator::Alloc<ir::ClassDefinition>(
        allocator_, allocator_, ident, ir::ClassDefinitionModifiers::CLASS_DECL, ir::ModifierFlags::ABSTRACT,
        Language(Language::Id::ETS));
    classDef->SetRange(ns->Range());
    classDef->AddModifier(ns->Modifiers());
    auto *classDecl = NodeAllocator::Alloc<ir::ClassDeclaration>(allocator_, classDef, allocator_);
    classDecl->AddModifier(ns->Modifiers());
    classDef->SetNamespaceTransformed();
    ArenaVector<ir::AnnotationUsage *> annotations {allocator_->Adapter()};
    for (auto *anno : ns->Annotations()) {
        auto clone = anno->Clone(allocator_, classDef);
        annotations.push_back(clone);
    }

    classDef->SetAnnotations(std::move(annotations));
    return classDecl;
}

void GlobalClassHandler::SetupGlobalMethods(parser::Program *program, ArenaVector<ir::Statement *> &&initStatements,
                                            ArenaVector<ir::Statement *> &&initializerBlock,
                                            ir::ClassDefinition *globalClass, bool isDeclare)
{
    auto const insertInGlobal = [globalClass](ir::AstNode *node) {
        globalClass->Body().insert(globalClass->Body().begin(), node);
        node->SetParent(globalClass);
    };

    if (!isDeclare) {
        ir::MethodDefinition *initMethod =
            CreateGlobalMethod(compiler::Signatures::INIT_METHOD, std::move(initStatements), program);
        insertInGlobal(initMethod);
        if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
            AddInitCallFromStaticBlock(globalClass, initMethod);
        }

        ir::MethodDefinition *initializerBlockInit =
            CreateGlobalMethod(compiler::Signatures::INITIALIZER_BLOCK_INIT, std::move(initializerBlock), program);
        insertInGlobal(initializerBlockInit);
        if (!initializerBlockInit->Function()->Body()->AsBlockStatement()->Statements().empty()) {
            AddInitCallFromStaticBlock(globalClass, initializerBlockInit);
        }
    }
}

void GlobalClassHandler::MergeNamespace(ArenaVector<ir::ETSModule *> &namespaces, parser::Program *program)
{
    auto *parser = program->VarBinder()->GetContext()->parser->AsETSParser();
    ArenaUnorderedMap<util::StringView, ir::ETSModule *> nsMap {program->Allocator()->Adapter()};
    for (auto it = namespaces.begin(); it != namespaces.end();) {
        auto *ns = *it;
        auto res = nsMap.find(ns->Ident()->Name());
        if (res != nsMap.end()) {
            if (res->second->Modifiers() != ns->Modifiers()) {
                parser->LogError(diagnostic::NAMESPACE_MERGE_ERROR, {ns->Ident()->Name().Mutf8()}, ns->Start());
            }
            if (!res->second->Annotations().empty() && !ns->Annotations().empty()) {
                parser->LogError(diagnostic::NAMESPACE_ANNOTATION_CONFLICT, {ns->Ident()->Name().Mutf8()}, ns->Start());
            } else if (!ns->Annotations().empty()) {
                ES2PANDA_ASSERT(res->second->Annotations().empty());
                res->second->SetAnnotations(std::move(ns->Annotations()));
            }
            for (auto *statement : ns->Statements()) {
                res->second->Statements().emplace_back(statement);
            }
            namespaces.erase(it);
        } else {
            nsMap.insert({ns->Ident()->Name(), ns});
            ++it;
        }
    }
}

ArenaVector<ir::ClassDeclaration *> GlobalClassHandler::TransformNamespaces(ArenaVector<ir::ETSModule *> &namespaces,
                                                                            parser::Program *program)
{
    ArenaVector<ir::ClassDeclaration *> classDecls {allocator_->Adapter()};
    MergeNamespace(namespaces, program);
    for (auto ns : namespaces) {
        classDecls.emplace_back(TransformNamespace(ns, program));
    }
    return classDecls;
}

ir::ClassDeclaration *GlobalClassHandler::TransformNamespace(ir::ETSModule *ns, parser::Program *program)
{
    ir::ClassDeclaration *const globalDecl = CreateTransformedClass(ns);
    ir::ClassDefinition *const globalClass = globalDecl->Definition();

    ArenaVector<GlobalStmts> immediateInitializers(allocator_->Adapter());
    ArenaVector<GlobalStmts> initializerBlock(allocator_->Adapter());
    ArenaVector<ir::ETSModule *> namespaces(allocator_->Adapter());
    auto &body = ns->Statements();
    for (auto *statement : body) {
        statement->Iterate([this](ir::AstNode *node) { AddStaticBlockToClass(node); });
    }
    auto stmts = CollectProgramGlobalStatements(body, globalClass, ns);
    immediateInitializers.emplace_back(GlobalStmts {program, std::move(stmts[0])});
    initializerBlock.emplace_back(GlobalStmts {program, std::move(stmts[1])});
    AddStaticBlockToClass(globalClass);
    const ModuleDependencies md {allocator_->Adapter()};
    auto immediateInitStatements = FormInitMethodStatements(program, &md, std::move(immediateInitializers));
    auto initializerBlockStatements = FormInitMethodStatements(program, &md, std::move(initializerBlock));
    SetupGlobalMethods(program, std::move(immediateInitStatements), std::move(initializerBlockStatements), globalClass,
                       ns->IsDeclare());

    // remove namespaceDecl from orginal node
    auto end = std::remove_if(body.begin(), body.end(), [&namespaces](ir::AstNode *node) {
        if (node->IsETSModule()) {
            namespaces.emplace_back(node->AsETSModule());
            return true;
        }
        return false;
    });
    body.erase(end, body.end());
    auto globalClasses = TransformNamespaces(namespaces, program);
    for (auto *cls : globalClasses) {
        globalClass->Body().emplace_back(cls);
        cls->SetParent(globalClass);
        CollectNamespaceExportedClasses(cls->Definition());
    }

    // Add rest statement, such as type declaration
    for (auto *statement : body) {
        globalClass->Body().emplace_back(statement);
        statement->SetParent(globalClass);
    }
    body.clear();
    return globalDecl;
}

void GlobalClassHandler::CollectProgramGlobalClasses(parser::Program *program, ArenaVector<ir::ETSModule *> namespaces)
{
    auto classDecls = TransformNamespaces(namespaces, program);
    for (auto cls : classDecls) {
        program->Ast()->Statements().push_back(cls);
        cls->SetParent(program->Ast());
        CollectNamespaceExportedClasses(cls->Definition());
    }
}

void GlobalClassHandler::SetupGlobalClass(const ArenaVector<parser::Program *> &programs,
                                          const ModuleDependencies *moduleDependencies)
{
    if (programs.empty()) {
        return;
    }
    parser::Program *const globalProgram = programs.front();
    ir::ClassDeclaration *const globalDecl = CreateGlobalClass(globalProgram);
    ir::ClassDefinition *const globalClass = globalDecl->Definition();

    // NOTE(vpukhov): a clash inside program list is possible
    ES2PANDA_ASSERT(globalProgram->IsPackage() || programs.size() == 1);

    ArenaVector<GlobalStmts> statements(allocator_->Adapter());
    ArenaVector<ir::ETSModule *> namespaces(allocator_->Adapter());

    for (auto program : programs) {
        program->Ast()->IterateRecursively([this](ir::AstNode *node) { AddStaticBlockToClass(node); });
        auto &body = program->Ast()->Statements();
        auto stmts = CollectProgramGlobalStatements(body, globalClass, program->Ast());
        auto end = std::remove_if(body.begin(), body.end(), [&namespaces](ir::AstNode *node) {
            if (node->IsETSModule() && node->AsETSModule()->IsNamespace()) {
                namespaces.emplace_back(node->AsETSModule());
                return true;
            }
            return false;
        });
        body.erase(end, body.end());
        // NOTE: Initializer block for Package is to be done(xingshunxiang).
        statements.emplace_back(GlobalStmts {program, std::move(stmts[0])});
        program->SetGlobalClass(globalClass);
    }

    globalProgram->Ast()->Statements().emplace_back(globalDecl);
    globalDecl->SetParent(globalProgram->Ast());
    globalClass->SetGlobalInitialized();

    CollectProgramGlobalClasses(globalProgram, namespaces);

    CollectExportedClasses(globalClass, globalProgram->Ast()->Statements());

    // NOTE(vpukhov): stdlib checks are to be removed - do not extend the existing logic
    if (globalProgram->Kind() != parser::ScriptKind::STDLIB) {
        AddStaticBlockToClass(globalClass);
        if (!util::Helpers::IsStdLib(globalProgram)) {
            auto initStatements = FormInitMethodStatements(globalProgram, moduleDependencies, std::move(statements));
            SetupGlobalMethods(globalProgram, std::move(initStatements));
        }
    }
}

ir::MethodDefinition *GlobalClassHandler::CreateGlobalMethod(const std::string_view name,
                                                             ArenaVector<ir::Statement *> &&statements,
                                                             const parser::Program *program)
{
    const auto functionFlags = ir::ScriptFunctionFlags::NONE;
    auto functionModifiers = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC;
    auto ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, name, allocator_);
    auto body = NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator_, allocator_, std::move(statements));
    auto funcSignature = ir::FunctionSignature(nullptr, ArenaVector<ir::Expression *>(allocator_->Adapter()), nullptr);

    auto *func = NodeAllocator::Alloc<ir::ScriptFunction>(
        allocator_, allocator_,
        ir::ScriptFunction::ScriptFunctionData {
            body, std::move(funcSignature), functionFlags, {}, Language(Language::Id::ETS)});

    func->SetIdent(ident);
    func->AddModifier(functionModifiers);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, func);
    auto *methodDef = NodeAllocator::Alloc<ir::MethodDefinition>(allocator_, ir::MethodDefinitionKind::METHOD,
                                                                 ident->Clone(allocator_, nullptr)->AsExpression(),
                                                                 funcExpr, functionModifiers, allocator_, false);
    methodDef->SetRange({lexer::SourcePosition(program), lexer::SourcePosition(program)});
    return methodDef;
}

void GlobalClassHandler::AddInitCallFromStaticBlock(ir::ClassDefinition *globalClass, ir::MethodDefinition *initMethod)
{
    ES2PANDA_ASSERT(initMethod != nullptr);

    auto &globalBody = globalClass->Body();
    auto maybeStaticBlock = std::find_if(globalBody.begin(), globalBody.end(),
                                         [](ir::AstNode *node) { return node->IsClassStaticBlock(); });
    ES2PANDA_ASSERT(maybeStaticBlock != globalBody.end());

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
        auto name = std::string(prog->ModulePrefix()).append(Signatures::ETS_GLOBAL);
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

    if (!hasStaticField && !classDef->IsModule()) {
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
                                                ir::ModifierFlags::STATIC, Language(Language::Id::ETS)});

    func->SetIdent(id);

    auto *funcExpr = NodeAllocator::Alloc<ir::FunctionExpression>(allocator_, func);
    auto *staticBlock = NodeAllocator::Alloc<ir::ClassStaticBlock>(allocator_, funcExpr, allocator_);
    staticBlock->AddModifier(ir::ModifierFlags::STATIC);
    staticBlock->SetRange({classDef->Start(), classDef->Start()});
    return staticBlock;
}

ArenaVector<ArenaVector<ir::Statement *>> GlobalClassHandler::CollectProgramGlobalStatements(
    ArenaVector<ir::Statement *> &stmts, ir::ClassDefinition *classDef, ir::Statement const *stmt)
{
    auto globalDecl = GlobalDeclTransformer(allocator_, stmt, parser_);
    auto statements = globalDecl.TransformStatements(stmts);
    if (globalDecl.IsMultiInitializer()) {
        parser_->LogError(diagnostic::MULTIPLE_STATIC_BLOCK, {}, stmt->Start());
    }
    classDef->AddProperties(util::Helpers::ConvertVector<ir::AstNode>(statements.classProperties));
    /*
    initializers consists of two parts:
    immediate initializers and initializer blocks, the former should be executed firstly.

    Example code:
        namespace NS {
            let a: number;
            let b: number = 2;
            static {
                a = 1;
                b = 0;
            }
        }

    In the example code, execute order will be: b = 2, a = 1, b = 0;
    */
    globalDecl.FilterDeclarations(stmts);
    return std::move(statements.initializers);
}

ir::ClassDeclaration *GlobalClassHandler::CreateGlobalClass(const parser::Program *const globalProgram)
{
    const auto rangeToStartOfFile =
        lexer::SourceRange(lexer::SourcePosition(globalProgram), lexer::SourcePosition(globalProgram));
    auto *ident = NodeAllocator::Alloc<ir::Identifier>(allocator_, compiler::Signatures::ETS_GLOBAL, allocator_);
    ident->SetRange(rangeToStartOfFile);
    auto *classDef =
        NodeAllocator::Alloc<ir::ClassDefinition>(allocator_, allocator_, ident, ir::ClassDefinitionModifiers::GLOBAL,
                                                  ir::ModifierFlags::ABSTRACT, Language(Language::Id::ETS));
    classDef->SetRange(rangeToStartOfFile);
    auto *classDecl = NodeAllocator::Alloc<ir::ClassDeclaration>(allocator_, classDef, allocator_);
    classDecl->SetRange(rangeToStartOfFile);

    return classDecl;
}

static bool HasMethod(ir::ClassDefinition const *cls, const std::string_view name)
{
    return std::any_of(cls->Body().begin(), cls->Body().end(), [name](ir::AstNode const *node) {
        return node->IsMethodDefinition() && node->AsMethodDefinition()->Key()->AsIdentifier()->Name().Is(name);
    });
}

void GlobalClassHandler::SetupGlobalMethods(parser::Program *program, ArenaVector<ir::Statement *> &&initStatements)
{
    ir::ClassDefinition *const globalClass = program->GlobalClass();

    auto const insertInGlobal = [globalClass](ir::AstNode *node) {
        // NOTE(vpukhov): inserted to begin for some reason
        globalClass->Body().insert(globalClass->Body().begin(), node);
        node->SetParent(globalClass);
    };

    if (!program->IsDeclarationModule()) {
        ir::MethodDefinition *initMethod =
            CreateGlobalMethod(compiler::Signatures::INIT_METHOD, std::move(initStatements), program);
        insertInGlobal(initMethod);
        if (!initMethod->Function()->Body()->AsBlockStatement()->Statements().empty()) {
            AddInitCallFromStaticBlock(globalClass, initMethod);
        }
    }

    if (program->IsSeparateModule() && !HasMethod(globalClass, compiler::Signatures::MAIN)) {
        ir::MethodDefinition *mainMethod = CreateGlobalMethod(
            compiler::Signatures::MAIN, ArenaVector<ir::Statement *>(allocator_->Adapter()), program);
        insertInGlobal(mainMethod);
    }
}

}  // namespace ark::es2panda::compiler
