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

#include <utility>
#include "checker/ETSchecker.h"

#include "compiler/lowering/util.h"
#include "varbinder/declaration.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "checker/ets/dynamic/dynamicCall.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/thisExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/returnStatement.h"
#include "parser/program/program.h"
#include "util/helpers.h"
#include "util/language.h"
#include "generated/signatures.h"
#include "ir/ets/etsParameterExpression.h"

namespace ark::es2panda::checker {

void ProcessCheckerNode(ETSChecker *checker, ir::AstNode *node)
{
    auto scope = compiler::NearestScope(node);
    ES2PANDA_ASSERT(scope != nullptr);
    if (scope->IsGlobalScope()) {
        // NOTE(aleksisch): All classes are contained in ETSGlobal class scope (not just Global scope),
        // however it's parent is ETSModule. It should be fixed
        scope = checker->VarBinder()->Program()->GlobalClassScope();
    }

    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
    checker->VarBinder()->AsETSBinder()->ResolveReference(node);

    if (node->IsMethodDefinition()) {
        // NOTE(aleksisch): This should be done in varbinder,
        // however right now checker do it when called on ClassDefinition
        auto method = node->AsMethodDefinition();
        auto func = method->Value()->AsFunctionExpression()->Function();
        ES2PANDA_ASSERT(method->Id() != nullptr);
        func->Id()->SetVariable(method->Id()->Variable());
    }
    ScopeContext checkerScope(checker, scope);
    node->Check(checker);
}

void ProcessScopesNode(ETSChecker *checker, ir::AstNode *node)
{
    auto *scope = compiler::NearestScope(node);
    ES2PANDA_ASSERT(scope != nullptr);
    if (scope->IsGlobalScope()) {
        // NOTE(aleksisch): All classes are contained in ETSGlobal scope,
        // however it's parent is ETSModule (not ETSGlobal). It should be fixed
        scope = checker->VarBinder()->Program()->GlobalClassScope();
    }
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
    compiler::InitScopesPhaseETS::RunExternalNode(node, checker->VarBinder());
}

ir::ETSParameterExpression *ETSChecker::AddParam(util::StringView name, ir::TypeNode *type)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *paramIdent = ProgramAllocNode<ir::Identifier>(name, ProgramAllocator());
    if (type != nullptr) {
        paramIdent->SetTsTypeAnnotation(type);
        type->SetParent(paramIdent);
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return ProgramAllocNode<ir::ETSParameterExpression>(paramIdent, false, ProgramAllocator());
}

template <typename T>
ir::MethodDefinition *ETSChecker::CreateDynamicCallIntrinsic(ir::Expression *callee, const ArenaVector<T *> &arguments,
                                                             Language lang)
{
    ArenaVector<ir::Expression *> params(ProgramAllocator()->Adapter());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto dynamicTypeNode = ProgramAllocNode<ir::OpaqueTypeNode>(GlobalBuiltinDynamicType(lang), ProgramAllocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto intTypeNode = ProgramAllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, ProgramAllocator());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *objParam = AddParam("obj", dynamicTypeNode);
    params.push_back(objParam);

    ir::ETSParameterExpression *param2;
    if (!DynamicCall::IsByValue(VarBinder()->AsETSBinder(), callee)) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        param2 = AddParam("qname_start", intTypeNode);
        params.push_back(param2);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        param2 = AddParam("qname_len", intTypeNode->Clone(ProgramAllocator(), nullptr));
    } else {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        param2 = AddParam("this", dynamicTypeNode->Clone(ProgramAllocator(), nullptr));
    }

    params.push_back(param2);

    for (size_t i = 0; i < arguments.size(); i++) {
        util::UString paramName("p" + std::to_string(i), ProgramAllocator());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto paramType = arguments[i]->TsType()->IsLambdaObject()
                             // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                             ? dynamicTypeNode->Clone(ProgramAllocator(), nullptr)
                             // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                             : ProgramAllocNode<ir::OpaqueTypeNode>(arguments[i]->TsType(), ProgramAllocator());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        params.emplace_back(AddParam(paramName.View(), paramType));
    }

    auto funcSignature =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ir::FunctionSignature(nullptr, std::move(params), dynamicTypeNode->Clone(ProgramAllocator(), nullptr));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = ProgramAllocNode<ir::ScriptFunction>(
        ProgramAllocator(),
        ir::ScriptFunction::ScriptFunctionData {nullptr, std::move(funcSignature), ir::ScriptFunctionFlags::METHOD,
                                                ir::ModifierFlags::NONE});

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *name = ProgramAllocNode<ir::Identifier>(compiler::Signatures::STATIC_INVOKE_METHOD, ProgramAllocator());
    func->SetIdent(name);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = ProgramAllocNode<ir::FunctionExpression>(func);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *method = ProgramAllocNode<ir::MethodDefinition>(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ir::MethodDefinitionKind::METHOD, func->Id()->Clone(ProgramAllocator(), nullptr), funcExpr,
        ir::ModifierFlags::PUBLIC | ir::ModifierFlags::NATIVE | ir::ModifierFlags::STATIC, ProgramAllocator(), false);
    return method;
}

static void ToString(ETSChecker *checker, const ArenaVector<ir::Expression *> &arguments, std::stringstream &ss)
{
    for (auto *arg : arguments) {
        auto type = arg->Check(checker);
        ss << "-";
        type->ToString(ss);
    }
}

static void ToString([[maybe_unused]] ETSChecker *checker, const ArenaVector<varbinder::LocalVariable *> &arguments,
                     std::stringstream &ss)
{
    for (auto *arg : arguments) {
        auto *type = arg->TsType();
        ss << "-";
        type->ToString(ss);
    }
}

template <typename T>
Signature *ETSChecker::ResolveDynamicCallExpression(ir::Expression *callee, const ArenaVector<T *> &arguments,
                                                    Language lang, bool isConstruct)
{
    auto &dynamicIntrinsics = *DynamicCallIntrinsics(isConstruct);

    auto mapIt = dynamicIntrinsics.find(lang);
    if (mapIt == dynamicIntrinsics.cend()) {
        std::tie(mapIt, std::ignore) = dynamicIntrinsics.emplace(lang, ProgramAllocator()->Adapter());
    }

    auto &map = mapIt->second;

    std::stringstream ss;
    ss << "dyncall";
    if (DynamicCall::IsByValue(VarBinder()->AsETSBinder(), callee)) {
        ss << "-byvalue";
    } else {
        const auto callNames = DynamicCall::ResolveCall(VarBinder()->AsETSBinder(), callee);
        DynamicCallNames(isConstruct)->try_emplace(callNames.name, 0);
    }

    ToString(this, arguments, ss);

    auto key = ss.str();
    auto it = map.find(util::StringView(key));
    if (it == map.end()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto klass = GetDynamicClass(lang, isConstruct);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *method = CreateDynamicCallIntrinsic(callee, arguments, lang);
        auto props = ArenaVector<ir::AstNode *>(ProgramAllocator()->Adapter());
        props.emplace_back(method);
        klass->Definition()->AddProperties(std::move(props));

        {
            auto prevClass = VarBinder()->AsETSBinder()->GetGlobalRecordTable()->ClassDefinition();
            VarBinder()->AsETSBinder()->GetGlobalRecordTable()->SetClassDefinition(klass->Definition());
            ProcessScopesNode(this, method);
            ProcessCheckerNode(this, method);
            VarBinder()->AsETSBinder()->GetGlobalRecordTable()->SetClassDefinition(prevClass);
        }
        method->Function()->Signature()->SetReturnType(GlobalBuiltinDynamicType(lang));

        map.emplace(util::UString(key, ProgramAllocator()).View(), method->Function());
        return method->Function()->Signature();
    }

    return it->second->Signature();
}

template Signature *ETSChecker::ResolveDynamicCallExpression<ir::Expression>(
    ir::Expression *callee, const ArenaVector<ir::Expression *> &arguments, Language lang, bool isConstruct);

template Signature *ETSChecker::ResolveDynamicCallExpression<varbinder::LocalVariable>(
    ir::Expression *callee, const ArenaVector<varbinder::LocalVariable *> &arguments, Language lang, bool isConstruct);

std::pair<ir::ScriptFunction *, ir::Identifier *> ETSChecker::CreateStaticScriptFunction(
    ClassInitializerBuilder const &builder)
{
    ArenaVector<ir::Statement *> statements(ProgramAllocator()->Adapter());
    ArenaVector<ir::Expression *> params(ProgramAllocator()->Adapter());

    ir::ScriptFunction *func;
    ir::Identifier *id;

    builder(&statements, nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = ProgramAllocNode<ir::BlockStatement>(ProgramAllocator(), std::move(statements));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    id = ProgramAllocNode<ir::Identifier>(compiler::Signatures::CCTOR, ProgramAllocator());
    auto signature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
    // clang-format off
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    func = ProgramAllocNode<ir::ScriptFunction>(
        ProgramAllocator(), ir::ScriptFunction::ScriptFunctionData {
                        body,
                        std::move(signature),
                        ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::EXPRESSION,
                        ir::ModifierFlags::STATIC,
                     });
    // clang-format on
    ES2PANDA_ASSERT(func != nullptr);
    func->SetIdent(id);

    return std::make_pair(func, id);
}

std::pair<ir::ScriptFunction *, ir::Identifier *> ETSChecker::CreateScriptFunction(
    ClassInitializerBuilder const &builder)
{
    ArenaVector<ir::Statement *> statements(ProgramAllocator()->Adapter());
    ArenaVector<ir::Expression *> params(ProgramAllocator()->Adapter());

    ir::ScriptFunction *func;
    ir::Identifier *id;

    builder(&statements, &params);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = ProgramAllocNode<ir::BlockStatement>(ProgramAllocator(), std::move(statements));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    id = ProgramAllocNode<ir::Identifier>(compiler::Signatures::CTOR, ProgramAllocator());
    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    func = ProgramAllocNode<ir::ScriptFunction>(
        ProgramAllocator(), ir::ScriptFunction::ScriptFunctionData {body, std::move(funcSignature),
                                                                    ir::ScriptFunctionFlags::CONSTRUCTOR |
                                                                        ir::ScriptFunctionFlags::EXPRESSION,
                                                                    ir::ModifierFlags::PUBLIC});
    ES2PANDA_ASSERT(func != nullptr);
    func->SetIdent(id);

    return std::make_pair(func, id);
}

ir::ClassStaticBlock *ETSChecker::CreateClassStaticInitializer(const ClassInitializerBuilder &builder,
                                                               [[maybe_unused]] ETSObjectType *type)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto [func, id] = CreateStaticScriptFunction(builder);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = ProgramAllocNode<ir::FunctionExpression>(func);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *staticBlock = ProgramAllocNode<ir::ClassStaticBlock>(funcExpr, ProgramAllocator());
    ES2PANDA_ASSERT(staticBlock != nullptr);
    staticBlock->AddModifier(ir::ModifierFlags::STATIC);

    return staticBlock;
}

ir::MethodDefinition *ETSChecker::CreateClassInstanceInitializer(const ClassInitializerBuilder &builder,
                                                                 [[maybe_unused]] ETSObjectType *type)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto [func, id] = CreateScriptFunction(builder);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = ProgramAllocNode<ir::FunctionExpression>(func);

    auto *ctor =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR,
                                               // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                               id->Clone(ProgramAllocator(), nullptr), funcExpr,
                                               ir::ModifierFlags::NONE, ProgramAllocator(), false);
    return ctor;
}

ir::ClassStaticBlock *ETSChecker::CreateDynamicCallClassInitializer(Language lang, bool isConstruct)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateClassStaticInitializer(
        [this, lang, isConstruct](ArenaVector<ir::Statement *> *statements,
                                  [[maybe_unused]] ArenaVector<ir::Expression *> *params) {
            auto [builtin_class_name, builtin_method_name] =
                util::Helpers::SplitSignature(isConstruct ? compiler::Signatures::Dynamic::InitNewClassBuiltin(lang)
                                                          : compiler::Signatures::Dynamic::InitCallClassBuiltin(lang));
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *classId = ProgramAllocNode<ir::Identifier>(builtin_class_name, ProgramAllocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *methodId = ProgramAllocNode<ir::Identifier>(builtin_method_name, ProgramAllocator());
            auto *callee =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                ProgramAllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                       false, false);

            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *initCall = ProgramAllocNode<ir::CallExpression>(
                callee, ArenaVector<ir::Expression *>(ProgramAllocator()->Adapter()), nullptr, false);

            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            statements->push_back(ProgramAllocNode<ir::ExpressionStatement>(initCall));
        });
}

ir::ClassDeclaration *ETSChecker::BuildClass(util::StringView name, const ClassBuilder &builder)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classId = ProgramAllocNode<ir::Identifier>(name, ProgramAllocator());

    auto *classDef =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::ClassDefinition>(ProgramAllocator(), classId, ir::ClassDefinitionModifiers::CLASS_DECL,
                                              ir::ModifierFlags::NONE, Language(Language::Id::ETS));

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classDecl = ProgramAllocNode<ir::ClassDeclaration>(classDef, ProgramAllocator());

    VarBinder()->Program()->Ast()->Statements().push_back(classDecl);
    classDecl->SetParent(VarBinder()->Program()->Ast());

    auto varBinder = VarBinder()->AsETSBinder();
    bool isExternal = VarBinder()->Program() != varBinder->GetGlobalRecordTable()->Program();
    auto recordTable = isExternal ? varBinder->GetExternalRecordTable().at(varBinder->Program())
                                  : VarBinder()->AsETSBinder()->GetGlobalRecordTable();
    varbinder::BoundContext boundCtx(recordTable, classDef);

    ArenaVector<ir::AstNode *> classBody(ProgramAllocator()->Adapter());

    builder(&classBody);

    classDef->AddProperties(std::move(classBody));

    ProcessScopesNode(this, classDecl);
    ProcessCheckerNode(this, classDecl);
    return classDecl;
}

ir::ClassProperty *ETSChecker::CreateStaticReadonlyField(const char *name)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldIdent = ProgramAllocNode<ir::Identifier>(name, ProgramAllocator());
    auto flags = ir::ModifierFlags::STATIC | ir::ModifierFlags::PRIVATE | ir::ModifierFlags::READONLY;
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *field = ProgramAllocNode<ir::ClassProperty>(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        fieldIdent, nullptr, ProgramAllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, ProgramAllocator()), flags,
        ProgramAllocator(), false);
    return field;
}

ir::ClassDeclaration *ETSChecker::GetDynamicClass(Language lang, bool isConstruct)
{
    auto &klasses = dynamicClasses_[static_cast<size_t>(isConstruct)];
    if (klasses.count(lang) != 0U) {
        return klasses[lang];
    }
    auto className =
        isConstruct ? compiler::Signatures::Dynamic::NewClass(lang) : compiler::Signatures::Dynamic::CallClass(lang);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto klass = BuildClass(className, [this, lang, isConstruct](ArenaVector<ir::AstNode *> *classBody) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        classBody->push_back(CreateStaticReadonlyField("qname_start_from"));
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        classBody->push_back(CreateDynamicCallClassInitializer(lang, isConstruct));
    });
    klasses.emplace(lang, klass);
    return klass;
}

void ETSChecker::ClassInitializerFromImport(ir::ETSImportDeclaration *import, ArenaVector<ir::Statement *> *statements)
{
    auto builtin = compiler::Signatures::Dynamic::LoadModuleBuiltin(import->Language());
    auto [builtin_class_name, builtin_method_name] = util::Helpers::SplitSignature(builtin);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classId = ProgramAllocNode<ir::Identifier>(builtin_class_name, ProgramAllocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *methodId = ProgramAllocNode<ir::Identifier>(builtin_method_name, ProgramAllocator());
    auto *callee =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS, false,
                                               false);

    // NOTE: #23698. Make 'ohmUrl' mandatory in 'dynamicPaths'.
    util::StringView ohmUrl = util::UString(import->OhmUrl(), ProgramAllocator()).View();
    if (ohmUrl.Empty()) {
        ohmUrl = import->ResolvedSource();
        if (ark::os::file::File::IsRegularFile(ohmUrl.Mutf8())) {
            ohmUrl = util::UString(ark::os::RemoveExtension(ohmUrl.Mutf8()), ProgramAllocator()).View();
        }
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ArenaVector<ir::Expression *> callParams({ProgramAllocNode<ir::StringLiteral>(ohmUrl)},
                                             ProgramAllocator()->Adapter());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *loadCall = ProgramAllocNode<ir::CallExpression>(callee, std::move(callParams), nullptr, false);
    auto *moduleClassId =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::Identifier>(compiler::Signatures::DYNAMIC_MODULE_CLASS, ProgramAllocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldId = ProgramAllocNode<ir::Identifier>(import->AssemblerName(), ProgramAllocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *property = ProgramAllocNode<ir::MemberExpression>(moduleClassId, fieldId,
                                                            ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    auto *initializer =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::AssignmentExpression>(property, loadCall, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    statements->push_back(ProgramAllocNode<ir::ExpressionStatement>(initializer));
}

ir::ClassStaticBlock *ETSChecker::CreateDynamicModuleClassInitializer(
    const std::vector<ir::ETSImportDeclaration *> &imports)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateClassStaticInitializer([this, imports](ArenaVector<ir::Statement *> *statements,
                                                        [[maybe_unused]] ArenaVector<ir::Expression *> *params) {
        for (auto *import : imports) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ClassInitializerFromImport(import, statements);
        }
    });
}

ir::MethodDefinition *ETSChecker::CreateClassMethod(const std::string_view name, ir::ScriptFunctionFlags funcFlags,
                                                    ir::ModifierFlags modifierFlags, const MethodBuilder &builder)
{
    ArenaVector<ir::Expression *> params(ProgramAllocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *id = ProgramAllocNode<ir::Identifier>(name, ProgramAllocator());

    ArenaVector<ir::Statement *> statements(ProgramAllocator()->Adapter());
    Type *returnType = nullptr;

    builder(&statements, &params, &returnType);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = ProgramAllocNode<ir::BlockStatement>(ProgramAllocator(), std::move(statements));
    auto funcSignature = ir::FunctionSignature(
        nullptr, std::move(params),
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        returnType == nullptr ? nullptr : ProgramAllocNode<ir::OpaqueTypeNode>(returnType, ProgramAllocator()));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = ProgramAllocNode<ir::ScriptFunction>(
        ProgramAllocator(),
        ir::ScriptFunction::ScriptFunctionData {body, std::move(funcSignature), funcFlags, modifierFlags});

    func->SetIdent(id);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = ProgramAllocNode<ir::FunctionExpression>(func);
    auto *method =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD,
                                               // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                               func->Id()->Clone(ProgramAllocator(), nullptr), funcExpr, modifierFlags,
                                               ProgramAllocator(), false);

    return method;
}

ir::MethodDefinition *ETSChecker::CreateDynamicModuleClassInitMethod()
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateClassMethod(compiler::Signatures::DYNAMIC_MODULE_CLASS_INIT, ir::ScriptFunctionFlags::METHOD,
                             ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC,
                             [this]([[maybe_unused]] ArenaVector<ir::Statement *> *statements,
                                    [[maybe_unused]] ArenaVector<ir::Expression *> *params,
                                    Type **returnType) { *returnType = GlobalVoidType(); });
}

ir::MethodDefinition *ETSChecker::CreateLambdaObjectClassInvokeMethod(Signature *invokeSignature,
                                                                      ir::TypeNode *retTypeAnnotation)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateClassMethod(
        compiler::Signatures::LAMBDA_OBJECT_INVOKE, ir::ScriptFunctionFlags::METHOD, ir::ModifierFlags::PUBLIC,
        [this, invokeSignature, retTypeAnnotation](ArenaVector<ir::Statement *> *statements,
                                                   ArenaVector<ir::Expression *> *params, Type **returnType) {
            util::UString thisParamName(std::string("this"), ProgramAllocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ir::ETSParameterExpression *thisParam = AddParam(thisParamName.View(), nullptr);
            params->push_back(thisParam);

            ArenaVector<ir::Expression *> callParams(ProgramAllocator()->Adapter());
            for (auto *invokeParam : invokeSignature->Params()) {
                auto paramName =
                    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                    util::UString(std::string("p") + std::to_string(callParams.size()), ProgramAllocator()).View();
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                auto *param = AddParam(paramName,
                                       // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                       ProgramAllocNode<ir::OpaqueTypeNode>(invokeParam->TsType(), ProgramAllocator()));
                params->push_back(param);
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                callParams.push_back(param->Clone(ProgramAllocator(), nullptr));
            }

            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *properyId = ProgramAllocNode<ir::Identifier>("jsvalue_lambda", ProgramAllocator());
            auto *callee =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                ProgramAllocNode<ir::MemberExpression>(thisParam->Clone(ProgramAllocator(), nullptr), properyId,
                                                       ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *callLambda = ProgramAllocNode<ir::CallExpression>(callee, std::move(callParams), nullptr, false);

            auto *castToRetTypeExpr =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                ProgramAllocNode<ir::TSAsExpression>(callLambda, retTypeAnnotation->Clone(ProgramAllocator(), nullptr),
                                                     false);
            castToRetTypeExpr->SetTsType(invokeSignature->ReturnType());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *retStatement = ProgramAllocNode<ir::ReturnStatement>(castToRetTypeExpr);
            statements->push_back(retStatement);

            *returnType = invokeSignature->ReturnType();
        });
}

void ETSChecker::EmitDynamicModuleClassInitCall()
{
    auto *globalClass = VarBinder()->Program()->GlobalClass();
    auto &body = globalClass->Body();
    auto it = std::find_if(body.begin(), body.end(), [](ir::AstNode *node) { return node->IsClassStaticBlock(); });

    ES2PANDA_ASSERT(it != body.end());

    auto *staticBlock = (*it)->AsClassStaticBlock();
    auto *cctorBody = staticBlock->Function()->Body()->AsBlockStatement();

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classId = ProgramAllocNode<ir::Identifier>(compiler::Signatures::DYNAMIC_MODULE_CLASS, ProgramAllocator());
    auto *methodId =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::Identifier>(compiler::Signatures::DYNAMIC_MODULE_CLASS_INIT, ProgramAllocator());
    auto *callee =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProgramAllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS, false,
                                               false);

    ArenaVector<ir::Expression *> callParams(ProgramAllocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *initCall = ProgramAllocNode<ir::CallExpression>(callee, std::move(callParams), nullptr, false);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const node = ProgramAllocNode<ir::ExpressionStatement>(initCall);
    node->SetParent(cctorBody);
    cctorBody->Statements().push_back(node);

    ProcessScopesNode(this, node);
    ProcessCheckerNode(this, node);
}

void ETSChecker::BuildClassBodyFromDynamicImports(const ArenaVector<ir::ETSImportDeclaration *> &dynamicImports,
                                                  ArenaVector<ir::AstNode *> *classBody)
{
    std::unordered_set<util::StringView> fields;
    std::vector<ir::ETSImportDeclaration *> imports;

    for (auto *import : dynamicImports) {
        auto source = import->Source()->Str();
        if (fields.find(source) != fields.cend()) {
            continue;
        }

        auto assemblyName = std::string(source);
        std::replace_if(
            assemblyName.begin(), assemblyName.end(), [](char c) { return std::isalnum(c) == 0; }, '_');
        assemblyName.append(std::to_string(fields.size()));

        import->AssemblerName() = util::UString(assemblyName, ProgramAllocator()).View();
        fields.insert(import->AssemblerName());
        imports.push_back(import);

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *fieldIdent = ProgramAllocNode<ir::Identifier>(import->AssemblerName(), ProgramAllocator());
        auto flags = ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::READONLY;
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *field = ProgramAllocNode<ir::ClassProperty>(
            fieldIdent, nullptr,
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ProgramAllocNode<ir::OpaqueTypeNode>(GlobalBuiltinDynamicType(import->Language()), ProgramAllocator()),
            flags, ProgramAllocator(), false);

        classBody->push_back(field);
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    classBody->push_back(CreateDynamicModuleClassInitializer(imports));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    classBody->push_back(CreateDynamicModuleClassInitMethod());
}

void ETSChecker::BuildDynamicImportClass()
{
    const auto &dynamicImports = VarBinder()->AsETSBinder()->DynamicImports();
    if (dynamicImports.empty()) {
        return;
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    BuildClass(compiler::Signatures::DYNAMIC_MODULE_CLASS,
               [this, dynamicImports](ArenaVector<ir::AstNode *> *classBody) {
                   // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                   BuildClassBodyFromDynamicImports(dynamicImports, classBody);
               });

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    EmitDynamicModuleClassInitCall();
}

ir::MethodDefinition *ETSChecker::CreateLambdaObjectClassInitializer(ETSObjectType *functionalInterface)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateClassInstanceInitializer(
        [this](ArenaVector<ir::Statement *> *statements, ArenaVector<ir::Expression *> *params) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ir::ETSParameterExpression *thisParam = AddParam(varbinder::VarBinder::MANDATORY_PARAM_THIS, nullptr);
            params->push_back(thisParam);

            util::UString jsvalueParamName(std::string("jsvalue_param"), ProgramAllocator());
            ir::ETSParameterExpression *jsvalueParam =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                AddParam(jsvalueParamName.View(),
                         // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                         ProgramAllocNode<ir::OpaqueTypeNode>(GlobalBuiltinJSValueType(), ProgramAllocator()));
            params->push_back(jsvalueParam);
            auto *moduleClassId =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                ProgramAllocNode<ir::Identifier>(varbinder::VarBinder::MANDATORY_PARAM_THIS, ProgramAllocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *fieldId = ProgramAllocNode<ir::Identifier>("jsvalue_lambda", ProgramAllocator());
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *property = ProgramAllocNode<ir::MemberExpression>(
                moduleClassId, fieldId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *initializer = ProgramAllocNode<ir::AssignmentExpression>(
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                property, jsvalueParam->Clone(ProgramAllocator(), nullptr), lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            statements->push_back(ProgramAllocNode<ir::ExpressionStatement>(initializer));
        },
        functionalInterface);
}

void ETSChecker::BuildLambdaObjectClass(ETSObjectType *functionalInterface, ir::TypeNode *retTypeAnnotation)
{
    auto *invokeMethod = functionalInterface->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(
        compiler::Signatures::STATIC_INVOKE_METHOD);
    ES2PANDA_ASSERT(invokeMethod != nullptr);
    auto *invokeSignature = invokeMethod->TsType()->AsETSFunctionType()->CallSignatures()[0];
    ES2PANDA_ASSERT(invokeSignature != nullptr);
    std::stringstream ss;
    ss << compiler::Signatures::LAMBDA_OBJECT;
    ToString(this, invokeSignature->Params(), ss);
    auto syntheticLambdaObjName = ss.str();
    if (dynamicLambdaSignatureCache_.count(syntheticLambdaObjName) != 0) {
        functionalInterface->AddConstructSignature(dynamicLambdaSignatureCache_[syntheticLambdaObjName]);
        return;
    }

    auto buildBody = [this, invokeSignature, retTypeAnnotation,
                      functionalInterface](ArenaVector<ir::AstNode *> *classBody) {
        auto assemblyName = "jsvalue_lambda";
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *fieldIdent = ProgramAllocNode<ir::Identifier>(assemblyName, ProgramAllocator());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *field = ProgramAllocNode<ir::ClassProperty>(
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            fieldIdent, nullptr, ProgramAllocNode<ir::OpaqueTypeNode>(GlobalBuiltinJSValueType(), ProgramAllocator()),
            ir::ModifierFlags::PRIVATE, ProgramAllocator(), false);
        classBody->push_back(field);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        classBody->push_back(CreateLambdaObjectClassInitializer(functionalInterface));
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        classBody->push_back(CreateLambdaObjectClassInvokeMethod(invokeSignature, retTypeAnnotation));
    };

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    BuildClass(util::StringView(syntheticLambdaObjName), buildBody);

    dynamicLambdaSignatureCache_[syntheticLambdaObjName] = functionalInterface->ConstructSignatures()[0];
}

}  // namespace ark::es2panda::checker
