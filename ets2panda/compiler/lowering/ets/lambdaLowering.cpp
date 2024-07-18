/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lambdaLowering.h"

#include "checker/ets/typeRelationContext.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::compiler {

struct LambdaInfo {
    ir::ClassDeclaration *calleeClass = nullptr;
    ir::ScriptFunction *enclosingFunction = nullptr;
    util::StringView name = "";
    ArenaSet<varbinder::Variable *> *capturedVars = nullptr;
    ir::Expression *callReceiver = nullptr;
};

struct CalleeMethodInfo {
    util::StringView calleeName;
    ir::AstNode *body = nullptr;
    checker::Type *forcedReturnType = nullptr;
    ir::ModifierFlags auxModifierFlags = ir::ModifierFlags::NONE;
    ir::ScriptFunctionFlags auxFunctionFlags = ir::ScriptFunctionFlags::NONE;
};

struct LambdaClassInvokeInfo {
    checker::Signature *lambdaSignature = nullptr;
    ir::MethodDefinition *callee = nullptr;
    ir::ClassDefinition *classDefinition = nullptr;
    checker::Substitution *substitution = nullptr;
};

static std::pair<ir::ClassDeclaration *, ir::ScriptFunction *> FindEnclosingClassAndFunction(ir::AstNode *ast)
{
    ir::ScriptFunction *function = nullptr;
    for (ir::AstNode *curr = ast->Parent(); curr != nullptr; curr = curr->Parent()) {
        if (curr->IsClassDeclaration()) {
            return {curr->AsClassDeclaration(), function};
        }
        if (curr->IsScriptFunction()) {
            function = curr->AsScriptFunction();
        }
    }
    UNREACHABLE();
}

static bool CheckIfNeedThis(ir::ArrowFunctionExpression const *lambda)
{
    return lambda->IsAnyChild([](ir::AstNode *ast) { return ast->IsThisExpression(); });
}

static size_t g_calleeCount = 0;

// Make calleeCount behaviour predictable
static void ResetCalleeCount()
{
    g_calleeCount = 0;
}

static util::StringView CreateCalleeName(ArenaAllocator *allocator)
{
    auto name = util::UString(util::StringView("lambda$invoke$"), allocator);
    name.Append(std::to_string(g_calleeCount++));
    return name.View();
}

static std::pair<ir::TSTypeParameterDeclaration *, checker::Substitution *> CloneTypeParams(
    public_lib::Context *ctx, ir::TSTypeParameterDeclaration *oldIrTypeParams, ir::ScriptFunction *enclosingFunction,
    varbinder::Scope *enclosingScope)
{
    if (oldIrTypeParams == nullptr) {
        return {nullptr, nullptr};
    }

    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();

    auto *newScope = allocator->New<varbinder::LocalScope>(allocator, enclosingScope);
    auto newTypeParams = ArenaVector<checker::ETSTypeParameter *>(allocator->Adapter());
    auto newTypeParamNodes = ArenaVector<ir::TSTypeParameter *>(allocator->Adapter());
    auto *substitution = checker->NewSubstitution();

    for (size_t ix = 0; ix < oldIrTypeParams->Params().size(); ix++) {
        auto *oldTypeParamNode = oldIrTypeParams->Params()[ix];
        auto *oldTypeParam = enclosingFunction->Signature()->TypeParams()[ix]->AsETSTypeParameter();
        auto *newTypeParamId = allocator->New<ir::Identifier>(oldTypeParamNode->Name()->Name(), allocator);
        auto *newTypeParamNode =
            util::NodeAllocator::ForceSetParent<ir::TSTypeParameter>(allocator, newTypeParamId, nullptr, nullptr);
        auto *newTypeParam = allocator->New<checker::ETSTypeParameter>();
        newTypeParam->SetDeclNode(newTypeParamNode);

        auto *newTypeParamDecl = allocator->New<varbinder::TypeParameterDecl>(newTypeParamId->Name());
        newTypeParamDecl->BindNode(newTypeParamNode);
        auto *newTypeParamVar =
            allocator->New<varbinder::LocalVariable>(newTypeParamDecl, varbinder::VariableFlags::TYPE_PARAMETER);

        newTypeParamVar->SetTsType(newTypeParam);
        newScope->InsertBinding(newTypeParamId->Name(), newTypeParamVar);
        newTypeParamId->SetVariable(newTypeParamVar);

        newTypeParams.push_back(newTypeParam);
        newTypeParamNodes.push_back(newTypeParamNode);
        substitution->emplace(oldTypeParam, newTypeParam);
    }

    for (size_t ix = 0; ix < oldIrTypeParams->Params().size(); ix++) {
        auto *oldTypeParam = enclosingFunction->Signature()->TypeParams()[ix]->AsETSTypeParameter();

        if (auto *oldConstraint = oldTypeParam->GetConstraintType(); oldConstraint != nullptr) {
            auto *newConstraint = oldConstraint->Substitute(checker->Relation(), substitution);
            newTypeParams[ix]->SetConstraintType(newConstraint);
            newTypeParamNodes[ix]->SetConstraint(allocator->New<ir::OpaqueTypeNode>(newConstraint));
            newTypeParamNodes[ix]->Constraint()->SetParent(newTypeParamNodes[ix]);
        }
        if (auto *oldDefault = oldTypeParam->GetDefaultType(); oldDefault != nullptr) {
            auto *newDefault = oldDefault->Substitute(checker->Relation(), substitution);
            newTypeParams[ix]->SetDefaultType(newDefault);
            newTypeParamNodes[ix]->SetDefaultType(allocator->New<ir::OpaqueTypeNode>(newDefault));
            newTypeParamNodes[ix]->DefaultType()->SetParent(newTypeParamNodes[ix]);
        }
    }

    auto *newIrTypeParams = util::NodeAllocator::ForceSetParent<ir::TSTypeParameterDeclaration>(
        allocator, std::move(newTypeParamNodes), oldIrTypeParams->RequiredParams());
    newIrTypeParams->SetScope(newScope);

    return {newIrTypeParams, substitution};
}

using ParamsAndVarMap =
    std::pair<ArenaVector<ir::Expression *>, ArenaMap<varbinder::Variable *, varbinder::Variable *>>;
ParamsAndVarMap CreateLambdaCalleeParameters(public_lib::Context *ctx, ir::ArrowFunctionExpression *lambda,
                                             ArenaSet<varbinder::Variable *> const &captured,
                                             varbinder::ParamScope *paramScope, checker::Substitution *substitution)
{
    auto allocator = ctx->allocator;
    auto checker = ctx->checker->AsETSChecker();
    auto varBinder = ctx->checker->VarBinder();
    auto resParams = ArenaVector<ir::Expression *>(allocator->Adapter());
    auto varMap = ArenaMap<varbinder::Variable *, varbinder::Variable *>(allocator->Adapter());

    auto paramLexScope = varbinder::LexicalScope<varbinder::ParamScope>::Enter(varBinder, paramScope);

    for (auto capturedVar : captured) {
        auto *newType = capturedVar->TsType()->Substitute(checker->Relation(), substitution);
        auto newId = util::NodeAllocator::ForceSetParent<ir::Identifier>(
            allocator, capturedVar->Name(), allocator->New<ir::OpaqueTypeNode>(newType), allocator);
        auto param = util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, newId, nullptr);
        auto [_, var] = varBinder->AddParamDecl(param);
        (void)_;
        var->SetTsType(newType);
        var->SetScope(paramScope);
        param->SetVariable(var);
        param->SetTsType(newType);
        resParams.push_back(param);
        varMap[capturedVar] = var;
    }

    for (auto *oldParam : lambda->Function()->Params()) {
        auto *oldParamType = oldParam->AsETSParameterExpression()->Ident()->TypeAnnotation()->TsType();
        auto *newParamType = oldParamType->Substitute(checker->Relation(), substitution);
        auto *newParam = oldParam->AsETSParameterExpression()->Clone(allocator, nullptr);
        newParam->Ident()->SetVariable(nullptr);  // Remove the cloned variable.
        auto [_, var] = varBinder->AddParamDecl(newParam);
        (void)_;
        var->SetTsType(newParamType);
        var->SetScope(paramScope);
        newParam->SetVariable(var);
        newParam->SetTsType(newParamType);
        newParam->Ident()->SetTsType(newParamType);
        resParams.push_back(newParam);
        varMap[oldParam->AsETSParameterExpression()->Variable()] = var;
    }

    return {resParams, varMap};
}

static void ProcessCalleeMethodBody(ir::AstNode *body, checker::ETSChecker *checker, varbinder::Scope *paramScope,
                                    checker::Substitution *substitution,
                                    ArenaMap<varbinder::Variable *, varbinder::Variable *> const &varMap)
{
    if (body == nullptr) {
        return;
    }
    body->Scope()->SetParent(paramScope);
    body->IterateRecursively([&](ir::AstNode *node) {
        if (node->IsIdentifier()) {
            auto *id = node->AsIdentifier();
            if (auto ref = varMap.find(id->Variable()); ref != varMap.end()) {
                id->SetVariable(ref->second);
            }
        }
        if (substitution == nullptr) {
            return;
        }
        if (node->IsTyped() && node->AsTyped()->TsType() != nullptr) {
            node->AsTyped()->SetTsType(node->AsTyped()->TsType()->Substitute(checker->Relation(), substitution));
        }
        if (node->IsCallExpression()) {
            node->AsCallExpression()->SetSignature(
                node->AsCallExpression()->Signature()->Substitute(checker->Relation(), substitution));
        }
        if (node->IsETSNewClassInstanceExpression()) {
            node->AsETSNewClassInstanceExpression()->SetSignature(
                node->AsETSNewClassInstanceExpression()->GetSignature()->Substitute(checker->Relation(), substitution));
        }
        if (node->IsScriptFunction()) {
            node->AsScriptFunction()->SetSignature(
                node->AsScriptFunction()->Signature()->Substitute(checker->Relation(), substitution));
        }
        if (node->IsVariableDeclarator()) {
            auto *id = node->AsVariableDeclarator()->Id();
            id->Variable()->SetTsType(id->Variable()->TsType()->Substitute(checker->Relation(), substitution));
        }
    });
}

static ir::MethodDefinition *SetUpCalleeMethod(public_lib::Context *ctx, LambdaInfo const *info,
                                               CalleeMethodInfo const *cmInfo, ir::ScriptFunction *func,
                                               varbinder::Scope *scopeForMethod)
{
    auto *allocator = ctx->allocator;
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();

    auto *calleeClass = info->calleeClass;
    auto *funcScope = func->Scope();
    auto *paramScope = funcScope->ParamScope();
    auto modifierFlags = ir::ModifierFlags::PUBLIC |
                         (info->callReceiver != nullptr ? ir::ModifierFlags::NONE : ir::ModifierFlags::STATIC) |
                         cmInfo->auxModifierFlags;

    auto *calleeNameId = allocator->New<ir::Identifier>(cmInfo->calleeName, allocator);
    func->SetIdent(calleeNameId);
    calleeNameId->SetParent(func);

    auto *calleeNameClone = calleeNameId->Clone(allocator, nullptr);
    auto *funcExpr = util::NodeAllocator::ForceSetParent<ir::FunctionExpression>(allocator, func);
    auto *method = util::NodeAllocator::ForceSetParent<ir::MethodDefinition>(
        allocator, ir::MethodDefinitionKind::METHOD, calleeNameClone, funcExpr, modifierFlags, allocator, false);
    calleeClass->Definition()->Body().push_back(method);
    method->SetParent(calleeClass->Definition());

    auto [_, var] = varBinder->NewVarDecl<varbinder::FunctionDecl>(func->Start(), allocator, cmInfo->calleeName, func);
    (void)_;
    var->AddFlag(varbinder::VariableFlags::METHOD);
    var->SetScope(scopeForMethod);
    func->Id()->SetVariable(var);
    method->Id()->SetVariable(var);
    if (info->callReceiver != nullptr) {
        auto paramScopeCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(varBinder, paramScope);
        varBinder->AddMandatoryParam(varbinder::TypedBinder::MANDATORY_PARAM_THIS);
        calleeClass->Definition()->TsType()->AsETSObjectType()->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
            var->AsLocalVariable());
    } else {
        calleeClass->Definition()->TsType()->AsETSObjectType()->AddProperty<checker::PropertyType::STATIC_METHOD>(
            var->AsLocalVariable());
    }

    varbinder::BoundContext bctx {varBinder->GetRecordTable(), calleeClass->Definition(), true};
    varBinder->ResolveReferencesForScopeWithContext(func, funcScope);

    auto checkerCtx = checker::SavedCheckerContext(ctx->checker, checker::CheckerStatus::IN_CLASS,
                                                   calleeClass->Definition()->TsType()->AsETSObjectType());
    method->Check(ctx->checker->AsETSChecker());

    return method;
}

static ir::MethodDefinition *CreateCalleeMethod(public_lib::Context *ctx, ir::ArrowFunctionExpression *lambda,
                                                LambdaInfo const *info, CalleeMethodInfo const *cmInfo)
{
    auto *allocator = ctx->allocator;
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    auto *checker = ctx->checker->AsETSChecker();

    auto *classScope = info->calleeClass->Definition()->Scope()->AsClassScope();

    auto *oldTypeParams = (info->enclosingFunction != nullptr) ? info->enclosingFunction->TypeParams() : nullptr;
    auto enclosingScope =
        info->callReceiver != nullptr ? classScope->InstanceMethodScope() : classScope->StaticMethodScope();

    auto [newTypeParams, subst0] = CloneTypeParams(ctx, oldTypeParams, info->enclosingFunction, enclosingScope);
    auto *substitution = subst0;  // NOTE(gogabr): needed to capture in a lambda later.
    auto *scopeForMethod = newTypeParams != nullptr ? newTypeParams->Scope() : enclosingScope;

    auto lexScope = varbinder::LexicalScope<varbinder::LocalScope>::Enter(varBinder, enclosingScope);
    auto paramScope = allocator->New<varbinder::FunctionParamScope>(allocator, scopeForMethod);

    auto [params, vMap] = CreateLambdaCalleeParameters(ctx, lambda, *info->capturedVars, paramScope, substitution);
    auto varMap = std::move(vMap);

    auto *returnType =
        cmInfo->forcedReturnType != nullptr
            ? cmInfo->forcedReturnType
            : lambda->Function()->Signature()->ReturnType()->Substitute(checker->Relation(), substitution);
    auto returnTypeAnnotation = allocator->New<ir::OpaqueTypeNode>(returnType);

    auto funcFlags = ir::ScriptFunctionFlags::METHOD | cmInfo->auxFunctionFlags;
    auto modifierFlags = ir::ModifierFlags::PUBLIC |
                         (info->callReceiver != nullptr ? ir::ModifierFlags::NONE : ir::ModifierFlags::STATIC) |
                         cmInfo->auxModifierFlags;

    auto func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {
            cmInfo->body, ir::FunctionSignature(newTypeParams, std::move(params), returnTypeAnnotation), funcFlags,
            modifierFlags});
    auto *funcScope = cmInfo->body == nullptr ? allocator->New<varbinder::FunctionScope>(allocator, paramScope)
                                              : cmInfo->body->Scope()->AsFunctionScope();
    funcScope->BindName(info->calleeClass->Definition()->TsType()->AsETSObjectType()->AssemblerName());
    func->SetScope(funcScope);

    ProcessCalleeMethodBody(cmInfo->body, checker, paramScope, substitution, varMap);

    for (auto *param : func->Params()) {
        param->SetParent(func);
    }

    // Bind the scopes
    funcScope->BindNode(func);
    paramScope->BindNode(func);
    funcScope->AssignParamScope(paramScope);
    paramScope->BindFunctionScope(funcScope);

    /* NOTE(gogabr): Why does function scope need to replicate bindings from param scope?.
       Keeping it for now.
    */
    for (auto [ov, nv] : varMap) {
        ASSERT(ov->Name() == nv->Name());
        auto name = ov->Name();
        funcScope->EraseBinding(name);
        funcScope->InsertBinding(name, nv);
    }

    return SetUpCalleeMethod(ctx, info, cmInfo, func, scopeForMethod);
}

static ir::MethodDefinition *CreateCallee(public_lib::Context *ctx, ir::ArrowFunctionExpression *lambda,
                                          LambdaInfo const *info)
{
    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();
    auto *body = lambda->Function()->Body()->AsBlockStatement();
    auto calleeName = lambda->Function()->IsAsyncFunc()
                          ? (util::UString {checker::ETSChecker::GetAsyncImplName(info->name), allocator}).View()
                          : info->name;
    auto *forcedReturnType = lambda->Function()->IsAsyncFunc() ? checker->GlobalETSNullishObjectType() : nullptr;

    CalleeMethodInfo cmInfo;
    cmInfo.calleeName = calleeName;
    cmInfo.body = body;
    cmInfo.forcedReturnType = forcedReturnType;
    auto *method = CreateCalleeMethod(ctx, lambda, info, &cmInfo);

    if (lambda->Function()->IsAsyncFunc()) {
        CalleeMethodInfo cmInfoAsync;
        cmInfoAsync.calleeName = info->name;
        cmInfoAsync.body = nullptr;
        cmInfoAsync.forcedReturnType = nullptr;
        cmInfoAsync.auxModifierFlags = ir::ModifierFlags::NATIVE;
        cmInfoAsync.auxFunctionFlags = ir::ScriptFunctionFlags::ASYNC;
        auto *asyncMethod = CreateCalleeMethod(ctx, lambda, info, &cmInfoAsync);
        return asyncMethod;
    }

    return method;
}

// The name "=t" used in extension methods has special meaning for the code generator;
// avoid it as parameter and field name in our generated code.
static util::StringView AvoidMandatoryThis(util::StringView name)
{
    return (name == varbinder::TypedBinder::MANDATORY_PARAM_THIS) ? "$extensionThis" : name;
}

static void CreateLambdaClassFields(public_lib::Context *ctx, ir::ClassDefinition *classDefinition,
                                    LambdaInfo const *info, checker::Substitution *substitution)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();
    auto props = ArenaVector<ir::AstNode *>(allocator->Adapter());

    if (info->callReceiver != nullptr) {
        auto *outerThisDeclaration = parser->CreateFormattedClassFieldDefinition(
            "@@I1: @@T2", "$this",
            info->calleeClass->Definition()->TsType()->Substitute(checker->Relation(), substitution));
        props.push_back(outerThisDeclaration);
    }

    for (auto *captured : *info->capturedVars) {
        auto *varDeclaration = parser->CreateFormattedClassFieldDefinition(
            "@@I1: @@T2", AvoidMandatoryThis(captured->Name()),
            captured->TsType()->Substitute(checker->Relation(), substitution));
        props.push_back(varDeclaration);
    }

    classDefinition->AddProperties(std::move(props));
}

static void CreateLambdaClassConstructor(public_lib::Context *ctx, ir::ClassDefinition *classDefinition,
                                         LambdaInfo const *info, checker::Substitution *substitution)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();

    auto params = ArenaVector<ir::Expression *>(allocator->Adapter());
    auto makeParam = [checker, allocator, substitution, &params](util::StringView name, checker::Type *type) {
        auto *substitutedType = type->Substitute(checker->Relation(), substitution);
        auto *id = util::NodeAllocator::ForceSetParent<ir::Identifier>(
            allocator, name, allocator->New<ir::OpaqueTypeNode>(substitutedType), allocator);
        auto *param = util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, id, nullptr);
        params.push_back(param);
    };

    if (info->callReceiver != nullptr) {
        makeParam("$this", info->calleeClass->Definition()->TsType());
    }
    for (auto *var : *info->capturedVars) {
        makeParam(AvoidMandatoryThis(var->Name()), var->TsType());
    }

    auto bodyStmts = ArenaVector<ir::Statement *>(allocator->Adapter());
    auto makeStatement = [&parser, &bodyStmts](util::StringView name) {
        auto adjustedName = AvoidMandatoryThis(name);
        auto *statement = parser->CreateFormattedStatement("this.@@I1 = @@I2", adjustedName, adjustedName);
        bodyStmts.push_back(statement);
    };
    if (info->callReceiver != nullptr) {
        makeStatement("$this");
    }
    for (auto *var : *info->capturedVars) {
        makeStatement(var->Name());
    }
    auto *body = util::NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator, allocator, std::move(bodyStmts));

    auto *constructorId = allocator->New<ir::Identifier>("constructor", allocator);
    auto *constructorIdClone = constructorId->Clone(allocator, nullptr);

    auto *func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::CONSTRUCTOR |
                                                    ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED});
    func->SetIdent(constructorId);
    auto *funcExpr = util::NodeAllocator::ForceSetParent<ir::FunctionExpression>(allocator, func);

    auto *ctor = util::NodeAllocator::ForceSetParent<ir::MethodDefinition>(
        allocator, ir::MethodDefinitionKind::CONSTRUCTOR, constructorIdClone, funcExpr, ir::ModifierFlags::NONE,
        allocator, false);

    classDefinition->Body().push_back(ctor);
    ctor->SetParent(classDefinition);
}

static ir::CallExpression *CreateCallForLambdaClassInvoke(public_lib::Context *ctx, LambdaInfo const *info,
                                                          LambdaClassInvokeInfo const *lciInfo, bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();

    auto callArguments = ArenaVector<ir::Expression *>(allocator->Adapter());
    for (auto *captured : *info->capturedVars) {
        auto *arg = parser->CreateFormattedExpression("this.@@I1", AvoidMandatoryThis(captured->Name()));
        callArguments.push_back(arg);
    }
    for (auto *lambdaParam : lciInfo->lambdaSignature->Params()) {
        auto argName = lambdaParam->Name();
        auto *type = lambdaParam->TsType()->Substitute(checker->Relation(), lciInfo->substitution);
        auto *arg = wrapToObject ? parser->CreateFormattedExpression("@@I1 as @@T2 as @@T3", argName,
                                                                     checker->MaybePromotedBuiltinType(type), type)
                                 : allocator->New<ir::Identifier>(argName, allocator);
        callArguments.push_back(arg);
    }

    ir::Expression *calleeReceiver;
    if (info->callReceiver != nullptr) {
        calleeReceiver = parser->CreateFormattedExpression("this.@@I1", "$this");
    } else {
        calleeReceiver = lciInfo->callee->Parent()->AsClassDefinition()->Ident()->Clone(allocator, nullptr);
    }

    auto *calleeMemberExpr = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, calleeReceiver, lciInfo->callee->Key()->Clone(allocator, nullptr)->AsExpression(),
        ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *call = parser->CreateFormattedExpression("@@E1(@@[E2)", calleeMemberExpr, std::move(callArguments))
                     ->AsCallExpression();

    if (lciInfo->classDefinition->TypeParams() != nullptr) {
        auto typeArgs = ArenaVector<ir::TypeNode *>(allocator->Adapter());
        for (auto *tp : lciInfo->classDefinition->TypeParams()->Params()) {
            typeArgs.push_back(allocator->New<ir::OpaqueTypeNode>(tp->Name()->AsIdentifier()->Variable()->TsType()));
        }
        auto *typeArg =
            util::NodeAllocator::ForceSetParent<ir::TSTypeParameterInstantiation>(allocator, std::move(typeArgs));
        call->SetTypeParams(typeArg);
        typeArg->SetParent(call);
    }

    return call;
}

static void CreateLambdaClassInvoke(public_lib::Context *ctx, LambdaInfo const *info,
                                    LambdaClassInvokeInfo const *lciInfo, util::StringView methodName,
                                    bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();
    auto *anyType = checker->GlobalETSNullishObjectType();

    auto params = ArenaVector<ir::Expression *>(allocator->Adapter());
    for (auto *lparam : lciInfo->lambdaSignature->Params()) {
        auto *type = wrapToObject ? anyType : lparam->TsType()->Substitute(checker->Relation(), lciInfo->substitution);
        auto *id = util::NodeAllocator::ForceSetParent<ir::Identifier>(
            allocator, lparam->Name(), allocator->New<ir::OpaqueTypeNode>(type), allocator);
        auto *param = util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, id, nullptr);
        params.push_back(param);
    }

    auto *call = CreateCallForLambdaClassInvoke(ctx, info, lciInfo, wrapToObject);

    auto bodyStmts = ArenaVector<ir::Statement *>(allocator->Adapter());
    if (lciInfo->lambdaSignature->ReturnType() == checker->GlobalVoidType()) {
        auto *callStmt = util::NodeAllocator::ForceSetParent<ir::ExpressionStatement>(allocator, call);
        bodyStmts.push_back(callStmt);
        if (wrapToObject) {
            auto *returnStmt = util::NodeAllocator::ForceSetParent<ir::ReturnStatement>(
                allocator, allocator->New<ir::UndefinedLiteral>());
            bodyStmts.push_back(returnStmt);
        }
    } else {
        auto *returnExpr = wrapToObject ? parser->CreateFormattedExpression("@@E1 as @@T2", call, anyType) : call;
        auto *returnStmt = util::NodeAllocator::ForceSetParent<ir::ReturnStatement>(allocator, returnExpr);
        bodyStmts.push_back(returnStmt);
    }

    auto body = util::NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator, allocator, std::move(bodyStmts));
    auto *returnType2 = allocator->New<ir::OpaqueTypeNode>(
        wrapToObject ? anyType
                     : lciInfo->lambdaSignature->ReturnType()->Substitute(checker->Relation(), lciInfo->substitution));
    auto *func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), returnType2),
                                                ir::ScriptFunctionFlags::METHOD});

    auto *invokeId = allocator->New<ir::Identifier>(methodName, allocator);
    func->SetIdent(invokeId);

    auto *funcExpr = util::NodeAllocator::ForceSetParent<ir::FunctionExpression>(allocator, func);

    auto *invokeIdClone = invokeId->Clone(allocator, nullptr);
    auto *invokeMethod = util::NodeAllocator::ForceSetParent<ir::MethodDefinition>(
        allocator, ir::MethodDefinitionKind::METHOD, invokeIdClone, funcExpr, ir::ModifierFlags::NONE, allocator,
        false);

    lciInfo->classDefinition->Body().push_back(invokeMethod);
    invokeMethod->SetParent(lciInfo->classDefinition);
}

static ir::ClassDeclaration *CreateLambdaClass(public_lib::Context *ctx, checker::Signature *lambdaSig,
                                               ir::MethodDefinition *callee, LambdaInfo const *info)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();

    auto *oldTypeParams = (info->enclosingFunction != nullptr) ? info->enclosingFunction->TypeParams() : nullptr;
    auto [newTypeParams, subst0] =
        CloneTypeParams(ctx, oldTypeParams, info->enclosingFunction, ctx->parserProgram->GlobalClassScope());
    auto *substitution = subst0;  // NOTE(gogabr): needed to capture in a lambda later.

    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, ctx->parserProgram->GlobalClassScope());

    auto lambdaClassName = util::UString {std::string_view {"LambdaObject-"}, allocator};
    lambdaClassName.Append(info->calleeClass->Definition()->Ident()->Name());
    lambdaClassName.Append("$");
    lambdaClassName.Append(info->name);

    auto *funcIface =
        checker->FunctionTypeToFunctionalInterfaceType(lambdaSig->Substitute(checker->Relation(), substitution));
    auto *classDeclaration =
        parser->CreateFormattedTopLevelStatement("final class @@I1 implements @@T2 {}", lambdaClassName, funcIface)
            ->AsClassDeclaration();
    auto *classDefinition = classDeclaration->Definition();

    // Adjust the class definition compared to what the parser gives.
    classDefinition->Body().clear();  // remove the default empty constructor
    classDefinition->AddModifier(ir::ModifierFlags::PUBLIC | ir::ModifierFlags::FUNCTIONAL);
    if (newTypeParams != nullptr) {
        classDefinition->SetTypeParams(newTypeParams);
        newTypeParams->SetParent(classDefinition);
    }

    auto *program = varBinder->GetRecordTable()->Program();
    program->Ast()->Statements().push_back(classDeclaration);
    classDeclaration->SetParent(program->Ast());

    CreateLambdaClassFields(ctx, classDefinition, info, substitution);
    CreateLambdaClassConstructor(ctx, classDefinition, info, substitution);

    LambdaClassInvokeInfo lciInfo;
    lciInfo.lambdaSignature = lambdaSig;
    lciInfo.callee = callee;
    lciInfo.classDefinition = classDefinition;
    lciInfo.substitution = substitution;

    CreateLambdaClassInvoke(ctx, info, &lciInfo, "invoke0", true);
    CreateLambdaClassInvoke(ctx, info, &lciInfo, "invoke", false);

    InitScopesPhaseETS::RunExternalNode(classDeclaration, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(classDeclaration, varBinder->TopScope());
    classDeclaration->Check(checker);

    return classDeclaration;
}

static ir::ETSNewClassInstanceExpression *CreateConstructorCall(public_lib::Context *ctx, ir::AstNode *lambdaOrFuncRef,
                                                                ir::ClassDeclaration *lambdaClass,
                                                                LambdaInfo const *info)
{
    auto *allocator = ctx->allocator;
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    auto *checker = ctx->checker->AsETSChecker();

    auto args = ArenaVector<ir::Expression *>(allocator->Adapter());
    if (info->callReceiver != nullptr) {
        args.push_back(info->callReceiver);
    }
    for (auto captured : *info->capturedVars) {
        auto *id = allocator->New<ir::Identifier>(captured->Name(), allocator);
        args.push_back(id);
    }

    checker::ETSObjectType *constructedType = lambdaClass->Definition()->TsType()->AsETSObjectType();
    if (info->enclosingFunction != nullptr) {
        constructedType = constructedType->SubstituteArguments(checker->Relation(),
                                                               info->enclosingFunction->Signature()->TypeParams());
    }
    auto *newExpr = util::NodeAllocator::ForceSetParent<ir::ETSNewClassInstanceExpression>(
        allocator, allocator->New<ir::OpaqueTypeNode>(constructedType), std::move(args), nullptr);
    newExpr->SetParent(lambdaOrFuncRef->Parent());

    auto *nearestScope = NearestScope(lambdaOrFuncRef);
    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, nearestScope);
    varBinder->ResolveReferencesForScopeWithContext(newExpr, nearestScope);

    auto checkerCtx = checker::SavedCheckerContext(ctx->checker, checker::CheckerStatus::IN_CLASS,
                                                   info->calleeClass->Definition()->TsType()->AsETSObjectType());
    auto scopeCtx = checker::ScopeContext(ctx->checker, nearestScope);
    newExpr->Check(checker);

    return newExpr;
}

static ir::AstNode *ConvertLambda(public_lib::Context *ctx, ir::ArrowFunctionExpression *lambda)
{
    auto *allocator = ctx->allocator;

    LambdaInfo info;
    std::tie(info.calleeClass, info.enclosingFunction) = FindEnclosingClassAndFunction(lambda);
    info.name = CreateCalleeName(allocator);
    auto capturedVars = FindCaptured(allocator, lambda);
    info.capturedVars = &capturedVars;
    info.callReceiver = CheckIfNeedThis(lambda) ? allocator->New<ir::ThisExpression>() : nullptr;

    auto *callee = CreateCallee(ctx, lambda, &info);
    ASSERT(lambda->TsType()->IsETSFunctionType());
    auto *lambdaType = lambda->TsType()->AsETSFunctionType();
    ASSERT(lambdaType->CallSignatures().size() == 1);
    auto *lambdaClass = CreateLambdaClass(ctx, lambdaType->CallSignatures()[0], callee, &info);
    auto *constructorCall = CreateConstructorCall(ctx, lambda, lambdaClass, &info);
    return constructorCall;
}

static checker::Signature *GuessSignature(checker::ETSChecker *checker, ir::Expression *ast)
{
    ASSERT(ast->TsType()->IsETSFunctionType());
    auto *type = ast->TsType()->AsETSFunctionType();

    if (type->CallSignatures().size() == 1) {
        return type->CallSignatures()[0];
    }

    if (!ast->Parent()->IsCallExpression()) {
        checker->ThrowTypeError(
            std::initializer_list<checker::TypeErrorMessageElement> {"Cannot deduce call signature"}, ast->Start());
    }

    auto &args = ast->Parent()->AsCallExpression()->Arguments();
    for (size_t ix = 0; ix < args.size(); ix++) {
        if (args[ix] != ast) {
            continue;
        }

        auto *argType = ast->Parent()->AsCallExpression()->Signature()->Params()[ix]->TsType();
        checker::Signature *sigFound = nullptr;

        for (auto *sig : type->CallSignatures()) {
            auto *tmpFunType = checker->Allocator()->New<checker::ETSFunctionType>("", sig, checker->Allocator());
            checker::AssignmentContext actx {
                checker->Relation(), ast, tmpFunType, argType, ast->Start(), {}, checker::TypeRelationFlag::NO_THROW};
            if (!actx.IsAssignable()) {
                continue;
            }
            if (sigFound != nullptr) {
                // ambiguiuty
                checker->ThrowTypeError(
                    std::initializer_list<checker::TypeErrorMessageElement> {"Cannot deduce call signature"},
                    ast->Start());
            }
            sigFound = sig;
        }
        if (sigFound != nullptr) {
            return sigFound;
        }
    }

    checker->ThrowTypeError({"Cannot deduce call signature"}, ast->Start());
}

static ir::ArrowFunctionExpression *CreateWrappingLambda(public_lib::Context *ctx, ir::Expression *funcRef)
{
    auto *allocator = ctx->allocator;
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    auto *signature = GuessSignature(ctx->checker->AsETSChecker(), funcRef);

    auto *parent = funcRef->Parent();

    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto *p : signature->Params()) {
        params.push_back(util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(
            allocator,
            allocator->New<ir::Identifier>(p->Name(), allocator->New<ir::OpaqueTypeNode>(p->TsType()), allocator),
            nullptr));
    }
    auto *func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {
            nullptr,
            ir::FunctionSignature {nullptr, std::move(params),
                                   allocator->New<ir::OpaqueTypeNode>(signature->ReturnType())},
            ir::ScriptFunctionFlags::ARROW});

    ArenaVector<ir::Statement *> bodyStmts {allocator->Adapter()};
    ArenaVector<ir::Expression *> callArgs {allocator->Adapter()};

    for (auto *p : func->Params()) {
        callArgs.push_back(p->AsETSParameterExpression()->Ident()->Clone(allocator, nullptr));
    }
    auto *callExpr = util::NodeAllocator::ForceSetParent<ir::CallExpression>(allocator, funcRef, std::move(callArgs),
                                                                             nullptr, false);
    ir::Statement *stmt;
    if (signature->ReturnType() == ctx->checker->AsETSChecker()->GlobalVoidType()) {
        stmt = util::NodeAllocator::ForceSetParent<ir::ExpressionStatement>(allocator, callExpr);
    } else {
        stmt = util::NodeAllocator::ForceSetParent<ir::ReturnStatement>(allocator, callExpr);
    }
    bodyStmts.push_back(stmt);
    func->SetBody(util::NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator, allocator, std::move(bodyStmts)));
    func->Body()->SetParent(func);
    auto *lambda = util::NodeAllocator::ForceSetParent<ir::ArrowFunctionExpression>(allocator, func);
    lambda->SetParent(parent);

    auto *nearestScope = NearestScope(lambda);
    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, nearestScope);
    InitScopesPhaseETS::RunExternalNode(lambda, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(lambda, nearestScope);

    auto [enclosingClass, enclosingFun] = FindEnclosingClassAndFunction(parent);
    (void)enclosingFun;

    auto checkerCtx = checker::SavedCheckerContext(ctx->checker, checker::CheckerStatus::IN_CLASS,
                                                   enclosingClass->Definition()->TsType()->AsETSObjectType());
    auto scopeCtx = checker::ScopeContext(ctx->checker, nearestScope);
    lambda->Check(ctx->checker->AsETSChecker());

    return lambda;
}

static ir::AstNode *ConvertFunctionReference(public_lib::Context *ctx, ir::Expression *funcRef)
{
    auto *allocator = ctx->allocator;
    ASSERT(funcRef->IsIdentifier() ||
           (funcRef->IsMemberExpression() &&
            funcRef->AsMemberExpression()->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS &&
            funcRef->AsMemberExpression()->Property()->IsIdentifier()));
    varbinder::Variable *var;
    if (funcRef->IsIdentifier()) {
        var = funcRef->AsIdentifier()->Variable();
    } else {
        auto *mexpr = funcRef->AsMemberExpression();
        // NOTE(gogabr): mexpr->PropVar() is a synthetic variable wwith no reference to the method definition. Why?
        var = mexpr->Object()->TsType()->AsETSObjectType()->GetProperty(
            mexpr->Property()->AsIdentifier()->Name(),
            checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD | checker::PropertySearchFlags::SEARCH_STATIC_METHOD |
                checker::PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);
        ASSERT(var != nullptr);
    }

    ASSERT(var->Declaration()->Node()->IsMethodDefinition());
    auto *method = var->Declaration()->Node()->AsMethodDefinition();

    if (method->IsPrivate() || method->IsProtected()) {
        // Direct reference to method will be impossible from the lambda class, so replace func ref with a lambda
        // that will translate to a proxy method
        auto *lam = CreateWrappingLambda(ctx, funcRef);
        return ConvertLambda(ctx, lam);
    }

    LambdaInfo info;
    info.calleeClass = method->Parent()->Parent()->AsClassDeclaration();
    info.enclosingFunction = nullptr;
    info.name = CreateCalleeName(allocator);
    auto emptySet = ArenaSet<varbinder::Variable *>(allocator->Adapter());
    info.capturedVars = &emptySet;
    if (method->IsStatic()) {
        info.callReceiver = nullptr;
    } else {
        ASSERT(funcRef->IsMemberExpression());
        info.callReceiver = funcRef->AsMemberExpression()->Object();
    }

    auto *signature = GuessSignature(ctx->checker->AsETSChecker(), funcRef);
    auto *lambdaClass = CreateLambdaClass(ctx, signature, method, &info);
    auto *constructorCall = CreateConstructorCall(ctx, funcRef, lambdaClass, &info);
    return constructorCall;
}

static bool IsFunctionOrMethodCall(checker::ETSChecker *checker, ir::AstNode const *node)
{
    ASSERT(node->IsCallExpression());
    auto const *callee = node->AsCallExpression()->Callee();

    if (callee->TsType()->IsETSExtensionFuncHelperType()) {
        return true;
    }
    if (callee->IsMemberExpression() && (callee->AsMemberExpression()->Object()->TsType()->IsETSEnumType() ||
                                         callee->AsMemberExpression()->Object()->TsType()->IsETSStringEnumType())) {
        return true;
    }

    varbinder::Variable *var = nullptr;
    if (callee->IsMemberExpression() &&
        callee->AsMemberExpression()->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS) {
        var = callee->AsMemberExpression()->Property()->Variable();
    } else if (callee->IsIdentifier()) {
        var = callee->AsIdentifier()->Variable();
    }
    return var != nullptr && !checker->IsVariableGetterSetter(var) &&
           (var->Flags() & varbinder::VariableFlags::METHOD) != 0;
}

static ir::AstNode *InsertInvokeCall(public_lib::Context *ctx, ir::CallExpression *call)
{
    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();
    auto *varBinder = checker->VarBinder()->AsETSBinder();

    auto *oldCallee = call->Callee();
    auto *ifaceType = oldCallee->TsType()->IsETSObjectType()
                          ? oldCallee->TsType()->AsETSObjectType()
                          : checker->FunctionTypeToFunctionalInterfaceType(call->Signature());
    if (ifaceType->IsETSDynamicType()) {
        return call;
    }
    auto *prop = ifaceType->GetProperty(checker::FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME,
                                        checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                            checker::PropertySearchFlags::SEARCH_IN_INTERFACES);
    ASSERT(prop != nullptr);
    auto *invoke0Id = allocator->New<ir::Identifier>(checker::FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME, allocator);
    invoke0Id->SetTsType(prop->TsType());
    invoke0Id->SetVariable(prop);

    auto *newCallee = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, oldCallee, invoke0Id, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    newCallee->SetTsType(prop->TsType());
    newCallee->SetObjectType(ifaceType);

    call->SetCallee(newCallee);
    call->SetSignature(prop->TsType()->AsETSFunctionType()->CallSignatures()[0]);

    /* NOTE(gogabr): argument types may have been spoiled by widening/narrowing conversions.
       Repair them here.
       In the future, make sure those conversions behave appropriately.
    */
    for (auto *arg : call->Arguments()) {
        auto boxingFlags = arg->GetBoxingUnboxingFlags();
        Recheck(varBinder, checker, arg);
        arg->SetBoxingUnboxingFlags(boxingFlags);
    }

    return call;
}

static bool IsRedirectingConstructorCall(ir::CallExpression *expr)
{
    return expr->Callee()->IsThisExpression() || expr->Callee()->IsSuperExpression();
}

static bool IsInCalleePosition(ir::Expression *expr)
{
    return expr->Parent()->IsCallExpression() && expr->Parent()->AsCallExpression()->Callee() == expr;
}

static ir::AstNode *BuildLambdaClassWhenNeeded(public_lib::Context *ctx, ir::AstNode *node)
{
    if (node->IsArrowFunctionExpression()) {
        return ConvertLambda(ctx, node->AsArrowFunctionExpression());
    }
    if (node->IsIdentifier()) {
        auto *id = node->AsIdentifier();
        auto *var = id->Variable();
        if (id->IsReference() && id->TsType() != nullptr && id->TsType()->IsETSFunctionType() && var != nullptr &&
            var->Declaration()->IsFunctionDecl() && !IsInCalleePosition(id)) {
            return ConvertFunctionReference(ctx, id);
        }
    }
    if (node->IsMemberExpression()) {
        auto *mexpr = node->AsMemberExpression();
        if (mexpr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS && mexpr->TsType() != nullptr &&
            mexpr->TsType()->IsETSFunctionType() && mexpr->Object()->TsType()->IsETSObjectType()) {
            ASSERT(mexpr->Property()->IsIdentifier());
            auto *var = mexpr->Object()->TsType()->AsETSObjectType()->GetProperty(
                mexpr->Property()->AsIdentifier()->Name(),
                checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                    checker::PropertySearchFlags::SEARCH_STATIC_METHOD |
                    checker::PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);
            if (var != nullptr && var->Declaration()->IsFunctionDecl() && !IsInCalleePosition(mexpr)) {
                return ConvertFunctionReference(ctx, mexpr);
            }
        }
    }
    return node;
}

static void CallPerformForExtSources(LambdaConversionPhase *phase, public_lib::Context *ctx, parser::Program *program)
{
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            varbinder::RecordTableContext bctx {varBinder, extProg};
            phase->Perform(ctx, extProg);
        }
    }
}

bool LambdaConversionPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    parser::SavedFormattingFileName savedFormattingName(ctx->parser->AsETSParser(), "lambda-conversion");
    auto *checker = ctx->checker->AsETSChecker();

    // For reproducibility of results when several compilation sessions are executed during
    // the same process's lifetime.
    if (program == ctx->parserProgram) {
        ResetCalleeCount();
    }

    if (ctx->config->options->CompilerOptions().compilationMode == CompilationMode::GEN_STD_LIB) {
        CallPerformForExtSources(this, ctx, program);
    }

    program->Ast()->TransformChildrenRecursivelyPostorder(
        [ctx](ir::AstNode *node) { return BuildLambdaClassWhenNeeded(ctx, node); }, Name());

    auto insertInvokeIfNeeded = [ctx, checker](ir::AstNode *node) {
        if (node->IsCallExpression() && !IsFunctionOrMethodCall(checker, node) &&
            !IsRedirectingConstructorCall(node->AsCallExpression())) {
            return InsertInvokeCall(ctx, node->AsCallExpression());
        }
        return node;
    };
    program->Ast()->TransformChildrenRecursively(insertInvokeIfNeeded, Name());

    return true;
}

bool LambdaConversionPhase::Postcondition([[maybe_unused]] public_lib::Context *ctx, parser::Program const *program)
{
    return !program->Ast()->IsAnyChild([](ir::AstNode const *node) { return node->IsArrowFunctionExpression(); });
}

}  // namespace ark::es2panda::compiler
