/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "util/options.h"

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
    size_t arity = 0;
    util::StringView restParameterIdentifier = "";
    util::StringView restArgumentIdentifier = "";
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
    ES2PANDA_UNREACHABLE();
}

static bool CheckIfNeedThis(ir::ArrowFunctionExpression *lambda, checker::ETSChecker *checker)
{
    auto *lambdaClass = ContainingClass(lambda);
    return lambda->IsAnyChild([&checker, &lambdaClass](ir::AstNode *ast) {
        return (ast->IsThisExpression() || ast->IsSuperExpression()) &&
               checker->Relation()->IsIdenticalTo(lambdaClass, ContainingClass(ast));
    });
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
        auto *newTypeParamNode = util::NodeAllocator::ForceSetParent<ir::TSTypeParameter>(allocator, newTypeParamId,
                                                                                          nullptr, nullptr, allocator);
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
            newTypeParamNodes[ix]->SetConstraint(allocator->New<ir::OpaqueTypeNode>(newConstraint, allocator));
            newTypeParamNodes[ix]->Constraint()->SetParent(newTypeParamNodes[ix]);
        }
        if (auto *oldDefault = oldTypeParam->GetDefaultType(); oldDefault != nullptr) {
            auto *newDefault = oldDefault->Substitute(checker->Relation(), substitution);
            newTypeParams[ix]->SetDefaultType(newDefault);
            newTypeParamNodes[ix]->SetDefaultType(allocator->New<ir::OpaqueTypeNode>(newDefault, allocator));
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
            allocator, capturedVar->Name(), allocator->New<ir::OpaqueTypeNode>(newType, allocator), allocator);
        auto param =
            util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, newId, false, allocator);
        auto *var = varBinder->AddParamDecl(param);
        var->SetTsType(newType);
        var->SetScope(paramScope);
        param->SetVariable(var);
        param->SetTsType(newType);
        resParams.push_back(param);
        varMap[capturedVar] = var;
    }

    for (auto *oldParam : lambda->Function()->Params()) {
        auto *oldParamType = oldParam->AsETSParameterExpression()->Ident()->TsType();
        auto *newParamType = oldParamType->Substitute(checker->Relation(), substitution);
        auto *newParam = oldParam->AsETSParameterExpression()->Clone(allocator, nullptr);
        if (newParam->IsOptional()) {
            newParam->SetOptional(false);
            newParamType = checker->CreateETSUnionType({newParamType, checker->GlobalETSUndefinedType()});
        }
        newParam->Ident()->SetTsTypeAnnotation(allocator->New<ir::OpaqueTypeNode>(newParamType, allocator));
        newParam->Ident()->TypeAnnotation()->SetParent(newParam->Ident());
        newParam->Ident()->SetVariable(nullptr);  // Remove the cloned variable.
        auto *var = varBinder->AddParamDecl(newParam);
        var->SetTsType(newParamType);
        var->SetScope(paramScope);
        newParam->SetVariable(var);
        newParam->SetTsType(newParamType);
        newParam->Ident()->SetTsType(newParamType);
        resParams.push_back(newParam);
        varMap[oldParam->AsETSParameterExpression()->Variable()] = var;

        if (newParam->TypeAnnotation()->IsETSFunctionType()) {
            // Parameter can be a function with other parameters inside
            // Restart varbinder to set correct scopes for inner parameters
            InitScopesPhaseETS::RunExternalNode(newParam->TypeAnnotation(), varBinder);
        }
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
            if (node->IsTSNonNullExpression()) {
                auto expr = node->AsTSNonNullExpression();
                expr->SetOriginalType(expr->OriginalType()->Substitute(checker->Relation(), substitution));
            }
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

    auto *var =
        std::get<1>(varBinder->NewVarDecl<varbinder::FunctionDecl>(func->Start(), allocator, cmInfo->calleeName, func));
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

using ISS = ir::ScriptFunction::ScriptFunctionData;
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
    auto returnTypeAnnotation = allocator->New<ir::OpaqueTypeNode>(returnType, allocator);

    auto funcFlags = ir::ScriptFunctionFlags::METHOD | cmInfo->auxFunctionFlags;
    auto modifierFlags = ir::ModifierFlags::PUBLIC |
                         (info->callReceiver != nullptr ? ir::ModifierFlags::NONE : ir::ModifierFlags::STATIC) |
                         cmInfo->auxModifierFlags;

    auto func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ISS {cmInfo->body,
             ir::FunctionSignature(newTypeParams, std::move(params), returnTypeAnnotation,
                                   lambda->Function()->HasReceiver()),
             funcFlags, modifierFlags});
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
        ES2PANDA_ASSERT(ov->Name() == nv->Name());
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
            allocator, name, allocator->New<ir::OpaqueTypeNode>(substitutedType, allocator), allocator);
        auto *param = util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, id, false, allocator);
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

// NOTE(vpukhov): requires the optimization based on the array type
static ArenaVector<ark::es2panda::ir::Statement *> CreateRestArgumentsArrayReallocation(
    public_lib::Context *ctx, LambdaClassInvokeInfo const *lciInfo)
{
    if (!lciInfo->lambdaSignature->HasRestParameter()) {
        return ArenaVector<ir::Statement *>(ctx->allocator->Adapter());
    }

    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();

    auto *restParameterType = lciInfo->lambdaSignature->RestVar()->TsType();
    auto *restParameterSubstituteType = restParameterType->Substitute(checker->Relation(), lciInfo->substitution);
    auto *elementType = restParameterSubstituteType->AsETSArrayType()->ElementType();
    auto restParameterIndex = GenName(allocator).View();
    auto spreadArrIterator = GenName(allocator).View();

    std::stringstream statements;
    statements << "let @@I1: int = 0;";
    if (elementType->IsETSReferenceType()) {
        // NOTE(vpukhov): this is a clear null-safety violation that should be rewitten with a runtime intrinsic
        statements << "let @@I2: @@T3[] = (new (@@T4 | undefined)[@@I5.length]) as @@T6[];";
    } else {
        statements << "let @@I2: @@T3[] = (new (@@T4)[@@I5.length]) as @@T6[];";
    }
    statements << "for (let @@I7: @@T8 of @@I9){"
               << "    @@I10[@@I11] = @@I12 as @@T13 as @@T14;"
               << "    @@I15 = @@I16 + 1;"
               << "}";
    auto *args = parser->CreateFormattedStatement(
        statements.str(), restParameterIndex, lciInfo->restArgumentIdentifier, elementType, elementType,
        lciInfo->restParameterIdentifier, elementType, spreadArrIterator, checker->GlobalETSNullishObjectType(),
        lciInfo->restParameterIdentifier, lciInfo->restArgumentIdentifier, restParameterIndex, spreadArrIterator,
        checker->MaybeBoxType(elementType), elementType, restParameterIndex, restParameterIndex);
    return ArenaVector<ir::Statement *>(std::move(args->AsBlockStatement()->Statements()));
}

static void CreateInvokeMethodRestParameter(public_lib::Context *ctx, LambdaClassInvokeInfo *lciInfo,
                                            ArenaVector<ir::Expression *> *params)
{
    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();
    auto *anyType = checker->GlobalETSNullishObjectType();

    auto *restIdent = Gensym(allocator);
    lciInfo->restParameterIdentifier = restIdent->Name();
    lciInfo->restArgumentIdentifier = GenName(allocator).View();
    auto *spread = allocator->New<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, allocator, restIdent);
    auto *arr = checker->CreateETSArrayType(anyType, false);
    auto *typeAnnotation = allocator->New<ir::OpaqueTypeNode>(arr, allocator);

    spread->SetTsTypeAnnotation(typeAnnotation);
    spread->SetTsType(arr);
    restIdent->SetTsType(arr);
    auto *param = allocator->New<ir::ETSParameterExpression>(spread, nullptr, allocator);

    restIdent->SetParent(spread);
    typeAnnotation->SetParent(spread);
    spread->SetParent(param);
    params->push_back(param);
}

static ArenaVector<ir::Expression *> CreateCallArgumentsForLambdaClassInvoke(public_lib::Context *ctx,
                                                                             LambdaInfo const *info,
                                                                             LambdaClassInvokeInfo const *lciInfo,
                                                                             bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();

    auto callArguments = ArenaVector<ir::Expression *>(allocator->Adapter());
    for (auto *captured : *info->capturedVars) {
        auto *arg = parser->CreateFormattedExpression("this.@@I1", AvoidMandatoryThis(captured->Name()));
        callArguments.push_back(arg);
    }
    for (size_t idx = 0; idx < lciInfo->lambdaSignature->ArgCount(); ++idx) {
        auto lambdaParam = lciInfo->lambdaSignature->Params().at(idx);
        if (idx >= lciInfo->arity) {
            callArguments.push_back(allocator->New<ir::UndefinedLiteral>());
            continue;
        }
        auto argName = lambdaParam->Name();
        auto *type = lambdaParam->TsType()->Substitute(checker->Relation(), lciInfo->substitution);
        auto *arg = wrapToObject ? parser->CreateFormattedExpression("@@I1 as @@T2 as @@T3", argName,
                                                                     checker->MaybeBoxType(type), type)
                                 : allocator->New<ir::Identifier>(argName, allocator);
        callArguments.push_back(arg);
    }

    if (lciInfo->lambdaSignature->HasRestParameter()) {
        auto *restIdent = allocator->New<ir::Identifier>(lciInfo->restArgumentIdentifier, allocator);
        auto *spread = allocator->New<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, allocator, restIdent);
        restIdent->SetParent(spread);
        callArguments.push_back(spread);
    }
    return callArguments;
}

static ir::CallExpression *CreateCallForLambdaClassInvoke(public_lib::Context *ctx, LambdaInfo const *info,
                                                          LambdaClassInvokeInfo const *lciInfo, bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();

    auto callArguments = CreateCallArgumentsForLambdaClassInvoke(ctx, info, lciInfo, wrapToObject);
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
            typeArgs.push_back(
                allocator->New<ir::OpaqueTypeNode>(tp->Name()->AsIdentifier()->Variable()->TsType(), allocator));
        }
        auto *typeArg =
            util::NodeAllocator::ForceSetParent<ir::TSTypeParameterInstantiation>(allocator, std::move(typeArgs));
        call->SetTypeParams(typeArg);
        typeArg->SetParent(call);
    }

    return call;
}

static ir::BlockStatement *CreateLambdaClassInvokeBody(public_lib::Context *ctx, LambdaInfo const *info,
                                                       LambdaClassInvokeInfo const *lciInfo, bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();
    auto *anyType = checker->GlobalETSNullishObjectType();

    auto *call = CreateCallForLambdaClassInvoke(ctx, info, lciInfo, wrapToObject);
    auto bodyStmts = CreateRestArgumentsArrayReallocation(ctx, lciInfo);

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

    return util::NodeAllocator::ForceSetParent<ir::BlockStatement>(allocator, allocator, std::move(bodyStmts));
}

static void CreateLambdaClassInvokeMethod(public_lib::Context *ctx, LambdaInfo const *info,
                                          LambdaClassInvokeInfo *lciInfo, util::StringView methodName,
                                          bool wrapToObject)
{
    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();
    auto *anyType = checker->GlobalETSNullishObjectType();

    auto params = ArenaVector<ir::Expression *>(allocator->Adapter());
    for (size_t idx = 0; idx < lciInfo->arity; ++idx) {
        auto lparam = lciInfo->lambdaSignature->Params().at(idx);
        auto *type = wrapToObject ? anyType : lparam->TsType()->Substitute(checker->Relation(), lciInfo->substitution);
        auto *id = util::NodeAllocator::ForceSetParent<ir::Identifier>(
            allocator, lparam->Name(), allocator->New<ir::OpaqueTypeNode>(type, allocator), allocator);
        auto *param = util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(allocator, id, false, allocator);
        params.push_back(param);
    }

    if (lciInfo->lambdaSignature->HasRestParameter()) {
        CreateInvokeMethodRestParameter(ctx, lciInfo, &params);
    }

    auto *returnType2 = allocator->New<ir::OpaqueTypeNode>(
        wrapToObject ? anyType
                     : lciInfo->lambdaSignature->ReturnType()->Substitute(checker->Relation(), lciInfo->substitution),
        allocator);
    bool hasReceiver = lciInfo->lambdaSignature->HasSignatureFlag(checker::SignatureFlags::EXTENSION_FUNCTION);
    ir::ScriptFunctionFlags functionFlag = ir::ScriptFunctionFlags::METHOD;
    auto *func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {
            CreateLambdaClassInvokeBody(ctx, info, lciInfo, wrapToObject),
            ir::FunctionSignature(nullptr, std::move(params), returnType2, hasReceiver), functionFlag});

    auto *invokeId = allocator->New<ir::Identifier>(methodName, allocator);
    func->SetIdent(invokeId);

    auto *funcExpr = util::NodeAllocator::ForceSetParent<ir::FunctionExpression>(allocator, func);

    auto *invokeIdClone = invokeId->Clone(allocator, nullptr);
    auto *invokeMethod = util::NodeAllocator::ForceSetParent<ir::MethodDefinition>(
        allocator, ir::MethodDefinitionKind::METHOD, invokeIdClone, funcExpr, ir::ModifierFlags::NONE, allocator,
        false);
    ES2PANDA_ASSERT(!invokeMethod->IsStatic());

    lciInfo->classDefinition->Body().push_back(invokeMethod);
    invokeMethod->SetParent(lciInfo->classDefinition);
}

static checker::ETSObjectType *FunctionTypeToLambdaProviderType(checker::ETSChecker *checker,
                                                                checker::Signature *signature)
{
    if (signature->RestVar() != nullptr) {
        return checker->GlobalBuiltinLambdaType(signature->ArgCount(), true)->AsETSObjectType();
    }
    // Note: FunctionN is not supported yet
    if (signature->ArgCount() >= checker->GlobalBuiltinFunctionTypeVariadicThreshold()) {
        return nullptr;
    }
    return checker->GlobalBuiltinLambdaType(signature->ArgCount(), false)->AsETSObjectType();
}

// The `invoke` and `invoke0` of extension lambda class has two `this` identifier in parameter scope,
// first one is the lambdaClass itself and second one is the receiver class,
// the true `this` of the `invoke` and `invoke0` functionScope is the lambdaClass.
static void CorrectTheTrueThisForExtensionLambda(public_lib::Context *ctx, ir::ClassDeclaration *lambdaClass,
                                                 size_t arity, bool hasRestParam)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *classScope = lambdaClass->Definition()->Scope();
    ArenaVector<varbinder::Variable *> invokeFuncsOfLambda(checker->Allocator()->Adapter());
    auto invokeName = checker::FunctionalInterfaceInvokeName(arity, hasRestParam);
    invokeFuncsOfLambda.emplace_back(
        classScope->FindLocal(compiler::Signatures::LAMBDA_OBJECT_INVOKE, varbinder::ResolveBindingOptions::METHODS));
    invokeFuncsOfLambda.emplace_back(
        classScope->FindLocal(util::StringView(invokeName), varbinder::ResolveBindingOptions::METHODS));
    for (auto *invokeFuncOfLambda : invokeFuncsOfLambda) {
        if (invokeFuncOfLambda == nullptr) {
            continue;
        }
        auto *scriptFunc = invokeFuncOfLambda->Declaration()
                               ->AsFunctionDecl()
                               ->Node()
                               ->AsMethodDefinition()
                               ->Value()
                               ->AsFunctionExpression()
                               ->Function();
        if (!scriptFunc->Signature()->HasSignatureFlag(checker::SignatureFlags::EXTENSION_FUNCTION)) {
            ES2PANDA_ASSERT(!scriptFunc->IsExtensionMethod());
            continue;
        }
        ES2PANDA_ASSERT(scriptFunc->IsExtensionMethod());
        auto *functionScope = scriptFunc->Scope();
        auto *functionParamScope = scriptFunc->Scope()->ParamScope();
        auto *theTrueThisVar = functionParamScope->Params()[0];
        auto &bindings = const_cast<varbinder::Scope::VariableMap &>(functionScope->Bindings());
        bindings.erase(varbinder::ETSBinder::MANDATORY_PARAM_THIS);
        bindings.insert({varbinder::ETSBinder::MANDATORY_PARAM_THIS, theTrueThisVar});
    }
}

static ir::ClassDeclaration *CreateEmptyLambdaClassDeclaration(public_lib::Context *ctx, LambdaInfo const *info,
                                                               ir::TSTypeParameterDeclaration *newTypeParams,
                                                               checker::ETSObjectType *fnInterface,
                                                               checker::ETSObjectType *lambdaProviderClass)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();

    auto lambdaClassName = util::UString {std::string_view {"LambdaObject-"}, allocator};
    lambdaClassName.Append(info->calleeClass->Definition()->Ident()->Name()).Append("$").Append(info->name);

    auto *providerTypeReference = checker->AllocNode<ir::ETSTypeReference>(
        checker->AllocNode<ir::ETSTypeReferencePart>(
            checker->AllocNode<ir::Identifier>(lambdaProviderClass->AsETSObjectType()->Name(), checker->Allocator()),
            nullptr, nullptr, allocator),
        allocator);
    auto *classDeclaration = parser
                                 ->CreateFormattedTopLevelStatement("final class @@I1 extends @@T2 implements @@T3 {}",
                                                                    lambdaClassName, providerTypeReference, fnInterface)
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

    return classDeclaration;
}

static ir::ClassDeclaration *CreateLambdaClass(public_lib::Context *ctx, checker::ETSFunctionType *fntype,
                                               ir::MethodDefinition *callee, LambdaInfo const *info)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();

    auto *oldTypeParams = (info->enclosingFunction != nullptr) ? info->enclosingFunction->TypeParams() : nullptr;
    auto [newTypeParams, subst0] =
        CloneTypeParams(ctx, oldTypeParams, info->enclosingFunction, ctx->parserProgram->GlobalClassScope());
    auto *substitution = subst0;  // NOTE(gogabr): needed to capture in a lambda later.

    auto fnInterface = fntype->Substitute(checker->Relation(), substitution)->ArrowToFunctionalInterface(checker);
    auto lambdaProviderClass = FunctionTypeToLambdaProviderType(checker, fntype->ArrowSignature());

    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, ctx->parserProgram->GlobalClassScope());

    auto classDeclaration =
        CreateEmptyLambdaClassDeclaration(ctx, info, newTypeParams, fnInterface, lambdaProviderClass);
    auto classDefinition = classDeclaration->Definition();

    CreateLambdaClassFields(ctx, classDefinition, info, substitution);
    CreateLambdaClassConstructor(ctx, classDefinition, info, substitution);

    auto signature = fntype->ArrowSignature();

    LambdaClassInvokeInfo lciInfo;
    lciInfo.callee = callee;
    lciInfo.classDefinition = classDefinition;
    lciInfo.substitution = substitution;
    lciInfo.lambdaSignature = signature;

    for (size_t arity = signature->MinArgCount(); arity <= signature->ArgCount(); ++arity) {
        lciInfo.arity = arity;
        auto invokeMethodName =
            util::UString {checker::FunctionalInterfaceInvokeName(arity, signature->HasRestParameter()), ctx->allocator}
                .View();
        CreateLambdaClassInvokeMethod(ctx, info, &lciInfo, invokeMethodName, true);
        // NOTE(vpukhov): for optional methods, the required invokeRk k={min, max-1} is not emitted
    }
    CreateLambdaClassInvokeMethod(ctx, info, &lciInfo, compiler::Signatures::LAMBDA_OBJECT_INVOKE, false);

    InitScopesPhaseETS::RunExternalNode(classDeclaration, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(classDeclaration, varBinder->TopScope());
    classDeclaration->Check(checker);
    CorrectTheTrueThisForExtensionLambda(ctx, classDeclaration, signature->MinArgCount(),
                                         signature->HasRestParameter());
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
        allocator, allocator->New<ir::OpaqueTypeNode>(constructedType, allocator), std::move(args));
    auto *lambdaOrFuncRefParent = lambdaOrFuncRef->Parent();
    newExpr->SetParent(lambdaOrFuncRefParent);
    // NOTE(dslynko, #19869): Required for correct debug-info generation
    newExpr->SetRange(lambdaOrFuncRefParent != nullptr ? lambdaOrFuncRefParent->Range() : lambdaOrFuncRef->Range());

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
    auto *checker = ctx->checker->AsETSChecker();

    lambda->Check(checker);
    ES2PANDA_ASSERT(lambda->TsType()->IsETSFunctionType());

    LambdaInfo info;
    std::tie(info.calleeClass, info.enclosingFunction) = FindEnclosingClassAndFunction(lambda);
    info.name = CreateCalleeName(allocator);
    auto capturedVars = FindCaptured(allocator, lambda);
    info.capturedVars = &capturedVars;
    info.callReceiver = CheckIfNeedThis(lambda, checker) ? allocator->New<ir::ThisExpression>() : nullptr;

    auto *callee = CreateCallee(ctx, lambda, &info);
    auto *lambdaType = lambda->TsType()->AsETSFunctionType();
    auto *lambdaClass = CreateLambdaClass(ctx, lambdaType, callee, &info);
    return CreateConstructorCall(ctx, lambda, lambdaClass, &info);
}

static ir::ScriptFunction *GetWrappingLambdaParentFunction(public_lib::Context *ctx, ir::Expression *funcRef,
                                                           checker::Signature *signature)
{
    auto *allocator = ctx->allocator;
    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto *p : signature->Params()) {
        params.push_back(util::NodeAllocator::ForceSetParent<ir::ETSParameterExpression>(
            allocator,
            allocator->New<ir::Identifier>(p->Name(), allocator->New<ir::OpaqueTypeNode>(p->TsType(), allocator),
                                           allocator),
            false, allocator));
    }
    auto *func = util::NodeAllocator::ForceSetParent<ir::ScriptFunction>(
        allocator, allocator,
        ir::ScriptFunction::ScriptFunctionData {
            nullptr,
            ir::FunctionSignature {nullptr, std::move(params),
                                   allocator->New<ir::OpaqueTypeNode>(signature->ReturnType(), allocator)},
            ir::ScriptFunctionFlags::ARROW});

    ArenaVector<ir::Statement *> bodyStmts {allocator->Adapter()};
    ArenaVector<ir::Expression *> callArgs {allocator->Adapter()};

    for (auto *p : func->Params()) {
        ir::Identifier *clone = p->AsETSParameterExpression()->Ident()->Clone(allocator, nullptr);
        if (clone->IsIdentifier() && (clone->IsReference(ScriptExtension::ETS)) &&
            (clone->TypeAnnotation() != nullptr)) {
            clone->SetTsTypeAnnotation(nullptr);
        }
        callArgs.push_back(clone);
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
    return func;
}

static ir::ArrowFunctionExpression *CreateWrappingLambda(public_lib::Context *ctx, ir::Expression *funcRef)
{
    auto *allocator = ctx->allocator;
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    ES2PANDA_ASSERT(funcRef->TsType()->IsETSArrowType());
    auto signature = funcRef->TsType()->AsETSFunctionType()->ArrowSignature();

    auto *parent = funcRef->Parent();
    auto *func = GetWrappingLambdaParentFunction(ctx, funcRef, signature);

    auto *lambda = util::NodeAllocator::ForceSetParent<ir::ArrowFunctionExpression>(allocator, func, allocator);
    lambda->SetParent(parent);

    auto *nearestScope = NearestScope(lambda);
    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, nearestScope);
    InitScopesPhaseETS::RunExternalNode(lambda, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(lambda, nearestScope);

    auto [enclosingClass, _] = FindEnclosingClassAndFunction(parent);

    auto checkerCtx = checker::SavedCheckerContext(ctx->checker, checker::CheckerStatus::IN_CLASS,
                                                   enclosingClass->Definition()->TsType()->AsETSObjectType());
    auto scopeCtx = checker::ScopeContext(ctx->checker, nearestScope);
    lambda->Check(ctx->checker->AsETSChecker());

    return lambda;
}

static ir::AstNode *ConvertFunctionReference(public_lib::Context *ctx, ir::Expression *funcRef)
{
    auto *allocator = ctx->allocator;
    ES2PANDA_ASSERT(funcRef->IsIdentifier() ||
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
                checker::PropertySearchFlags::SEARCH_IN_BASE |
                checker::PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);
        ES2PANDA_ASSERT(var != nullptr);
    }

    ES2PANDA_ASSERT(var->Declaration()->Node()->IsMethodDefinition());
    auto *method = var->Declaration()->Node()->AsMethodDefinition();

    if (method->IsPrivate() || method->IsProtected()) {
        // Direct reference to method will be impossible from the lambda class, so replace func ref with a lambda
        // that will translate to a proxy method
        auto *lam = CreateWrappingLambda(ctx, funcRef);
        if (lam == nullptr) {
            return funcRef;
        }
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
        ES2PANDA_ASSERT(funcRef->IsMemberExpression());
        info.callReceiver = funcRef->AsMemberExpression()->Object();
    }

    ES2PANDA_ASSERT(funcRef->TsType()->IsETSArrowType());
    auto *lambdaClass = CreateLambdaClass(ctx, funcRef->TsType()->AsETSFunctionType(), method, &info);
    auto *constructorCall = CreateConstructorCall(ctx, funcRef, lambdaClass, &info);
    return constructorCall;
}

static bool IsVariableOriginalAccessor(const varbinder::Variable *var)
{
    return checker::ETSChecker::IsVariableGetterSetter(var) && !(checker::ETSChecker::IsVariableExtensionAccessor(var));
}

static bool IsFunctionOrMethodCall(checker::ETSChecker *checker, ir::CallExpression const *node)
{
    auto const *callee = node->Callee();
    if (callee->TsType() != nullptr && callee->TsType()->IsETSExtensionFuncHelperType()) {
        return true;
    }

    // NOTE: Skip if invoke pattern Union.<method>()
    // Not skip if invoke pattern Union.<field>() where field is of ETSArrowType
    if (callee->IsMemberExpression()) {
        auto me = callee->AsMemberExpression();
        if (me->Object()->TsType() != nullptr && checker->GetApparentType(me->Object()->TsType())->IsETSUnionType() &&
            me->TsType()->IsETSMethodType()) {
            return true;
        }
    }

    varbinder::Variable *var = nullptr;
    if (callee->IsMemberExpression() &&
        (callee->AsMemberExpression()->Kind() & ir::MemberExpressionKind::PROPERTY_ACCESS) != 0) {
        var = callee->AsMemberExpression()->Property()->Variable();
    } else if (callee->IsIdentifier()) {
        var = callee->AsIdentifier()->Variable();
    }

    return var != nullptr && !IsVariableOriginalAccessor(var) && (var->Flags() & varbinder::VariableFlags::METHOD) != 0;
}

static ir::AstNode *InsertInvokeCall(public_lib::Context *ctx, ir::CallExpression *call)
{
    auto *allocator = ctx->allocator;
    auto *checker = ctx->checker->AsETSChecker();
    auto *varBinder = checker->VarBinder()->AsETSBinder();

    auto *oldCallee = call->Callee();
    auto *oldType = checker->GetApparentType(oldCallee->TsType());
    size_t arity = call->Arguments().size();
    auto *ifaceType = oldType->IsETSObjectType()
                          ? oldType->AsETSObjectType()
                          : oldType->AsETSFunctionType()->ArrowToFunctionalInterfaceDesiredArity(checker, arity);
    if (ifaceType->IsETSDynamicType()) {
        return call;
    }
    bool hasRestParam =
        oldType->IsETSFunctionType() && oldType->AsETSFunctionType()->ArrowSignature()->HasRestParameter();
    util::StringView invokeMethodName =
        util::UString {checker::FunctionalInterfaceInvokeName(arity, hasRestParam), allocator}.View();
    auto *prop = ifaceType->GetProperty(invokeMethodName, checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                                              checker::PropertySearchFlags::SEARCH_IN_INTERFACES);
    ES2PANDA_ASSERT(prop != nullptr);
    auto *invoke0Id = allocator->New<ir::Identifier>(invokeMethodName, allocator);
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
        Recheck(ctx->phaseManager, varBinder, checker, arg);
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

static bool IsEnumFunctionCall(const ir::Identifier *const id)
{
    if (id->Parent() != nullptr && id->Parent()->IsMemberExpression()) {
        const auto *const expr = id->Parent()->AsMemberExpression();
        if (expr->Object()->TsType()->IsETSEnumType()) {
            return true;
        }
    }

    return false;
}

static bool IsValidFunctionDeclVar(const varbinder::Variable *const var)
{
    // Note: If a function is accessor, then no need to build lambda class.
    return var != nullptr && var->Declaration() != nullptr && var->Declaration()->IsFunctionDecl() &&
           !var->TsType()->HasTypeFlag(checker::TypeFlag::GETTER_SETTER);
}

static ir::AstNode *BuildLambdaClassWhenNeeded(public_lib::Context *ctx, ir::AstNode *node)
{
    if (node->IsArrowFunctionExpression()) {
        return ConvertLambda(ctx, node->AsArrowFunctionExpression());
    }

    if (node->IsIdentifier()) {
        auto *id = node->AsIdentifier();
        auto *var = id->Variable();
        // We are running this lowering only for ETS files
        // so it is correct to pass ETS extension here to isReference()
        if (id->IsReference(ScriptExtension::ETS) && id->TsType() != nullptr && id->TsType()->IsETSFunctionType() &&
            !IsInCalleePosition(id) && !IsEnumFunctionCall(id) && IsValidFunctionDeclVar(var)) {
            return ConvertFunctionReference(ctx, id);
        }
    }
    if (node->IsMemberExpression()) {
        auto *mexpr = node->AsMemberExpression();
        if (mexpr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS && mexpr->TsType() != nullptr &&
            mexpr->TsType()->IsETSFunctionType() && mexpr->Object()->TsType()->IsETSObjectType()) {
            ES2PANDA_ASSERT(mexpr->Property()->IsIdentifier());
            auto *var = mexpr->Object()->TsType()->AsETSObjectType()->GetProperty(
                mexpr->Property()->AsIdentifier()->Name(),
                checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                    checker::PropertySearchFlags::SEARCH_STATIC_METHOD | checker::PropertySearchFlags::SEARCH_IN_BASE |
                    checker::PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);
            if (IsValidFunctionDeclVar(var) && !IsInCalleePosition(mexpr)) {
                return ConvertFunctionReference(ctx, mexpr);
            }
        }
    }
    return node;
}

static ir::AstNode *LowerTypeNodeIfNeeded(public_lib::Context *ctx, ir::AstNode *node)
{
    if (!node->IsExpression() || !node->AsExpression()->IsTypeNode()) {
        return node;
    }

    auto type = node->AsExpression()->AsTypeNode()->TsType();
    if (type == nullptr || !type->IsETSArrowType()) {
        return node;
    }

    auto allocator = ctx->allocator;
    auto checker = ctx->checker->AsETSChecker();

    auto newTypeNode =
        allocator->New<ir::OpaqueTypeNode>(type->AsETSFunctionType()->ArrowToFunctionalInterface(checker), allocator);
    newTypeNode->SetParent(node->Parent());
    return newTypeNode;
}

bool LambdaConversionPhase::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    auto *varBinder = ctx->checker->VarBinder()->AsETSBinder();
    varbinder::RecordTableContext bctx {varBinder, program == ctx->parserProgram ? nullptr : program};
    parser::SavedFormattingFileName savedFormattingName(ctx->parser->AsETSParser(), "lambda-conversion");

    // For reproducibility of results when several compilation sessions are executed during
    // the same process's lifetime.
    if (program == ctx->parserProgram) {
        ResetCalleeCount();
    }

    program->Ast()->TransformChildrenRecursivelyPostorder(
        [ctx](ir::AstNode *node) { return BuildLambdaClassWhenNeeded(ctx, node); }, Name());

    program->Ast()->TransformChildrenRecursivelyPreorder(
        [ctx](ir::AstNode *node) { return LowerTypeNodeIfNeeded(ctx, node); }, Name());

    auto insertInvokeIfNeeded = [ctx](ir::AstNode *node) {
        if (node->IsCallExpression() &&
            !IsFunctionOrMethodCall(ctx->checker->AsETSChecker(), node->AsCallExpression()) &&
            !IsRedirectingConstructorCall(node->AsCallExpression())) {
            return InsertInvokeCall(ctx, node->AsCallExpression());
        }
        return node;
    };

    // at this moment, the AST in subexpressions is not consistent, so the preorder is chosen
    program->Ast()->TransformChildrenRecursivelyPreorder(insertInvokeIfNeeded, Name());

    return true;
}

bool LambdaConversionPhase::PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                                   parser::Program const *program)
{
    return !program->Ast()->IsAnyChild([](ir::AstNode const *node) { return node->IsArrowFunctionExpression(); });
}

}  // namespace ark::es2panda::compiler
