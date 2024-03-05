/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "localClassLowering.h"
#include "checker/ETSchecker.h"
#include "varbinder/ETSBinder.h"
#include "../util.h"

namespace ark::es2panda::compiler {

std::string_view LocalClassConstructionPhase::Name() const
{
    return "LocalClassConstructionPhase";
}

void LocalClassConstructionPhase::ReplaceReferencesFromTheParametersToTheLocalVariavbles(
    ir::ClassDefinition *classDef, const ArenaMap<varbinder::Variable *, varbinder::Variable *> &newLocalVariablesMap,
    const ArenaSet<ir::Identifier *> &initializers)
{
    // Replace the parameter variables with the newly created temporal variables and change all the references to
    // the new temporal variable
    for (auto boxedVarParamsIt = newLocalVariablesMap.begin(); boxedVarParamsIt != newLocalVariablesMap.end();
         ++boxedVarParamsIt) {
        auto paramVar = boxedVarParamsIt->first;
        auto newVar = boxedVarParamsIt->second;

        classDef->EraseCapturedVariable(paramVar);
        classDef->CaptureVariable(newVar);

        auto *scope = paramVar->GetScope();
        scope = scope->AsFunctionParamScope()->GetFunctionScope();

        auto *block = scope->AsFunctionScope()->Node()->AsScriptFunction()->Body()->AsBlockStatement();

        block->IterateRecursively([&newLocalVariablesMap, &initializers](ir::AstNode *childNode) {
            if (childNode->Type() != ir::AstNodeType::IDENTIFIER ||
                initializers.find(childNode->AsIdentifier()) != initializers.end()) {
                return;
            }
            const auto &newMapIt = newLocalVariablesMap.find(childNode->AsIdentifier()->Variable());
            if (newMapIt != newLocalVariablesMap.end()) {
                LOG(DEBUG, ES2PANDA) << "      Remap param variable: " << childNode->AsIdentifier()->Name()
                                     << " (identifier:" << (void *)childNode
                                     << ") variable:" << (void *)childNode->AsIdentifier()->Variable()
                                     << " -> temporal variable:" << (void *)newMapIt->second;
                childNode->AsIdentifier()->SetVariable(newMapIt->second);
            }
        });
    }
}

void LocalClassConstructionPhase::CreateTemporalLocalVariableForModifiedParameters(public_lib::Context *ctx,
                                                                                   ir::ClassDefinition *classDef)
{
    // Store the new variables created for the function parameters needed to be boxed
    ArenaMap<varbinder::Variable *, varbinder::Variable *> newLocalVariablesMap(ctx->allocator->Adapter());

    // Store the new variables created for the function parameters needed to be boxed
    ArenaSet<ir::Identifier *> initializers(ctx->allocator->Adapter());

    // Create local variables for modified parameters since the parameters can not be boxed
    for (auto var : classDef->CapturedVariables()) {
        if (var->Declaration() != nullptr && var->Declaration()->IsParameterDecl() &&
            classDef->IsLocalVariableNeeded(var)) {
            auto *scope = var->GetScope();
            ASSERT(scope->IsFunctionParamScope());
            scope = scope->AsFunctionParamScope()->GetFunctionScope();
            ASSERT(scope->AsFunctionScope()->Node()->IsScriptFunction());
            ASSERT(scope->AsFunctionScope()->Node()->AsScriptFunction()->Body()->IsBlockStatement());
            auto *param = var->Declaration()->AsParameterDecl();
            auto *block = scope->AsFunctionScope()->Node()->AsScriptFunction()->Body()->AsBlockStatement();

            auto *newVarIdentifier = Gensym(ctx->allocator);

            auto *newVar = scope->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(
                ctx->allocator, newVarIdentifier->Name(), varbinder::VariableFlags::LOCAL);

            newVarIdentifier->SetVariable(newVar);
            newVar->SetTsType(var->TsType());
            newVar->AddFlag(varbinder::VariableFlags::BOXED);

            auto *initializer = ctx->allocator->New<ir::Identifier>(param->Name(), ctx->allocator);
            initializer->SetVariable(var);
            initializer->SetTsType(var->TsType());

            initializers.insert(initializer);
            auto *declarator = ctx->allocator->New<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET,
                                                                           newVarIdentifier, initializer);

            newVarIdentifier->SetParent(declarator);
            initializer->SetParent(declarator);

            ArenaVector<ir::VariableDeclarator *> declarators(ctx->allocator->Adapter());
            declarators.push_back(declarator);

            auto *newVariableDeclaration = ctx->allocator->New<ir::VariableDeclaration>(
                ir::VariableDeclaration::VariableDeclarationKind::LET, ctx->allocator, std::move(declarators), false);

            declarator->SetParent(newVariableDeclaration);
            newVariableDeclaration->SetParent(block);
            block->Statements().insert(block->Statements().begin(), newVariableDeclaration);

            newLocalVariablesMap[var] = newVar;
        }
    }

    ReplaceReferencesFromTheParametersToTheLocalVariavbles(classDef, newLocalVariablesMap, initializers);
}

void LocalClassConstructionPhase::CreateClassPropertiesForCapturedVariables(
    public_lib::Context *ctx, ir::ClassDefinition *classDef,
    ArenaMap<varbinder::Variable *, varbinder::Variable *> &variableMap,
    ArenaMap<varbinder::Variable *, ir::ClassProperty *> &propertyMap)
{
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();
    size_t idx = 0;
    ArenaVector<ir::AstNode *> properties(ctx->allocator->Adapter());
    for (auto var : classDef->CapturedVariables()) {
        ASSERT(classDef->Scope()->Type() == varbinder::ScopeType::CLASS);
        auto *property = checker->CreateLambdaCapturedField(
            var, reinterpret_cast<varbinder::ClassScope *>(classDef->Scope()), idx, classDef->Start());
        LOG(DEBUG, ES2PANDA) << "  - Creating property (" << property->Id()->Name()
                             << ") for captured variable: " << var->Name();
        properties.push_back(property);
        variableMap[var] = property->Id()->Variable();
        propertyMap[var] = property;
        idx++;
    }

    classDef->AddProperties(std::move(properties));
}

ir::ETSParameterExpression *LocalClassConstructionPhase::CreateParam(checker::ETSChecker *const checker,
                                                                     varbinder::FunctionParamScope *scope,
                                                                     util::StringView name, checker::Type *type)
{
    auto newParam = checker->AddParam(name, nullptr);
    newParam->SetTsType(type);
    newParam->Ident()->SetTsType(type);
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(checker->VarBinder(), scope, false);

    auto *paramVar = std::get<1>(checker->VarBinder()->AddParamDecl(newParam));
    paramVar->SetTsType(newParam->TsType());
    newParam->Ident()->SetVariable(paramVar);
    return newParam;
}

void LocalClassConstructionPhase::ModifyConstructorParameters(
    public_lib::Context *ctx, ir::ClassDefinition *classDef,
    ArenaMap<varbinder::Variable *, varbinder::Variable *> &variableMap,
    ArenaMap<varbinder::Variable *, varbinder::Variable *> &parameterMap)

{
    auto *classType = classDef->TsType()->AsETSObjectType();
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    for (auto *signature : classType->ConstructSignatures()) {
        LOG(DEBUG, ES2PANDA) << "  - Modifying Constructor: " << signature->InternalName();
        auto constructor = signature->Function();
        auto &parameters = constructor->Params();
        auto &sigParams = signature->Params();
        signature->GetSignatureInfo()->minArgCount += classDef->CapturedVariables().size();

        ASSERT(signature == constructor->Signature());
        for (auto var : classDef->CapturedVariables()) {
            auto *newParam =
                CreateParam(checker, constructor->Scope()->ParamScope(), var->Name(), checker->MaybeBoxedType(var));
            newParam->SetParent(constructor);
            // NOTE(psiket) : Moving the parameter after the 'this'. Should modify the AddParam
            // to be able to insert after the this.
            auto &paramScopeParams = constructor->Scope()->ParamScope()->Params();
            auto thisParamIt = ++paramScopeParams.begin();
            paramScopeParams.insert(thisParamIt, paramScopeParams.back());
            paramScopeParams.pop_back();

            parameters.insert(parameters.begin(), newParam);
            ASSERT(newParam->Variable()->Type() == varbinder::VariableType::LOCAL);
            sigParams.insert(sigParams.begin(), newParam->Ident()->Variable()->AsLocalVariable());
            parameterMap[var] = newParam->Ident()->Variable()->AsLocalVariable();
        }
        reinterpret_cast<varbinder::ETSBinder *>(checker->VarBinder())->BuildFunctionName(constructor);
        LOG(DEBUG, ES2PANDA) << "    Transformed Constructor: " << signature->InternalName();

        auto *body = constructor->Body();
        ArenaVector<ir::Statement *> initStatements(ctx->allocator->Adapter());
        for (auto var : classDef->CapturedVariables()) {
            auto *propertyVar = variableMap[var];
            auto *initStatement = checker->CreateLambdaCtorFieldInit(propertyVar->Name(), propertyVar);
            auto *fieldInit = initStatement->AsExpressionStatement()->GetExpression()->AsAssignmentExpression();
            auto *ctorParamVar = parameterMap[var];
            auto *fieldVar = variableMap[var];
            auto *leftHandSide = fieldInit->Left();
            leftHandSide->AsMemberExpression()->SetObjectType(classType);
            leftHandSide->AsMemberExpression()->SetPropVar(fieldVar->AsLocalVariable());
            leftHandSide->AsMemberExpression()->SetIgnoreBox();
            leftHandSide->AsMemberExpression()->SetTsType(fieldVar->TsType());
            leftHandSide->AsMemberExpression()->Object()->SetTsType(classType);
            fieldInit->Right()->AsIdentifier()->SetVariable(ctorParamVar);
            fieldInit->Right()->SetTsType(ctorParamVar->TsType());
            initStatement->SetParent(body);
            initStatements.push_back(initStatement);
        }
        auto &statements = body->AsBlockStatement()->Statements();
        statements.insert(statements.begin(), initStatements.begin(), initStatements.end());
    }
}

void LocalClassConstructionPhase::RemapReferencesFromCapturedVariablesToClassProperties(
    ir::ClassDefinition *classDef, ArenaMap<varbinder::Variable *, varbinder::Variable *> &variableMap)
{
    auto *classType = classDef->TsType()->AsETSObjectType();
    auto remapCapturedVariables = [&variableMap](ir::AstNode *childNode) {
        if (childNode->Type() == ir::AstNodeType::IDENTIFIER) {
            LOG(DEBUG, ES2PANDA) << "    checking var:" << (void *)childNode;
            const auto &mapIt = variableMap.find(childNode->AsIdentifier()->Variable());
            if (mapIt != variableMap.end()) {
                LOG(DEBUG, ES2PANDA) << "      Remap: " << childNode->AsIdentifier()->Name()
                                     << " (identifier:" << (void *)childNode
                                     << ") variable:" << (void *)childNode->AsIdentifier()->Variable()
                                     << " -> property variable:" << (void *)mapIt->second;
                childNode->AsIdentifier()->SetVariable(mapIt->second);
            } else {
            }
        }
    };

    for (auto *it : classDef->Body()) {
        if (it->IsMethodDefinition() && !it->AsMethodDefinition()->IsConstructor()) {
            LOG(DEBUG, ES2PANDA) << "  - Rebinding variable rerferences in: "
                                 << it->AsMethodDefinition()->Id()->Name().Mutf8().c_str();
            it->AsMethodDefinition()->Function()->Body()->IterateRecursively(remapCapturedVariables);
        }
    }
    // Since the constructor with zero parameter is not listed in the class_def body the constructors
    // processed separately
    for (auto *signature : classType->ConstructSignatures()) {
        auto *constructor = signature->Function();
        LOG(DEBUG, ES2PANDA) << "  - Rebinding variable rerferences in: " << constructor->Id()->Name();
        constructor->Body()->IterateRecursively(remapCapturedVariables);
    }
}

bool LocalClassConstructionPhase::Perform(public_lib::Context *ctx, parser::Program * /*program*/)
{
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();
    for (auto *classDef : checker->GetLocalClasses()) {
        LOG(DEBUG, ES2PANDA) << "Altering local class with the captured variables: " << classDef->InternalName();
        // Map the captured variable to the variable of the class property
        ArenaMap<varbinder::Variable *, varbinder::Variable *> variableMap(ctx->allocator->Adapter());
        // Map the captured variable to the class property
        ArenaMap<varbinder::Variable *, ir::ClassProperty *> propertyMap(ctx->allocator->Adapter());
        // Map the captured variable to the constructor parameter
        ArenaMap<varbinder::Variable *, varbinder::Variable *> parameterMap(ctx->allocator->Adapter());

        CreateTemporalLocalVariableForModifiedParameters(ctx, classDef);
        CreateClassPropertiesForCapturedVariables(ctx, classDef, variableMap, propertyMap);
        ModifyConstructorParameters(ctx, classDef, variableMap, parameterMap);
        RemapReferencesFromCapturedVariablesToClassProperties(classDef, variableMap);
    }

    // Alter the instantiations
    for (auto *newExpr : checker->GetLocalClassInstantiations()) {
        checker::Type *calleeType = newExpr->GetTypeRef()->Check(checker);
        auto *calleeObj = calleeType->AsETSObjectType();
        auto *classDef = calleeObj->GetDeclNode()->AsClassDefinition();
        LOG(DEBUG, ES2PANDA) << "Instantiating local class: " << classDef->Ident()->Name();
        for (auto *var : classDef->CapturedVariables()) {
            LOG(DEBUG, ES2PANDA) << "  - Extending constructor argument with captured variable: " << var->Name();

            auto *param = checker->AllocNode<ir::Identifier>(var->Name(), ctx->allocator);
            param->SetVariable(var);
            param->SetIgnoreBox();
            param->SetTsType(checker->AsETSChecker()->MaybeBoxedType(param->Variable()));
            param->SetParent(newExpr);
            newExpr->AddToArgumentsFront(param);
        }
    }

    return true;
}

}  // namespace ark::es2panda::compiler
