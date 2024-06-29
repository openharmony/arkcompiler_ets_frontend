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

static ir::ClassProperty *CreateCapturedField(checker::ETSChecker *checker, const varbinder::Variable *capturedVar,
                                              varbinder::ClassScope *scope, size_t &idx,
                                              const lexer::SourcePosition &pos)
{
    auto *allocator = checker->Allocator();
    auto *varBinder = checker->VarBinder();

    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(varBinder, scope->InstanceFieldScope());

    // Create the name for the synthetic property node
    util::UString fieldName(util::StringView("field#"), allocator);
    fieldName.Append(std::to_string(idx));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldIdent = allocator->New<ir::Identifier>(fieldName.View(), allocator);

    // Create the synthetic class property node
    auto *field =
        allocator->New<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);
    fieldIdent->SetParent(field);

    // Add the declaration to the scope, and set the type based on the captured variable's scope
    auto [decl, var] = varBinder->NewVarDecl<varbinder::LetDecl>(pos, fieldIdent->Name());
    var->SetScope(scope->InstanceFieldScope());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(capturedVar->TsType());

    fieldIdent->SetVariable(var);
    field->SetTsType(capturedVar->TsType());
    decl->BindNode(field);
    return field;
}

static ir::Statement *CreateCtorFieldInit(checker::ETSChecker *checker, util::StringView name, varbinder::Variable *var)
{
    // Create synthetic field initializers for the local class fields
    // The node structure is the following: this.field0 = field0, where the left hand side refers to the local
    // classes field, and the right hand side is refers to the constructors parameter
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *allocator = checker->Allocator();

    auto *thisExpr = allocator->New<ir::ThisExpression>();
    auto *fieldAccessExpr = allocator->New<ir::Identifier>(name, allocator);
    fieldAccessExpr->SetReference();
    auto *leftHandSide = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, thisExpr, fieldAccessExpr, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *rightHandSide = allocator->New<ir::Identifier>(name, allocator);
    rightHandSide->SetVariable(var);
    auto *initializer = util::NodeAllocator::ForceSetParent<ir::AssignmentExpression>(
        allocator, leftHandSide, rightHandSide, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    initializer->SetTsType(var->TsType());
    return util::NodeAllocator::ForceSetParent<ir::ExpressionStatement>(allocator, initializer);
}

void LocalClassConstructionPhase::CreateClassPropertiesForCapturedVariables(
    public_lib::Context *ctx, ir::ClassDefinition *classDef, ArenaSet<varbinder::Variable *> const &capturedVars,
    ArenaMap<varbinder::Variable *, varbinder::Variable *> &variableMap,
    ArenaMap<varbinder::Variable *, ir::ClassProperty *> &propertyMap)
{
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();
    size_t idx = 0;
    ArenaVector<ir::AstNode *> properties(ctx->allocator->Adapter());
    for (auto var : capturedVars) {
        ASSERT(classDef->Scope()->Type() == varbinder::ScopeType::CLASS);
        auto *property = CreateCapturedField(checker, var, reinterpret_cast<varbinder::ClassScope *>(classDef->Scope()),
                                             idx, classDef->Start());
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
    public_lib::Context *ctx, ir::ClassDefinition *classDef, ArenaSet<varbinder::Variable *> const &capturedVars,
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
        signature->GetSignatureInfo()->minArgCount += capturedVars.size();

        ASSERT(signature == constructor->Signature());
        for (auto var : capturedVars) {
            auto *newParam = CreateParam(checker, constructor->Scope()->ParamScope(), var->Name(), var->TsType());
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
        for (auto var : capturedVars) {
            auto *propertyVar = variableMap[var];
            auto *initStatement = CreateCtorFieldInit(checker, propertyVar->Name(), propertyVar);
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

bool LocalClassConstructionPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    auto *allocator = ctx->allocator;
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();
    ArenaUnorderedMap<ir::ClassDefinition *, ArenaSet<varbinder::Variable *>> capturedVarsMap {allocator->Adapter()};

    auto handleLocalClass = [this, ctx, &capturedVarsMap](ir::ClassDefinition *classDef) {
        LOG(DEBUG, ES2PANDA) << "Altering local class with the captured variables: " << classDef->InternalName();
        auto capturedVars = FindCaptured(ctx->allocator, classDef);
        // Map the captured variable to the variable of the class property
        ArenaMap<varbinder::Variable *, varbinder::Variable *> variableMap(ctx->allocator->Adapter());
        // Map the captured variable to the class property
        ArenaMap<varbinder::Variable *, ir::ClassProperty *> propertyMap(ctx->allocator->Adapter());
        // Map the captured variable to the constructor parameter
        ArenaMap<varbinder::Variable *, varbinder::Variable *> parameterMap(ctx->allocator->Adapter());

        CreateClassPropertiesForCapturedVariables(ctx, classDef, capturedVars, variableMap, propertyMap);
        ModifyConstructorParameters(ctx, classDef, capturedVars, variableMap, parameterMap);
        RemapReferencesFromCapturedVariablesToClassProperties(classDef, variableMap);
        capturedVarsMap.emplace(classDef, std::move(capturedVars));
    };

    program->Ast()->IterateRecursivelyPostorder([&](ir::AstNode *ast) {
        if (ast->IsClassDefinition() && ast->AsClassDefinition()->IsLocal()) {
            handleLocalClass(ast->AsClassDefinition());
        }
    });

    // Alter the instantiations
    auto handleLocalClassInstantiation = [ctx, checker, &capturedVarsMap](ir::ClassDefinition *classDef,
                                                                          ir::ETSNewClassInstanceExpression *newExpr) {
        LOG(DEBUG, ES2PANDA) << "Instantiating local class: " << classDef->Ident()->Name();
        auto capturedVarsIt = capturedVarsMap.find(classDef);
        ASSERT(capturedVarsIt != capturedVarsMap.cend());
        auto &capturedVars = capturedVarsIt->second;
        for (auto *var : capturedVars) {
            LOG(DEBUG, ES2PANDA) << "  - Extending constructor argument with captured variable: " << var->Name();

            auto *param = checker->AllocNode<ir::Identifier>(var->Name(), ctx->allocator);
            param->SetVariable(var);
            param->SetIgnoreBox();
            param->SetTsType(param->Variable()->TsType());
            param->SetParent(newExpr);
            newExpr->AddToArgumentsFront(param);
        }
    };

    program->Ast()->IterateRecursivelyPostorder([&](ir::AstNode *ast) {
        if (ast->IsETSNewClassInstanceExpression()) {
            auto *newExpr = ast->AsETSNewClassInstanceExpression();
            checker::Type *calleeType = newExpr->GetTypeRef()->Check(checker);
            auto *calleeObj = calleeType->AsETSObjectType();
            auto *classDef = calleeObj->GetDeclNode()->AsClassDefinition();
            if (classDef->IsLocal()) {
                handleLocalClassInstantiation(classDef, newExpr);
            }
        }
    });

    return true;
}

}  // namespace ark::es2panda::compiler
