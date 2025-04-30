/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "restTupleLowering.h"
#include "checker/ETSchecker.h"
#include "ir/base/scriptFunction.h"
#include "compiler/lowering/util.h"
#include "checker/types/type.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

bool MethodDefinitionHasRestTuple(const ir::AstNode *def)
{
    auto pred = [](const auto *param) {
        return param->IsETSParameterExpression() && param->AsETSParameterExpression()->IsRestParameter() &&
               param->AsETSParameterExpression()->TypeAnnotation() &&
               param->AsETSParameterExpression()->TypeAnnotation()->IsETSTuple();
    };

    bool isScriptFunction = def->IsMethodDefinition() && (def->AsMethodDefinition()->Value() != nullptr) &&
                            def->AsMethodDefinition()->Value()->AsFunctionExpression()->Function()->IsScriptFunction();
    if (isScriptFunction) {
        auto params =
            def->AsMethodDefinition()->Value()->AsFunctionExpression()->Function()->AsScriptFunction()->Params();
        return std::any_of(params.begin(), params.end(), pred);
    }
    return false;
}

bool IsClassDefinitionWithTupleRest(ir::AstNode *node)
{
    bool isClassDefinition = node->IsClassDefinition();
    if (isClassDefinition) {
        auto definitions = node->AsClassDefinition()->Body();
        return std::any_of(definitions.begin(), definitions.end(),
                           [](const auto *def) { return MethodDefinitionHasRestTuple(def); });
    }

    return false;
}

ir::Expression *CreateMemberOrThisExpression(public_lib::Context *ctx, ir::Expression *funcExpr,
                                             ir::AstNode *definition)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    if (definition->IsConstructor()) {
        return checker->AllocNode<ir::ThisExpression>();
    }

    auto scriptFunc = funcExpr->AsFunctionExpression()->Function()->AsScriptFunction();

    ir::Expression *ident = nullptr;

    if (definition->AsMethodDefinition()->IsStatic()) {
        auto *parentClass = util::Helpers::FindAncestorGivenByType(definition, ir::AstNodeType::CLASS_DEFINITION);
        ES2PANDA_ASSERT(parentClass != nullptr);
        ident = parentClass->AsClassDefinition()->Ident()->AsIdentifier()->Clone(allocator, parentClass->Parent());
    } else {
        ident = checker->AllocNode<ir::ThisExpression>();
    }

    auto *newPropertyId = scriptFunc->Id()->Clone(allocator, nullptr);
    auto *memberExpr = checker->AllocNode<ir::MemberExpression>(
        ident, newPropertyId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    newPropertyId->SetParent(memberExpr);

    return memberExpr;
}

ir::CallExpression *CreateNewCallExpression(public_lib::Context *ctx, ir::Expression *funcExpr, ir::AstNode *definition,
                                            ir::TSAsExpression *asExpression)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Expression *> callArguments({}, checker->Allocator()->Adapter());
    for (auto arg : funcExpr->AsFunctionExpression()->Function()->AsScriptFunction()->Params()) {
        if (!arg->AsETSParameterExpression()->IsRestParameter()) {
            auto *id = arg->AsETSParameterExpression()->Ident()->Clone(allocator, nullptr);
            id->SetTsTypeAnnotation(nullptr);
            callArguments.push_back(id);
        } else {
            auto spreadElement =
                checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, allocator, asExpression);
            asExpression->SetParent(spreadElement);
            callArguments.push_back(spreadElement);
        }
    }

    // Create member expression if method is not a constructor
    ir::Expression *memberExpr = CreateMemberOrThisExpression(ctx, funcExpr, definition);

    auto *newCallExpr = checker->AllocNode<ir::CallExpression>(memberExpr, std::move(callArguments), nullptr, false);

    if (definition->IsConstructor()) {
        memberExpr->SetParent(newCallExpr);
    }
    for (auto *arg : newCallExpr->Arguments()) {
        arg->SetParent(newCallExpr);
    }

    return newCallExpr;
}

ArenaVector<ir::Expression *> CreateFunctionRestParams(public_lib::Context *ctx, ir::AstNode *funcExpr)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto param : funcExpr->AsFunctionExpression()->Function()->AsScriptFunction()->Params()) {
        if (param->AsETSParameterExpression()->IsRestParameter()) {
            for (auto tupleTypeAnno :
                 param->AsETSParameterExpression()->TypeAnnotation()->AsETSTuple()->GetTupleTypeAnnotationsList()) {
                ir::Identifier *id = Gensym(allocator);
                auto *newParam = checker->AsETSChecker()->AllocNode<ir::ETSParameterExpression>(id, false, allocator);
                auto newAnnotation = tupleTypeAnno->Clone(allocator, id);
                id->SetParent(newParam);
                id->SetTsTypeAnnotation(newAnnotation);
                params.push_back(newParam);
            }
        }
    }
    return params;
}

ArenaVector<ir::Expression *> CreateFunctionNormalParams(public_lib::Context *ctx, ir::AstNode *funcExpr)
{
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto param : funcExpr->AsFunctionExpression()->Function()->AsScriptFunction()->Params()) {
        if (!param->AsETSParameterExpression()->IsRestParameter()) {
            auto newParam = param->AsETSParameterExpression()->Clone(allocator, nullptr);
            params.push_back(newParam);
        }
    }
    return params;
}

ArenaVector<ir::Expression *> MergeParams(public_lib::Context *ctx,
                                          const ArenaVector<ir::Expression *> &newNormalParams,
                                          const ArenaVector<ir::Expression *> &newRestParams)
{
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Expression *> params {allocator->Adapter()};
    for (auto newNormalParam : newNormalParams) {
        params.push_back(newNormalParam);
    }
    for (auto newRestParam : newRestParams) {
        params.push_back(newRestParam);
    }
    return params;
}

ir::ArrayExpression *CreateArrayExpression(public_lib::Context *ctx, const ArenaVector<ir::Expression *> &newRestParams)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Expression *> elementsInit(checker->Allocator()->Adapter());
    ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());

    auto *arrayExpr = checker->AllocNode<ir::ArrayExpression>(std::move(elementsInit), checker->Allocator());
    for (auto tupleElementAnno : newRestParams) {
        auto &tupleElementName = tupleElementAnno->AsETSParameterExpression()->Ident()->AsIdentifier()->Name();
        ir::Expression *arg = checker->AllocNode<ir::Identifier>(tupleElementName, allocator);
        arg->SetParent(arrayExpr);
        elements.push_back(arg);
    }
    arrayExpr->SetElements(std::move(elements));
    return arrayExpr;
}

ir::ScriptFunction *CreateNewScriptFunction(public_lib::Context *ctx, ir::ScriptFunction *scriptFunc,
                                            ArenaVector<ir::Expression *> newParams)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    ArenaVector<ir::Statement *> statements(allocator->Adapter());
    auto *body = checker->AllocNode<ir::BlockStatement>(allocator, std::move(statements));
    ir::TypeNode *newReturnTypeAnno = nullptr;
    if (scriptFunc->ReturnTypeAnnotation() != nullptr) {
        newReturnTypeAnno = scriptFunc->ReturnTypeAnnotation()->Clone(allocator, nullptr);
    }

    auto *newScriptFunc = checker->AllocNode<ir::ScriptFunction>(
        checker->Allocator(),
        ir::ScriptFunction::ScriptFunctionData {
            body, ir::FunctionSignature(scriptFunc->TypeParams(), std::move(newParams), newReturnTypeAnno),
            scriptFunc->Flags()});
    newScriptFunc->AddModifier(scriptFunc->AsScriptFunction()->Modifiers());

    if (newReturnTypeAnno != nullptr) {
        newReturnTypeAnno->SetParent(newScriptFunc);
    }

    for (auto param : newScriptFunc->AsScriptFunction()->Params()) {
        param->SetParent(newScriptFunc);
    }

    ir::Identifier *newScriptFuncId = scriptFunc->Id()->Clone(allocator, newScriptFunc);
    newScriptFunc->SetIdent(newScriptFuncId);

    return newScriptFunc;
}

ir::VariableDeclaration *CreateNewVariableDeclaration(public_lib::Context *ctx, ir::ETSParameterExpression *restParam,
                                                      ir::ArrayExpression *newTuple)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    util::StringView tupleIdentName = restParam->Ident()->Name();
    auto *newId = checker->AllocNode<ir::Identifier>(tupleIdentName, allocator);
    ir::TypeNode *typeAnnotation = restParam->TypeAnnotation()->Clone(allocator, newId);
    newId->SetTsTypeAnnotation(typeAnnotation);
    newTuple->SetParent(typeAnnotation);

    auto *const declarator =
        checker->AllocNode<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, newId, newTuple);
    newId->SetParent(declarator);
    ArenaVector<ir::VariableDeclarator *> declarators(checker->Allocator()->Adapter());
    declarators.push_back(declarator);

    auto *const declaration = checker->AllocNode<ir::VariableDeclaration>(
        ir::VariableDeclaration::VariableDeclarationKind::LET, checker->Allocator(), std::move(declarators));
    declarator->SetParent(declaration);
    return declaration;
}

ArenaVector<ir::Statement *> CreateReturnOrExpressionStatement(public_lib::Context *ctx, ir::ScriptFunction *scriptFunc,
                                                               ir::CallExpression *callExpr)
{
    auto *checker = ctx->checker->AsETSChecker();

    ArenaVector<ir::Statement *> statements(checker->Allocator()->Adapter());

    if (scriptFunc->ReturnTypeAnnotation() != nullptr) {
        auto returnStatement = checker->AllocNode<ir::ReturnStatement>(callExpr);
        statements.insert(statements.end(), returnStatement);
    } else {
        auto expressionStatement = checker->AllocNode<ir::ExpressionStatement>(callExpr);
        statements.insert(statements.end(), expressionStatement);
        callExpr->SetParent(expressionStatement);
    }
    return statements;
}

void CreateNewMethodDefinition(public_lib::Context *ctx, ir::AstNode *node)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *allocator = ctx->allocator;

    for (auto definition : node->AsClassDefinition()->Body()) {
        if (definition->IsMethodDefinition() && MethodDefinitionHasRestTuple(definition->AsMethodDefinition())) {
            auto funcExpr = definition->AsMethodDefinition()->Value();
            ir::ETSParameterExpression *restParam = funcExpr->AsFunctionExpression()
                                                        ->Function()
                                                        ->AsScriptFunction()
                                                        ->Params()
                                                        .back()
                                                        ->AsETSParameterExpression();
            ir::ScriptFunction *scriptFunc = funcExpr->AsFunctionExpression()->Function()->AsScriptFunction();

            ArenaVector<ir::Expression *> newNormalParams = CreateFunctionNormalParams(ctx, funcExpr);
            ArenaVector<ir::Expression *> newRestParams = CreateFunctionRestParams(ctx, funcExpr);
            ArenaVector<ir::Expression *> mergedParams = MergeParams(ctx, newNormalParams, newRestParams);

            ir::ScriptFunction *newScriptFunc = CreateNewScriptFunction(ctx, scriptFunc, mergedParams);

            ir::ArrayExpression *const newArrayExpr = CreateArrayExpression(ctx, newRestParams);

            ir::TypeNode *newTypeAnnotation = restParam->TypeAnnotation()->Clone(allocator, nullptr);

            auto *asExpression = checker->AllocNode<ir::TSAsExpression>(newArrayExpr, newTypeAnnotation, false);

            auto *callExpr = CreateNewCallExpression(ctx, funcExpr, definition, asExpression);

            ArenaVector<ir::Statement *> statements = CreateReturnOrExpressionStatement(ctx, scriptFunc, callExpr);

            // Build new script function
            newScriptFunc->AsScriptFunction()->Body()->AsBlockStatement()->SetStatements(std::move(statements));

            // Build new functionExpression
            auto *function = checker->AllocNode<ir::FunctionExpression>(newScriptFunc);

            newTypeAnnotation->SetParent(asExpression);
            newArrayExpr->SetParent(asExpression);
            function->SetParent(funcExpr->Parent());

            // Build new methodDefinition
            auto *const methodDef = definition->AsMethodDefinition()->Clone(allocator, definition->Parent());
            methodDef->SetValue(function);

            node->AsClassDefinition()->Body().push_back(methodDef);
        }
    }
}

bool RestTupleConstructionPhase::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    program->Ast()->TransformChildrenRecursively(
        [ctx](ir::AstNode *const node) -> AstNodePtr {
            if (IsClassDefinitionWithTupleRest(node)) {
                CreateNewMethodDefinition(ctx, node);
            }
            return node;
        },
        Name());
    return true;
}

}  // namespace ark::es2panda::compiler
