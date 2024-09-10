/**
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

#include "defaultParameterLowering.h"
#include <iostream>
#include "checker/ETSchecker.h"
#include "parser/ETSparser.h"
#include "parser/parserImpl.h"
#include "lexer.h"
#include "utils/arena_containers.h"
#include "ir/statement.h"
#include "varbinder/ETSBinder.h"

namespace ark::es2panda::compiler {

std::pair<bool, std::size_t> DefaultParameterLowering::HasDefaultParam(const ir::ScriptFunction *function,
                                                                       parser::Program *program)
{
    bool hasDefaultParameter = false;
    bool hasRestParameter = false;
    std::size_t requiredParametersNumber = 0U;

    for (auto *const it : function->Params()) {
        auto const *const param = it->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            hasRestParameter = true;
            continue;
        }

        if (hasRestParameter) {
            ThrowSyntaxError("Rest parameter should be the last one.", param->Start(), program);
        }

        if (param->IsDefault()) {
            hasDefaultParameter = true;
            continue;
        }

        if (hasDefaultParameter) {
            ThrowSyntaxError("Required parameter follows default parameter(s).", param->Start(), program);
        }

        ++requiredParametersNumber;
    }

    if (hasDefaultParameter && hasRestParameter) {
        ThrowSyntaxError("Both optional and rest parameters are not allowed in function's parameter list.",
                         function->Start(), program);
    }

    return std::make_pair(hasDefaultParameter, requiredParametersNumber);
}

ir::TSTypeParameterDeclaration *DefaultParameterLowering::CreateParameterDeclaraion(ir::MethodDefinition *method,
                                                                                    public_lib::Context *ctx)
{
    auto *checker = ctx->checker->AsETSChecker();
    if (method->Function()->TypeParams() == nullptr || method->Function()->TypeParams()->Params().empty()) {
        return nullptr;
    }

    ArenaVector<ir::TSTypeParameter *> typeParams(checker->Allocator()->Adapter());

    auto parentParams = method->Function()->TypeParams()->Params();
    std::for_each(parentParams.begin(), parentParams.end(), [&typeParams, checker](ir::TSTypeParameter *par) {
        ir::Identifier *ident = par->Name()->Clone(checker->Allocator(), nullptr)->AsIdentifier();
        auto *constraint = par->Constraint() != nullptr
                               ? par->Constraint()->Clone(checker->Allocator(), nullptr)->AsTypeNode()
                               : nullptr;
        auto *defaultType = par->DefaultType() != nullptr
                                ? par->DefaultType()->Clone(checker->Allocator(), nullptr)->AsTypeNode()
                                : nullptr;
        auto *typeParam = checker->AllocNode<ir::TSTypeParameter>(ident, constraint, defaultType);
        typeParams.push_back(typeParam);
    });
    return checker->AllocNode<ir::TSTypeParameterDeclaration>(std::move(typeParams), typeParams.size());
}

ir::FunctionSignature DefaultParameterLowering::CreateFunctionSignature(ir::MethodDefinition *method,
                                                                        ArenaVector<ir::Expression *> funcParam,
                                                                        public_lib::Context *ctx)
{
    auto *checker = ctx->checker->AsETSChecker();

    ir::TSTypeParameterDeclaration *typeParamDecl = CreateParameterDeclaraion(method, ctx);
    auto *returnTypeAnnotation =
        method->Function()->ReturnTypeAnnotation() != nullptr
            ? method->Function()->ReturnTypeAnnotation()->Clone(checker->Allocator(), nullptr)->AsTypeNode()
            : nullptr;

    return ir::FunctionSignature(typeParamDecl, std::move(funcParam), returnTypeAnnotation);
}

ir::TSTypeParameterInstantiation *DefaultParameterLowering::CreateTypeParameterInstantiation(
    ir::MethodDefinition *method, public_lib::Context *ctx)
{
    auto *checker = ctx->checker->AsETSChecker();
    ArenaVector<ir::TypeNode *> params(checker->Allocator()->Adapter());

    if (method->Function()->TypeParams() == nullptr || method->Function()->TypeParams()->Params().empty()) {
        return nullptr;
    }
    ArenaVector<ir::TypeNode *> selfParams(checker->Allocator()->Adapter());
    ir::ETSTypeReferencePart *referencePart = nullptr;

    for (const auto &param : method->Function()->TypeParams()->Params()) {
        auto *identRef =
            checker->AllocNode<ir::Identifier>(param->AsTSTypeParameter()->Name()->Name(), checker->Allocator());

        referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(identRef, nullptr, nullptr);

        auto *typeReference = checker->AllocNode<ir::ETSTypeReference>(referencePart);

        selfParams.push_back(typeReference);
    }

    return checker->AllocNode<ir::TSTypeParameterInstantiation>(std::move(selfParams));
}

ir::BlockStatement *DefaultParameterLowering::CreateFunctionBody(ir::MethodDefinition *method, public_lib::Context *ctx,
                                                                 ArenaVector<ir::Expression *> funcCallArgs)
{
    auto *checker = ctx->checker->AsETSChecker();
    ArenaVector<ir::Statement *> funcStatements(checker->Allocator()->Adapter());

    ir::CallExpression *callExpression = nullptr;
    ir::Expression *id = nullptr;
    ir::Expression *accessor = nullptr;
    auto *const callee = checker->AllocNode<ir::Identifier>(method->Id()->Name(), checker->Allocator());

    if (method->IsConstructor()) {
        accessor = checker->AllocNode<ir::ThisExpression>();
    } else {
        if (method->Parent()->IsClassDefinition() && (!method->Parent()->AsClassDefinition()->IsGlobal())) {
            if (method->IsStatic()) {
                id = checker->AllocNode<ir::Identifier>(method->Parent()->AsClassDefinition()->Ident()->Name(),
                                                        checker->Allocator());
            } else {
                id = checker->AllocNode<ir::ThisExpression>();
            }
            accessor = checker->AllocNode<ir::MemberExpression>(id, callee, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                                false, false);
        }
    }
    auto *paramInst = CreateTypeParameterInstantiation(method, ctx);
    callExpression = checker->AllocNode<ir::CallExpression>(accessor != nullptr ? accessor : callee,
                                                            std::move(funcCallArgs), paramInst, false, false);
    callExpression->SetRange(method->Range());  // NOTE: Used to locate the original node when an error occurs
    ir::Statement *stmt = nullptr;
    if ((method->Function()->ReturnTypeAnnotation() != nullptr) ||
        ((method->Function()->AsScriptFunction()->Flags() & ir::ScriptFunctionFlags::HAS_RETURN) != 0)) {
        if ((method->Function()->ReturnTypeAnnotation() != nullptr) &&
            method->Function()->ReturnTypeAnnotation()->IsTSThisType()) {
            // NOTE: special case if parent function has return type set as 'this'
            //       so we need to putu only explciit 'return this' to overload,
            //       but call parent function with default parameter before it.
            stmt = checker->AllocNode<ir::ExpressionStatement>(callExpression);
            funcStatements.push_back(stmt);

            // build 'return this;' expression.
            auto *thisExpr = checker->AllocNode<ir::ThisExpression>();
            stmt = checker->AllocNode<ir::ReturnStatement>(thisExpr);
        } else {
            stmt = checker->AllocNode<ir::ReturnStatement>(callExpression);
        }
    } else {
        stmt = checker->AllocNode<ir::ExpressionStatement>(callExpression);
    }
    funcStatements.push_back(stmt);

    return checker->AllocNode<ir::BlockStatement>(checker->Allocator(), std::move(funcStatements));
}

ir::FunctionExpression *DefaultParameterLowering::CreateFunctionExpression(
    ir::MethodDefinition *method, public_lib::Context *ctx, ArenaVector<ir::Expression *> funcDefinitionArgs,
    ArenaVector<ir::Expression *> funcCallArgs)
{
    lexer::SourcePosition startLoc(method->Start().line, method->Start().index);
    lexer::SourcePosition endLoc = startLoc;
    ir::FunctionSignature signature = CreateFunctionSignature(method, std::move(funcDefinitionArgs), ctx);

    auto *checker = ctx->checker->AsETSChecker();
    ir::Identifier *id = nullptr;

    ir::BlockStatement *body = nullptr;
    if (!(method->IsNative() || method->IsDeclare() || method->IsAbstract())) {
        body = CreateFunctionBody(method, ctx, std::move(funcCallArgs));
    }
    auto *funcNode = checker->AllocNode<ir::ScriptFunction>(
        checker->Allocator(),
        ir::ScriptFunction::ScriptFunctionData {
            body, std::move(signature), method->Function()->Flags(), {}, false, method->Function()->Language()});
    funcNode->AddModifier(method->Function()->Modifiers());
    funcNode->SetRange({startLoc, endLoc});

    id = method->Id()->Clone(checker->Allocator(), nullptr)->AsIdentifier();
    funcNode->SetIdent(id);
    return checker->AllocNode<ir::FunctionExpression>(funcNode);
}

void DefaultParameterLowering::CreateOverloadFunction(ir::MethodDefinition *method,
                                                      ArenaVector<ir::Expression *> funcCallArgs,
                                                      ArenaVector<ir::Expression *> funcDefinitionArgs,
                                                      public_lib::Context *ctx)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto *funcExpression =
        CreateFunctionExpression(method, ctx, std::move(funcDefinitionArgs), std::move(funcCallArgs));
    auto *ident = funcExpression->Function()->Id()->Clone(checker->Allocator(), nullptr);
    auto *const overloadMethod = checker->AllocNode<ir::MethodDefinition>(
        method->Kind(), ident, funcExpression, method->Modifiers(), checker->Allocator(), false);

    overloadMethod->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
    overloadMethod->SetRange(funcExpression->Range());

    if (method->Parent()->IsTSInterfaceBody()) {
        overloadMethod->Function()->Body()->AsBlockStatement()->Statements().clear();
    }

    method->AddOverload(overloadMethod);
    overloadMethod->SetStart(method->Start());  // NOTE: Used to locate the original node when an error occurs
    overloadMethod->SetParent(method);          // NOTE(aleksisch): It's incorrect and don't exist in class body
}

void DefaultParameterLowering::RemoveInitializers(ArenaVector<ir::Expression *> params)
{
    std::for_each(params.begin(), params.end(), [](ir::Expression *expr) {
        if (expr->AsETSParameterExpression()->IsDefault()) {
            expr->AsETSParameterExpression()->SetInitializer();
        }
    });
}

void DefaultParameterLowering::ProcessGlobalFunctionDefinition(ir::MethodDefinition *method, public_lib::Context *ctx)
{
    auto *checker = ctx->checker->AsETSChecker();
    auto params = method->Function()->Params();

    // go through default parameters list and create overloading for each combination of them
    // i.e. each new overload method has less actual paramaters than previous one and more
    // default parameters values used to call original method.

    // NOTE: args counter (i), intentionally starts with 1 as we would need to process at least 1 argument with
    // initializer.
    for (auto [it, i] = std::tuple {params.rbegin(), 1}; it != params.rend(); ++it, i++) {
        if (!((*it)->AsETSParameterExpression()->IsDefault())) {
            // do not process regular arguments;
            break;
        }

        ArenaVector<ir::Expression *> defaultArgs(checker->Allocator()->Adapter());  // will have Initializers
        ArenaVector<ir::Expression *> funcDefinitionArgs(
            checker->Allocator()->Adapter());  // will have ETSParameterExpression
        ArenaVector<ir::Expression *> funcCallArgs(checker->Allocator()->Adapter());  // will have ir::Identifier

        // create function/method definition with less mandatory args than overloaded one
        // 1. create copy of found function arguemnts
        // 2. move out of them optional ones (one by one),and each time the one
        // optional is moved out we need to create new overload method with the rest of
        // arguments (as new method args) and move the optional one(s) to the explicit
        // call to the original method
        //
        // foo(x : int = 0, y : int = 1, z : int = 2)
        //
        //  1. loop step 1
        //          foo (x : int, y : int)
        //            calls foo(x, y, 2)
        //  2. loop step 2
        //          foo (x :int)
        //              calls  foo(x, 1, 2)
        //  3. loop step 3
        //          foo ()
        //              calls foo(0, 1, 2)
        auto pt = it;
        do {
            // extract default value from pt and make the function call argument out of it
            // for now simple put whole parameter node to vector
            ir::Expression *clone = nullptr;
            auto *par = (*pt)->AsETSParameterExpression();
            if (par->Initializer()->IsArrowFunctionExpression()) {
                clone = par->Initializer();
            } else {
                clone = par->Initializer()->Clone(checker->Allocator(), nullptr)->AsExpression();
            }
            if (clone != nullptr) {
                defaultArgs.push_back(clone);
            }
        } while (params.rbegin() != pt--);

        // ok, now we need to copy the 'valid' (for now) arguments from original function
        // and make the arguments for current overload out of them.

        funcCallArgs.reserve(params.size());
        funcDefinitionArgs.reserve(params.size() - i);
        std::for_each(
            params.begin(), params.end() - i, [&funcCallArgs, &funcDefinitionArgs, checker](ir::Expression *expr) {
                // NOTE: we don't need Initializer here, as overload-method will have strict list of parameters
                //       will reset all of them once parsing loop completes
                auto *funcArg =
                    expr->AsETSParameterExpression()->Ident()->Clone(checker->Allocator(), nullptr)->AsIdentifier();

                // update list of functional call arguments
                funcCallArgs.push_back(funcArg);

                auto *ident =
                    expr->AsETSParameterExpression()->Ident()->Clone(checker->Allocator(), nullptr)->AsIdentifier();
                auto *funcParam = checker->AllocNode<ir::ETSParameterExpression>(ident->AsIdentifier(), nullptr);

                ASSERT(ident->TypeAnnotation()->Parent() == ident);
                // prepare args list for overloade method definition
                funcDefinitionArgs.push_back(funcParam);
            });

        // finally  append arguemnts list with hard-coded literals,
        // so eventually we have list of call expression arguments
        funcCallArgs.insert(funcCallArgs.end(), defaultArgs.begin(), defaultArgs.end());
        CreateOverloadFunction(method, std::move(funcCallArgs), std::move(funcDefinitionArgs), ctx);
    }

    // done with overloads, now need  to cleanup all initializers,
    // to make parent function signature strict
    RemoveInitializers(std::move(params));
}

bool DefaultParameterLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *checker = ctx->checker->AsETSChecker();
    ArenaVector<ir::MethodDefinition *> foundNodes(checker->Allocator()->Adapter());
    program->Ast()->IterateRecursively([&foundNodes, this, program](ir::AstNode *ast) {
        if (ast->IsMethodDefinition()) {
            auto [hasDefaultParam, requiredParamsCount] =
                HasDefaultParam(ast->AsMethodDefinition()->Function(), program);
            if (hasDefaultParam) {
                // store all nodes (which is function definition with default/optional parameters)
                // to specific list, to process them later, as for now we can't modify AST in the
                // middle of walking through it
                foundNodes.push_back(ast->AsMethodDefinition());
            }
        }
    });

    for (auto &it : foundNodes) {
        ProcessGlobalFunctionDefinition(it, ctx);
    }
    return true;
}

}  // namespace ark::es2panda::compiler
