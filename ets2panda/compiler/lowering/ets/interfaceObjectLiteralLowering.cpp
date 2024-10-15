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

#include "interfaceObjectLiteralLowering.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "ir/expressions/assignmentExpression.h"
#include "util/helpers.h"

namespace ark::es2panda::compiler {

std::string_view InterfaceObjectLiteralLowering::Name() const
{
    return "InterfaceObjectLiteralLowering";
}

static inline bool IsInterfaceType(const checker::Type *type)
{
    return type != nullptr && type->IsETSObjectType() &&
           type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::INTERFACE) &&
           !type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::DYNAMIC);
}

static ir::AstNode *CreateAnonClassImplCtor(checker::ETSChecker *checker)
{
    checker::ETSChecker::ClassInitializerBuilder initBuilder =
        [checker]([[maybe_unused]] ArenaVector<ir::Statement *> *statements,
                  [[maybe_unused]] ArenaVector<ir::Expression *> *params) {
            checker->AddParam(varbinder::VarBinder::MANDATORY_PARAM_THIS, nullptr);
        };

    return checker->CreateClassInstanceInitializer(initBuilder);
}

static ir::ClassProperty *CreateAnonClassField(ir::MethodDefinition *ifaceMethod, checker::ETSChecker *checker)
{
    auto *const allocator = checker->Allocator();

    // Field type annotation
    auto *fieldType = ifaceMethod->Function()->Signature()->ReturnType();
    if (IsInterfaceType(fieldType)) {
        auto *anonClass = fieldType->AsETSObjectType()->GetDeclNode()->AsTSInterfaceDeclaration()->GetAnonClass();
        ASSERT(anonClass != nullptr);
        fieldType = anonClass->Definition()->TsType();
    }
    ASSERT(fieldType != nullptr);
    auto *fieldTypeNode = checker->AllocNode<ir::OpaqueTypeNode>(fieldType);

    // Field identifier
    util::UString fieldName(std::string("_"), allocator);
    fieldName.Append(ifaceMethod->Id()->Name());
    auto *fieldId = checker->AllocNode<ir::Identifier>(fieldName.View(), nullptr, allocator);

    // Field modifiers flags
    ir::ModifierFlags fieldMF = ir::ModifierFlags::PRIVATE;

    // No overloads means no setter function with the same name, so the field is readonly
    if (ifaceMethod->Overloads().empty()) {
        fieldMF |= ir::ModifierFlags::READONLY;
    }

    // Create synthetic class property node
    auto *field = checker->AllocNode<ir::ClassProperty>(fieldId, nullptr, fieldTypeNode->Clone(allocator, nullptr),
                                                        fieldMF, allocator, false);
    field->SetRange(ifaceMethod->Range());

    return field;
}

static ir::MethodDefinition *CreateAnonClassFieldGetterSetter(checker::ETSChecker *checker,
                                                              ir::MethodDefinition *ifaceMethod, bool isSetter)
{
    checker::ETSChecker::MethodBuilder methodBuilder = [checker, ifaceMethod,
                                                        isSetter](ArenaVector<ir::Statement *> *statements,
                                                                  ArenaVector<ir::Expression *> *params,
                                                                  checker::Type **returnType) {
        auto *const allocator = checker->Allocator();

        // Adding mandatory 'this' parameter
        checker->AddParam(varbinder::VarBinder::MANDATORY_PARAM_THIS, nullptr);

        // ifaceMethod is getter, so it should have return type
        auto *retType = ifaceMethod->Function()->Signature()->ReturnType();
        if (IsInterfaceType(retType)) {
            auto *anonClass = retType->AsETSObjectType()->GetDeclNode()->AsTSInterfaceDeclaration()->GetAnonClass();
            ASSERT(anonClass != nullptr);
            retType = anonClass->Definition()->TsType();
        }
        ASSERT(retType != nullptr);

        // Field identifier
        util::UString fieldName(std::string("_"), allocator);
        fieldName.Append(ifaceMethod->Id()->Name());
        auto *fieldId = checker->AllocNode<ir::Identifier>(fieldName.View(), nullptr, allocator);

        if (isSetter) {
            // Setter call params
            ir::ETSParameterExpression *param =
                checker->AddParam(ifaceMethod->Id()->Name(), checker->AllocNode<ir::OpaqueTypeNode>(retType));
            params->push_back(param);

            // Setter body:
            // this.<fieldName> = <callParam>;
            auto *thisExpr = checker->AllocNode<ir::ThisExpression>();
            auto *lhs = checker->AllocNode<ir::MemberExpression>(
                thisExpr, fieldId->Clone(allocator, nullptr), ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            auto *rhs = param->Ident()->Clone(allocator, nullptr);

            auto *assignment =
                checker->AllocNode<ir::AssignmentExpression>(lhs, rhs, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            auto *statement = checker->AllocNode<ir::ExpressionStatement>(assignment);
            statements->push_back(statement);

            // Setter return type
            *returnType = checker->GlobalVoidType();
        } else {
            // Getter call params are empty

            // Getter body:
            // Just return this.<fieldName>;
            auto *thisExpr = checker->AllocNode<ir::ThisExpression>();
            auto *argument = checker->AllocNode<ir::MemberExpression>(
                thisExpr, fieldId->Clone(allocator, nullptr), ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

            auto *statement = checker->AllocNode<ir::ReturnStatement>(argument);
            statements->push_back(statement);

            // Getter return type
            *returnType = retType;
        }
    };

    ir::ModifierFlags modifierFlags = ir::ModifierFlags::PUBLIC;
    modifierFlags |= isSetter ? ir::ModifierFlags::SETTER : ir::ModifierFlags::GETTER;
    ir::ScriptFunctionFlags funcFlags = ir::ScriptFunctionFlags::METHOD;
    funcFlags |= isSetter ? ir::ScriptFunctionFlags::SETTER : ir::ScriptFunctionFlags::GETTER;

    return checker->CreateClassMethod(ifaceMethod->Id()->Name().Utf8(), funcFlags, modifierFlags, methodBuilder);
}

static void FillClassBody(checker::ETSChecker *checker, ArenaVector<ir::AstNode *> *classBody,
                          const ArenaVector<ir::AstNode *> &ifaceBody, ir::ObjectExpression *objExpr)
{
    for (auto *it : ifaceBody) {
        ASSERT(it->IsMethodDefinition());
        auto *ifaceMethod = it->AsMethodDefinition();

        if (!ifaceMethod->Function()->IsGetter() && !ifaceMethod->Function()->IsSetter()) {
            checker->ThrowTypeError("Interface has methods", objExpr->Start());
        }

        if (!ifaceMethod->Function()->IsGetter()) {
            continue;
        }

        auto *field = CreateAnonClassField(ifaceMethod, checker);
        classBody->push_back(field);

        auto *getter = CreateAnonClassFieldGetterSetter(checker, ifaceMethod, false);
        classBody->push_back(getter);

        if (ifaceMethod->Overloads().size() == 1 && ifaceMethod->Overloads()[0]->Function()->IsSetter()) {
            auto *setter = CreateAnonClassFieldGetterSetter(checker, ifaceMethod, true);
            classBody->push_back(setter);
        }
    }
}

static void FillAnonClassBody(checker::ETSChecker *checker, ArenaVector<ir::AstNode *> *classBody,
                              ir::TSInterfaceDeclaration *ifaceNode, ir::ObjectExpression *objExpr)
{
    for (auto *extendedIface : ifaceNode->TsType()->AsETSObjectType()->Interfaces()) {
        auto extendedIfaceBody = extendedIface->GetDeclNode()->AsTSInterfaceDeclaration()->Body()->Body();
        FillClassBody(checker, classBody, extendedIfaceBody, objExpr);
    }

    FillClassBody(checker, classBody, ifaceNode->Body()->Body(), objExpr);
}

static checker::ETSObjectType *GenerateAnonClassTypeFromInterface(checker::ETSChecker *checker,
                                                                  ir::TSInterfaceDeclaration *ifaceNode,
                                                                  ir::ObjectExpression *objExpr)
{
    if (ifaceNode->GetAnonClass() != nullptr) {
        return ifaceNode->GetAnonClass()->Definition()->TsType()->AsETSObjectType();
    }

    auto classBodyBuilder = [checker, ifaceNode, objExpr](ArenaVector<ir::AstNode *> *classBody) {
        if (ifaceNode->TsType() == nullptr) {
            ifaceNode->Check(checker);
        }

        FillAnonClassBody(checker, classBody, ifaceNode, objExpr);
        classBody->push_back(CreateAnonClassImplCtor(checker));
    };

    util::UString className(util::StringView("$anonymous_class$"), checker->Allocator());
    className.Append(ifaceNode->Id()->Name());
    auto *classDecl = checker->BuildClass(className.View(), classBodyBuilder);
    auto *classDef = classDecl->Definition();
    auto *classType = classDef->TsType()->AsETSObjectType();

    // Class type params
    if (ifaceNode->TypeParams() != nullptr) {
        // NOTE: to be done
        checker->ThrowTypeError("Object literal cannot be of typed interface type", objExpr->Start());
    }

    // Class implements
    auto *classImplements =
        checker->AllocNode<ir::TSClassImplements>(checker->AllocNode<ir::OpaqueTypeNode>(ifaceNode->TsType()));
    classImplements->SetParent(classDef);
    classDef->Implements().emplace_back(classImplements);
    classType->RemoveObjectFlag(checker::ETSObjectFlags::RESOLVED_INTERFACES);
    checker->GetInterfacesOfClass(classType);

    ifaceNode->SetAnonClass(classDecl);
    return classType;
}

static void HandleInterfaceLowering(checker::ETSChecker *checker, ir::ObjectExpression *objExpr)
{
    const auto *const targetType = objExpr->TsType();
    ASSERT(targetType->AsETSObjectType()->GetDeclNode()->IsTSInterfaceDeclaration());
    auto *ifaceNode = targetType->AsETSObjectType()->GetDeclNode()->AsTSInterfaceDeclaration();
    auto *resultType = GenerateAnonClassTypeFromInterface(checker, ifaceNode, objExpr);

    if (const auto *const parent = objExpr->Parent(); parent->IsArrayExpression()) {
        for (auto *elem : parent->AsArrayExpression()->Elements()) {
            if (!elem->IsObjectExpression()) {
                continue;
            }
            // Adjusting ts types of other object literals in array
            elem->AsObjectExpression()->SetTsType(resultType);
        }
    }
    objExpr->SetTsType(resultType);
}

bool InterfaceObjectLiteralLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    auto *checker = ctx->checker->AsETSChecker();

    program->Ast()->IterateRecursivelyPostorder([checker](ir::AstNode *ast) -> void {
        if (ast->IsObjectExpression() && IsInterfaceType(ast->AsObjectExpression()->TsType())) {
            HandleInterfaceLowering(checker, ast->AsObjectExpression());
        }
    });

    return true;
}

bool InterfaceObjectLiteralLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) -> bool {
        return ast->IsObjectExpression() && IsInterfaceType(ast->AsObjectExpression()->TsType());
    });
}
}  // namespace ark::es2panda::compiler
