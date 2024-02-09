/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"
#include "checker/ETSchecker.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceBody.h"
#include "parser/program/program.h"
#include "ir/ets/etsParameterExpression.h"

namespace ark::es2panda::checker {

namespace {
void AppendParentNames(util::UString &qualifiedName, const ir::AstNode *const node)
{
    if (node != nullptr && !node->IsProgram()) {
        AppendParentNames(qualifiedName, node->Parent());
        if (node->IsTSInterfaceDeclaration()) {
            qualifiedName.Append(node->AsTSInterfaceDeclaration()->Id()->Name());
        } else if (node->IsClassDefinition()) {
            qualifiedName.Append(node->AsClassDefinition()->Ident()->Name());
        } else {
            ASSERT(node->IsClassDeclaration() || node->IsTSInterfaceBody());
            return;
        }
        qualifiedName.Append('#');
    }
}

[[nodiscard]] ir::Identifier *MakeQualifiedIdentifier(ark::ArenaAllocator *const allocator,
                                                      const ir::TSEnumDeclaration *const enumDecl,
                                                      const util::StringView &name)
{
    util::UString qualifiedName(util::StringView("#"), allocator);
    AppendParentNames(qualifiedName, enumDecl->Parent());
    qualifiedName.Append(enumDecl->Key()->Name());
    qualifiedName.Append('#');
    qualifiedName.Append(name);
    return allocator->New<ir::Identifier>(qualifiedName.View(), allocator);
}

template <typename ElementMaker>
[[nodiscard]] ir::Identifier *MakeArray(ETSChecker *const checker, varbinder::ETSBinder *const varbinder,
                                        const ETSEnumInterface *const enumType, const util::StringView &name,
                                        Type *const elementType, ElementMaker &&elementMaker)
{
    ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
    elements.reserve(enumType->GetMembers().size());
    for (const auto *const member : enumType->GetMembers()) {
        elements.push_back(elementMaker(member->AsTSEnumMember()));
    }

    auto *const arrayExpr = checker->Allocator()->New<ir::ArrayExpression>(std::move(elements), checker->Allocator());
    arrayExpr->SetPreferredType(elementType);
    arrayExpr->SetTsType(checker->CreateETSArrayType(elementType));

    auto *const arrayIdent = MakeQualifiedIdentifier(checker->Allocator(), enumType->GetDecl(), name);

    auto *const arrayClassProp = checker->Allocator()->New<ir::ClassProperty>(
        arrayIdent, arrayExpr, nullptr,
        ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::CONST, checker->Allocator(), false);
    arrayClassProp->SetTsType(arrayExpr->TsType());
    arrayClassProp->SetParent(varbinder->Program()->GlobalClass());
    arrayIdent->SetTsType(arrayClassProp->TsType());
    varbinder->Program()->GlobalClass()->Body().push_back(arrayClassProp);

    auto [array_decl, array_var] =
        varbinder->NewVarDecl<varbinder::ConstDecl>(arrayIdent->Start(), arrayIdent->Name(), arrayClassProp);
    arrayIdent->SetVariable(array_var);
    array_var->SetTsType(arrayClassProp->TsType());
    array_var->AddFlag(varbinder::VariableFlags::PUBLIC | varbinder::VariableFlags::STATIC |
                       varbinder::VariableFlags::PROPERTY);
    array_decl->Node()->SetParent(varbinder->Program()->GlobalClass());
    return arrayIdent;
}

[[nodiscard]] ir::ETSParameterExpression *MakeFunctionParam(ETSChecker *const checker,
                                                            varbinder::ETSBinder *const varbinder,
                                                            varbinder::FunctionParamScope *const scope,
                                                            const util::StringView &name, Type *const type)
{
    const auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(varbinder, scope, false);
    auto *const paramIdent = checker->Allocator()->New<ir::Identifier>(name, checker->Allocator());
    auto *const param = checker->Allocator()->New<ir::ETSParameterExpression>(paramIdent, nullptr);
    auto *const paramVar = std::get<1>(varbinder->AddParamDecl(param));
    paramVar->SetTsType(type);
    param->Ident()->SetVariable(paramVar);
    param->Ident()->SetTsType(type);
    param->SetTsType(type);
    return param;
}

[[nodiscard]] ir::ETSTypeReference *MakeTypeReference(ark::ArenaAllocator *allocator, const util::StringView &name)
{
    auto *const ident = allocator->New<ir::Identifier>(name, allocator);
    auto *const referencePart = allocator->New<ir::ETSTypeReferencePart>(ident);
    return allocator->New<ir::ETSTypeReference>(referencePart);
}

[[nodiscard]] ir::ScriptFunction *MakeFunction(ETSChecker *const checker, varbinder::ETSBinder *const varbinder,
                                               varbinder::FunctionParamScope *const paramScope,
                                               ArenaVector<ir::Expression *> &&params,
                                               ArenaVector<ir::Statement *> &&body,
                                               ir::TypeNode *const returnTypeAnnotation, bool isDeclare)
{
    auto *const functionScope = varbinder->Allocator()->New<varbinder::FunctionScope>(checker->Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);

    auto *const bodyBlock = checker->Allocator()->New<ir::BlockStatement>(checker->Allocator(), std::move(body));
    bodyBlock->SetScope(functionScope);

    auto flags = ir::ModifierFlags::PUBLIC;

    if (isDeclare) {
        flags |= ir::ModifierFlags::DECLARE;
    }

    auto *const function = checker->Allocator()->New<ir::ScriptFunction>(
        ir::FunctionSignature(nullptr, std::move(params), returnTypeAnnotation), bodyBlock,
        ir::ScriptFunctionFlags::METHOD, flags, isDeclare, Language(Language::Id::ETS));
    function->SetScope(functionScope);

    varbinder->AsETSBinder()->BuildInternalName(function);
    varbinder->AsETSBinder()->AddCompilableFunction(function);
    paramScope->BindNode(function);
    functionScope->BindNode(function);

    return function;
}

void MakeMethodDef(ETSChecker *const checker, varbinder::ETSBinder *const varbinder, ir::Identifier *const ident,
                   ir::ScriptFunction *const function)
{
    auto *const functionExpr = checker->Allocator()->New<ir::FunctionExpression>(function);
    function->SetParent(functionExpr);

    auto *const methodDef = checker->Allocator()->New<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, ident, functionExpr, ir::ModifierFlags::PUBLIC, checker->Allocator(), false);
    methodDef->SetParent(varbinder->Program()->GlobalClass());
    functionExpr->SetParent(methodDef);

    auto *const methodVar = std::get<1>(varbinder->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), checker->Allocator(), methodDef->Id()->Name(), methodDef));
    methodVar->AddFlag(varbinder::VariableFlags::STATIC | varbinder::VariableFlags::SYNTHETIC |
                       varbinder::VariableFlags::METHOD);
    methodDef->Function()->Id()->SetVariable(methodVar);
}

[[nodiscard]] ETSFunctionType *MakeProxyFunctionType(ETSChecker *const checker, const util::StringView &name,
                                                     const std::initializer_list<varbinder::LocalVariable *> &params,
                                                     ir::ScriptFunction *const globalFunction, Type *const returnType)
{
    auto *const signatureInfo = checker->CreateSignatureInfo();
    signatureInfo->params.insert(signatureInfo->params.end(), params);
    signatureInfo->minArgCount = signatureInfo->params.size();

    auto *const signature = checker->CreateSignature(signatureInfo, returnType, name);
    signature->SetFunction(globalFunction);
    signature->AddSignatureFlag(SignatureFlags::PROXY);

    return checker->CreateETSFunctionType(signature, name);
}

[[nodiscard]] Signature *MakeGlobalSignature(ETSChecker *const checker, ir::ScriptFunction *const function,
                                             Type *const returnType)
{
    auto *const signatureInfo = checker->CreateSignatureInfo();
    signatureInfo->params.reserve(function->Params().size());
    for (const auto *const param : function->Params()) {
        signatureInfo->params.push_back(param->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }
    signatureInfo->minArgCount = signatureInfo->params.size();

    auto *const signature = checker->CreateSignature(signatureInfo, returnType, function);
    signature->AddSignatureFlag(SignatureFlags::PUBLIC | SignatureFlags::STATIC);
    function->SetSignature(signature);

    return signature;
}
}  // namespace

ir::Identifier *ETSChecker::CreateEnumNamesArray(ETSEnumInterface const *const enumType)
{
    // clang-format off
    return MakeArray(this, VarBinder()->AsETSBinder(), enumType, "NamesArray", GlobalBuiltinETSStringType(),
                    [this](const ir::TSEnumMember *const member) {
                        auto *const enumNameStringLiteral =
                            Allocator()->New<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                        enumNameStringLiteral->SetTsType(GlobalBuiltinETSStringType());
                        return enumNameStringLiteral;
                    });
    // clang-format on
}

ir::Identifier *ETSChecker::CreateEnumValuesArray(ETSEnumType *const enumType)
{
    return MakeArray(
        this, VarBinder()->AsETSBinder(), enumType, "ValuesArray", GlobalIntType(),
        [this](const ir::TSEnumMember *const member) {
            auto *const enumValueLiteral = Allocator()->New<ir::NumberLiteral>(lexer::Number(
                member->AsTSEnumMember()->Init()->AsNumberLiteral()->Number().GetValue<ETSEnumType::ValueType>()));
            enumValueLiteral->SetTsType(GlobalIntType());
            return enumValueLiteral;
        });
}

ir::Identifier *ETSChecker::CreateEnumStringValuesArray(ETSEnumInterface *const enumType)
{
    return MakeArray(this, VarBinder()->AsETSBinder(), enumType, "StringValuesArray", GlobalETSStringLiteralType(),
                     [this, isStringEnum = enumType->IsETSStringEnumType()](const ir::TSEnumMember *const member) {
                         auto const stringValue =
                             isStringEnum ? member->AsTSEnumMember()->Init()->AsStringLiteral()->Str()
                                          : util::UString(std::to_string(member->AsTSEnumMember()
                                                                             ->Init()
                                                                             ->AsNumberLiteral()
                                                                             ->Number()
                                                                             .GetValue<ETSEnumType::ValueType>()),
                                                          Allocator())
                                                .View();
                         auto *const enumValueStringLiteral = Allocator()->New<ir::StringLiteral>(stringValue);
                         enumValueStringLiteral->SetTsType(GlobalETSStringLiteralType());
                         return enumValueStringLiteral;
                     });
}

ir::Identifier *ETSChecker::CreateEnumItemsArray(ETSEnumInterface *const enumType)
{
    auto *const enumTypeIdent = Allocator()->New<ir::Identifier>(enumType->GetName(), Allocator());
    enumTypeIdent->SetTsType(enumType);

    return MakeArray(
        this, VarBinder()->AsETSBinder(), enumType, "ItemsArray", enumType,
        [this, enumTypeIdent](const ir::TSEnumMember *const member) {
            auto *const enumMemberIdent =
                Allocator()->New<ir::Identifier>(member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
            auto *const enumMemberExpr = Allocator()->New<ir::MemberExpression>(
                enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            enumMemberExpr->SetTsType(member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType());
            return enumMemberExpr;
        });
}

ETSEnumType::Method ETSChecker::CreateEnumFromIntMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const inputOrdinalIdent =
        MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", GlobalIntType());

    auto *const inArraySizeExpr = [this, namesArrayIdent, inputOrdinalIdent]() {
        auto *const lengthIdent = Allocator()->New<ir::Identifier>("length", Allocator());
        auto *const valuesArrayLengthExpr = Allocator()->New<ir::MemberExpression>(
            namesArrayIdent, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        auto *const expr = Allocator()->New<ir::BinaryExpression>(inputOrdinalIdent, valuesArrayLengthExpr,
                                                                  lexer::TokenType::PUNCTUATOR_LESS_THAN);
        expr->SetOperationType(GlobalIntType());
        expr->SetTsType(GlobalETSBooleanType());
        return expr;
    }();

    auto *const returnEnumStmt = [this, inputOrdinalIdent, enumType]() {
        inputOrdinalIdent->SetTsType(enumType);
        return Allocator()->New<ir::ReturnStatement>(inputOrdinalIdent);
    }();

    auto *const ifOrdinalExistsStmt = Allocator()->New<ir::IfStatement>(inArraySizeExpr, returnEnumStmt, nullptr);

    auto *const throwNoEnumStmt = [this, inputOrdinalIdent, enumType]() {
        auto *const exceptionReference = MakeTypeReference(Allocator(), "Exception");

        util::UString messageString(util::StringView("No enum constant in "), Allocator());
        messageString.Append(enumType->GetName());
        messageString.Append(" with ordinal value ");

        auto *const message = Allocator()->New<ir::StringLiteral>(messageString.View());
        auto *const newExprArg =
            Allocator()->New<ir::BinaryExpression>(message, inputOrdinalIdent, lexer::TokenType::PUNCTUATOR_PLUS);
        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
        newExprArgs.push_back(newExprArg);

        auto *const newExpr = Allocator()->New<ir::ETSNewClassInstanceExpression>(
            exceptionReference, std::move(newExprArgs),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());

        newExpr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), newExpr->GetArguments(), newExpr->Start()));
        newExpr->SetTsType(GlobalBuiltinExceptionType());

        return Allocator()->New<ir::ThrowStatement>(newExpr);
    }();

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputOrdinalIdent);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(ifOrdinalExistsStmt);
    body.push_back(throwNoEnumStmt);
    body.push_back(returnEnumStmt);

    auto *const enumTypeAnnotation = MakeTypeReference(Allocator(), enumType->GetName());

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumTypeAnnotation, enumType->GetDecl()->IsDeclare());
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);

    auto *const ident = MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::FROM_INT_METHOD_NAME);
    function->SetIdent(ident);
    function->Scope()->BindInternalName(ident->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), ident, function);

    return {MakeGlobalSignature(this, function, enumType), nullptr};
}

ETSEnumType::Method ETSChecker::CreateEnumToStringMethod(ir::Identifier *const stringValuesArrayIdent,
                                                         ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());

    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", enumType);

    auto *const returnStmt = [this, inputEnumIdent, stringValuesArrayIdent]() {
        auto *const arrayAccessExpr = Allocator()->New<ir::MemberExpression>(
            stringValuesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalETSStringLiteralType());

        return Allocator()->New<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);

    auto *const stringTypeAnnotation = MakeTypeReference(Allocator(), GlobalBuiltinETSStringType()->Name());
    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), stringTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent =
        MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::TO_STRING_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    return {
        MakeGlobalSignature(this, function, GlobalETSStringLiteralType()),
        MakeProxyFunctionType(this, ETSEnumType::TO_STRING_METHOD_NAME, {}, function, GlobalETSStringLiteralType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetValueMethod(ir::Identifier *const valuesArrayIdent,
                                                         ETSEnumType *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());

    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "e", enumType);

    auto *const returnStmt = [this, inputEnumIdent, valuesArrayIdent]() {
        auto *const arrayAccessExpr = Allocator()->New<ir::MemberExpression>(
            valuesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalIntType());

        return Allocator()->New<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);

    auto *const intTypeAnnotation = Allocator()->New<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), intTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent =
        MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::GET_VALUE_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    return {MakeGlobalSignature(this, function, GlobalIntType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_VALUE_METHOD_NAME, {}, function, GlobalIntType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetNameMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", enumType);

    auto *const returnStmt = [this, inputEnumIdent, namesArrayIdent]() {
        auto *const arrayAccessExpr = Allocator()->New<ir::MemberExpression>(
            namesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalBuiltinETSStringType());

        return Allocator()->New<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);

    auto *const stringTypeAnnotation = MakeTypeReference(Allocator(), GlobalBuiltinETSStringType()->Name());

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), stringTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent =
        MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::GET_NAME_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    return {MakeGlobalSignature(this, function, GlobalBuiltinETSStringType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_NAME_METHOD_NAME, {}, function, GlobalBuiltinETSStringType())};
}

ETSEnumType::Method ETSChecker::CreateEnumValueOfMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const inputNameIdent =
        MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "name", GlobalBuiltinETSStringType());

    varbinder::LexicalScope<varbinder::LoopDeclarationScope> loopDeclScope(VarBinder());

    auto *const forLoopIIdent = [this]() {
        auto *const ident = Allocator()->New<ir::Identifier>("i", Allocator());
        ident->SetTsType(GlobalIntType());
        auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(ident->Start(), ident->Name());
        ident->SetVariable(var);
        var->SetTsType(GlobalIntType());
        var->SetScope(VarBinder()->GetScope());
        var->AddFlag(varbinder::VariableFlags::LOCAL);
        decl->BindNode(ident);
        return ident;
    }();

    auto *const forLoopInitVarDecl = [this, forLoopIIdent]() {
        auto *const init = Allocator()->New<ir::NumberLiteral>("0");
        init->SetTsType(GlobalIntType());
        auto *const decl =
            Allocator()->New<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, forLoopIIdent, init);
        decl->SetTsType(GlobalIntType());
        ArenaVector<ir::VariableDeclarator *> decls(Allocator()->Adapter());
        decls.push_back(decl);
        return Allocator()->New<ir::VariableDeclaration>(ir::VariableDeclaration::VariableDeclarationKind::LET,
                                                         Allocator(), std::move(decls), false);
    }();

    auto *const forLoopTest = [this, namesArrayIdent, forLoopIIdent]() {
        auto *const lengthIdent = Allocator()->New<ir::Identifier>("length", Allocator());
        auto *const arrayLengthExpr = Allocator()->New<ir::MemberExpression>(
            namesArrayIdent, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        arrayLengthExpr->SetTsType(GlobalIntType());
        auto *const binaryExpr = Allocator()->New<ir::BinaryExpression>(forLoopIIdent, arrayLengthExpr,
                                                                        lexer::TokenType::PUNCTUATOR_LESS_THAN);
        binaryExpr->SetOperationType(GlobalIntType());
        binaryExpr->SetTsType(GlobalETSBooleanType());
        return binaryExpr;
    }();

    auto *const forLoopUpdate = [this, forLoopIIdent]() {
        auto *const incrementExpr =
            Allocator()->New<ir::UpdateExpression>(forLoopIIdent, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, true);
        incrementExpr->SetTsType(GlobalIntType());
        return incrementExpr;
    }();

    auto *const ifStmt = [this, namesArrayIdent, forLoopIIdent, inputNameIdent]() {
        auto *const namesArrayElementExpr = Allocator()->New<ir::MemberExpression>(
            namesArrayIdent, forLoopIIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        namesArrayElementExpr->SetTsType(GlobalBuiltinETSStringType());

        auto *const namesEqualExpr = Allocator()->New<ir::BinaryExpression>(inputNameIdent, namesArrayElementExpr,
                                                                            lexer::TokenType::PUNCTUATOR_EQUAL);
        namesEqualExpr->SetOperationType(GlobalBuiltinETSStringType());
        namesEqualExpr->SetTsType(GlobalETSBooleanType());

        auto *const returnStmt = Allocator()->New<ir::ReturnStatement>(forLoopIIdent);
        return Allocator()->New<ir::IfStatement>(namesEqualExpr, returnStmt, nullptr);
    }();

    varbinder::LexicalScope<varbinder::LoopScope> loopScope(VarBinder());
    loopScope.GetScope()->BindDecls(loopDeclScope.GetScope());

    auto *const forLoop =
        Allocator()->New<ir::ForUpdateStatement>(forLoopInitVarDecl, forLoopTest, forLoopUpdate, ifStmt);
    loopScope.GetScope()->BindNode(forLoop);
    forLoop->SetScope(loopScope.GetScope());
    loopScope.GetScope()->DeclScope()->BindNode(forLoop);

    auto *const throwStmt = [this, inputNameIdent, enumType]() {
        util::UString messageString(util::StringView("No enum constant "), Allocator());
        messageString.Append(enumType->GetName());
        messageString.Append('.');

        auto *const message = Allocator()->New<ir::StringLiteral>(messageString.View());
        auto *const newExprArg =
            Allocator()->New<ir::BinaryExpression>(message, inputNameIdent, lexer::TokenType::PUNCTUATOR_PLUS);

        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
        newExprArgs.push_back(newExprArg);

        auto *const exceptionReference = MakeTypeReference(Allocator(), "Exception");

        auto *const newExpr = Allocator()->New<ir::ETSNewClassInstanceExpression>(
            exceptionReference, std::move(newExprArgs),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());
        newExpr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), newExpr->GetArguments(), newExpr->Start()));
        newExpr->SetTsType(GlobalBuiltinExceptionType());

        return Allocator()->New<ir::ThrowStatement>(newExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputNameIdent);

    auto *const enumTypeAnnotation = MakeTypeReference(Allocator(), enumType->GetName());

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumTypeAnnotation, enumType->GetDecl()->IsDeclare());
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);

    auto *const functionIdent =
        MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::VALUE_OF_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    return {MakeGlobalSignature(this, function, enumType),
            MakeProxyFunctionType(this, ETSEnumType::VALUE_OF_METHOD_NAME,
                                  {function->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable()},
                                  function, enumType)};
}

ETSEnumType::Method ETSChecker::CreateEnumValuesMethod(ir::Identifier *const itemsArrayIdent,
                                                       ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const returnStmt = Allocator()->New<ir::ReturnStatement>(itemsArrayIdent);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *const enumArrayTypeAnnotation =
        Allocator()->New<ir::TSArrayType>(MakeTypeReference(Allocator(), enumType->GetName()));

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumArrayTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent =
        MakeQualifiedIdentifier(Allocator(), enumType->GetDecl(), ETSEnumType::VALUES_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    return {MakeGlobalSignature(this, function, CreateETSArrayType(enumType)),
            MakeProxyFunctionType(this, ETSEnumType::VALUES_METHOD_NAME, {}, function, CreateETSArrayType(enumType))};
}
}  // namespace ark::es2panda::checker
