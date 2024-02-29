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

#include "util/ustring.h"
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

[[nodiscard]] ir::Identifier *MakeQualifiedIdentifier(ETSChecker *const checker,
                                                      const ir::TSEnumDeclaration *const enumDecl,
                                                      const util::StringView &name)
{
    util::UString qualifiedName(util::StringView("#"), checker->Allocator());
    AppendParentNames(qualifiedName, enumDecl->Parent());
    qualifiedName.Append(enumDecl->Key()->Name());
    qualifiedName.Append('#');
    qualifiedName.Append(name);
    return checker->AllocNode<ir::Identifier>(qualifiedName.View(), checker->Allocator());
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
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const arrayExpr = checker->AllocNode<ir::ArrayExpression>(std::move(elements), checker->Allocator());
    arrayExpr->SetPreferredType(elementType);
    arrayExpr->SetTsType(checker->CreateETSArrayType(elementType));

    auto *const arrayIdent = MakeQualifiedIdentifier(checker, enumType->GetDecl(), name);

    auto *const arrayClassProp = checker->AllocNode<ir::ClassProperty>(
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
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const paramIdent = checker->AllocNode<ir::Identifier>(name, checker->Allocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const param = checker->AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
    auto *const paramVar = std::get<1>(varbinder->AddParamDecl(param));
    paramVar->SetTsType(type);
    param->Ident()->SetVariable(paramVar);
    param->Ident()->SetTsType(type);
    param->SetTsType(type);
    return param;
}

[[nodiscard]] ir::ETSTypeReference *MakeTypeReference(ETSChecker *const checker, const util::StringView &name)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const ident = checker->AllocNode<ir::Identifier>(name, checker->Allocator());
    ident->SetReference();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(ident);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return checker->AllocNode<ir::ETSTypeReference>(referencePart);
}

[[nodiscard]] ir::ScriptFunction *MakeFunction(ETSChecker *const checker, varbinder::ETSBinder *const varbinder,
                                               varbinder::FunctionParamScope *const paramScope,
                                               ArenaVector<ir::Expression *> &&params,
                                               ArenaVector<ir::Statement *> &&body,
                                               ir::TypeNode *const returnTypeAnnotation, bool isDeclare)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const functionScope = varbinder->Allocator()->New<varbinder::FunctionScope>(checker->Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const bodyBlock = checker->AllocNode<ir::BlockStatement>(checker->Allocator(), std::move(body));
    bodyBlock->SetScope(functionScope);

    auto flags = ir::ModifierFlags::PUBLIC;

    if (isDeclare) {
        flags |= ir::ModifierFlags::DECLARE;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    // clang-format off
    auto *const function = checker->AllocNode<ir::ScriptFunction>(
        checker->Allocator(), ir::ScriptFunction::ScriptFunctionData {
            bodyBlock, ir::FunctionSignature(nullptr, std::move(params), returnTypeAnnotation),
            ir::ScriptFunctionFlags::METHOD, flags, isDeclare});
    // clang-format on
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
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const functionExpr = checker->AllocNode<ir::FunctionExpression>(function);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const identClone = ident->Clone(checker->Allocator(), nullptr);
    identClone->SetTsType(ident->TsType());

    auto *const methodDef =
        checker->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, identClone, functionExpr,
                                                 ir::ModifierFlags::PUBLIC, checker->Allocator(), false);
    methodDef->SetParent(varbinder->Program()->GlobalClass());

    auto *const methodVar = std::get<1>(varbinder->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), checker->Allocator(), methodDef->Id()->Name(), methodDef));
    methodVar->AddFlag(varbinder::VariableFlags::STATIC | varbinder::VariableFlags::SYNTHETIC |
                       varbinder::VariableFlags::METHOD);
    methodDef->Function()->Id()->SetVariable(methodVar);
    methodDef->Id()->SetVariable(methodVar);
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
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return MakeArray(this, VarBinder()->AsETSBinder(), enumType, "NamesArray", GlobalBuiltinETSStringType(),
                    [this](const ir::TSEnumMember *const member) {
                        auto *const enumNameStringLiteral =
                                    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                            AllocNode<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                        enumNameStringLiteral->SetTsType(GlobalBuiltinETSStringType());
                        return enumNameStringLiteral;
                    });
    // clang-format on
}

ir::Identifier *ETSChecker::CreateEnumValuesArray(ETSEnumType *const enumType)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return MakeArray(
        this, VarBinder()->AsETSBinder(), enumType, "ValuesArray", GlobalIntType(),
        [this](const ir::TSEnumMember *const member) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *const enumValueLiteral = AllocNode<ir::NumberLiteral>(lexer::Number(
                member->AsTSEnumMember()->Init()->AsNumberLiteral()->Number().GetValue<ETSEnumType::ValueType>()));
            enumValueLiteral->SetTsType(GlobalIntType());
            return enumValueLiteral;
        });
}

ir::Identifier *ETSChecker::CreateEnumStringValuesArray(ETSEnumInterface *const enumType)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return MakeArray(this, VarBinder()->AsETSBinder(), enumType, "StringValuesArray", GlobalETSStringLiteralType(),
                     [this, enumType](const ir::TSEnumMember *const member) {
                         auto *const init = member->AsTSEnumMember()->Init();
                         util::StringView stringValue;

                         if (enumType->IsETSStringEnumType()) {
                             stringValue = init->AsStringLiteral()->Str();
                         } else {
                             auto str =
                                 std::to_string(init->AsNumberLiteral()->Number().GetValue<ETSEnumType::ValueType>());
                             stringValue = util::UString(str, Allocator()).View();
                         }

                         auto *const enumValueStringLiteral = AllocNode<ir::StringLiteral>(stringValue);
                         enumValueStringLiteral->SetTsType(GlobalETSStringLiteralType());
                         return enumValueStringLiteral;
                     });
}

ir::Identifier *ETSChecker::CreateEnumItemsArray(ETSEnumInterface *const enumType)
{
    return MakeArray(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        this, VarBinder()->AsETSBinder(), enumType, "ItemsArray", enumType,
        [this, enumType](const ir::TSEnumMember *const member) {
            auto *const enumTypeIdent = AllocNode<ir::Identifier>(enumType->GetName(), Allocator());
            enumTypeIdent->SetTsType(enumType);
            enumTypeIdent->SetReference();

            auto *const enumMemberIdent =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                AllocNode<ir::Identifier>(member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
            enumMemberIdent->SetReference();
            auto *const enumMemberExpr = AllocNode<ir::MemberExpression>(
                enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            enumMemberExpr->SetTsType(member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType());

            return enumMemberExpr;
        });
}

ETSEnumType::Method ETSChecker::CreateEnumFromIntMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const inputOrdinalIdent =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", GlobalIntType());

    auto *const inArraySizeExpr = [this, namesArrayIdent, inputOrdinalIdent]() {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const lengthIdent = AllocNode<ir::Identifier>("length", Allocator());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const valuesArrayLengthExpr = AllocNode<ir::MemberExpression>(
            namesArrayIdent, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const expr = AllocNode<ir::BinaryExpression>(inputOrdinalIdent, valuesArrayLengthExpr,
                                                           lexer::TokenType::PUNCTUATOR_LESS_THAN);
        expr->SetOperationType(GlobalIntType());
        expr->SetTsType(GlobalETSBooleanType());
        return expr;
    }();

    auto *const returnEnumStmt = [this, inputOrdinalIdent, enumType]() {
        auto *const identClone = inputOrdinalIdent->Clone(Allocator(), nullptr);
        identClone->SetTsType(enumType);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return AllocNode<ir::ReturnStatement>(identClone);
    }();

    auto *const ifOrdinalExistsStmt = AllocNode<ir::IfStatement>(inArraySizeExpr, returnEnumStmt, nullptr);

    auto *const throwNoEnumStmt = [this, inputOrdinalIdent, enumType]() {
        auto *const exceptionReference = MakeTypeReference(this, "Exception");

        util::UString messageString(util::StringView("No enum constant in "), Allocator());
        messageString.Append(enumType->GetName());
        messageString.Append(" with ordinal value ");
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const identClone = inputOrdinalIdent->Clone(Allocator(), nullptr);
        identClone->SetTsType(GlobalIntType());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const message = AllocNode<ir::StringLiteral>(messageString.View());
        auto *const newExprArg =
            AllocNode<ir::BinaryExpression>(message, identClone, lexer::TokenType::PUNCTUATOR_PLUS);
        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
        newExprArgs.push_back(newExprArg);

        auto *const newExpr = AllocNode<ir::ETSNewClassInstanceExpression>(
            exceptionReference, std::move(newExprArgs),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());

        newExpr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), newExpr->GetArguments(), newExpr->Start()));
        newExpr->SetTsType(GlobalBuiltinExceptionType());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return AllocNode<ir::ThrowStatement>(newExpr);
    }();

    auto *const identClone = inputOrdinalIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(inputOrdinalIdent->TsType());
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(identClone);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(ifOrdinalExistsStmt);
    body.push_back(throwNoEnumStmt);
    body.push_back(returnEnumStmt);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const enumTypeAnnotation = MakeTypeReference(this, enumType->GetName());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumTypeAnnotation, enumType->GetDecl()->IsDeclare());
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const ident = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::FROM_INT_METHOD_NAME);
    function->SetIdent(ident);
    function->Scope()->BindInternalName(ident->Name());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    MakeMethodDef(this, VarBinder()->AsETSBinder(), ident, function);

    ident->SetReference();

    return {MakeGlobalSignature(this, function, enumType), nullptr};
}

ETSEnumType::Method ETSChecker::CreateEnumToStringMethod(ir::Identifier *const stringValuesArrayIdent,
                                                         ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", enumType);

    auto *const returnStmt = [this, inputEnumIdent, stringValuesArrayIdent]() {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const arrayAccessExpr = AllocNode<ir::MemberExpression>(
            stringValuesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalETSStringLiteralType());

        return AllocNode<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    auto *const identClone = inputEnumIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(enumType);
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(identClone);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const stringTypeAnnotation = MakeTypeReference(this, GlobalBuiltinETSStringType()->Name());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), stringTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::TO_STRING_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    functionIdent->SetReference();

    return {
        MakeGlobalSignature(this, function, GlobalETSStringLiteralType()),
        MakeProxyFunctionType(this, ETSEnumType::TO_STRING_METHOD_NAME, {}, function, GlobalETSStringLiteralType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetValueMethod(ir::Identifier *const valuesArrayIdent,
                                                         ETSEnumType *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "e", enumType);

    auto *const returnStmt = [this, inputEnumIdent, valuesArrayIdent]() {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const arrayAccessExpr = AllocNode<ir::MemberExpression>(
            valuesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalIntType());

        return AllocNode<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    auto *const identClone = inputEnumIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(enumType);
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(identClone);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const intTypeAnnotation = AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), intTypeAnnotation, enumType->GetDecl()->IsDeclare());

    auto *const functionIdent = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::GET_VALUE_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    functionIdent->SetReference();

    return {MakeGlobalSignature(this, function, GlobalIntType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_VALUE_METHOD_NAME, {}, function, GlobalIntType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetNameMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const inputEnumIdent = MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "ordinal", enumType);

    auto *const returnStmt = [this, inputEnumIdent, namesArrayIdent]() {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const arrayAccessExpr = AllocNode<ir::MemberExpression>(
            namesArrayIdent, inputEnumIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        arrayAccessExpr->SetTsType(GlobalBuiltinETSStringType());

        return AllocNode<ir::ReturnStatement>(arrayAccessExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    auto *const identClone = inputEnumIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(enumType);
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(identClone);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const stringTypeAnnotation = MakeTypeReference(this, GlobalBuiltinETSStringType()->Name());

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), stringTypeAnnotation, enumType->GetDecl()->IsDeclare());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const functionIdent = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::GET_NAME_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    functionIdent->SetReference();

    return {MakeGlobalSignature(this, function, GlobalBuiltinETSStringType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_NAME_METHOD_NAME, {}, function, GlobalBuiltinETSStringType())};
}

ETSEnumType::Method ETSChecker::CreateEnumValueOfMethod(ir::Identifier *const namesArrayIdent,
                                                        ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    varbinder::LexicalScope<varbinder::LoopDeclarationScope> loopDeclScope(VarBinder());

    auto *const forLoopIIdent = [this]() {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const ident = AllocNode<ir::Identifier>("i", Allocator());
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
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const init = AllocNode<ir::NumberLiteral>("0");
        init->SetTsType(GlobalIntType());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const decl = AllocNode<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, forLoopIIdent, init);
        decl->SetTsType(GlobalIntType());
        ArenaVector<ir::VariableDeclarator *> decls(Allocator()->Adapter());
        decls.push_back(decl);
        return AllocNode<ir::VariableDeclaration>(ir::VariableDeclaration::VariableDeclarationKind::LET, Allocator(),
                                                  std::move(decls), false);
    }();

    auto *const forLoopTest = [this, namesArrayIdent, forLoopIIdent]() {
        auto *const lengthIdent = AllocNode<ir::Identifier>("length", Allocator());
        auto *const arrayLengthExpr = AllocNode<ir::MemberExpression>(
            namesArrayIdent, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        arrayLengthExpr->SetTsType(GlobalIntType());
        auto *const binaryExpr =
            AllocNode<ir::BinaryExpression>(forLoopIIdent, arrayLengthExpr, lexer::TokenType::PUNCTUATOR_LESS_THAN);
        binaryExpr->SetOperationType(GlobalIntType());
        binaryExpr->SetTsType(GlobalETSBooleanType());
        return binaryExpr;
    }();

    auto *const forLoopUpdate = [this, forLoopIIdent]() {
        auto *const incrementExpr =
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            AllocNode<ir::UpdateExpression>(forLoopIIdent, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, true);
        incrementExpr->SetTsType(GlobalIntType());
        return incrementExpr;
    }();

    auto *const inputNameIdent =
        MakeFunctionParam(this, VarBinder()->AsETSBinder(), paramScope, "name", GlobalBuiltinETSStringType());

    auto *const ifStmt = [this, namesArrayIdent, forLoopIIdent, inputNameIdent]() {
        auto *const identClone = namesArrayIdent->Clone(this->Allocator(), nullptr);
        identClone->SetTsType(namesArrayIdent->TsType());
        auto *const namesArrayElementExpr = AllocNode<ir::MemberExpression>(
            identClone, forLoopIIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        namesArrayElementExpr->SetTsType(GlobalBuiltinETSStringType());

        auto *const namesEqualExpr =
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            AllocNode<ir::BinaryExpression>(inputNameIdent, namesArrayElementExpr, lexer::TokenType::PUNCTUATOR_EQUAL);
        namesEqualExpr->SetOperationType(GlobalBuiltinETSStringType());
        namesEqualExpr->SetTsType(GlobalETSBooleanType());

        auto *const returnStmt = AllocNode<ir::ReturnStatement>(forLoopIIdent);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return AllocNode<ir::IfStatement>(namesEqualExpr, returnStmt, nullptr);
    }();

    varbinder::LexicalScope<varbinder::LoopScope> loopScope(VarBinder());
    loopScope.GetScope()->BindDecls(loopDeclScope.GetScope());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const forLoop = AllocNode<ir::ForUpdateStatement>(forLoopInitVarDecl, forLoopTest, forLoopUpdate, ifStmt);
    loopScope.GetScope()->BindNode(forLoop);
    forLoop->SetScope(loopScope.GetScope());
    loopScope.GetScope()->DeclScope()->BindNode(forLoop);

    auto *const throwStmt = [this, inputNameIdent, enumType]() {
        util::UString messageString(util::StringView("No enum constant "), Allocator());
        messageString.Append(enumType->GetName());
        messageString.Append('.');

        auto *const identClone = inputNameIdent->Clone(Allocator(), nullptr);
        identClone->SetTsType(inputNameIdent->TsType());
        auto *const message = AllocNode<ir::StringLiteral>(messageString.View());
        auto *const newExprArg =
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            AllocNode<ir::BinaryExpression>(message, identClone, lexer::TokenType::PUNCTUATOR_PLUS);

        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
        newExprArgs.push_back(newExprArg);

        auto *const exceptionReference = MakeTypeReference(this, "Exception");

        auto *const newExpr = AllocNode<ir::ETSNewClassInstanceExpression>(
            exceptionReference, std::move(newExprArgs),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());
        newExpr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), newExpr->GetArguments(), newExpr->Start()));
        newExpr->SetTsType(GlobalBuiltinExceptionType());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return AllocNode<ir::ThrowStatement>(newExpr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    auto *const identClone = inputNameIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(inputNameIdent->TsType());
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(identClone);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const enumTypeAnnotation = MakeTypeReference(this, enumType->GetName());

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumTypeAnnotation, enumType->GetDecl()->IsDeclare());
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const functionIdent = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::VALUE_OF_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    functionIdent->SetReference();

    return {MakeGlobalSignature(this, function, enumType),
            MakeProxyFunctionType(this, ETSEnumType::VALUE_OF_METHOD_NAME,
                                  {function->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable()},
                                  function, enumType)};
}

ETSEnumType::Method ETSChecker::CreateEnumValuesMethod(ir::Identifier *const itemsArrayIdent,
                                                       ETSEnumInterface *const enumType)
{
    auto *const paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), Program()->GlobalScope());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const returnStmt = AllocNode<ir::ReturnStatement>(itemsArrayIdent);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const enumArrayTypeAnnotation = AllocNode<ir::TSArrayType>(MakeTypeReference(this, enumType->GetName()));

    auto *const function = MakeFunction(this, VarBinder()->AsETSBinder(), paramScope, std::move(params),
                                        std::move(body), enumArrayTypeAnnotation, enumType->GetDecl()->IsDeclare());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const functionIdent = MakeQualifiedIdentifier(this, enumType->GetDecl(), ETSEnumType::VALUES_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(this, VarBinder()->AsETSBinder(), functionIdent, function);

    functionIdent->SetReference();

    return {MakeGlobalSignature(this, function, CreateETSArrayType(enumType)),
            MakeProxyFunctionType(this, ETSEnumType::VALUES_METHOD_NAME, {}, function, CreateETSArrayType(enumType))};
}
}  // namespace ark::es2panda::checker
