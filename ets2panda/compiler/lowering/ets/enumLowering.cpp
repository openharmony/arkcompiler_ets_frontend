/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "enumLowering.h"
#include "checker/types/ets/etsEnumType.h"
#include "checker/ETSchecker.h"
#include "checker/types/type.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"

namespace ark::es2panda::compiler {

namespace {

[[nodiscard]] ir::ETSParameterExpression *MakeFunctionParam(checker::ETSChecker *const checker,
                                                            varbinder::ETSBinder *const varbinder,
                                                            varbinder::FunctionParamScope *const scope,
                                                            const util::StringView &name,
                                                            ir::TypeNode *const typeAnnotation)
{
    const auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(varbinder, scope, false);
    auto *const paramIdent = checker->AllocNode<ir::Identifier>(name, typeAnnotation, checker->Allocator());
    auto *const param = checker->AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
    auto *const paramVar = std::get<1>(varbinder->AddParamDecl(param));
    param->Ident()->SetVariable(paramVar);
    return param;
}

[[nodiscard]] ir::Identifier *MakeParamRefIdent(checker::ETSChecker *const checker,
                                                ir::ETSParameterExpression *paramExpr)
{
    auto *const refIdent = checker->AllocNode<ir::Identifier>(paramExpr->Ident()->Name(), checker->Allocator());
    refIdent->SetVariable(paramExpr->Ident()->Variable());
    return refIdent;
}

[[nodiscard]] ir::ETSTypeReference *MakeTypeReference(checker::ETSChecker *const checker, const util::StringView &name)
{
    auto *const ident = checker->AllocNode<ir::Identifier>(name, checker->Allocator());
    ident->SetReference();
    auto *const referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(ident);
    return checker->AllocNode<ir::ETSTypeReference>(referencePart);
}

ir::MethodDefinition *MakeMethodDef(checker::ETSChecker *const checker, ir::ClassDefinition *globalClass,
                                    varbinder::ETSBinder *const varbinder, ir::Identifier *const ident,
                                    ir::ScriptFunction *const function)
{
    auto *const functionExpr = checker->AllocNode<ir::FunctionExpression>(function);
    auto *const identClone = ident->Clone(checker->Allocator(), nullptr);
    auto *const methodDef = checker->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, identClone, functionExpr,
        ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC, checker->Allocator(), false);
    methodDef->SetParent(globalClass);
    globalClass->Body().push_back(methodDef);
    auto *const methodVar = std::get<1>(varbinder->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), checker->Allocator(), methodDef->Id()->Name(), methodDef));
    methodVar->AddFlag(varbinder::VariableFlags::STATIC | varbinder::VariableFlags::SYNTHETIC |
                       varbinder::VariableFlags::METHOD);
    methodDef->Function()->Id()->SetVariable(methodVar);
    methodDef->Id()->SetVariable(methodVar);
    return methodDef;
}

}  // namespace

[[nodiscard]] ir::ScriptFunction *EnumLoweringPhase::MakeFunction(varbinder::FunctionParamScope *const paramScope,
                                                                  ArenaVector<ir::Expression *> &&params,
                                                                  ArenaVector<ir::Statement *> &&body,
                                                                  ir::TypeNode *const returnTypeAnnotation,
                                                                  const ir::TSEnumDeclaration *const enumDecl)
{
    auto *const functionScope =
        varbinder_->Allocator()->New<varbinder::FunctionScope>(checker_->Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);
    auto *const bodyBlock = checker_->AllocNode<ir::BlockStatement>(checker_->Allocator(), std::move(body));
    bodyBlock->SetScope(functionScope);

    auto flags = ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC;

    if (enumDecl->IsDeclare()) {
        flags |= ir::ModifierFlags::DECLARE;
    }
    // clang-format off
    auto *const function = checker_->AllocNode<ir::ScriptFunction>(
        checker_->Allocator(), ir::ScriptFunction::ScriptFunctionData {
            bodyBlock, ir::FunctionSignature(nullptr, std::move(params), returnTypeAnnotation),
            ir::ScriptFunctionFlags::METHOD, flags, enumDecl->IsDeclare()});
    // clang-format on
    function->SetScope(functionScope);

    varbinder_->AsETSBinder()->AddCompilableFunction(function);
    paramScope->BindNode(function);
    functionScope->BindNode(function);

    return function;
}

void EnumLoweringPhase::AppendParentNames(util::UString &qualifiedName, const ir::AstNode *const node)
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

util::UString EnumLoweringPhase::GetQualifiedName(checker::ETSChecker *checker,
                                                  const ir::TSEnumDeclaration *const enumDecl,
                                                  const util::StringView &name)
{
    util::UString qualifiedName(util::StringView("#"), checker->Allocator());
    AppendParentNames(qualifiedName, enumDecl->Parent());
    qualifiedName.Append(enumDecl->Key()->Name());
    qualifiedName.Append('#');
    qualifiedName.Append(name);
    return qualifiedName;
}

[[nodiscard]] ir::Identifier *EnumLoweringPhase::MakeQualifiedIdentifier(const ir::TSEnumDeclaration *const enumDecl,
                                                                         const util::StringView &name)
{
    return checker_->AllocNode<ir::Identifier>(GetQualifiedName(checker_, enumDecl, name).View(),
                                               checker_->Allocator());
}

template <typename ElementMaker>
[[nodiscard]] ir::Identifier *EnumLoweringPhase::MakeArray(const ir::TSEnumDeclaration *const enumDecl,
                                                           ir::ClassDefinition *globalClass,
                                                           const util::StringView &name,
                                                           ir::TypeNode *const typeAnnotation,
                                                           ElementMaker &&elementMaker)
{
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder_, globalClass->Scope()->AsClassScope()->StaticFieldScope());
    ArenaVector<ir::Expression *> elements(checker_->Allocator()->Adapter());
    elements.reserve(enumDecl->Members().size());
    for (const auto *const member : enumDecl->Members()) {
        elements.push_back(elementMaker(member->AsTSEnumMember()));
    }
    auto *const arrayExpr = checker_->AllocNode<ir::ArrayExpression>(std::move(elements), checker_->Allocator());
    auto *const arrayIdent = MakeQualifiedIdentifier(enumDecl, name);
    auto *const arrayClassProp = checker_->AllocNode<ir::ClassProperty>(
        arrayIdent, arrayExpr, typeAnnotation,
        ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::CONST, checker_->Allocator(), false);
    arrayClassProp->SetParent(globalClass);
    globalClass->Body().push_back(arrayClassProp);

    auto [array_decl, array_var] =
        varbinder_->NewVarDecl<varbinder::ConstDecl>(arrayIdent->Start(), arrayIdent->Name(), arrayClassProp);
    arrayIdent->SetVariable(array_var);
    array_var->AddFlag(varbinder::VariableFlags::PUBLIC | varbinder::VariableFlags::STATIC |
                       varbinder::VariableFlags::PROPERTY);
    array_decl->Node()->SetParent(globalClass);
    return arrayIdent;
}

ir::Identifier *EnumLoweringPhase::CreateEnumNamesArray(const ir::TSEnumDeclaration *const enumDecl)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation);

    // clang-format off
    return MakeArray(enumDecl, program_->GlobalClass(), "NamesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumNameStringLiteral =
                            checker_->AllocNode<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                        return enumNameStringLiteral;
                    });
    // clang-format on
}

void EnumLoweringPhase::CreateEnumIntClassFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl)
{
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl);

    auto *identClone = namesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumGetNameMethod(enumDecl, identClone);

    identClone = namesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumValueOfMethod(enumDecl, identClone);

    auto *const valuesArrayIdent = CreateEnumValuesArray(enumDecl);

    identClone = valuesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumGetValueMethod(enumDecl, identClone);

    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl);

    identClone = stringValuesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumToStringMethod(enumDecl, identClone);

    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl);

    identClone = itemsArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumValuesMethod(enumDecl, identClone);

    identClone = itemsArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, identClone);
}

void EnumLoweringPhase::CreateEnumStringClassFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl)
{
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl);

    auto *identClone = namesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumGetNameMethod(enumDecl, identClone);

    identClone = namesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumValueOfMethod(enumDecl, identClone);

    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl);

    identClone = stringValuesArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumToStringMethod(enumDecl, identClone);

    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl);

    identClone = itemsArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumValuesMethod(enumDecl, identClone);

    identClone = itemsArrayIdent->Clone(checker_->Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, identClone);
}

bool EnumLoweringPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    if (program->Extension() != ScriptExtension::ETS) {
        return true;
    }

    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    checker_ = ctx->checker->AsETSChecker();
    varbinder_ = ctx->parserProgram->VarBinder()->AsETSBinder();
    program_ = program;
    program->Ast()->IterateRecursively([this](ir::AstNode *ast) -> void {
        if (ast->IsTSEnumDeclaration()) {
            auto *enumDecl = ast->AsTSEnumDeclaration();

            if (auto *const itemInit = enumDecl->Members().front()->AsTSEnumMember()->Init();
                itemInit->IsNumberLiteral()) {
                CreateEnumIntClassFromEnumDeclaration(enumDecl);
            } else if (itemInit->IsStringLiteral()) {
                CreateEnumStringClassFromEnumDeclaration(enumDecl);
            } else {
                checker_->ThrowTypeError("Invalid enumeration value type.", enumDecl->Start());
            }
        }
    });
    return true;
}

ir::Identifier *EnumLoweringPhase::CreateEnumValuesArray(const ir::TSEnumDeclaration *const enumDecl)
{
    auto *const intType = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(intType);
    // clang-format off
    return MakeArray(enumDecl, program_->GlobalClass(), "ValuesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumValueLiteral = checker_->AllocNode<ir::NumberLiteral>(
                            lexer::Number(member->AsTSEnumMember()
                                                ->Init()
                                                ->AsNumberLiteral()
                                                ->Number()
                                                .GetValue<checker::ETSEnumType::ValueType>()));
                        return enumValueLiteral;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateEnumStringValuesArray(const ir::TSEnumDeclaration *const enumDecl)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation);

    // clang-format off
    return MakeArray(enumDecl, program_->GlobalClass(), "StringValuesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const init = member->AsTSEnumMember()->Init();
                        util::StringView stringValue;

                        if (init->IsStringLiteral()) {
                            stringValue = init->AsStringLiteral()->Str();
                        } else {
                            auto str = std::to_string(
                                init->AsNumberLiteral()->Number().GetValue<checker::ETSEnumType::ValueType>());
                            stringValue = util::UString(str, checker_->Allocator()).View();
                        }

                        auto *const enumValueStringLiteral = checker_->AllocNode<ir::StringLiteral>(stringValue);
                        return enumValueStringLiteral;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl)
{
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(enumTypeAnnotation);
    // clang-format off
    return MakeArray(enumDecl, program_->GlobalClass(), "ItemsArray", arrayTypeAnnotation,
                     [this, enumDecl](const ir::TSEnumMember *const member) {
                        auto *const enumTypeIdent =
                            checker_->AllocNode<ir::Identifier>(enumDecl->Key()->Name(), checker_->Allocator());
                        enumTypeIdent->SetReference();

                        auto *const enumMemberIdent = checker_->AllocNode<ir::Identifier>(
                            member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), checker_->Allocator());
                        enumMemberIdent->SetReference();
                        auto *const enumMemberExpr = checker_->AllocNode<ir::MemberExpression>(
                            enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
                        return enumMemberExpr;
                    });
    // clang-format on
}

namespace {

ir::BinaryExpression *CreateIfTest(EnumLoweringPhase *const elp, ir::Identifier *const itemsArrayIdentifier,
                                   ir::ETSParameterExpression *const parameter)
{
    auto *const checker = elp->Checker();
    auto *const lengthIdent = checker->AllocNode<ir::Identifier>("length", checker->Allocator());
    lengthIdent->SetReference();
    auto *const valuesArrayLengthExpr = checker->AllocNode<ir::MemberExpression>(
        itemsArrayIdentifier, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto *const expr = checker->AllocNode<ir::BinaryExpression>(paramRefIdent, valuesArrayLengthExpr,
                                                                lexer::TokenType::PUNCTUATOR_LESS_THAN);
    paramRefIdent->SetParent(expr);
    return expr;
}
ir::ReturnStatement *CreateReturnEnumStatement(EnumLoweringPhase *const elp, ir::Identifier *const itemsArrayIdentifier,
                                               ir::ETSParameterExpression *const parameter)
{
    auto *const checker = elp->Checker();
    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto itemsArrayIdentClone = itemsArrayIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const arrayAccessExpr = checker->AllocNode<ir::MemberExpression>(
        itemsArrayIdentClone, paramRefIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
    paramRefIdent->SetParent(arrayAccessExpr);

    auto *const returnStatement = checker->AllocNode<ir::ReturnStatement>(arrayAccessExpr);
    return returnStatement;
}

ir::ThrowStatement *CreateThrowStatement(EnumLoweringPhase *const elp, ir::ETSParameterExpression *const parameter,
                                         const util::UString &messageString)
{
    auto *const checker = elp->Checker();

    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto *const message = checker->AllocNode<ir::StringLiteral>(messageString.View());
    auto *const newExprArg =
        checker->AllocNode<ir::BinaryExpression>(message, paramRefIdent, lexer::TokenType::PUNCTUATOR_PLUS);

    paramRefIdent->SetParent(newExprArg);
    ArenaVector<ir::Expression *> newExprArgs(checker->Allocator()->Adapter());
    newExprArgs.push_back(newExprArg);

    auto *const exceptionReference = MakeTypeReference(checker, "Exception");
    auto *const newExpr =
        checker->AllocNode<ir::ETSNewClassInstanceExpression>(exceptionReference, std::move(newExprArgs), nullptr);
    return checker->AllocNode<ir::ThrowStatement>(newExpr);
}

ir::ReturnStatement *CreateReturnWitAsStatement(EnumLoweringPhase *const elp, ir::Identifier *const arrayIdentifier,
                                                ir::ETSParameterExpression *const parameter)
{
    auto *const checker = elp->Checker();
    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto intType = checker->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto asExpression = checker->AllocNode<ir::TSAsExpression>(paramRefIdent, intType, false);
    paramRefIdent->SetParent(asExpression);

    auto *const arrayAccessExpr = checker->AllocNode<ir::MemberExpression>(
        arrayIdentifier, asExpression, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    return checker->AllocNode<ir::ReturnStatement>(arrayAccessExpr);
}

}  // namespace

void EnumLoweringPhase::CreateEnumFromIntMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::Identifier *const itemsArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(), program_->GlobalScope());

    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const inputOrdinalParameter =
        MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", intTypeAnnotation);
    auto *const inArraySizeExpr = CreateIfTest(this, itemsArrayIdent, inputOrdinalParameter);
    auto *const returnEnumStmt = CreateReturnEnumStatement(this, itemsArrayIdent, inputOrdinalParameter);
    auto *const ifOrdinalExistsStmt = checker_->AllocNode<ir::IfStatement>(inArraySizeExpr, returnEnumStmt, nullptr);

    util::UString messageString(util::StringView("No enum constant in "), checker_->Allocator());
    messageString.Append(enumDecl->Key()->Name());
    messageString.Append(" with ordinal value ");

    auto *const throwNoEnumStmt = CreateThrowStatement(this, inputOrdinalParameter, messageString);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    params.push_back(inputOrdinalParameter);

    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(ifOrdinalExistsStmt);
    body.push_back(throwNoEnumStmt);
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());

    auto *const function = MakeFunction(paramScope, std::move(params), std::move(body), enumTypeAnnotation, enumDecl);
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    auto *const ident = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::FROM_INT_METHOD_NAME);
    function->SetIdent(ident);
    function->Scope()->BindInternalName(ident->Name());

    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, ident, function);
    ident->SetReference();
}

void EnumLoweringPhase::CreateEnumToStringMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                 ir::Identifier *const stringValuesArrayIdent)
{
    auto *const paramScope = varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(),
                                                                                         program_->GlobalClassScope());
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, stringValuesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const function = MakeFunction(paramScope, std::move(params), std::move(body), stringTypeAnnotation, enumDecl);

    auto *const functionIdent = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::TO_STRING_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());
    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, functionIdent, function);
    functionIdent->SetReference();
}

void EnumLoweringPhase::CreateEnumGetValueMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                 ir::Identifier *const valuesArrayIdent)
{
    auto *const paramScope = varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(),
                                                                                         program_->GlobalClassScope());

    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "e", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, valuesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const function = MakeFunction(paramScope, std::move(params), std::move(body), intTypeAnnotation, enumDecl);

    auto *const functionIdent = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::GET_VALUE_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, functionIdent, function);

    functionIdent->SetReference();
}

void EnumLoweringPhase::CreateEnumGetNameMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::Identifier *const namesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(), program_->GlobalScope());

    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, namesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?

    auto *const function = MakeFunction(paramScope, std::move(params), std::move(body), stringTypeAnnotation, enumDecl);

    auto *const functionIdent = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::GET_NAME_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, functionIdent, function);
    functionIdent->SetReference();
}

namespace {

ir::Identifier *CreateForLoopIdent(EnumLoweringPhase *const elp)
{
    auto *const ident = elp->Checker()->AllocNode<ir::Identifier>("i", elp->Checker()->Allocator());
    auto [decl, var] = elp->Varbinder()->NewVarDecl<varbinder::LetDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);
    var->SetScope(elp->Varbinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::LOCAL);
    decl->BindNode(ident);
    return ident;
}

ir::VariableDeclaration *CreateForLoopInitVariableDeclaration(EnumLoweringPhase *const elp,
                                                              ir::Identifier *const loopIdentifier)
{
    auto *const checker = elp->Checker();
    auto *const init = checker->AllocNode<ir::NumberLiteral>("0");
    auto *const decl =
        checker->AllocNode<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, loopIdentifier, init);
    loopIdentifier->SetParent(decl);
    ArenaVector<ir::VariableDeclarator *> decls(checker->Allocator()->Adapter());
    decls.push_back(decl);
    auto *const declaration = checker->AllocNode<ir::VariableDeclaration>(
        ir::VariableDeclaration::VariableDeclarationKind::LET, checker->Allocator(), std::move(decls), false);
    decl->SetParent(declaration);
    return declaration;
}

ir::BinaryExpression *CreateForLoopTest(EnumLoweringPhase *const elp, ir::Identifier *const namesArrayIdentifier,
                                        ir::Identifier *const loopIdentifier)
{
    auto *const checker = elp->Checker();
    auto *const lengthIdent = checker->AllocNode<ir::Identifier>("length", checker->Allocator());
    lengthIdent->SetReference();
    auto *const arrayLengthExpr = checker->AllocNode<ir::MemberExpression>(
        namesArrayIdentifier, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *const forLoopIdentClone = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const binaryExpr = checker->AllocNode<ir::BinaryExpression>(forLoopIdentClone, arrayLengthExpr,
                                                                      lexer::TokenType::PUNCTUATOR_LESS_THAN);
    return binaryExpr;
}

ir::UpdateExpression *CreateForLoopUpdate(EnumLoweringPhase *const elp, ir::Identifier *const loopIdentifier)
{
    auto *const checker = elp->Checker();
    auto *const forLoopIdentClone = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const incrementExpr =
        checker->AllocNode<ir::UpdateExpression>(forLoopIdentClone, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, true);
    return incrementExpr;
}

ir::IfStatement *CreateIf(EnumLoweringPhase *const elp, const ir::TSEnumDeclaration *const enumDecl,
                          ir::Identifier *const namesArrayIdentifier, ir::Identifier *const loopIdentifier,
                          ir::ETSParameterExpression *const parameter)
{
    auto *const checker = elp->Checker();
    auto *const identClone = namesArrayIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const forLoopIdentClone1 = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const namesArrayElementExpr = checker->AllocNode<ir::MemberExpression>(
        identClone, forLoopIdentClone1, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto *const namesEqualExpr = checker->AllocNode<ir::BinaryExpression>(paramRefIdent, namesArrayElementExpr,
                                                                          lexer::TokenType::PUNCTUATOR_EQUAL);
    paramRefIdent->SetParent(namesEqualExpr);
    auto *const forLoopIdentClone2 = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const enumTypeAnnotation = MakeTypeReference(checker, enumDecl->Key()->Name());
    auto asExpression = checker->AllocNode<ir::TSAsExpression>(forLoopIdentClone2, enumTypeAnnotation, false);

    auto *const returnStmt = checker->AllocNode<ir::ReturnStatement>(asExpression);
    return checker->AllocNode<ir::IfStatement>(namesEqualExpr, returnStmt, nullptr);
}

}  // namespace

void EnumLoweringPhase::CreateEnumValueOfMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::Identifier *const namesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(), program_->GlobalScope());

    varbinder::LexicalScope<varbinder::LoopDeclarationScope> loopDeclScope(varbinder_);

    auto *const forLoopIIdent = CreateForLoopIdent(this);
    auto *const forLoopInitVarDecl = CreateForLoopInitVariableDeclaration(this, forLoopIIdent);
    auto *const forLoopTest = CreateForLoopTest(this, namesArrayIdent, forLoopIIdent);
    auto *const forLoopUpdate = CreateForLoopUpdate(this, forLoopIIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const inputNameIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "name", stringTypeAnnotation);
    auto *const ifStmt = CreateIf(this, enumDecl, namesArrayIdent, forLoopIIdent, inputNameIdent);

    varbinder::LexicalScope<varbinder::LoopScope> loopScope(varbinder_);
    loopScope.GetScope()->BindDecls(loopDeclScope.GetScope());
    auto *const forLoop =
        checker_->AllocNode<ir::ForUpdateStatement>(forLoopInitVarDecl, forLoopTest, forLoopUpdate, ifStmt);
    loopScope.GetScope()->BindNode(forLoop);
    forLoop->SetScope(loopScope.GetScope());
    loopScope.GetScope()->DeclScope()->BindNode(forLoop);

    util::UString messageString(util::StringView("No enum constant "), checker_->Allocator());
    messageString.Append(enumDecl->Key()->Name());
    messageString.Append('.');

    auto *const throwStmt = CreateThrowStatement(this, inputNameIdent, messageString);

    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    params.push_back(inputNameIdent);
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());

    auto *const function = MakeFunction(paramScope, std::move(params), std::move(body), enumTypeAnnotation, enumDecl);
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    auto *const functionIdent = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::VALUE_OF_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());
    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, functionIdent, function);
    functionIdent->SetReference();
}

void EnumLoweringPhase::CreateEnumValuesMethod(const ir::TSEnumDeclaration *const enumDecl,
                                               ir::Identifier *const itemsArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(checker_->Allocator(), program_->GlobalScope());
    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(itemsArrayIdent);
    ArenaVector<ir::Statement *> body(checker_->Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(checker_->Allocator()->Adapter());
    auto *const enumArrayTypeAnnotation =
        checker_->AllocNode<ir::TSArrayType>(MakeTypeReference(checker_, enumDecl->Key()->Name()));

    auto *const function =
        MakeFunction(paramScope, std::move(params), std::move(body), enumArrayTypeAnnotation, enumDecl);
    auto *const functionIdent = MakeQualifiedIdentifier(enumDecl, checker::ETSEnumType::VALUES_METHOD_NAME);
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, program_->GlobalClass(), varbinder_, functionIdent, function);
    functionIdent->SetReference();
}

}  // namespace ark::es2panda::compiler