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
    auto *const referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(ident);
    return checker->AllocNode<ir::ETSTypeReference>(referencePart);
}

ir::MethodDefinition *MakeMethodDef(checker::ETSChecker *const checker, ir::ClassDefinition *enumClass,
                                    varbinder::ETSBinder *const varbinder, ir::Identifier *const ident,
                                    ir::ScriptFunction *const function)
{
    auto *const functionExpr = checker->AllocNode<ir::FunctionExpression>(function);
    auto *const identClone = ident->Clone(checker->Allocator(), nullptr);

    auto *const methodDef = checker->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, identClone, functionExpr, function->Modifiers(), checker->Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder, enumClass->Scope()->AsClassScope()->StaticMethodScope());

    auto *const methodVar = std::get<1>(varbinder->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), checker->Allocator(), methodDef->Id()->Name(), methodDef));

    varbinder::VariableFlags varFlags = varbinder::VariableFlags::SYNTHETIC | varbinder::VariableFlags::METHOD;
    if ((function->Modifiers() & ir::ModifierFlags::STATIC) != 0) {
        varFlags |= varbinder::VariableFlags::STATIC;
    }

    methodVar->AddFlag(varFlags);
    methodDef->Function()->Id()->SetVariable(methodVar);
    methodDef->Id()->SetVariable(methodVar);
    return methodDef;
}

}  // namespace

[[nodiscard]] ir::ScriptFunction *EnumLoweringPhase::MakeFunction(FunctionInfo &&functionInfo)
{
    auto *const functionScope =
        varbinder_->Allocator()->New<varbinder::FunctionScope>(Allocator(), functionInfo.paramScope);
    functionScope->BindParamScope(functionInfo.paramScope);
    functionInfo.paramScope->BindFunctionScope(functionScope);
    ir::BlockStatement *bodyBlock = nullptr;

    if (functionInfo.enumDecl->IsDeclare()) {
        functionInfo.flags |= ir::ModifierFlags::DECLARE;
    } else {
        bodyBlock = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(functionInfo.body));
        bodyBlock->SetScope(functionScope);
    }
    // clang-format off
    auto *const function = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
            bodyBlock,
            ir::FunctionSignature(nullptr, std::move(functionInfo.params), functionInfo.returnTypeAnnotation),
            ir::ScriptFunctionFlags::METHOD, functionInfo.flags, functionInfo.enumDecl->IsDeclare()});
    // clang-format on
    function->SetScope(functionScope);

    if (!function->Declare()) {
        varbinder_->AsETSBinder()->AddCompilableFunction(function);
    }
    functionInfo.paramScope->BindNode(function);
    functionScope->BindNode(function);

    return function;
}

util::UString EnumLoweringPhase::GetEnumClassName(checker::ETSChecker *checker,
                                                  const ir::TSEnumDeclaration *const enumDecl)
{
    util::UString className(util::StringView("#"), checker->Allocator());
    className.Append(enumDecl->Key()->Name());
    return className;
}

template <typename ElementMaker>
[[nodiscard]] ir::Identifier *EnumLoweringPhase::MakeArray(const ir::TSEnumDeclaration *const enumDecl,
                                                           ir::ClassDefinition *const enumClass,
                                                           const util::StringView &name,
                                                           ir::TypeNode *const typeAnnotation,
                                                           ElementMaker &&elementMaker)
{
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder_, enumClass->Scope()->AsClassScope()->StaticFieldScope());
    ArenaVector<ir::Expression *> elements(Allocator()->Adapter());
    elements.reserve(enumDecl->Members().size());
    for (const auto *const member : enumDecl->Members()) {
        elements.push_back(elementMaker(member->AsTSEnumMember()));
    }
    auto *const arrayExpr = checker_->AllocNode<ir::ArrayExpression>(std::move(elements), Allocator());
    auto *const arrayIdent = checker_->AllocNode<ir::Identifier>(name, Allocator());
    auto *const arrayClassProp = checker_->AllocNode<ir::ClassProperty>(
        arrayIdent, arrayExpr, typeAnnotation,
        ir::ModifierFlags::STATIC | ir::ModifierFlags::PROTECTED | ir::ModifierFlags::CONST, Allocator(), false);
    arrayClassProp->SetParent(enumClass);
    enumClass->Body().push_back(arrayClassProp);

    auto [array_decl, array_var] =
        varbinder_->NewVarDecl<varbinder::ConstDecl>(arrayIdent->Start(), arrayIdent->Name(), arrayClassProp);
    arrayIdent->SetVariable(array_var);
    array_var->AddFlag(varbinder::VariableFlags::PROTECTED | varbinder::VariableFlags::STATIC |
                       varbinder::VariableFlags::PROPERTY);
    array_var->SetScope(enumClass->Scope()->AsClassScope()->StaticFieldScope());
    array_decl->Node()->SetParent(enumClass);
    return arrayIdent;
}

ir::Identifier *EnumLoweringPhase::CreateEnumNamesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                        ir::ClassDefinition *const enumClass)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation);

    // clang-format off
    return MakeArray(enumDecl, enumClass, "NamesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumNameStringLiteral =
                            checker_->AllocNode<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                        return enumNameStringLiteral;
                    });
    // clang-format on
}

ir::ClassDefinition *EnumLoweringPhase::CreateClass(ir::TSEnumDeclaration *const enumDecl)
{
    auto globalCtx = varbinder::LexicalScope<varbinder::GlobalScope>::Enter(varbinder_, program_->GlobalScope());
    auto *ident = Allocator()->New<ir::Identifier>(GetEnumClassName(checker_, enumDecl).View(), Allocator());
    auto [decl, var] = varbinder_->NewVarDecl<varbinder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(varbinder_);
    auto *classDef = checker_->AllocNode<ir::ClassDefinition>(
        Allocator(), ident,
        enumDecl->IsDeclare() ? ir::ClassDefinitionModifiers::DECLARATION : ir::ClassDefinitionModifiers::NONE,
        enumDecl->IsDeclare() ? ir::ModifierFlags::DECLARE : ir::ModifierFlags::NONE, Language(Language::Id::ETS));

    classDef->SetScope(classCtx.GetScope());
    auto *classDecl = checker_->AllocNode<ir::ClassDeclaration>(classDef, Allocator());
    classDef->Scope()->BindNode(classDef);
    decl->BindNode(classDecl);
    program_->Ast()->Statements().push_back(classDecl);
    classDecl->SetParent(program_->Ast());
    enumDecl->SetBoxedClass(classDef);

    CreateOrdinalField(classDef);
    CreateCCtorForEnumClass(classDef);
    CreateCtorForEnumClass(classDef);

    return classDef;
}

void EnumLoweringPhase::CreateCCtorForEnumClass(ir::ClassDefinition *const enumClass)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *id = checker_->AllocNode<ir::Identifier>(compiler::Signatures::CCTOR, Allocator());

    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), program_->GlobalScope());
    auto *const functionScope = varbinder_->Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    auto *body = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::HIDDEN,
                                                ir::ModifierFlags::STATIC, false, Language(Language::Id::ETS)});

    func->SetIdent(id);
    id->SetParent(func);
    body->SetScope(functionScope);
    func->SetScope(functionScope);
    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);

    varbinder_->AsETSBinder()->AddCompilableFunction(func);
    functionScope->BindNode(func);
    paramScope->BindNode(func);

    auto *const identClone = id->Clone(Allocator(), nullptr);
    auto *const methodDef = checker_->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, identClone, funcExpr, ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC,
        Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder_, enumClass->Scope()->AsClassScope()->StaticMethodScope());
    auto *const methodVar = std::get<1>(varbinder_->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), Allocator(), methodDef->Id()->Name(), methodDef));
    methodVar->AddFlag(varbinder::VariableFlags::STATIC | varbinder::VariableFlags::SYNTHETIC |
                       varbinder::VariableFlags::METHOD);
    methodDef->Function()->Id()->SetVariable(methodVar);
    methodDef->Id()->SetVariable(methodVar);
}

ir::ClassProperty *EnumLoweringPhase::CreateOrdinalField(ir::ClassDefinition *const enumClass)
{
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder_, enumClass->Scope()->AsClassScope()->InstanceFieldScope());

    auto *const fieldIdent = Allocator()->New<ir::Identifier>("ordinal", Allocator());
    auto *const intTypeAnnotation = Allocator()->New<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *field = checker_->AllocNode<ir::ClassProperty>(fieldIdent, nullptr, intTypeAnnotation,
                                                         ir::ModifierFlags::PROTECTED, Allocator(), false);

    auto [decl, var] = varbinder_->NewVarDecl<varbinder::LetDecl>(lexer::SourcePosition(), fieldIdent->Name());
    var->SetScope(enumClass->Scope()->AsClassScope()->InstanceFieldScope());
    var->AddFlag(varbinder::VariableFlags::PROPERTY | varbinder::VariableFlags::PROTECTED);
    fieldIdent->SetVariable(var);
    decl->BindNode(field);

    enumClass->Body().push_back(field);
    field->SetParent(enumClass);
    return field;
}

void EnumLoweringPhase::CreateCtorForEnumClass(ir::ClassDefinition *const enumClass)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), program_->GlobalScope());

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const inputOrdinalParam = MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", intTypeAnnotation);
    params.push_back(inputOrdinalParam);

    auto *id = checker_->AllocNode<ir::Identifier>("constructor", Allocator());
    auto *const functionScope = varbinder_->Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    auto *body = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::CONSTRUCTOR, ir::ModifierFlags::CONSTRUCTOR,
                                                false, Language(Language::Id::ETS)});

    func->SetIdent(id);
    body->SetScope(functionScope);
    func->SetScope(functionScope);
    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);

    varbinder_->AsETSBinder()->AddCompilableFunction(func);
    functionScope->BindNode(func);
    paramScope->BindNode(func);

    auto *thisExpr = Allocator()->New<ir::ThisExpression>();
    auto *fieldIdentifier = Allocator()->New<ir::Identifier>("ordinal", Allocator());
    auto *leftHandSide = checker_->AllocNode<ir::MemberExpression>(
        thisExpr, fieldIdentifier, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *rightHandSide = checker_->AllocNode<ir::Identifier>("ordinal", Allocator());
    rightHandSide->SetVariable(inputOrdinalParam->Ident()->Variable());
    auto *initializer = checker_->AllocNode<ir::AssignmentExpression>(leftHandSide, rightHandSide,
                                                                      lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    auto initStatement = checker_->AllocNode<ir::ExpressionStatement>(initializer);
    initStatement->SetParent(body);
    body->Statements().push_back(initStatement);

    auto *const identClone = id->Clone(Allocator(), nullptr);
    auto *const methodDef = checker_->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::CONSTRUCTOR, identClone, funcExpr, ir::ModifierFlags::PUBLIC, Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        varbinder_, enumClass->Scope()->AsClassScope()->StaticMethodScope());
    auto *const methodVar = std::get<1>(varbinder_->NewVarDecl<varbinder::FunctionDecl>(
        methodDef->Start(), Allocator(), methodDef->Id()->Name(), methodDef));
    methodVar->AddFlag(varbinder::VariableFlags::SYNTHETIC | varbinder::VariableFlags::METHOD);
    methodDef->Function()->Id()->SetVariable(methodVar);
    methodDef->Id()->SetVariable(methodVar);
}

void EnumLoweringPhase::CreateEnumIntClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl)
{
    auto *const enumClass = CreateClass(enumDecl);
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl, enumClass);
    auto *const valuesArrayIdent = CreateEnumValuesArray(enumDecl, enumClass);
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl, enumClass);
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl, enumClass);
    auto *const boxedItemsArrayIdent = CreateBoxedEnumItemsArray(enumDecl, enumClass);

    auto *identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumGetNameMethod(enumDecl, enumClass, identClone);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumGetValueOfMethod(enumDecl, enumClass, identClone);

    identClone = valuesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumValueOfMethod(enumDecl, enumClass, identClone);

    identClone = stringValuesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumToStringMethod(enumDecl, enumClass, identClone);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumValuesMethod(enumDecl, enumClass, identClone);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, enumClass, identClone, checker::ETSEnumType::FROM_INT_METHOD_NAME,
                            enumDecl->Key()->Name());

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateUnboxingMethod(enumDecl, enumClass, identClone);

    identClone = boxedItemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, enumClass, identClone, checker::ETSEnumType::BOXED_FROM_INT_METHOD_NAME,
                            GetEnumClassName(checker_, enumDecl).View());
}

void EnumLoweringPhase::CreateEnumStringClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl)
{
    auto *const enumClass = CreateClass(enumDecl);
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl, enumClass);
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl, enumClass);
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl, enumClass);
    auto *const boxedItemsArrayIdent = CreateBoxedEnumItemsArray(enumDecl, enumClass);

    auto *identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumGetNameMethod(enumDecl, enumClass, identClone);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumGetValueOfMethod(enumDecl, enumClass, identClone);

    identClone = stringValuesArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumToStringMethod(enumDecl, enumClass, identClone);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumValuesMethod(enumDecl, enumClass, identClone);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, enumClass, identClone, checker::ETSEnumType::FROM_INT_METHOD_NAME,
                            enumDecl->Key()->Name());

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    CreateUnboxingMethod(enumDecl, enumClass, identClone);

    identClone = boxedItemsArrayIdent->Clone(Allocator(), nullptr);
    CreateEnumFromIntMethod(enumDecl, enumClass, identClone, checker::ETSEnumType::BOXED_FROM_INT_METHOD_NAME,
                            GetEnumClassName(checker_, enumDecl).View());
}

bool EnumLoweringPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    bool isPerformedSuccess = true;
    if (program->Extension() != ScriptExtension::ETS) {
        return isPerformedSuccess;
    }

    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            isPerformedSuccess &= Perform(ctx, extProg);
        }
    }

    checker_ = ctx->checker->AsETSChecker();
    varbinder_ = ctx->parserProgram->VarBinder()->AsETSBinder();
    program_ = program;
    program->Ast()->IterateRecursively([this, &isPerformedSuccess](ir::AstNode *ast) -> void {
        if (ast->IsTSEnumDeclaration()) {
            auto *enumDecl = ast->AsTSEnumDeclaration();

            if (auto *const itemInit = enumDecl->Members().front()->AsTSEnumMember()->Init();
                itemInit->IsNumberLiteral()) {
                CreateEnumIntClassFromEnumDeclaration(enumDecl);
            } else if (itemInit->IsStringLiteral()) {
                CreateEnumStringClassFromEnumDeclaration(enumDecl);
            } else {
                checker_->LogTypeError("Invalid enumeration value type.", enumDecl->Start());
                isPerformedSuccess = false;
            }
        }
    });
    return isPerformedSuccess;
}

ir::Identifier *EnumLoweringPhase::CreateEnumValuesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                         ir::ClassDefinition *const enumClass)
{
    auto *const intType = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(intType);
    // clang-format off
    return MakeArray(enumDecl, enumClass, "ValuesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumValueLiteral = checker_->AllocNode<ir::NumberLiteral>(
                            lexer::Number(member->AsTSEnumMember()
                                                ->Init()
                                                ->AsNumberLiteral()
                                                ->Number()
                                                .GetValue<checker::ETSIntEnumType::ValueType>()));
                        return enumValueLiteral;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateEnumStringValuesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                               ir::ClassDefinition *const enumClass)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation);

    // clang-format off
    return MakeArray(enumDecl, enumClass, "StringValuesArray", arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const init = member->AsTSEnumMember()->Init();
                        util::StringView stringValue;

                        if (init->IsStringLiteral()) {
                            stringValue = init->AsStringLiteral()->Str();
                        } else {
                            auto str = std::to_string(
                                init->AsNumberLiteral()->Number().GetValue<checker::ETSIntEnumType::ValueType>());
                            stringValue = util::UString(str, Allocator()).View();
                        }

                        auto *const enumValueStringLiteral = checker_->AllocNode<ir::StringLiteral>(stringValue);
                        return enumValueStringLiteral;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl,
                                                        ir::ClassDefinition *const enumClass)
{
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(enumTypeAnnotation);
    // clang-format off
    return MakeArray(enumDecl, enumClass, "ItemsArray", arrayTypeAnnotation,
                     [this, enumDecl](const ir::TSEnumMember *const member) {
                        auto *const enumTypeIdent =
                            checker_->AllocNode<ir::Identifier>(enumDecl->Key()->Name(), Allocator());

                        auto *const enumMemberIdent = checker_->AllocNode<ir::Identifier>(
                            member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
                        auto *const enumMemberExpr = checker_->AllocNode<ir::MemberExpression>(
                            enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
                        return enumMemberExpr;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateBoxedEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl,
                                                             ir::ClassDefinition *const enumClass)
{
    auto boxedClassName = GetEnumClassName(checker_, enumDecl).View();
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, boxedClassName);
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(enumTypeAnnotation);
    // clang-format off
    return MakeArray(enumDecl, enumClass, "BoxedItemsArray", arrayTypeAnnotation,
                     [this, enumDecl, &boxedClassName](const ir::TSEnumMember *const member) {
                        auto *const enumTypeIdent =
                            checker_->AllocNode<ir::Identifier>(enumDecl->Key()->Name(), Allocator());

                        auto *const enumMemberIdent = checker_->AllocNode<ir::Identifier>(
                            member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
                        auto *const enumMemberExpr = checker_->AllocNode<ir::MemberExpression>(
                            enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

                        auto intType = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
                        auto asExpression = checker_->AllocNode<ir::TSAsExpression>(enumMemberExpr, intType, false);

                        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
                        newExprArgs.push_back(asExpression);

                        auto boxedTypeRef = MakeTypeReference(checker_, boxedClassName);
                        
                        auto *const newExpression = checker_->AllocNode<ir::ETSNewClassInstanceExpression>(
                            boxedTypeRef, std::move(newExprArgs), nullptr);
                        return newExpression;
                    });
    // clang-format on
}

namespace {

ir::BinaryExpression *CreateIfTest(EnumLoweringPhase *const elp, ir::Identifier *const itemsArrayIdentifier,
                                   ir::ETSParameterExpression *const parameter)
{
    auto *const checker = elp->Checker();
    auto *const lengthIdent = checker->AllocNode<ir::Identifier>("length", checker->Allocator());
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
                                                ir::ClassDefinition *const enumClass, ir::Identifier *const arrayIdent,
                                                const util::StringView &methodName,
                                                const util::StringView &returnTypeName)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());

    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const inputOrdinalParameter =
        MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", intTypeAnnotation);
    auto *const inArraySizeExpr = CreateIfTest(this, arrayIdent, inputOrdinalParameter);
    auto *const returnEnumStmt = CreateReturnEnumStatement(this, arrayIdent, inputOrdinalParameter);
    auto *const ifOrdinalExistsStmt = checker_->AllocNode<ir::IfStatement>(inArraySizeExpr, returnEnumStmt, nullptr);

    util::UString messageString(util::StringView("No enum constant in "), Allocator());
    messageString.Append(enumDecl->Key()->Name());
    messageString.Append(" with ordinal value ");

    auto *const throwNoEnumStmt = CreateThrowStatement(this, inputOrdinalParameter, messageString);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputOrdinalParameter);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(ifOrdinalExistsStmt);
    body.push_back(throwNoEnumStmt);
    auto *const returnTypeAnnotation = MakeTypeReference(checker_, returnTypeName);

    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), returnTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    auto *const ident = checker_->AllocNode<ir::Identifier>(methodName, Allocator());

    function->SetIdent(ident);
    function->Scope()->BindInternalName(ident->Name());

    MakeMethodDef(checker_, enumClass, varbinder_, ident, function);
}

void EnumLoweringPhase::CreateEnumToStringMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                 ir::ClassDefinition *const enumClass,
                                                 ir::Identifier *const stringValuesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, stringValuesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?
    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), stringTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});

    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::TO_STRING_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());
    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumValueOfMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::ClassDefinition *const enumClass,
                                                ir::Identifier *const valuesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());

    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "e", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, valuesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), intTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::VALUE_OF_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumGetNameMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::ClassDefinition *const enumClass,
                                                ir::Identifier *const namesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());

    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());
    auto *const inputEnumIdent = MakeFunctionParam(checker_, varbinder_, paramScope, "ordinal", enumTypeAnnotation);
    auto *const returnStmt = CreateReturnWitAsStatement(this, namesArrayIdent, inputEnumIdent);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputEnumIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, "String");  // NOTE String -> Builtin?

    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), stringTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::GET_NAME_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
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

void EnumLoweringPhase::CreateEnumGetValueOfMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                   ir::ClassDefinition *const enumClass,
                                                   ir::Identifier *const namesArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());

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

    util::UString messageString(util::StringView("No enum constant "), Allocator());
    messageString.Append(enumDecl->Key()->Name());
    messageString.Append('.');

    auto *const throwStmt = CreateThrowStatement(this, inputNameIdent, messageString);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputNameIdent);
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());

    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), enumTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::GET_VALUE_OF_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());
    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumValuesMethod(const ir::TSEnumDeclaration *const enumDecl,
                                               ir::ClassDefinition *const enumClass,
                                               ir::Identifier *const itemsArrayIdent)
{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());
    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(itemsArrayIdent);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const enumArrayTypeAnnotation =
        checker_->AllocNode<ir::TSArrayType>(MakeTypeReference(checker_, enumDecl->Key()->Name()));

    auto *const function = MakeFunction({paramScope, std::move(params), std::move(body), enumArrayTypeAnnotation,
                                         enumDecl, ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::VALUES_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
}

void EnumLoweringPhase::CreateUnboxingMethod(ir::TSEnumDeclaration const *const enumDecl,
                                             ir::ClassDefinition *const enumClass,
                                             ir::Identifier *const itemsArrayIdent)

{
    auto *const paramScope =
        varbinder_->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), enumClass->Scope());

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());

    auto *thisExpr = Allocator()->New<ir::ThisExpression>();
    auto *fieldIdentifier = Allocator()->New<ir::Identifier>("ordinal", Allocator());
    auto *arrayIndexExpr = checker_->AllocNode<ir::MemberExpression>(
        thisExpr, fieldIdentifier, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    auto itemsArrayIdentClone = itemsArrayIdent->Clone(checker_->Allocator(), nullptr);
    auto *const arrayAccessExpr = checker_->AllocNode<ir::MemberExpression>(
        itemsArrayIdentClone, arrayIndexExpr, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(arrayAccessExpr);
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *const returnTypeAnnotation = MakeTypeReference(checker_, enumDecl->Key()->Name());

    auto *const function = MakeFunction(
        {paramScope, std::move(params), std::move(body), returnTypeAnnotation, enumDecl, ir::ModifierFlags::PUBLIC});

    varbinder_->AddFunctionThisParam(function);
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::UNBOX_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);
    function->Scope()->BindInternalName(functionIdent->Name());

    MakeMethodDef(checker_, enumClass, varbinder_, functionIdent, function);
}

ArenaAllocator *EnumLoweringPhase::Allocator()
{
    return checker_->Allocator();
}

}  // namespace ark::es2panda::compiler