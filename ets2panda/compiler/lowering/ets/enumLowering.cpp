/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "checker/types/ets/etsEnumType.h"
#include "checker/types/type.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "varbinder/ETSBinder.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

namespace {

[[nodiscard]] ir::ETSParameterExpression *MakeFunctionParam(checker::ETSChecker *const checker,
                                                            const util::StringView &name,
                                                            ir::TypeNode *const typeAnnotation)
{
    auto *const paramIdent = checker->AllocNode<ir::Identifier>(name, typeAnnotation, checker->Allocator());
    paramIdent->SetRange(typeAnnotation->Range());
    auto *const param = checker->AllocNode<ir::ETSParameterExpression>(paramIdent, false, checker->Allocator());

    return param;
}

[[nodiscard]] ir::Identifier *MakeParamRefIdent(checker::ETSChecker *const checker,
                                                ir::ETSParameterExpression *paramExpr)
{
    auto *const refIdent = checker->AllocNode<ir::Identifier>(paramExpr->Ident()->Name(), checker->Allocator());
    refIdent->SetRange(paramExpr->Ident()->Range());
    refIdent->SetVariable(paramExpr->Ident()->Variable());
    return refIdent;
}

[[nodiscard]] ir::ETSTypeReference *MakeTypeReference(checker::ETSChecker *const checker, const util::StringView &name)
{
    auto *const ident = checker->AllocNode<ir::Identifier>(name, checker->Allocator());
    auto *const referencePart = checker->AllocNode<ir::ETSTypeReferencePart>(ident, checker->Allocator());
    return checker->AllocNode<ir::ETSTypeReference>(referencePart, checker->Allocator());
}

ir::MethodDefinition *MakeMethodDef(checker::ETSChecker *const checker, ir::ClassDefinition *enumClass,
                                    ir::Identifier *const ident, ir::ScriptFunction *const function)
{
    auto *const functionExpr = checker->AllocNode<ir::FunctionExpression>(function);
    auto *const identClone = ident->Clone(checker->Allocator(), nullptr);

    auto *const methodDef = checker->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, identClone, functionExpr, function->Modifiers(), checker->Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);

    return methodDef;
}

}  // namespace

void EnumLoweringPhase::LogError(const diagnostic::DiagnosticKind &diagnostic,
                                 const util::DiagnosticMessageParams &diagnosticParams,
                                 const lexer::SourcePosition &pos)
{
    context_->diagnosticEngine->LogDiagnostic(diagnostic, diagnosticParams, pos);
}

template <typename TypeNode>
bool EnumLoweringPhase::CheckEnumMemberType(const ArenaVector<ir::AstNode *> &enumMembers, bool &hasLoggedError,
                                            bool &hasLongLiteral)
{
    for (auto *member : enumMembers) {
        auto *init = member->AsTSEnumMember()->Init();
        if constexpr (std::is_same_v<TypeNode, ir::NumberLiteral>) {
            if (!init->IsNumberLiteral() || !init->AsNumberLiteral()->Number().IsInteger()) {
                LogError(diagnostic::ENUM_INVALID_INIT, {}, init->Start());
                hasLoggedError = true;
                continue;
            }

            if (!init->AsNumberLiteral()->Number().IsLong()) {
                continue;
            }

            hasLongLiteral = true;
            // Invalid generated value.
            if (member->AsTSEnumMember()->IsGenerated() &&
                init->AsNumberLiteral()->Number().GetLong() == std::numeric_limits<int64_t>::min()) {
                LogError(diagnostic::ENUM_INVALID_INIT, {}, init->Start());
                hasLoggedError = true;
            }
        } else if constexpr (std::is_same_v<TypeNode, ir::StringLiteral>) {
            if (!init->IsStringLiteral()) {
                LogError(diagnostic::ENUM_INVALID_INIT, {}, init->Start());
                hasLoggedError = true;
            }
            if (member->AsTSEnumMember()->IsGenerated()) {
                LogError(diagnostic::ENUM_STRING_TYPE_ALL_ITEMS_INIT, {}, init->Start());
                hasLoggedError = true;
            }
        } else {
            static_assert(std::is_same_v<TypeNode, void>, "Unsupported TypeNode in CheckEnumMemberType.");
        }
    }
    return !hasLoggedError;
}

[[nodiscard]] ir::ScriptFunction *EnumLoweringPhase::MakeFunction(FunctionInfo &&functionInfo)
{
    ir::BlockStatement *bodyBlock = nullptr;

    if (functionInfo.enumDecl->IsDeclare()) {
        functionInfo.flags |= ir::ModifierFlags::DECLARE;
    } else {
        bodyBlock = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(functionInfo.body));
    }
    // clang-format off
    auto *const function = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
            bodyBlock,
            ir::FunctionSignature(nullptr, std::move(functionInfo.params), functionInfo.returnTypeAnnotation),
            ir::ScriptFunctionFlags::METHOD, functionInfo.flags});
    // clang-format on

    return function;
}

template <typename ElementMaker>
[[nodiscard]] ir::Identifier *EnumLoweringPhase::MakeArray(const ir::TSEnumDeclaration *const enumDecl,
                                                           ir::ClassDefinition *const enumClass,
                                                           const util::StringView &name,
                                                           ir::TypeNode *const typeAnnotation,
                                                           ElementMaker &&elementMaker)
{
    ArenaVector<ir::Expression *> elements(Allocator()->Adapter());
    elements.reserve(enumDecl->Members().size());
    for (const auto *const member : enumDecl->Members()) {
        elements.push_back(elementMaker(member->AsTSEnumMember()));
    }
    auto *const arrayExpr = checker_->AllocNode<ir::ArrayExpression>(std::move(elements), Allocator());
    auto *const arrayIdent = checker_->AllocNode<ir::Identifier>(name, Allocator());
    auto *const arrayClassProp = checker_->AllocNode<ir::ClassProperty>(
        arrayIdent, arrayExpr, typeAnnotation,
        ir::ModifierFlags::STATIC | ir::ModifierFlags::PRIVATE | ir::ModifierFlags::READONLY, Allocator(), false);
    arrayClassProp->SetParent(enumClass);
    enumClass->Body().push_back(arrayClassProp);

    return arrayIdent;
}

void EnumLoweringPhase::CreateEnumItemFields(const ir::TSEnumDeclaration *const enumDecl,
                                             ir::ClassDefinition *const enumClass, EnumType enumType)
{
    int32_t ordinal = 0;
    auto createEnumItemField = [this, enumClass, enumType, &ordinal](ir::TSEnumMember *const member) {
        auto *const enumMemberIdent =
            checker_->AllocNode<ir::Identifier>(member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
        auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumClass->Ident()->Name());

        auto *const ordinalLiteral = checker_->AllocNode<ir::NumberLiteral>(lexer::Number(ordinal));
        ordinal++;
        ArenaVector<ir::Expression *> newExprArgs(Allocator()->Adapter());
        newExprArgs.push_back(ordinalLiteral);

        ir::Expression *valueArgument = nullptr;
        switch (enumType) {
            case EnumType::INT: {
                auto enumFieldValue =
                    member->AsTSEnumMember()->Init()->AsNumberLiteral()->Number().GetValue<std::int32_t>();
                valueArgument = checker_->AllocNode<ir::NumberLiteral>(lexer::Number(enumFieldValue));
                break;
            }
            case EnumType::LONG: {
                auto enumFieldValue =
                    member->AsTSEnumMember()->Init()->AsNumberLiteral()->Number().GetValue<std::int64_t>();
                valueArgument = checker_->AllocNode<ir::NumberLiteral>(lexer::Number(enumFieldValue));
                break;
            }
            case EnumType::STRING: {
                auto enumFieldValue = member->AsTSEnumMember()->Init()->AsStringLiteral()->Str();
                valueArgument = checker_->AllocNode<ir::StringLiteral>(enumFieldValue);
                break;
            }
        }
        newExprArgs.push_back(valueArgument);

        auto enumTypeAnnotation1 = enumTypeAnnotation->Clone(Allocator(), nullptr);
        auto *const newExpression =
            checker_->AllocNode<ir::ETSNewClassInstanceExpression>(enumTypeAnnotation1, std::move(newExprArgs));

        auto *field = checker_->AllocNode<ir::ClassProperty>(
            enumMemberIdent, newExpression, enumTypeAnnotation,
            ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC | ir::ModifierFlags::READONLY, Allocator(), false);
        enumMemberIdent->SetRange(member->Key()->Range());
        newExpression->SetRange(member->Init()->Range());
        field->SetRange(member->Range());
        field->SetOrigEnumMember(member->AsTSEnumMember());
        field->SetParent(enumClass);
        return field;
    };
    for (auto *const member : enumDecl->Members()) {
        enumClass->Body().push_back(createEnumItemField(member->AsTSEnumMember()));
    }
}

ir::Identifier *EnumLoweringPhase::CreateEnumNamesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                        ir::ClassDefinition *const enumClass)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation, Allocator());

    // clang-format off
    return MakeArray(enumDecl, enumClass, NAMES_ARRAY_NAME, arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumNameStringLiteral =
                            checker_->AllocNode<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                        return enumNameStringLiteral;
                    });
    // clang-format on
}

static ir::TypeNode *CreateType(checker::ETSChecker *checker, EnumLoweringPhase::EnumType enumType)
{
    switch (enumType) {
        case EnumLoweringPhase::EnumType::INT: {
            return checker->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, checker->Allocator());
        }
        case EnumLoweringPhase::EnumType::LONG: {
            return checker->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::LONG, checker->Allocator());
        }
        case EnumLoweringPhase::EnumType::STRING: {
            return MakeTypeReference(checker, EnumLoweringPhase::STRING_REFERENCE_TYPE);
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    return nullptr;
}

ir::ClassDeclaration *EnumLoweringPhase::CreateClass(ir::TSEnumDeclaration *const enumDecl,
                                                     const DeclarationFlags flags, EnumType enumType)
{
    auto *ident = Allocator()->New<ir::Identifier>(enumDecl->Key()->Name(), Allocator());
    ident->SetRange(enumDecl->Key()->Range());
    auto enumFlag = enumType == EnumType::INT || enumType == EnumType::LONG
                        ? ir::ClassDefinitionModifiers::INT_ENUM_TRANSFORMED
                        : ir::ClassDefinitionModifiers::STRING_ENUM_TRANSFORMED;
    auto baseClassDefinitionFlag = ir::ClassDefinitionModifiers::CLASS_DECL | enumFlag;

    auto typeParamsVector = ArenaVector<ir::TypeNode *>(checker_->Allocator()->Adapter());
    typeParamsVector.push_back(CreateType(checker_, enumType));
    auto *typeParam = checker_->AllocNode<ir::TSTypeParameterInstantiation>(std::move(typeParamsVector));

    auto *identRef = checker_->AllocNode<ir::Identifier>(util::StringView(BASE_CLASS_NAME), checker_->Allocator());
    auto *typeRefPart =
        checker_->AllocNode<ir::ETSTypeReferencePart>(identRef, typeParam, nullptr, checker_->Allocator());
    auto *superClass = checker_->AllocNode<ir::ETSTypeReference>(typeRefPart, checker_->Allocator());

    auto *classDef = checker_->AllocNode<ir::ClassDefinition>(
        Allocator(), ident,
        flags.isLocal ? baseClassDefinitionFlag | ir::ClassDefinitionModifiers::LOCAL : baseClassDefinitionFlag,
        enumDecl->IsDeclare() ? ir::ModifierFlags::FINAL | ir::ModifierFlags::DECLARE : ir::ModifierFlags::FINAL,
        Language(Language::Id::ETS));

    classDef->SetSuper(superClass);
    auto *classDecl = checker_->AllocNode<ir::ClassDeclaration>(classDef, Allocator());

    if (enumDecl->IsExported()) {
        classDecl->AddModifier(ir::ModifierFlags::EXPORT);
    } else if (enumDecl->IsDefaultExported()) {
        classDecl->AddModifier(ir::ModifierFlags::DEFAULT_EXPORT);
    }

    classDef->SetOrigEnumDecl(enumDecl);

    CreateOrdinalField(classDef);
    if (!enumDecl->IsDeclare()) {
        CreateCCtorForEnumClass(classDef);
    }
    CreateCtorForEnumClass(classDef, enumType);

    return classDecl;
}

void EnumLoweringPhase::CreateCCtorForEnumClass(ir::ClassDefinition *const enumClass)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *id = checker_->AllocNode<ir::Identifier>(compiler::Signatures::CCTOR, Allocator());

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    auto *body = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::STATIC_BLOCK | ir::ScriptFunctionFlags::HIDDEN,
                                                ir::ModifierFlags::STATIC, Language(Language::Id::ETS)});

    func->SetIdent(id);
    id->SetParent(func);

    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);

    auto *const identClone = id->Clone(Allocator(), nullptr);
    auto *const methodDef = checker_->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, identClone, funcExpr, ir::ModifierFlags::PRIVATE | ir::ModifierFlags::STATIC,
        Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);
}

ir::ClassProperty *EnumLoweringPhase::CreateOrdinalField(ir::ClassDefinition *const enumClass)
{
    auto *const fieldIdent = Allocator()->New<ir::Identifier>(ORDINAL_NAME, Allocator());
    auto *const intTypeAnnotation = Allocator()->New<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, Allocator());
    auto *field = checker_->AllocNode<ir::ClassProperty>(fieldIdent, nullptr, intTypeAnnotation,
                                                         ir::ModifierFlags::PRIVATE | ir::ModifierFlags::READONLY,
                                                         Allocator(), false);

    enumClass->Body().push_back(field);
    field->SetParent(enumClass);
    return field;
}

ir::ScriptFunction *EnumLoweringPhase::CreateFunctionForCtorOfEnumClass(ir::ClassDefinition *const enumClass,
                                                                        EnumType enumType)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *const intTypeAnnotation = checker_->AllocNode<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, Allocator());
    auto *const inputOrdinalParam = MakeFunctionParam(checker_, PARAM_ORDINAL, intTypeAnnotation);
    params.push_back(inputOrdinalParam);

    ir::TypeNode *typeAnnotation = CreateType(checker_, enumType);
    auto *const inputValueParam = MakeFunctionParam(checker_, PARAM_VALUE, typeAnnotation);
    params.push_back(inputValueParam);

    auto *id = checker_->AllocNode<ir::Identifier>("constructor", Allocator());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    auto *body = checker_->AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));

    auto scriptFlags = ir::ScriptFunctionFlags::CONSTRUCTOR;
    scriptFlags |= enumClass->IsDeclare() ? ir::ScriptFunctionFlags::EXTERNAL : ir::ScriptFunctionFlags::NONE;

    auto *func = checker_->AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                scriptFlags,  // CC-OFF(G.FMT.02) project code style
                                                ir::ModifierFlags::CONSTRUCTOR |
                                                    ir::ModifierFlags::PRIVATE,  // CC-OFF(G.FMT.02) project code style
                                                Language(Language::Id::ETS)});   // CC-OFF(G.FMT.02) project code style

    func->SetIdent(id);

    if (enumClass->IsDeclare()) {
        // NOTE: In aliveAnalyzer call to super is processed and leads to error. Need to invetigate it
        return func;
    }

    auto *valueIdentifier = checker_->AllocNode<ir::Identifier>(PARAM_VALUE, Allocator());
    valueIdentifier->SetVariable(inputValueParam->Ident()->Variable());

    ArenaVector<ir::Expression *> callArguments(checker_->Allocator()->Adapter());
    auto *callee = checker_->AllocNode<ir::SuperExpression>();
    callArguments.push_back(valueIdentifier);
    auto *superConstructorCall =
        checker_->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
    auto *superCallStatement = checker_->AllocNode<ir::ExpressionStatement>(superConstructorCall);
    superCallStatement->SetParent(body);
    body->Statements().push_back(superCallStatement);

    auto *thisExpr = Allocator()->New<ir::ThisExpression>();
    auto *fieldIdentifier = Allocator()->New<ir::Identifier>(ORDINAL_NAME, Allocator());
    auto *leftHandSide = checker_->AllocNode<ir::MemberExpression>(
        thisExpr, fieldIdentifier, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *rightHandSide = checker_->AllocNode<ir::Identifier>(PARAM_ORDINAL, Allocator());
    rightHandSide->SetVariable(inputOrdinalParam->Ident()->Variable());
    auto *initializer = checker_->AllocNode<ir::AssignmentExpression>(leftHandSide, rightHandSide,
                                                                      lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    auto initStatement = checker_->AllocNode<ir::ExpressionStatement>(initializer);
    initStatement->SetParent(body);
    body->Statements().push_back(initStatement);

    return func;
}

void EnumLoweringPhase::CreateCtorForEnumClass(ir::ClassDefinition *const enumClass, EnumType enumType)
{
    auto *func = CreateFunctionForCtorOfEnumClass(enumClass, enumType);
    auto *funcExpr = checker_->AllocNode<ir::FunctionExpression>(func);

    auto *const identClone = func->Id()->Clone(Allocator(), nullptr);
    auto *const methodDef = checker_->AllocNode<ir::MethodDefinition>(
        ir::MethodDefinitionKind::CONSTRUCTOR, identClone, funcExpr, ir::ModifierFlags::PUBLIC, Allocator(), false);
    methodDef->SetParent(enumClass);
    enumClass->Body().push_back(methodDef);
}

void EnumLoweringPhase::ProcessEnumClassDeclaration(ir::TSEnumDeclaration *const enumDecl,
                                                    const DeclarationFlags &flags, ir::ClassDeclaration *enumClassDecl)
{
    varbinder::Variable *var = nullptr;
    auto *ident = enumClassDecl->Definition()->Ident();
    if (flags.isLocal) {
        auto *scope = NearestScope(enumDecl->Parent());
        auto localCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder_, scope);
        scope->EraseBinding(ident->Name());
        InitScopesPhaseETS::RunExternalNode(enumClassDecl, varbinder_);
        var = varbinder_->GetScope()->FindLocal(ident->Name(), varbinder::ResolveBindingOptions::ALL);
    } else if (flags.isTopLevel) {
        auto *scope = program_->GlobalClassScope();
        auto localCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder_, scope);
        scope->StaticDeclScope()->EraseBinding(ident->Name());
        InitScopesPhaseETS::RunExternalNode(enumClassDecl, varbinder_);
        var = varbinder_->GetScope()->FindLocal(ident->Name(), varbinder::ResolveBindingOptions::ALL);
        if (var != nullptr) {
            program_->GlobalScope()->InsertBinding(ident->Name(), var);
        }
    } else if (flags.isNamespace) {
        auto *scope = enumDecl->Parent()->Scope();
        auto localCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder_, scope);
        scope->AsClassScope()->StaticDeclScope()->EraseBinding(ident->Name());
        InitScopesPhaseETS::RunExternalNode(enumClassDecl, varbinder_);
        var = varbinder_->GetScope()->FindLocal(ident->Name(), varbinder::ResolveBindingOptions::DECLARATION);
    } else {
        ES2PANDA_UNREACHABLE();
    }
    if (var != nullptr) {
        // Although it enum was transformed to class, it should still be regarded as enum.
        var->RemoveFlag(varbinder::VariableFlags::CLASS);
        var->AddFlag(varbinder::VariableFlags::ENUM_LITERAL);
    }
}

template <ir::PrimitiveType TYPE>
ir::ClassDeclaration *EnumLoweringPhase::CreateEnumIntClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl,
                                                                               const DeclarationFlags flags)
{
    EnumType enumType = EnumType::INT;
    if constexpr (TYPE == ir::PrimitiveType::LONG) {
        enumType = EnumType::LONG;
    }

    auto *const enumClassDecl = CreateClass(enumDecl, flags, enumType);
    auto *const enumClass = enumClassDecl->Definition();

    CreateEnumItemFields(enumDecl, enumClass, enumType);
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl, enumClass);
    auto *const valuesArrayIdent = CreateEnumValuesArray<TYPE>(enumDecl, enumClass);
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl, enumClass);
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl, enumClass);

    CreateEnumGetNameMethod(enumDecl, enumClass, namesArrayIdent);

    CreateEnumGetValueOfMethod(enumDecl, enumClass, namesArrayIdent, itemsArrayIdent);

    CreateEnumFromValueMethod(enumDecl, enumClass, valuesArrayIdent, itemsArrayIdent, TYPE);

    CreateEnumValueOfMethod(enumDecl, enumClass, valuesArrayIdent, TYPE);

    CreateEnumToStringMethod(enumDecl, enumClass, stringValuesArrayIdent);

    CreateEnumValuesMethod(enumDecl, enumClass, itemsArrayIdent);

    CreateEnumGetOrdinalMethod(enumDecl, enumClass);

    CreateEnumDollarGetMethod(enumDecl, enumClass);

    SetDefaultPositionInUnfilledClassNodes(enumClassDecl, enumDecl);

    enumClassDecl->SetParent(enumDecl->Parent());
    ProcessEnumClassDeclaration(enumDecl, flags, enumClassDecl);

    return enumClassDecl;
}

ir::ClassDeclaration *EnumLoweringPhase::CreateEnumStringClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl,
                                                                                  const DeclarationFlags flags)
{
    auto *const enumClassDecl = CreateClass(enumDecl, flags, EnumType::STRING);
    auto *const enumClass = enumClassDecl->Definition();

    CreateEnumItemFields(enumDecl, enumClass, EnumType::STRING);
    auto *const namesArrayIdent = CreateEnumNamesArray(enumDecl, enumClass);
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumDecl, enumClass);
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumDecl, enumClass);

    CreateEnumGetNameMethod(enumDecl, enumClass, namesArrayIdent);

    CreateEnumGetValueOfMethod(enumDecl, enumClass, namesArrayIdent, itemsArrayIdent);

    CreateEnumFromValueMethod(enumDecl, enumClass, stringValuesArrayIdent, itemsArrayIdent, std::nullopt);

    CreateEnumValueOfMethod(enumDecl, enumClass, stringValuesArrayIdent, std::nullopt);

    CreateEnumToStringMethod(enumDecl, enumClass, stringValuesArrayIdent);

    CreateEnumValuesMethod(enumDecl, enumClass, itemsArrayIdent);

    CreateEnumGetOrdinalMethod(enumDecl, enumClass);

    CreateEnumDollarGetMethod(enumDecl, enumClass);

    SetDefaultPositionInUnfilledClassNodes(enumClassDecl, enumDecl);

    enumClassDecl->SetParent(enumDecl->Parent());
    ProcessEnumClassDeclaration(enumDecl, flags, enumClassDecl);

    return enumClassDecl;
}

static EnumLoweringPhase::DeclarationFlags GetDeclFlags(ir::TSEnumDeclaration *const enumDecl)
{
    return {enumDecl->Parent() != nullptr && enumDecl->Parent()->IsETSModule() &&
                enumDecl->Parent()->AsETSModule()->IsETSScript(),
            enumDecl->Parent() != nullptr && enumDecl->Parent()->IsBlockStatement(),
            enumDecl->Parent() != nullptr && enumDecl->Parent()->IsClassDefinition() &&
                enumDecl->Parent()->AsClassDefinition()->IsNamespaceTransformed()};
}

bool EnumLoweringPhase::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    bool isPerformedSuccess = true;
    if (program->Extension() != ScriptExtension::ETS) {
        return isPerformedSuccess;
    }

    context_ = ctx;
    checker_ = ctx->checker->AsETSChecker();
    varbinder_ = ctx->parserProgram->VarBinder()->AsETSBinder();
    program_ = program;
    program->Ast()->TransformChildrenRecursively(
        [this, &isPerformedSuccess](ir::AstNode *ast) -> AstNodePtr {
            if (ast->IsTSEnumDeclaration()) {
                auto *enumDecl = ast->AsTSEnumDeclaration();
                auto const flags = GetDeclFlags(enumDecl);
                //  Skip processing possibly invalid enum declaration (for multi-error reporting)
                if (!flags.IsValid() || enumDecl->Members().empty()) {
                    return ast;
                }
                bool hasLoggedError = false;
                bool hasLongLiteral = false;
                auto *const itemInit = enumDecl->Members().front()->AsTSEnumMember()->Init();
                if (itemInit->IsNumberLiteral() &&
                    CheckEnumMemberType<ir::NumberLiteral>(enumDecl->Members(), hasLoggedError, hasLongLiteral)) {
                    auto res = hasLongLiteral
                                   ? CreateEnumIntClassFromEnumDeclaration<ir::PrimitiveType::LONG>(enumDecl, flags)
                                   : CreateEnumIntClassFromEnumDeclaration<ir::PrimitiveType::INT>(enumDecl, flags);
                    return res;
                }
                if (itemInit->IsStringLiteral() &&
                    CheckEnumMemberType<ir::StringLiteral>(enumDecl->Members(), hasLoggedError, hasLongLiteral)) {
                    return CreateEnumStringClassFromEnumDeclaration(enumDecl, flags);
                }
                if (!hasLoggedError) {
                    LogError(diagnostic::ENUM_INVALID_INIT, {}, itemInit->Start());
                    isPerformedSuccess = false;
                } else {
                    isPerformedSuccess = false;
                }
                return ast;
            }
            return ast;
        },
        Name());
    return isPerformedSuccess;
}

template <ir::PrimitiveType TYPE>
ir::Identifier *EnumLoweringPhase::CreateEnumValuesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                         ir::ClassDefinition *const enumClass)
{
    auto *const type = checker_->AllocNode<ir::ETSPrimitiveType>(TYPE, Allocator());
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(type, Allocator());
    // clang-format off
    return MakeArray(enumDecl, enumClass, VALUES_ARRAY_NAME, arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const enumValueLiteral = checker_->AllocNode<ir::NumberLiteral>(
                            lexer::Number(member->AsTSEnumMember()
                                                ->Init()
                                                ->AsNumberLiteral()
                                                ->Number()
                                                .GetValue<std::int64_t>()));
                        return enumValueLiteral;
                    });
    // clang-format on
}

ir::Identifier *EnumLoweringPhase::CreateEnumStringValuesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                               ir::ClassDefinition *const enumClass)
{
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);  // NOTE String -> Builtin?
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(stringTypeAnnotation, Allocator());

    // clang-format off
    return MakeArray(enumDecl, enumClass, STRING_VALUES_ARRAY_NAME, arrayTypeAnnotation,
                     [this](const ir::TSEnumMember *const member) {
                        auto *const init = member->AsTSEnumMember()->Init();
                        util::StringView stringValue;

                        if (init->IsStringLiteral()) {
                            stringValue = init->AsStringLiteral()->Str();
                        } else {
                            auto str = std::to_string(
                                init->AsNumberLiteral()->Number().GetValue<std::int64_t>());
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
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumClass->Ident()->Name());
    auto *const arrayTypeAnnotation = checker_->AllocNode<ir::TSArrayType>(enumTypeAnnotation, Allocator());
    // clang-format off
    return MakeArray(enumDecl, enumClass, ITEMS_ARRAY_NAME, arrayTypeAnnotation,
                     [this, enumClass, enumDecl](const ir::TSEnumMember *const member) {
                        auto *const enumTypeIdent =
                            checker_->AllocNode<ir::Identifier>(enumClass->Ident()->Name(), Allocator());
                        enumTypeIdent->SetRange(enumDecl->Key()->Range());
                        auto *const enumMemberIdent = checker_->AllocNode<ir::Identifier>(
                            member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
                        enumMemberIdent->SetRange(member->AsTSEnumMember()->Key()->Range());
                        auto *const enumMemberExpr = checker_->AllocNode<ir::MemberExpression>(
                            enumTypeIdent, enumMemberIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
                        return enumMemberExpr;
                    });
    // clang-format on
}

ir::MemberExpression *EnumLoweringPhase::CreateOrdinalAccessExpression()
{
    auto *thisExpr = checker_->AllocNode<ir::ThisExpression>();
    auto *fieldIdentifier = checker_->AllocNode<ir::Identifier>(ORDINAL_NAME, checker_->Allocator());
    auto *ordinalAccessExpr = checker_->AllocNode<ir::MemberExpression>(
        thisExpr, fieldIdentifier, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    return ordinalAccessExpr;
}

namespace {

ir::MemberExpression *CreateStaticAccessMemberExpression(checker::ETSChecker *checker,
                                                         ir::Identifier *const enumClassIdentifier,
                                                         ir::Identifier *const arrayIdentifier)
{
    auto *const enumClassIdentifierClone = enumClassIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const arrayIdentifierClone = arrayIdentifier->Clone(checker->Allocator(), nullptr);

    return checker->AllocNode<ir::MemberExpression>(enumClassIdentifierClone, arrayIdentifierClone,
                                                    ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
}

ir::ThrowStatement *CreateThrowStatement(checker::ETSChecker *checker, ir::ETSParameterExpression *const parameter,
                                         const util::UString &messageString)
{
    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto *const message = checker->AllocNode<ir::StringLiteral>(messageString.View());
    auto *const newExprArg =
        checker->AllocNode<ir::BinaryExpression>(message, paramRefIdent, lexer::TokenType::PUNCTUATOR_PLUS);

    paramRefIdent->SetParent(newExprArg);
    ArenaVector<ir::Expression *> newExprArgs(checker->Allocator()->Adapter());
    newExprArgs.push_back(newExprArg);

    auto *const exceptionReference = MakeTypeReference(checker, "Error");
    auto *const newExpr =
        checker->AllocNode<ir::ETSNewClassInstanceExpression>(exceptionReference, std::move(newExprArgs));
    return checker->AllocNode<ir::ThrowStatement>(newExpr);
}

ir::ReturnStatement *CreateReturnStatement(checker::ETSChecker *checker, ir::Identifier *const enumClassIdentifier,
                                           ir::Identifier *const arrayIdentifier, ir::Expression *const parameter)
{
    auto *const propertyAccessExpr = CreateStaticAccessMemberExpression(checker, enumClassIdentifier, arrayIdentifier);

    auto *const arrayAccessExpr = checker->AllocNode<ir::MemberExpression>(
        propertyAccessExpr, parameter, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    return checker->AllocNode<ir::ReturnStatement>(arrayAccessExpr);
}

ir::CallExpression *CreateCallInstanceMethod(checker::ETSChecker *checker, std::string_view methodName,
                                             ir::Expression *thisArg)
{
    auto methodId = checker->AllocNode<ir::Identifier>(methodName, checker->Allocator());
    auto callee = checker->AllocNode<ir::MemberExpression>(thisArg, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                           false, false);

    ArenaVector<ir::Expression *> callArguments({}, checker->Allocator()->Adapter());
    return checker->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
}

}  // namespace

void EnumLoweringPhase::CreateEnumToStringMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                 ir::ClassDefinition *const enumClass,
                                                 ir::Identifier *const stringValuesArrayIdent)
{
    auto *ordinalAccessExpr = CreateOrdinalAccessExpression();
    auto *const returnStmt =
        CreateReturnStatement(checker_, enumClass->Ident(), stringValuesArrayIdent, ordinalAccessExpr);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);  // NOTE String -> Builtin?
    auto *const function =
        MakeFunction({std::move(params), std::move(body), stringTypeAnnotation, enumDecl, ir::ModifierFlags::PUBLIC});

    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::TO_STRING_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumValueOfMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::ClassDefinition *const enumClass,
                                                ir::Identifier *const valuesArrayIdent,
                                                std::optional<ir::PrimitiveType> primitiveType)
{
    auto *ordinalAccessExpr = CreateOrdinalAccessExpression();
    auto *const returnStmt = CreateReturnStatement(checker_, enumClass->Ident(), valuesArrayIdent, ordinalAccessExpr);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const typeAnnotation =
        primitiveType.has_value()
            ? checker_->AllocNode<ir::ETSPrimitiveType>(primitiveType.value(), Allocator())->AsTypeNode()
            : MakeTypeReference(checker_, STRING_REFERENCE_TYPE)->AsTypeNode();
    auto *const function =
        MakeFunction({std::move(params), std::move(body), typeAnnotation, enumDecl, ir::ModifierFlags::PUBLIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::VALUE_OF_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);

    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumGetNameMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::ClassDefinition *const enumClass,
                                                ir::Identifier *const namesArrayIdent)
{
    auto ordinalAccessExpr = CreateOrdinalAccessExpression();
    auto *const returnStmt = CreateReturnStatement(checker_, enumClass->Ident(), namesArrayIdent, ordinalAccessExpr);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);  // NOTE String -> Builtin?

    auto *const function =
        MakeFunction({std::move(params), std::move(body), stringTypeAnnotation, enumDecl, ir::ModifierFlags::PUBLIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::GET_NAME_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);

    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

namespace {

ir::VariableDeclaration *CreateForLoopInitVariableDeclaration(checker::ETSChecker *checker,
                                                              ir::Identifier *const loopIdentifier)
{
    auto *const init = checker->AllocNode<ir::NumberLiteral>("0");
    auto *const decl =
        checker->AllocNode<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, loopIdentifier, init);
    loopIdentifier->SetParent(decl);
    ArenaVector<ir::VariableDeclarator *> decls(checker->Allocator()->Adapter());
    decls.push_back(decl);
    auto *const declaration = checker->AllocNode<ir::VariableDeclaration>(
        ir::VariableDeclaration::VariableDeclarationKind::LET, checker->Allocator(), std::move(decls));
    decl->SetParent(declaration);
    return declaration;
}

ir::BinaryExpression *CreateForLoopTest(checker::ETSChecker *checker, ir::Identifier *const enumClassIdentifier,
                                        ir::Identifier *const namesArrayIdentifier,
                                        ir::Identifier *const loopIdentifier)
{
    auto *const lengthIdent = checker->AllocNode<ir::Identifier>("length", checker->Allocator());
    auto *const propertyAccessExpr =
        CreateStaticAccessMemberExpression(checker, enumClassIdentifier, namesArrayIdentifier);
    auto *const arrayLengthExpr = checker->AllocNode<ir::MemberExpression>(
        propertyAccessExpr, lengthIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *const forLoopIdentClone = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const binaryExpr = checker->AllocNode<ir::BinaryExpression>(forLoopIdentClone, arrayLengthExpr,
                                                                      lexer::TokenType::PUNCTUATOR_LESS_THAN);
    return binaryExpr;
}

ir::UpdateExpression *CreateForLoopUpdate(checker::ETSChecker *checker, ir::Identifier *const loopIdentifier)
{
    auto *const forLoopIdentClone = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const incrementExpr =
        checker->AllocNode<ir::UpdateExpression>(forLoopIdentClone, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, true);
    return incrementExpr;
}

ir::IfStatement *CreateIf(checker::ETSChecker *checker, ir::MemberExpression *propertyAccessExpr,
                          ir::MemberExpression *itemAccessExpr, ir::Identifier *const loopIdentifier,
                          ir::ETSParameterExpression *const parameter)
{
    auto *const forLoopIdentClone1 = loopIdentifier->Clone(checker->Allocator(), nullptr);
    auto *const namesArrayElementExpr = checker->AllocNode<ir::MemberExpression>(
        propertyAccessExpr, forLoopIdentClone1, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    auto *const paramRefIdent = MakeParamRefIdent(checker, parameter);
    auto *const namesEqualExpr = checker->AllocNode<ir::BinaryExpression>(paramRefIdent, namesArrayElementExpr,
                                                                          lexer::TokenType::PUNCTUATOR_EQUAL);
    paramRefIdent->SetParent(namesEqualExpr);

    auto *const forLoopIdentClone2 = loopIdentifier->Clone(checker->Allocator(), nullptr);

    auto *const itemsArrayElementExpr = checker->AllocNode<ir::MemberExpression>(
        itemAccessExpr, forLoopIdentClone2, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);

    auto *const returnStmt = checker->AllocNode<ir::ReturnStatement>(itemsArrayElementExpr);
    return checker->AllocNode<ir::IfStatement>(namesEqualExpr, returnStmt, nullptr);
}

}  // namespace

void EnumLoweringPhase::CreateEnumGetValueOfMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                   ir::ClassDefinition *const enumClass,
                                                   ir::Identifier *const namesArrayIdent,
                                                   ir::Identifier *const itemsArrayIdent)
{
    auto *const forLoopIIdent = checker_->AllocNode<ir::Identifier>(IDENTIFIER_I, checker_->Allocator());
    auto *const forLoopInitVarDecl = CreateForLoopInitVariableDeclaration(checker_, forLoopIIdent);
    auto *const forLoopTest = CreateForLoopTest(checker_, enumClass->Ident(), namesArrayIdent, forLoopIIdent);
    auto *const forLoopUpdate = CreateForLoopUpdate(checker_, forLoopIIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);  // NOTE String -> Builtin?
    auto *const inputNameIdent = MakeFunctionParam(checker_, PARAM_NAME, stringTypeAnnotation);
    auto *const ifStmt =
        CreateIf(checker_, CreateStaticAccessMemberExpression(checker_, enumClass->Ident(), namesArrayIdent),
                 CreateStaticAccessMemberExpression(checker_, enumClass->Ident(), itemsArrayIdent), forLoopIIdent,
                 inputNameIdent);

    auto *const forLoop =
        checker_->AllocNode<ir::ForUpdateStatement>(forLoopInitVarDecl, forLoopTest, forLoopUpdate, ifStmt);

    util::UString messageString(util::StringView("No enum constant "), Allocator());
    messageString.Append(enumClass->Ident()->Name());
    messageString.Append('.');

    auto *const throwStmt = CreateThrowStatement(checker_, inputNameIdent, messageString);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputNameIdent);
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumClass->Ident()->Name());

    auto *const function = MakeFunction({std::move(params), std::move(body), enumTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::GET_VALUE_OF_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumFromValueMethod(ir::TSEnumDeclaration const *const enumDecl,
                                                  ir::ClassDefinition *const enumClass,
                                                  ir::Identifier *const valuesArrayIdent,
                                                  ir::Identifier *const itemsArrayIdent,
                                                  std::optional<ir::PrimitiveType> primitiveType)
{
    auto *const forLoopIIdent = checker_->AllocNode<ir::Identifier>(IDENTIFIER_I, checker_->Allocator());
    auto *const forLoopInitVarDecl = CreateForLoopInitVariableDeclaration(checker_, forLoopIIdent);
    auto *const forLoopTest = CreateForLoopTest(checker_, enumClass->Ident(), valuesArrayIdent, forLoopIIdent);
    auto *const forLoopUpdate = CreateForLoopUpdate(checker_, forLoopIIdent);
    auto *const typeAnnotation =
        primitiveType.has_value()
            ? checker_->AllocNode<ir::ETSPrimitiveType>(primitiveType.value(), Allocator())->AsTypeNode()
            : MakeTypeReference(checker_, STRING_REFERENCE_TYPE)->AsTypeNode();
    auto *const inputValueIdent = MakeFunctionParam(checker_, PARAM_VALUE, typeAnnotation);
    auto *const ifStmt =
        CreateIf(checker_, CreateStaticAccessMemberExpression(checker_, enumClass->Ident(), valuesArrayIdent),
                 CreateStaticAccessMemberExpression(checker_, enumClass->Ident(), itemsArrayIdent), forLoopIIdent,
                 inputValueIdent);

    auto *const forLoop =
        checker_->AllocNode<ir::ForUpdateStatement>(forLoopInitVarDecl, forLoopTest, forLoopUpdate, ifStmt);

    util::UString messageString(util::StringView("No enum "), Allocator());
    messageString.Append(enumClass->Ident()->Name());
    messageString.Append(" with value ");

    auto *const throwStmt = CreateThrowStatement(checker_, inputValueIdent, messageString);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(forLoop);
    body.push_back(throwStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputValueIdent);
    auto *const enumTypeAnnotation = MakeTypeReference(checker_, enumClass->Ident()->Name());

    auto *const function = MakeFunction({std::move(params), std::move(body), enumTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::FROM_VALUE_METHOD_NAME, Allocator());

    function->SetIdent(functionIdent);
    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumValuesMethod(const ir::TSEnumDeclaration *const enumDecl,
                                               ir::ClassDefinition *const enumClass,
                                               ir::Identifier *const itemsArrayIdent)
{
    auto *const propertyAccessExpr = CreateStaticAccessMemberExpression(checker_, enumClass->Ident(), itemsArrayIdent);
    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(propertyAccessExpr);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const enumArrayTypeAnnotation =
        checker_->AllocNode<ir::TSArrayType>(MakeTypeReference(checker_, enumClass->Ident()->Name()), Allocator());

    auto *const function = MakeFunction({std::move(params), std::move(body), enumArrayTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::VALUES_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);

    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumGetOrdinalMethod(const ir::TSEnumDeclaration *const enumDecl,
                                                   ir::ClassDefinition *const enumClass)
{
    auto ordinalAccessExpr = CreateOrdinalAccessExpression();
    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(ordinalAccessExpr);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *const intTypeAnnotation = Allocator()->New<ir::ETSPrimitiveType>(ir::PrimitiveType::INT, Allocator());

    auto *const function =
        MakeFunction({std::move(params), std::move(body), intTypeAnnotation, enumDecl, ir::ModifierFlags::PUBLIC});

    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::GET_ORDINAL_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);

    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::CreateEnumDollarGetMethod(ir::TSEnumDeclaration const *const enumDecl,
                                                  ir::ClassDefinition *const enumClass)
{
    auto *const inputTypeAnnotation = MakeTypeReference(checker_, enumClass->Ident()->Name());
    auto *const inputNameIdent = MakeFunctionParam(checker_, "e", inputTypeAnnotation);
    auto *const paramRefIdent = MakeParamRefIdent(checker_, inputNameIdent);
    auto *const callExpr =
        CreateCallInstanceMethod(checker_, checker::ETSEnumType::GET_NAME_METHOD_NAME, paramRefIdent);
    auto *const returnStmt = checker_->AllocNode<ir::ReturnStatement>(callExpr);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(returnStmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(inputNameIdent);
    auto *const stringTypeAnnotation = MakeTypeReference(checker_, STRING_REFERENCE_TYPE);
    auto *const function = MakeFunction({std::move(params), std::move(body), stringTypeAnnotation, enumDecl,
                                         ir::ModifierFlags::PUBLIC | ir::ModifierFlags::STATIC});
    auto *const functionIdent =
        checker_->AllocNode<ir::Identifier>(checker::ETSEnumType::DOLLAR_GET_METHOD_NAME, Allocator());
    function->SetIdent(functionIdent);

    MakeMethodDef(checker_, enumClass, functionIdent, function);
}

void EnumLoweringPhase::SetDefaultPositionInUnfilledClassNodes(const ir::ClassDeclaration *enumClassDecl,
                                                               ir::TSEnumDeclaration const *const enumDecl)
{
    // Range of "default" value is one point, because that code is not exist in initial source code
    // but createad by enum at this point
    const auto &defautlRange = lexer::SourceRange(enumDecl->Range().start, enumDecl->Range().start);
    enumClassDecl->IterateRecursively([&defautlRange](ir::AstNode *ast) -> void {
        // If SourcePostion is not set before, we set "default" which point to start of enum
        if (ast->Range().start.Program() == nullptr) {
            ast->SetRange(defautlRange);
        }
    });
}

ArenaAllocator *EnumLoweringPhase::Allocator()
{
    return checker_->Allocator();
}

}  // namespace ark::es2panda::compiler
