/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "varbinder/variableFlags.h"
#include "checker/checker.h"
#include "checker/checkerContext.h"
#include "checker/ets/narrowingWideningConverter.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsObjectType.h"
#include "ir/astNode.h"
#include "lexer/token/tokenType.h"
#include "ir/base/catchClause.h"
#include "ir/expression.h"
#include "ir/typeNode.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/switchCaseStatement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/charLiteral.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ts/tsQualifiedName.h"
#include "varbinder/variable.h"
#include "varbinder/scope.h"
#include "varbinder/declaration.h"
#include "parser/ETSparser.h"
#include "parser/program/program.h"
#include "checker/ETSchecker.h"
#include "varbinder/ETSBinder.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/ets/boxingConverter.h"
#include "checker/ets/unboxingConverter.h"
#include "checker/types/ets/types.h"
#include "util/helpers.h"

namespace panda::es2panda::checker {
void ETSChecker::CheckTruthinessOfType(ir::Expression *expr)
{
    checker::Type *type = expr->Check(this);
    auto *unboxedType = ETSBuiltinTypeAsConditionalType(type);

    if (unboxedType == nullptr) {
        ThrowTypeError("Condition must be of possible condition type", expr->Start());
    }

    if (unboxedType == GlobalBuiltinVoidType() || unboxedType->IsETSVoidType()) {
        ThrowTypeError("An expression of type 'void' cannot be tested for truthiness", expr->Start());
    }

    if (!unboxedType->IsConditionalExprType()) {
        ThrowTypeError("Condition must be of possible condition type", expr->Start());
    }

    if (unboxedType != nullptr && unboxedType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(type, unboxedType, expr);
    }
    expr->SetTsType(unboxedType);
}

// NOTE: vpukhov. this entire function is isolated work-around until nullish type are not unions
Type *ETSChecker::CreateNullishType(Type *type, checker::TypeFlag nullishFlags, ArenaAllocator *allocator,
                                    TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    ASSERT((nullishFlags & ~TypeFlag::NULLISH) == 0);

    auto *const nullish = type->Instantiate(allocator, relation, globalTypes);

    // Doesnt work for primitive array types, because instantiated type is equal to original one

    if ((nullishFlags & TypeFlag::NULL_TYPE) != 0) {
        nullish->AddTypeFlag(checker::TypeFlag::NULL_TYPE);
    }
    if ((nullishFlags & TypeFlag::UNDEFINED) != 0) {
        nullish->AddTypeFlag(checker::TypeFlag::UNDEFINED);
        if (nullish->IsETSObjectType()) {
            nullish->AsETSObjectType()->SetAssemblerName(GlobalETSObjectType()->AssemblerName());
        }
    }
    ASSERT(!nullish->HasTypeFlag(TypeFlag::ETS_PRIMITIVE));
    return nullish;
}

void ETSChecker::CheckNonNullishType([[maybe_unused]] Type *type, [[maybe_unused]] lexer::SourcePosition lineInfo)
{
    // NOTE: vpukhov. enable check when type inference is implemented
    (void)type;
}

// NOTE: vpukhov. rewrite with union types
Type *ETSChecker::GetNonNullishType(Type *type) const
{
    if (type->IsETSArrayType()) {
        return type;  // give up
    }
    if (type->IsETSTypeParameter()) {
        return type->AsETSTypeParameter()->GetOriginal();
    }

    while (type->IsNullish()) {
        type = type->AsETSObjectType()->GetBaseType();
        ASSERT(type != nullptr);
    }
    return type;
}

// NOTE: vpukhov. rewrite with union types
const Type *ETSChecker::GetNonNullishType(const Type *type) const
{
    if (type->IsETSArrayType()) {
        return type;  // give up
    }
    if (type->IsETSTypeParameter()) {
        return type->AsETSTypeParameter()->GetOriginal();
    }

    while (type->IsNullish()) {
        type = type->AsETSObjectType()->GetBaseType();
        ASSERT(type != nullptr);
    }
    return type;
}

Type *ETSChecker::CreateOptionalResultType(Type *type)
{
    if (type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        type = PrimitiveTypeAsETSBuiltinType(type);
        ASSERT(type->IsETSObjectType());
        Relation()->GetNode()->AddBoxingUnboxingFlags(GetBoxingFlag(type));
    }

    return CreateNullishType(type, checker::TypeFlag::UNDEFINED, Allocator(), Relation(), GetGlobalTypesHolder());
}

bool ETSChecker::MayHaveNullValue(const Type *type) const
{
    if (type->ContainsNull() || type->IsETSNullType()) {
        return true;
    }
    if (type->IsETSTypeParameter()) {
        return MayHaveNullValue(type->AsETSTypeParameter()->EffectiveConstraint(this));
    }
    return false;
}

bool ETSChecker::MayHaveUndefinedValue(const Type *type) const
{
    if (type->ContainsUndefined() || type->IsETSUndefinedType()) {
        return true;
    }
    if (type->IsETSTypeParameter()) {
        return MayHaveUndefinedValue(type->AsETSTypeParameter()->EffectiveConstraint(this));
    }
    return false;
}

bool ETSChecker::MayHaveNulllikeValue(const Type *type) const
{
    if (type->IsNullishOrNullLike()) {
        return true;
    }
    if (type->IsETSTypeParameter()) {
        return MayHaveNulllikeValue(type->AsETSTypeParameter()->EffectiveConstraint(this));
    }
    return false;
}

bool ETSChecker::IsConstantExpression(ir::Expression *expr, Type *type)
{
    return (type->HasTypeFlag(TypeFlag::CONSTANT) && (expr->IsIdentifier() || expr->IsMemberExpression()));
}

Type *ETSChecker::GetNonConstantTypeFromPrimitiveType(Type *type)
{
    if (type->IsETSStringType()) {
        // NOTE: vpukhov. remove when nullish types are unions
        ASSERT(!type->IsNullish());
        return GlobalBuiltinETSStringType();
    }

    if (!type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        return type;
    }

    // NOTE: vpukhov. remove when nullish types are unions
    ASSERT(!type->IsNullish());

    if (type->HasTypeFlag(TypeFlag::LONG)) {
        return GlobalLongType();
    }

    if (type->HasTypeFlag(TypeFlag::BYTE)) {
        return GlobalByteType();
    }

    if (type->HasTypeFlag(TypeFlag::SHORT)) {
        return GlobalShortType();
    }

    if (type->HasTypeFlag(TypeFlag::CHAR)) {
        return GlobalCharType();
    }

    if (type->HasTypeFlag(TypeFlag::INT)) {
        return GlobalIntType();
    }

    if (type->HasTypeFlag(TypeFlag::FLOAT)) {
        return GlobalFloatType();
    }

    if (type->HasTypeFlag(TypeFlag::DOUBLE)) {
        return GlobalDoubleType();
    }

    if (type->IsETSBooleanType()) {
        return GlobalETSBooleanType();
    }
    return type;
}

Type *ETSChecker::GetTypeOfVariable(varbinder::Variable *const var)
{
    if (IsVariableGetterSetter(var)) {
        auto *propType = var->TsType()->AsETSFunctionType();
        if (propType->HasTypeFlag(checker::TypeFlag::GETTER)) {
            return propType->FindGetter()->ReturnType();
        }
        return propType->FindSetter()->Params()[0]->TsType();
    }

    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    // NOTE: kbaladurin. forbid usage of imported entities as types without declarations
    if (VarBinder()->AsETSBinder()->IsDynamicModuleVariable(var)) {
        auto *importData = VarBinder()->AsETSBinder()->DynamicImportDataForVar(var);
        if (importData->import->IsPureDynamic()) {
            return GlobalBuiltinDynamicType(importData->import->Language());
        }
    }

    varbinder::Decl *decl = var->Declaration();

    // Before computing the given variables type, we have to make a new checker context frame so that the checking is
    // done in the proper context, and have to enter the scope where the given variable is declared, so reference
    // resolution works properly
    checker::SavedCheckerContext savedContext(this, CheckerStatus::NO_OPTS);
    checker::ScopeContext scopeCtx(this, var->GetScope());
    auto *iter = decl->Node()->Parent();
    while (iter != nullptr) {
        if (iter->IsMethodDefinition()) {
            auto *methodDef = iter->AsMethodDefinition();
            ASSERT(methodDef->TsType());
            Context().SetContainingSignature(methodDef->Function()->Signature());
        }

        if (iter->IsClassDefinition()) {
            auto *classDef = iter->AsClassDefinition();
            ETSObjectType *containingClass {};

            if (classDef->TsType() == nullptr) {
                containingClass = BuildClassProperties(classDef);
            } else {
                containingClass = classDef->TsType()->AsETSObjectType();
            }

            ASSERT(classDef->TsType());
            Context().SetContainingClass(containingClass);
        }

        iter = iter->Parent();
    }

    switch (decl->Type()) {
        case varbinder::DeclType::CLASS: {
            auto *classDef = decl->Node()->AsClassDefinition();
            BuildClassProperties(classDef);
            return classDef->TsType();
        }
        case varbinder::DeclType::ENUM_LITERAL:
        case varbinder::DeclType::CONST:
        case varbinder::DeclType::LET:
        case varbinder::DeclType::VAR: {
            auto *declNode = decl->Node();

            if (decl->Node()->IsIdentifier()) {
                declNode = declNode->Parent();
            }

            return declNode->Check(this);
        }
        case varbinder::DeclType::FUNC: {
            return decl->Node()->Check(this);
        }
        case varbinder::DeclType::IMPORT: {
            return decl->Node()->Check(this);
        }
        case varbinder::DeclType::TYPE_ALIAS: {
            return GetTypeFromTypeAliasReference(var);
        }
        case varbinder::DeclType::INTERFACE: {
            return BuildInterfaceProperties(decl->Node()->AsTSInterfaceDeclaration());
        }
        default: {
            UNREACHABLE();
        }
    }

    return var->TsType();
}

// Determine if unchecked cast is needed and yield guaranteed source type
Type *ETSChecker::GuaranteedTypeForUncheckedCast(Type *base, Type *substituted)
{
    if (!base->IsETSTypeParameter()) {
        return nullptr;
    }
    auto *constr = base->AsETSTypeParameter()->EffectiveConstraint(this);
    // Constraint is supertype of TypeArg AND TypeArg is supertype of Constraint
    return Relation()->IsIdenticalTo(substituted, constr) ? nullptr : constr;
}

// Determine if substituted property access requires cast from erased type
Type *ETSChecker::GuaranteedTypeForUncheckedPropertyAccess(varbinder::Variable *const prop)
{
    if (IsVariableStatic(prop)) {
        return nullptr;
    }
    if (IsVariableGetterSetter(prop)) {
        auto *method = prop->TsType()->AsETSFunctionType();
        if (!method->HasTypeFlag(checker::TypeFlag::GETTER)) {
            return nullptr;
        }
        return GuaranteedTypeForUncheckedCallReturn(method->FindGetter());
    }
    // NOTE(vpukhov): mark ETSDynamicType properties
    if (prop->Declaration() == nullptr || prop->Declaration()->Node() == nullptr) {
        return nullptr;
    }

    auto *baseProp = prop->Declaration()->Node()->AsClassProperty()->Id()->Variable();
    if (baseProp == prop) {
        return nullptr;
    }
    return GuaranteedTypeForUncheckedCast(GetTypeOfVariable(baseProp), GetTypeOfVariable(prop));
}

// Determine if substituted method cast requires cast from erased type
Type *ETSChecker::GuaranteedTypeForUncheckedCallReturn(Signature *sig)
{
    if (sig->HasSignatureFlag(checker::SignatureFlags::THIS_RETURN_TYPE)) {
        return sig->ReturnType();
    }
    auto *baseSig = sig->Function()->Signature();
    if (baseSig == sig) {
        return nullptr;
    }
    return GuaranteedTypeForUncheckedCast(baseSig->ReturnType(), sig->ReturnType());
}

void ETSChecker::ValidatePropertyAccess(varbinder::Variable *var, ETSObjectType *obj, const lexer::SourcePosition &pos)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U) {
        return;
    }
    if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PRIVATE) || var->HasFlag(varbinder::VariableFlags::PROTECTED)) {
        if (Context().ContainingClass() == obj && obj->IsPropertyInherited(var)) {
            return;
        }

        if (var->HasFlag(varbinder::VariableFlags::PROTECTED) && Context().ContainingClass()->IsDescendantOf(obj) &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        auto *currentOutermost = Context().ContainingClass()->OutermostClass();
        auto *objOutermost = obj->OutermostClass();

        if (currentOutermost != nullptr && objOutermost != nullptr && currentOutermost == objOutermost &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        ThrowTypeError({"Property ", var->Name(), " is not visible here."}, pos);
    }
}

varbinder::Variable *ETSChecker::FindVariableInFunctionScope(const util::StringView name)
{
    return Scope()->FindInFunctionScope(name, varbinder::ResolveBindingOptions::ALL).variable;
}

std::pair<const varbinder::Variable *, const ETSObjectType *> ETSChecker::FindVariableInClassOrEnclosing(
    const util::StringView name, const ETSObjectType *classType)
{
    const auto searchFlags = PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE |
                             PropertySearchFlags::SEARCH_IN_INTERFACES;
    auto *resolved = classType->GetProperty(name, searchFlags);
    while (classType->EnclosingType() != nullptr && resolved == nullptr) {
        classType = classType->EnclosingType();
        resolved = classType->GetProperty(name, searchFlags);
    }

    return {resolved, classType};
}

varbinder::Variable *ETSChecker::FindVariableInGlobal(const ir::Identifier *const identifier)
{
    return Scope()->FindInGlobal(identifier->Name(), varbinder::ResolveBindingOptions::ALL).variable;
}

bool ETSChecker::IsVariableStatic(const varbinder::Variable *var)
{
    if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
        return var->TsType()->AsETSFunctionType()->CallSignatures()[0]->HasSignatureFlag(SignatureFlags::STATIC);
    }
    return var->HasFlag(varbinder::VariableFlags::STATIC);
}

bool ETSChecker::IsVariableGetterSetter(const varbinder::Variable *var)
{
    return var->TsType() != nullptr && var->TsType()->HasTypeFlag(TypeFlag::GETTER_SETTER);
}

void ETSChecker::ThrowError(ir::Identifier *const ident)
{
    ThrowTypeError({"Unresolved reference ", ident->Name()}, ident->Start());
}

void ETSChecker::CheckEtsFunctionType(ir::Identifier *const ident, ir::Identifier const *const id,
                                      ir::TypeNode const *const annotation)
{
    if (annotation == nullptr) {
        ThrowTypeError(
            {"Cannot infer type for ", id->Name(), " because method reference needs an explicit target type"},
            id->Start());
    }

    const auto *const targetType = GetTypeOfVariable(id->Variable());
    ASSERT(targetType != nullptr);

    if (!targetType->IsETSObjectType() || !targetType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        ThrowError(ident);
    }
}

void ETSChecker::NotResolvedError(ir::Identifier *const ident)
{
    const auto [class_var, class_type] = FindVariableInClassOrEnclosing(ident->Name(), Context().ContainingClass());
    if (class_var == nullptr) {
        ThrowError(ident);
    }

    if (IsVariableStatic(class_var)) {
        ThrowTypeError(
            {"Static property '", ident->Name(), "' must be accessed through it's class '", class_type->Name(), "'"},
            ident->Start());
    } else {
        ThrowTypeError({"Property '", ident->Name(), "' must be accessed through 'this'"}, ident->Start());
    }
}

void ETSChecker::ValidateCallExpressionIdentifier(ir::Identifier *const ident, Type *const type)
{
    if (ident->Parent()->AsCallExpression()->Callee() == ident && !type->IsETSFunctionType() &&
        !type->IsETSDynamicType() &&
        (!type->IsETSObjectType() || !type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) &&
        !TryTransformingToStaticInvoke(ident, type)) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateNewClassInstanceIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (ident->Parent()->AsETSNewClassInstanceExpression()->GetTypeRef() == ident &&
        !resolved->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE)) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateMemberIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                          Type *const type)
{
    if (ident->Parent()->AsMemberExpression()->IsComputed()) {
        if (!resolved->Declaration()->PossibleTDZ()) {
            ThrowError(ident);
        }

        return;
    }

    if (!IsReferenceType(type) && !type->IsETSEnumType() && !type->IsETSStringEnumType() &&
        !type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        ThrowError(ident);
    }
}

std::pair<const ir::Identifier *, ir::TypeNode *> ETSChecker::GetTargetIdentifierAndType(ir::Identifier *const ident)
{
    if (ident->Parent()->IsClassProperty()) {
        const auto *const classProp = ident->Parent()->AsClassProperty();
        ASSERT(classProp->Value() && classProp->Value() == ident);
        return std::make_pair(classProp->Key()->AsIdentifier(), classProp->TypeAnnotation());
    }
    const auto *const variableDecl = ident->Parent()->AsVariableDeclarator();
    ASSERT(variableDecl->Init() && variableDecl->Init() == ident);
    return std::make_pair(variableDecl->Id()->AsIdentifier(), variableDecl->Id()->AsIdentifier()->TypeAnnotation());
}

void ETSChecker::ValidatePropertyOrDeclaratorIdentifier(ir::Identifier *const ident,
                                                        varbinder::Variable *const resolved)
{
    const auto [target_ident, typeAnnotation] = GetTargetIdentifierAndType(ident);

    if (resolved->TsType()->IsETSFunctionType()) {
        CheckEtsFunctionType(ident, target_ident, typeAnnotation);
        return;
    }

    if (!resolved->Declaration()->PossibleTDZ()) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateAssignmentIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                              Type *const type)
{
    const auto *const assignmentExpr = ident->Parent()->AsAssignmentExpression();
    if (assignmentExpr->Left() == ident && !resolved->Declaration()->PossibleTDZ()) {
        ThrowError(ident);
    }

    if (assignmentExpr->Right() == ident) {
        const auto *const targetType = assignmentExpr->Left()->TsType();
        ASSERT(targetType != nullptr);

        if (targetType->IsETSObjectType() && targetType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
            if (!type->IsETSFunctionType() &&
                !(type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
                ThrowError(ident);
            }

            return;
        }

        if (!resolved->Declaration()->PossibleTDZ()) {
            ThrowError(ident);
        }
    }
}

bool ETSChecker::ValidateBinaryExpressionIdentifier(ir::Identifier *const ident, Type *const type)
{
    const auto *const binaryExpr = ident->Parent()->AsBinaryExpression();
    bool isFinished = false;
    if (binaryExpr->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF && binaryExpr->Right() == ident) {
        if (!type->IsETSObjectType()) {
            ThrowError(ident);
        }
        isFinished = true;
    }
    return isFinished;
}

void ETSChecker::ValidateResolvedIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (resolved == nullptr) {
        NotResolvedError(ident);
    }

    auto *const resolvedType = ETSChecker::GetApparentType(GetTypeOfVariable(resolved));

    switch (ident->Parent()->Type()) {
        case ir::AstNodeType::CALL_EXPRESSION: {
            ValidateCallExpressionIdentifier(ident, resolvedType);
            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            ValidateNewClassInstanceIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            ValidateMemberIdentifier(ident, resolved, resolvedType);
            break;
        }
        case ir::AstNodeType::BINARY_EXPRESSION: {
            if (ValidateBinaryExpressionIdentifier(ident, resolvedType)) {
                return;
            }

            [[fallthrough]];
        }
        case ir::AstNodeType::UPDATE_EXPRESSION:
        case ir::AstNodeType::UNARY_EXPRESSION: {
            if (!resolved->Declaration()->PossibleTDZ()) {
                ThrowError(ident);
            }
            break;
        }
        case ir::AstNodeType::CLASS_PROPERTY:
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            ValidatePropertyOrDeclaratorIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            ValidateAssignmentIdentifier(ident, resolved, resolvedType);
            break;
        }
        default: {
            if (!resolved->Declaration()->PossibleTDZ() && !resolvedType->IsETSFunctionType()) {
                ThrowError(ident);
            }
            break;
        }
    }
}

void ETSChecker::SaveCapturedVariable(varbinder::Variable *const var, const lexer::SourcePosition &pos)
{
    if (!HasStatus(CheckerStatus::IN_LAMBDA)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PROPERTY)) {
        Context().AddCapturedVar(var, pos);
        return;
    }

    if ((!var->HasFlag(varbinder::VariableFlags::LOCAL) && !var->HasFlag(varbinder::VariableFlags::METHOD)) ||
        (var->GetScope()->Node()->IsScriptFunction() && var->GetScope()->Node()->AsScriptFunction()->IsArrow())) {
        return;
    }

    const auto *scopeIter = Scope();
    while (scopeIter != var->GetScope()) {
        if (scopeIter->IsFunctionScope()) {
            Context().AddCapturedVar(var, pos);
            return;
        }
        scopeIter = scopeIter->Parent();
    }
}

Type *ETSChecker::ResolveIdentifier(ir::Identifier *const ident)
{
    if (ident->Variable() != nullptr) {
        auto *const resolved = ident->Variable();
        SaveCapturedVariable(resolved, ident->Start());
        return GetTypeOfVariable(resolved);
    }

    auto *resolved = FindVariableInFunctionScope(ident->Name());
    if (resolved == nullptr) {
        // If the reference is not found already in the current class, then it is not bound to the class, so we have to
        // find the reference in the global class first, then in the global scope
        resolved = FindVariableInGlobal(ident);
    }

    ValidateResolvedIdentifier(ident, resolved);

    if (resolved->HasFlag(varbinder::VariableFlags::METHOD)) {
        ASSERT(resolved->TsType()->IsETSFunctionType() &&
               !resolved->TsType()->AsETSFunctionType()->CallSignatures().empty());
        const auto *const funcType = resolved->TsType()->AsETSFunctionType();
        if (!funcType->CallSignatures().front()->Owner()->HasObjectFlag(checker::ETSObjectFlags::GLOBAL)) {
            // In the case of function references, it is not enough to find the first method field and use it's function
            // type, because at the position of the call we should be able to work with every possible signature, even
            // with ones that came from base classes.
            // NOTE: szd.  find a better way than making a synthetic variable
            resolved = funcType->CallSignatures().front()->Owner()->CreateSyntheticVarFromEverySignature(
                ident->Name(), PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_IN_BASE);
        }
    }

    ValidatePropertyAccess(resolved, Context().ContainingClass(), ident->Start());
    SaveCapturedVariable(resolved, ident->Start());

    ident->SetVariable(resolved);
    return GetTypeOfVariable(resolved);
}

void ETSChecker::ValidateUnaryOperatorOperand(varbinder::Variable *variable)
{
    if (IsVariableGetterSetter(variable)) {
        return;
    }

    if (variable->Declaration()->IsConstDecl()) {
        if (HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK) &&
            !variable->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            ThrowTypeError({"Cannot reassign constant field ", variable->Name()},
                           variable->Declaration()->Node()->Start());
        }
        if (!HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK) &&
            !variable->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            ThrowTypeError({"Cannot assign to a constant variable ", variable->Name()},
                           variable->Declaration()->Node()->Start());
        }
    }
}

std::tuple<Type *, bool> ETSChecker::ApplyBinaryOperatorPromotion(Type *left, Type *right, TypeFlag test,
                                                                  bool doPromotion)
{
    Type *unboxedL = ETSBuiltinTypeAsPrimitiveType(left);
    Type *unboxedR = ETSBuiltinTypeAsPrimitiveType(right);
    bool bothConst = false;

    if (unboxedL == nullptr || unboxedR == nullptr) {
        return {nullptr, false};
    }

    if (!unboxedL->HasTypeFlag(test) || !unboxedR->HasTypeFlag(test)) {
        return {nullptr, false};
    }

    if (unboxedL->HasTypeFlag(TypeFlag::CONSTANT) && unboxedR->HasTypeFlag(TypeFlag::CONSTANT)) {
        bothConst = true;
    }
    if (doPromotion) {
        if (unboxedL->HasTypeFlag(TypeFlag::ETS_NUMERIC) && unboxedR->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
            if (unboxedL->IsDoubleType() || unboxedR->IsDoubleType()) {
                return {GlobalDoubleType(), bothConst};
            }

            if (unboxedL->IsFloatType() || unboxedR->IsFloatType()) {
                return {GlobalFloatType(), bothConst};
            }

            if (unboxedL->IsLongType() || unboxedR->IsLongType()) {
                return {GlobalLongType(), bothConst};
            }

            return {GlobalIntType(), bothConst};
        }

        if (IsTypeIdenticalTo(unboxedL, unboxedR)) {
            return {unboxedL, bothConst};
        }
    }

    return {unboxedR, bothConst};
}

checker::Type *ETSChecker::ApplyConditionalOperatorPromotion(checker::ETSChecker *checker, checker::Type *unboxedL,
                                                             checker::Type *unboxedR)
{
    if ((unboxedL->HasTypeFlag(checker::TypeFlag::CONSTANT) && unboxedL->IsIntType()) ||
        (unboxedR->HasTypeFlag(checker::TypeFlag::CONSTANT) && unboxedR->IsIntType())) {
        int value = unboxedL->IsIntType() ? unboxedL->AsIntType()->GetValue() : unboxedR->AsIntType()->GetValue();
        checker::Type *otherType = !unboxedL->IsIntType() ? unboxedL : unboxedR;

        switch (checker::ETSChecker::ETSType(otherType)) {
            case checker::TypeFlag::BYTE:
            case checker::TypeFlag::CHAR: {
                if (value <= static_cast<int>(std::numeric_limits<char>::max()) &&
                    value >= static_cast<int>(std::numeric_limits<char>::min())) {
                    return checker->GetNonConstantTypeFromPrimitiveType(otherType);
                }
                break;
            }
            case checker::TypeFlag::SHORT: {
                if (value <= std::numeric_limits<int16_t>::max() && value >= std::numeric_limits<int16_t>::min()) {
                    return checker->GlobalShortType();
                }
                break;
            }
            default: {
                return otherType;
            }
        }
        return checker->GlobalIntType();
    }

    if (unboxedL->IsDoubleType() || unboxedR->IsDoubleType()) {
        return checker->GlobalDoubleType();
    }
    if (unboxedL->IsFloatType() || unboxedR->IsFloatType()) {
        return checker->GlobalFloatType();
    }
    if (unboxedL->IsLongType() || unboxedR->IsLongType()) {
        return checker->GlobalLongType();
    }
    if (unboxedL->IsIntType() || unboxedR->IsIntType() || unboxedL->IsCharType() || unboxedR->IsCharType()) {
        return checker->GlobalIntType();
    }
    if (unboxedL->IsShortType() || unboxedR->IsShortType()) {
        return checker->GlobalShortType();
    }
    if (unboxedL->IsByteType() || unboxedR->IsByteType()) {
        return checker->GlobalByteType();
    }

    UNREACHABLE();
}

Type *ETSChecker::ApplyUnaryOperatorPromotion(Type *type, const bool createConst, const bool doPromotion,
                                              const bool isCondExpr)
{
    Type *unboxedType = isCondExpr ? ETSBuiltinTypeAsConditionalType(type) : ETSBuiltinTypeAsPrimitiveType(type);

    if (unboxedType == nullptr) {
        return nullptr;
    }
    if (doPromotion) {
        switch (ETSType(unboxedType)) {
            case TypeFlag::BYTE:
            case TypeFlag::SHORT:
            case TypeFlag::CHAR: {
                if (!createConst) {
                    return GlobalIntType();
                }

                return CreateIntTypeFromType(unboxedType);
            }
            default: {
                break;
            }
        }
    }
    return unboxedType;
}

bool ETSChecker::IsNullLikeOrVoidExpression(const ir::Expression *expr) const
{
    return expr->TsType()->IsETSNullLike() || expr->TsType()->IsETSVoidType();
}

std::tuple<bool, bool> ETSChecker::IsResolvedAndValue(const ir::Expression *expr, Type *type) const
{
    auto [isResolve, isValue] =
        IsNullLikeOrVoidExpression(expr) ? std::make_tuple(true, false) : type->ResolveConditionExpr();

    const Type *tsType = expr->TsType();
    if (!tsType->ContainsUndefined() && !tsType->ContainsNull() && !tsType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        isResolve = true;
        isValue = true;
    }
    return std::make_tuple(isResolve, isValue);
}

Type *ETSChecker::HandleBooleanLogicalOperatorsExtended(Type *leftType, Type *rightType, ir::BinaryExpression *expr)
{
    ASSERT(leftType->IsConditionalExprType() && rightType->IsConditionalExprType());

    auto [resolveLeft, leftValue] = IsResolvedAndValue(expr->Left(), leftType);
    auto [resolveRight, rightValue] = IsResolvedAndValue(expr->Right(), rightType);

    if (!resolveLeft && !resolveRight) {
        if (IsTypeIdenticalTo(leftType, rightType)) {
            return leftType;
        }
        ArenaVector<checker::Type *> types(Allocator()->Adapter());
        types.push_back(leftType);
        types.push_back(rightType);
        return CreateETSUnionType(std::move(types));
    }

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            if (leftValue) {
                expr->SetResult(expr->Left());
                return leftType->IsETSBooleanType() ? CreateETSBooleanType(true) : leftType;
            }

            expr->SetResult(expr->Right());
            return rightType->IsETSBooleanType() && resolveRight ? CreateETSBooleanType(rightValue) : rightType;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            if (leftValue) {
                expr->SetResult(expr->Right());
                return rightType->IsETSBooleanType() && resolveRight ? CreateETSBooleanType(rightValue) : rightType;
            }

            expr->SetResult(expr->Left());
            return leftType->IsETSBooleanType() ? CreateETSBooleanType(false) : leftType;
        }
        default: {
            break;
        }
    }

    UNREACHABLE();
}

Type *ETSChecker::HandleBooleanLogicalOperators(Type *leftType, Type *rightType, lexer::TokenType tokenType)
{
    using UType = typename ETSBooleanType::UType;
    ASSERT(leftType->IsETSBooleanType() && rightType->IsETSBooleanType());

    if (!leftType->HasTypeFlag(checker::TypeFlag::CONSTANT) || !rightType->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return GlobalETSBooleanType();
    }

    UType leftValue = leftType->AsETSBooleanType()->GetValue();
    UType rightValue = rightType->AsETSBooleanType()->GetValue();

    switch (tokenType) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            return CreateETSBooleanType(leftValue ^ rightValue);
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            return CreateETSBooleanType((static_cast<uint8_t>(leftValue) & static_cast<uint8_t>(rightValue)) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            return CreateETSBooleanType((static_cast<uint8_t>(leftValue) | static_cast<uint8_t>(rightValue)) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            return CreateETSBooleanType(leftValue || rightValue);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            return CreateETSBooleanType(leftValue && rightValue);
        }
        default: {
            break;
        }
    }

    UNREACHABLE();
    return nullptr;
}

void ETSChecker::ResolveReturnStatement(checker::Type *funcReturnType, checker::Type *argumentType,
                                        ir::ScriptFunction *containingFunc, ir::ReturnStatement *st)
{
    if (funcReturnType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) ||
        argumentType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        // function return type should be of reference (object) type
        Relation()->SetFlags(checker::TypeRelationFlag::NONE);

        if (!argumentType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            argumentType = PrimitiveTypeAsETSBuiltinType(argumentType);
            if (argumentType == nullptr) {
                ThrowTypeError("Invalid return statement expression", st->Argument()->Start());
            }
            st->Argument()->AddBoxingUnboxingFlags(GetBoxingFlag(argumentType));
        }

        if (!funcReturnType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            funcReturnType = PrimitiveTypeAsETSBuiltinType(funcReturnType);
            if (funcReturnType == nullptr) {
                ThrowTypeError("Invalid return function expression", st->Start());
            }
        }

        funcReturnType = FindLeastUpperBound(funcReturnType, argumentType);
        containingFunc->Signature()->SetReturnType(funcReturnType);
        containingFunc->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
    } else if (funcReturnType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN) &&
               argumentType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN)) {
        // function return type is of primitive type (including enums):
        Relation()->SetFlags(checker::TypeRelationFlag::DIRECT_RETURN |
                             checker::TypeRelationFlag::IN_ASSIGNMENT_CONTEXT |
                             checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
        if (Relation()->IsAssignableTo(funcReturnType, argumentType)) {
            funcReturnType = argumentType;
            containingFunc->Signature()->SetReturnType(funcReturnType);
            containingFunc->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
        } else if (!Relation()->IsAssignableTo(argumentType, funcReturnType)) {
            ThrowTypeError(
                "Return statement type is not compatible with previous method's return statement "
                "type(s).",
                st->Argument()->Start());
        }
    } else {
        ThrowTypeError("Invalid return statement type(s).", st->Start());
    }
}

checker::Type *ETSChecker::CheckArrayElements(ir::Identifier *ident, ir::ArrayExpression *init)
{
    ArenaVector<ir::Expression *> elements = init->AsArrayExpression()->Elements();
    checker::Type *annotationType = nullptr;
    if (elements.empty()) {
        annotationType = Allocator()->New<ETSArrayType>(GlobalETSObjectType());
    } else {
        auto type = elements[0]->Check(this);
        auto const primType = ETSBuiltinTypeAsPrimitiveType(type);
        for (auto element : elements) {
            auto const eType = element->Check(this);
            auto const primEType = ETSBuiltinTypeAsPrimitiveType(eType);
            if (primEType != nullptr && primType != nullptr && primEType->HasTypeFlag(TypeFlag::ETS_NUMERIC) &&
                primType->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
                type = GlobalDoubleType();
            } else if (IsTypeIdenticalTo(type, eType)) {
                continue;
            } else {
                // NOTE: Create union type when implemented here
                ThrowTypeError({"Union type is not implemented yet!"}, ident->Start());
            }
        }
        annotationType = Allocator()->New<ETSArrayType>(type);
    }
    return annotationType;
}

checker::Type *ETSChecker::CheckVariableDeclaration(ir::Identifier *ident, ir::TypeNode *typeAnnotation,
                                                    ir::Expression *init, ir::ModifierFlags flags)
{
    const util::StringView &varName = ident->Name();
    ASSERT(ident->Variable());
    varbinder::Variable *const bindingVar = ident->Variable();
    checker::Type *annotationType = nullptr;

    const bool isConst = (flags & ir::ModifierFlags::CONST) != 0;

    if (typeAnnotation != nullptr) {
        annotationType = GetTypeFromTypeAnnotation(typeAnnotation);
        bindingVar->SetTsType(annotationType);
    }

    if (init == nullptr) {
        return annotationType;
    }

    if (typeAnnotation == nullptr) {
        if (init->IsArrayExpression()) {
            annotationType = CheckArrayElements(ident, init->AsArrayExpression());
            bindingVar->SetTsType(annotationType);
        }

        if (init->IsObjectExpression()) {
            ThrowTypeError(
                {"Cannot infer type for ", ident->Name(), " because class composite needs an explicit target type"},
                ident->Start());
        }
    }

    if (init->IsMemberExpression() && init->AsMemberExpression()->Object()->IsObjectExpression()) {
        ThrowTypeError({"Class composite must be constructed separately before referring their members."},
                       ident->Start());
    }

    if ((init->IsMemberExpression()) && (annotationType != nullptr)) {
        SetArrayPreferredTypeForNestedMemberExpressions(init->AsMemberExpression(), annotationType);
    }

    if (init->IsArrayExpression() && annotationType->IsETSArrayType()) {
        if (annotationType->IsETSTupleType()) {
            ValidateTupleMinElementSize(init->AsArrayExpression(), annotationType->AsETSTupleType());
        }

        init->AsArrayExpression()->SetPreferredType(annotationType);
    }

    if (init->IsObjectExpression()) {
        init->AsObjectExpression()->SetPreferredType(annotationType);
    }

    if (typeAnnotation != nullptr && typeAnnotation->IsETSFunctionType() && init->IsArrowFunctionExpression()) {
        auto *const arrowFuncExpr = init->AsArrowFunctionExpression();
        ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
        if (lambda->Params().size() == typeAnnotation->AsETSFunctionType()->Params().size() &&
            NeedTypeInference(lambda)) {
            InferTypesForLambda(lambda, typeAnnotation->AsETSFunctionType());
        }
    }
    checker::Type *initType = init->Check(this);

    if (initType == nullptr) {
        ThrowTypeError("Cannot get the expression type", init->Start());
    }

    if (typeAnnotation == nullptr &&
        (init->IsArrowFunctionExpression() ||
         (init->IsTSAsExpression() && init->AsTSAsExpression()->Expr()->IsArrowFunctionExpression()))) {
        if (init->IsArrowFunctionExpression()) {
            typeAnnotation = init->AsArrowFunctionExpression()->CreateTypeAnnotation(this);
        } else {
            typeAnnotation = init->AsTSAsExpression()->TypeAnnotation();
        }
        ident->SetTsTypeAnnotation(typeAnnotation);
        typeAnnotation->SetParent(ident);
        annotationType = GetTypeFromTypeAnnotation(typeAnnotation);
        bindingVar->SetTsType(annotationType);
    }

    if (annotationType != nullptr) {
        AssignmentContext(Relation(), init, initType, annotationType, init->Start(),
                          {"Initializers type is not assignable to the target type"});
        if (isConst && initType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) &&
            annotationType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
            bindingVar->SetTsType(init->TsType());
        }
        return bindingVar->TsType();
    }

    if (initType->IsETSNullLike()) {
        TypeFlag nullishFlags {0};

        if (initType->IsETSNullType()) {
            nullishFlags = TypeFlag::NULL_TYPE;
        }
        if (initType->IsETSUndefinedType()) {
            nullishFlags = TypeFlag::UNDEFINED;
        }
        initType = CreateNullishType(GetGlobalTypesHolder()->GlobalETSObjectType(), nullishFlags, Allocator(),
                                     Relation(), GetGlobalTypesHolder());
    }

    if (initType->IsETSObjectType() && initType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::ENUM) &&
        !init->IsMemberExpression()) {
        ThrowTypeError({"Cannot assign type '", initType->AsETSObjectType()->Name(), "' for variable ", varName, "."},
                       init->Start());
    }

    if (initType->IsNullish() || isConst) {
        bindingVar->SetTsType(initType);
    } else {
        bindingVar->SetTsType(GetNonConstantTypeFromPrimitiveType(initType));
    }

    return bindingVar->TsType();
}

void ETSChecker::SetArrayPreferredTypeForNestedMemberExpressions(ir::MemberExpression *expr, Type *annotationType)
{
    if ((expr == nullptr) || (annotationType == nullptr)) {
        return;
    }

    if (expr->Kind() != ir::MemberExpressionKind::ELEMENT_ACCESS) {
        return;
    }

    // Expand all member expressions
    Type *elementType = annotationType;
    ir::Expression *object = expr->Object();
    while ((object != nullptr) && (object->IsMemberExpression())) {
        ir::MemberExpression *memberExpr = object->AsMemberExpression();
        if (memberExpr->Kind() != ir::MemberExpressionKind::ELEMENT_ACCESS) {
            return;
        }

        object = memberExpr->Object();
        elementType = CreateETSArrayType(elementType);
    }

    // Set explicit target type for array
    if ((object != nullptr) && (object->IsArrayExpression())) {
        ir::ArrayExpression *array = object->AsArrayExpression();
        array->SetPreferredType(CreateETSArrayType(elementType));
    }
}

Type *ETSChecker::GetTypeFromTypeAliasReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *const aliasTypeNode = var->Declaration()->Node()->AsTSTypeAliasDeclaration();
    TypeStackElement tse(this, aliasTypeNode, "Circular type alias reference", aliasTypeNode->Start());
    aliasTypeNode->Check(this);
    auto *const aliasedType = GetTypeFromTypeAnnotation(aliasTypeNode->TypeAnnotation());

    var->SetTsType(aliasedType);
    return aliasedType;
}

Type *ETSChecker::GetTypeFromInterfaceReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *interfaceType = BuildInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    var->SetTsType(interfaceType);
    return interfaceType;
}

Type *ETSChecker::GetTypeFromClassReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *classType = BuildClassProperties(var->Declaration()->Node()->AsClassDefinition());
    var->SetTsType(classType);
    return classType;
}

void ETSChecker::ValidateGenericTypeAliasForClonedNode(ir::TSTypeAliasDeclaration *const typeAliasNode,
                                                       const ir::TSTypeParameterInstantiation *const exactTypeParams)
{
    auto *const clonedNode = typeAliasNode->TypeAnnotation()->Clone(Allocator(), typeAliasNode);

    // Basic check, we really don't want to change the original type nodes, more precise checking should be made
    ASSERT(clonedNode != typeAliasNode->TypeAnnotation());

    // Currently only reference types are checked. This should be extended for other types in a follow up patch, but for
    // complete usability, if the type isn't a simple reference type, then doN't check type alias declaration at all.
    bool checkTypealias = true;

    // Only transforming a temporary cloned node, so no modification is made in the AST
    clonedNode->TransformChildrenRecursively(
        [&checkTypealias, &exactTypeParams, typeAliasNode](ir::AstNode *const node) -> ir::AstNode * {
            if (!node->IsETSTypeReference()) {
                return node;
            }

            const auto *const nodeIdent = node->AsETSTypeReference()->Part()->Name()->AsIdentifier();

            size_t typeParamIdx = 0;
            for (const auto *const typeParam : typeAliasNode->TypeParams()->Params()) {
                if (typeParam->Name()->AsIdentifier()->Variable() == nodeIdent->Variable()) {
                    break;
                }
                typeParamIdx++;
            }

            if (typeParamIdx == typeAliasNode->TypeParams()->Params().size()) {
                return node;
            }

            auto *const typeParamType = exactTypeParams->Params().at(typeParamIdx);

            if (!typeParamType->IsETSTypeReference()) {
                checkTypealias = false;
                return node;
            }

            return typeParamType;
        });

    if (checkTypealias) {
        clonedNode->Check(this);
    }
}

Type *ETSChecker::HandleTypeAlias(ir::Expression *const name, const ir::TSTypeParameterInstantiation *const typeParams)
{
    ASSERT(name->IsIdentifier() && name->AsIdentifier()->Variable() &&
           name->AsIdentifier()->Variable()->Declaration()->IsTypeAliasDecl());

    auto *const typeAliasNode =
        name->AsIdentifier()->Variable()->Declaration()->AsTypeAliasDecl()->Node()->AsTSTypeAliasDeclaration();

    // NOTE (mmartin): modify for default params
    if ((typeParams == nullptr) != (typeAliasNode->TypeParams() == nullptr)) {
        if (typeParams == nullptr) {
            ThrowTypeError("Type alias declaration is generic, but no type parameters were provided", name->Start());
        }

        ThrowTypeError("Type alias declaration is not generic, but type parameters were provided", typeParams->Start());
    }

    if (typeParams == nullptr) {
        return GetReferencedTypeBase(name);
    }

    for (auto *const origTypeParam : typeParams->Params()) {
        origTypeParam->Check(this);
    }

    Type *const aliasType = GetReferencedTypeBase(name);
    auto *const aliasSub = NewSubstitution();

    if (typeAliasNode->TypeParams()->Params().size() != typeParams->Params().size()) {
        ThrowTypeError("Wrong number of type parameters for generic type alias", typeParams->Start());
    }

    for (std::size_t idx = 0; idx < typeAliasNode->TypeParams()->Params().size(); ++idx) {
        auto *typeAliasType = typeAliasNode->TypeParams()->Params().at(idx)->Name()->Variable()->TsType();
        if (typeAliasType->IsETSTypeParameter()) {
            aliasSub->insert({typeAliasType->AsETSTypeParameter(), typeParams->Params().at(idx)->TsType()});
        }
    }

    ValidateGenericTypeAliasForClonedNode(typeAliasNode->AsTSTypeAliasDeclaration(), typeParams);

    return aliasType->Substitute(Relation(), aliasSub);
}

Type *ETSChecker::GetTypeFromEnumReference([[maybe_unused]] varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto const *const enumDecl = var->Declaration()->Node()->AsTSEnumDeclaration();
    if (auto *const itemInit = enumDecl->Members().front()->AsTSEnumMember()->Init(); itemInit->IsNumberLiteral()) {
        return CreateETSEnumType(enumDecl);
    } else if (itemInit->IsStringLiteral()) {  // NOLINT(readability-else-after-return)
        return CreateETSStringEnumType(enumDecl);
    } else {  // NOLINT(readability-else-after-return)
        ThrowTypeError("Invalid enumeration value type.", enumDecl->Start());
    }
}

Type *ETSChecker::GetTypeFromTypeParameterReference(varbinder::LocalVariable *var, const lexer::SourcePosition &pos)
{
    ASSERT(var->Declaration()->Node()->IsTSTypeParameter());
    if ((var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsClassDefinition() ||
         var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsTSInterfaceDeclaration()) &&
        HasStatus(CheckerStatus::IN_STATIC_CONTEXT)) {
        ThrowTypeError({"Cannot make a static reference to the non-static type ", var->Name()}, pos);
    }

    return var->TsType();
}

std::vector<util::StringView> ETSChecker::GetNameForSynteticObjectType(const util::StringView &source)
{
    const std::string str = source.Mutf8();
    std::istringstream ss {str};
    const char delimiter = '.';
    std::string token;

    std::vector<util::StringView> syntheticName {};

    while (std::getline(ss, token, delimiter)) {
        if (!token.empty()) {
            util::UString sV(token, Allocator());
            syntheticName.emplace_back(sV.View());
        }
    }

    return syntheticName;
}

void ETSChecker::SetPropertiesForModuleObject(checker::ETSObjectType *moduleObjType, const util::StringView &importPath)
{
    auto *etsBinder = static_cast<varbinder::ETSBinder *>(VarBinder());

    auto extRecords = etsBinder->GetGlobalRecordTable()->Program()->ExternalSources();
    auto res = [etsBinder, extRecords, importPath]() {
        auto r = extRecords.find(importPath);
        return r != extRecords.end() ? r : extRecords.find(etsBinder->GetResolvedImportPath(importPath));
    }();

    // Check imported properties before assigning them to module object
    res->second.front()->Ast()->Check(this);

    for (auto [_, var] : res->second.front()->GlobalClassScope()->StaticFieldScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            moduleObjType->AddProperty<checker::PropertyType::STATIC_FIELD>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->StaticMethodScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            moduleObjType->AddProperty<checker::PropertyType::STATIC_METHOD>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->InstanceDeclScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            moduleObjType->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->TypeAliasScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            moduleObjType->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }
}

void ETSChecker::SetrModuleObjectTsType(ir::Identifier *local, checker::ETSObjectType *moduleObjType)
{
    auto *etsBinder = static_cast<varbinder::ETSBinder *>(VarBinder());

    for (auto [bindingName, var] : etsBinder->TopScope()->Bindings()) {
        if (bindingName.Is(local->Name().Mutf8())) {
            var->SetTsType(moduleObjType);
        }
    }
}

Type *ETSChecker::GetReferencedTypeFromBase([[maybe_unused]] Type *baseType, [[maybe_unused]] ir::Expression *name)
{
    return nullptr;
}

Type *ETSChecker::GetReferencedTypeBase(ir::Expression *name)
{
    if (name->IsTSQualifiedName()) {
        auto *qualified = name->AsTSQualifiedName();
        return qualified->Check(this);
    }

    ASSERT(name->IsIdentifier() && name->AsIdentifier()->Variable() != nullptr);

    // NOTE: kbaladurin. forbid usage imported entities as types without declarations
    auto *importData = VarBinder()->AsETSBinder()->DynamicImportDataForVar(name->AsIdentifier()->Variable());
    if (importData != nullptr && importData->import->IsPureDynamic()) {
        return GlobalBuiltinDynamicType(importData->import->Language());
    }

    auto *refVar = name->AsIdentifier()->Variable()->AsLocalVariable();

    switch (refVar->Declaration()->Node()->Type()) {
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return GetTypeFromInterfaceReference(refVar);
        }
        case ir::AstNodeType::CLASS_DECLARATION:
        case ir::AstNodeType::STRUCT_DECLARATION:
        case ir::AstNodeType::CLASS_DEFINITION: {
            return GetTypeFromClassReference(refVar);
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            return GetTypeFromEnumReference(refVar);
        }
        case ir::AstNodeType::TS_TYPE_PARAMETER: {
            return GetTypeFromTypeParameterReference(refVar, name->Start());
        }
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION: {
            return GetTypeFromTypeAliasReference(refVar);
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSChecker::ConcatConstantString(util::UString &target, Type *type)
{
    switch (ETSType(type)) {
        case TypeFlag::ETS_OBJECT: {
            ASSERT(type->IsETSStringType());
            target.Append(type->AsETSStringType()->GetValue());
            break;
        }
        case TypeFlag::ETS_BOOLEAN: {
            ETSBooleanType::UType value = type->AsETSBooleanType()->GetValue();
            target.Append(value ? "true" : "false");
            break;
        }
        case TypeFlag::BYTE: {
            ByteType::UType value = type->AsByteType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::CHAR: {
            CharType::UType value = type->AsCharType()->GetValue();
            std::string s(1, value);
            target.Append(s);
            break;
        }
        case TypeFlag::SHORT: {
            ShortType::UType value = type->AsShortType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::INT: {
            IntType::UType value = type->AsIntType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::LONG: {
            LongType::UType value = type->AsLongType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::FLOAT: {
            FloatType::UType value = type->AsFloatType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::DOUBLE: {
            DoubleType::UType value = type->AsDoubleType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

Type *ETSChecker::HandleStringConcatenation(Type *leftType, Type *rightType)
{
    ASSERT(leftType->IsETSStringType() || rightType->IsETSStringType());

    if (!leftType->HasTypeFlag(checker::TypeFlag::CONSTANT) || !rightType->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return GlobalETSStringLiteralType();
    }

    util::UString concatenated(Allocator());
    ConcatConstantString(concatenated, leftType);
    ConcatConstantString(concatenated, rightType);

    return CreateETSStringLiteralType(concatenated.View());
}

ETSFunctionType *ETSChecker::FindFunctionInVectorGivenByName(util::StringView name,
                                                             ArenaVector<ETSFunctionType *> &list)
{
    for (auto *it : list) {
        if (it->Name() == name) {
            return it;
        }
    }

    return nullptr;
}

bool ETSChecker::IsFunctionContainsSignature(ETSFunctionType *funcType, Signature *signature)
{
    for (auto *it : funcType->CallSignatures()) {
        Relation()->IsIdenticalTo(it, signature);
        if (Relation()->IsTrue()) {
            return true;
        }
    }

    return false;
}

void ETSChecker::CheckFunctionContainsClashingSignature(const ETSFunctionType *funcType, Signature *signature)
{
    for (auto *it : funcType->CallSignatures()) {
        SavedTypeRelationFlagsContext strfCtx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);
        Relation()->IsIdenticalTo(it, signature);
        if (Relation()->IsTrue() && it->Function()->Id()->Name() == signature->Function()->Id()->Name()) {
            std::stringstream ss;
            it->ToString(ss, nullptr, true);
            auto sigStr1 = ss.str();
            ss.str(std::string {});  // Clear buffer
            signature->ToString(ss, nullptr, true);
            auto sigStr2 = ss.str();
            ThrowTypeError({"Function '", it->Function()->Id()->Name(), sigStr1.c_str(),
                            "' is redeclared with different signature '", signature->Function()->Id()->Name(),
                            sigStr2.c_str(), "'"},
                           signature->Function()->ReturnTypeAnnotation()->Start());
        }
    }
}

void ETSChecker::MergeSignatures(ETSFunctionType *target, ETSFunctionType *source)
{
    for (auto *s : source->CallSignatures()) {
        if (IsFunctionContainsSignature(target, s)) {
            continue;
        }

        CheckFunctionContainsClashingSignature(target, s);
        target->AddCallSignature(s);
    }
}

void ETSChecker::MergeComputedAbstracts(ArenaVector<ETSFunctionType *> &merged, ArenaVector<ETSFunctionType *> &current)
{
    for (auto *curr : current) {
        auto name = curr->Name();
        auto *found = FindFunctionInVectorGivenByName(name, merged);
        if (found != nullptr) {
            MergeSignatures(found, curr);
            continue;
        }

        merged.push_back(curr);
    }
}

ir::AstNode *ETSChecker::FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type, const ir::AstNode *endNode)
{
    auto *iter = node->Parent();

    while (iter != endNode) {
        if (iter->Type() == type) {
            return iter;
        }

        iter = iter->Parent();
    }

    return nullptr;
}

util::StringView ETSChecker::GetContainingObjectNameFromSignature(Signature *signature)
{
    ASSERT(signature->Function());
    auto *iter = signature->Function()->Parent();

    while (iter != nullptr) {
        if (iter->IsClassDefinition()) {
            return iter->AsClassDefinition()->Ident()->Name();
        }

        if (iter->IsTSInterfaceDeclaration()) {
            return iter->AsTSInterfaceDeclaration()->Id()->Name();
        }

        iter = iter->Parent();
    }

    UNREACHABLE();
    return {""};
}

bool ETSChecker::IsTypeBuiltinType(const Type *type) const
{
    if (!type->IsETSObjectType()) {
        return false;
    }

    switch (type->AsETSObjectType()->BuiltInKind()) {
        case ETSObjectFlags::BUILTIN_BOOLEAN:
        case ETSObjectFlags::BUILTIN_BYTE:
        case ETSObjectFlags::BUILTIN_SHORT:
        case ETSObjectFlags::BUILTIN_CHAR:
        case ETSObjectFlags::BUILTIN_INT:
        case ETSObjectFlags::BUILTIN_LONG:
        case ETSObjectFlags::BUILTIN_FLOAT:
        case ETSObjectFlags::BUILTIN_DOUBLE: {
            return true;
        }
        default:
            return false;
    }
}

bool ETSChecker::IsReferenceType(const Type *type)
{
    return type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) || type->IsETSNullLike() ||
           type->IsETSStringType() || type->IsETSTypeParameter() || type->IsETSUnionType();
}

const ir::AstNode *ETSChecker::FindJumpTarget(ir::AstNodeType nodeType, const ir::AstNode *node,
                                              const ir::Identifier *target)
{
    const auto *iter = node->Parent();

    while (iter != nullptr) {
        switch (iter->Type()) {
            case ir::AstNodeType::LABELLED_STATEMENT: {
                if (const auto *labelled = iter->AsLabelledStatement(); labelled->Ident()->Name() == target->Name()) {
                    return nodeType == ir::AstNodeType::CONTINUE_STATEMENT ? labelled->GetReferencedStatement()
                                                                           : labelled;
                }
                break;
            }
            case ir::AstNodeType::DO_WHILE_STATEMENT:
            case ir::AstNodeType::WHILE_STATEMENT:
            case ir::AstNodeType::FOR_UPDATE_STATEMENT:
            case ir::AstNodeType::FOR_OF_STATEMENT:
            case ir::AstNodeType::SWITCH_STATEMENT: {
                if (target == nullptr) {
                    return iter;
                }
                break;
            }
            default: {
                break;
            }
        }

        iter = iter->Parent();
    }

    UNREACHABLE();
    return nullptr;
}

varbinder::VariableFlags ETSChecker::GetAccessFlagFromNode(const ir::AstNode *node)
{
    if (node->IsPrivate()) {
        return varbinder::VariableFlags::PRIVATE;
    }

    if (node->IsProtected()) {
        return varbinder::VariableFlags::PROTECTED;
    }

    return varbinder::VariableFlags::PUBLIC;
}

void ETSChecker::CheckSwitchDiscriminant(ir::Expression *discriminant)
{
    ASSERT(discriminant->TsType());

    auto discriminantType = discriminant->TsType();
    if (discriminantType->HasTypeFlag(TypeFlag::VALID_SWITCH_TYPE)) {
        return;
    }

    if (discriminantType->IsETSObjectType() &&
        discriminantType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::VALID_SWITCH_TYPE)) {
        if (discriminantType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
            discriminant->SetBoxingUnboxingFlags(GetUnboxingFlag(ETSBuiltinTypeAsPrimitiveType(discriminantType)));
        }
        return;
    }

    ThrowTypeError({"Incompatible types. Found: ", discriminantType,
                    ", required: char , byte , short , int, long , Char , Byte , Short , Int, Long , String "
                    "or an enum type"},
                   discriminant->Start());
}

Type *ETSChecker::ETSBuiltinTypeAsPrimitiveType(Type *objectType)
{
    if (objectType == nullptr) {
        return nullptr;
    }

    if (objectType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) || objectType->HasTypeFlag(TypeFlag::ETS_ENUM) ||
        objectType->HasTypeFlag(TypeFlag::ETS_STRING_ENUM)) {
        return objectType;
    }

    if (!objectType->IsETSObjectType() ||
        !objectType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
        return nullptr;
    }

    auto savedResult = Relation()->IsTrue();
    Relation()->Result(false);

    UnboxingConverter converter = UnboxingConverter(AsETSChecker(), Relation(), objectType, objectType);
    Relation()->Result(savedResult);
    return converter.Result();
}

Type *ETSChecker::ETSBuiltinTypeAsConditionalType(Type *objectType)
{
    if ((objectType == nullptr) || !objectType->IsConditionalExprType()) {
        return nullptr;
    }

    return objectType;
}

Type *ETSChecker::PrimitiveTypeAsETSBuiltinType(Type *objectType)
{
    if (objectType == nullptr) {
        return nullptr;
    }

    if (objectType->IsETSObjectType() && objectType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
        return objectType;
    }

    if (!objectType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) || objectType->IsETSVoidType()) {
        return nullptr;
    }

    auto savedResult = Relation()->IsTrue();
    Relation()->Result(false);

    if (Checker::GetGlobalTypesHolder()->GlobalIntegerBuiltinType() == nullptr) {
        InitializeBuiltin(VarBinder()->TopScope()->Bindings().find("Int")->second, "Int");
    }

    BoxingConverter converter = BoxingConverter(AsETSChecker(), Relation(), objectType,
                                                Checker::GetGlobalTypesHolder()->GlobalIntegerBuiltinType());
    Relation()->Result(savedResult);
    return converter.Result();
}

void ETSChecker::AddBoxingUnboxingFlagsToNode(ir::AstNode *node, Type *boxingUnboxingType)
{
    if (boxingUnboxingType->IsETSObjectType()) {
        node->AddBoxingUnboxingFlags(GetBoxingFlag(boxingUnboxingType));
    } else {
        node->AddBoxingUnboxingFlags(GetUnboxingFlag(boxingUnboxingType));
    }
}

ir::BoxingUnboxingFlags ETSChecker::GetBoxingFlag(Type *const boxingType)
{
    auto typeKind = TypeKind(ETSBuiltinTypeAsPrimitiveType(boxingType));
    switch (typeKind) {
        case TypeFlag::ETS_BOOLEAN: {
            return ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN;
        }
        case TypeFlag::BYTE: {
            return ir::BoxingUnboxingFlags::BOX_TO_BYTE;
        }
        case TypeFlag::CHAR: {
            return ir::BoxingUnboxingFlags::BOX_TO_CHAR;
        }
        case TypeFlag::SHORT: {
            return ir::BoxingUnboxingFlags::BOX_TO_SHORT;
        }
        case TypeFlag::INT: {
            return ir::BoxingUnboxingFlags::BOX_TO_INT;
        }
        case TypeFlag::LONG: {
            return ir::BoxingUnboxingFlags::BOX_TO_LONG;
        }
        case TypeFlag::FLOAT: {
            return ir::BoxingUnboxingFlags::BOX_TO_FLOAT;
        }
        case TypeFlag::DOUBLE: {
            return ir::BoxingUnboxingFlags::BOX_TO_DOUBLE;
        }
        default:
            UNREACHABLE();
    }
}

ir::BoxingUnboxingFlags ETSChecker::GetUnboxingFlag(Type const *const unboxingType) const
{
    auto typeKind = TypeKind(unboxingType);
    switch (typeKind) {
        case TypeFlag::ETS_BOOLEAN: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_BOOLEAN;
        }
        case TypeFlag::BYTE: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_BYTE;
        }
        case TypeFlag::CHAR: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_CHAR;
        }
        case TypeFlag::SHORT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_SHORT;
        }
        case TypeFlag::INT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_INT;
        }
        case TypeFlag::LONG: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_LONG;
        }
        case TypeFlag::FLOAT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_FLOAT;
        }
        case TypeFlag::DOUBLE: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_DOUBLE;
        }
        default:
            UNREACHABLE();
    }
}

Type *ETSChecker::MaybeBoxedType(const varbinder::Variable *var, ArenaAllocator *allocator) const
{
    auto *varType = var->TsType();
    if (var->HasFlag(varbinder::VariableFlags::BOXED)) {
        switch (TypeKind(varType)) {
            case TypeFlag::ETS_BOOLEAN:
                return GetGlobalTypesHolder()->GlobalBooleanBoxBuiltinType();
            case TypeFlag::BYTE:
                return GetGlobalTypesHolder()->GlobalByteBoxBuiltinType();
            case TypeFlag::CHAR:
                return GetGlobalTypesHolder()->GlobalCharBoxBuiltinType();
            case TypeFlag::SHORT:
                return GetGlobalTypesHolder()->GlobalShortBoxBuiltinType();
            case TypeFlag::INT:
                return GetGlobalTypesHolder()->GlobalIntBoxBuiltinType();
            case TypeFlag::LONG:
                return GetGlobalTypesHolder()->GlobalLongBoxBuiltinType();
            case TypeFlag::FLOAT:
                return GetGlobalTypesHolder()->GlobalFloatBoxBuiltinType();
            case TypeFlag::DOUBLE:
                return GetGlobalTypesHolder()->GlobalDoubleBoxBuiltinType();
            default: {
                Type *box = GetGlobalTypesHolder()->GlobalBoxBuiltinType()->Instantiate(allocator, Relation(),
                                                                                        GetGlobalTypesHolder());
                box->AddTypeFlag(checker::TypeFlag::GENERIC);
                box->AsETSObjectType()->TypeArguments().emplace_back(varType);
                return box;
            }
        }
    }
    return varType;
}

void ETSChecker::CheckForSameSwitchCases(ArenaVector<ir::SwitchCaseStatement *> *cases)
{
    //  Just to avoid extra nesting level
    auto const checkEnumType = [this](ir::Expression const *const caseTest, ETSEnumType const *const type) -> void {
        if (caseTest->TsType()->AsETSEnumType()->IsSameEnumLiteralType(type)) {
            ThrowTypeError("Case duplicate", caseTest->Start());
        }
    };

    for (size_t caseNum = 0; caseNum < cases->size(); caseNum++) {
        for (size_t compareCase = caseNum + 1; compareCase < cases->size(); compareCase++) {
            auto *caseTest = cases->at(caseNum)->Test();
            auto *compareCaseTest = cases->at(compareCase)->Test();

            if (caseTest == nullptr || compareCaseTest == nullptr) {
                continue;
            }

            if (caseTest->TsType()->IsETSEnumType()) {
                checkEnumType(caseTest, compareCaseTest->TsType()->AsETSEnumType());
                continue;
            }

            if (caseTest->IsIdentifier() || caseTest->IsMemberExpression()) {
                CheckIdentifierSwitchCase(caseTest, compareCaseTest, cases->at(caseNum)->Start());
                continue;
            }

            if (compareCaseTest->IsIdentifier() || compareCaseTest->IsMemberExpression()) {
                CheckIdentifierSwitchCase(compareCaseTest, caseTest, cases->at(compareCase)->Start());
                continue;
            }

            if (GetStringFromLiteral(caseTest) != GetStringFromLiteral(compareCaseTest)) {
                continue;
            }

            ThrowTypeError("Case duplicate", cases->at(compareCase)->Start());
        }
    }
}

std::string ETSChecker::GetStringFromIdentifierValue(checker::Type *caseType) const
{
    const auto identifierTypeKind = ETSChecker::TypeKind(caseType);
    switch (identifierTypeKind) {
        case TypeFlag::BYTE: {
            return std::to_string(caseType->AsByteType()->GetValue());
        }
        case TypeFlag::SHORT: {
            return std::to_string(caseType->AsShortType()->GetValue());
        }
        case TypeFlag::CHAR: {
            return std::to_string(caseType->AsCharType()->GetValue());
        }
        case TypeFlag::INT: {
            return std::to_string(caseType->AsIntType()->GetValue());
        }
        case TypeFlag::LONG: {
            return std::to_string(caseType->AsLongType()->GetValue());
        }
        case TypeFlag::ETS_OBJECT: {
            VarBinder()->ThrowError(caseType->AsETSObjectType()->Variable()->Declaration()->Node()->Start(),
                                    "not implemented");
        }
        default: {
            UNREACHABLE();
        }
    }
}

bool IsConstantMemberOrIdentifierExpression(ir::Expression *expression)
{
    if (expression->IsMemberExpression()) {
        return expression->AsMemberExpression()->PropVar()->Declaration()->IsConstDecl();
    }

    if (expression->IsIdentifier()) {
        return expression->AsIdentifier()->Variable()->Declaration()->IsConstDecl();
    }

    return false;
}

bool ETSChecker::CompareIdentifiersValuesAreDifferent(ir::Expression *compareValue, const std::string &caseValue)
{
    if (IsConstantMemberOrIdentifierExpression(compareValue)) {
        checker::Type *compareCaseType = compareValue->TsType();

        const auto compareCaseValue = GetStringFromIdentifierValue(compareCaseType);
        return caseValue != compareCaseValue;
    }

    return caseValue != GetStringFromLiteral(compareValue);
}

void ETSChecker::CheckIdentifierSwitchCase(ir::Expression *currentCase, ir::Expression *compareCase,
                                           const lexer::SourcePosition &pos)
{
    currentCase->Check(this);

    if (!IsConstantMemberOrIdentifierExpression(currentCase)) {
        ThrowTypeError("Constant expression required", pos);
    }

    checker::Type *caseType = currentCase->TsType();

    if (!CompareIdentifiersValuesAreDifferent(compareCase, GetStringFromIdentifierValue(caseType))) {
        ThrowTypeError("Variable has same value with another switch case", pos);
    }
}

std::string ETSChecker::GetStringFromLiteral(ir::Expression *caseTest) const
{
    switch (caseTest->Type()) {
        case ir::AstNodeType::CHAR_LITERAL: {
            return std::to_string(caseTest->AsCharLiteral()->Char());
        }
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::NUMBER_LITERAL: {
            return util::Helpers::LiteralToPropName(caseTest).Mutf8();
        }
        default:
            UNREACHABLE();
    }
}

bool ETSChecker::IsSameDeclarationType(varbinder::LocalVariable *target, varbinder::LocalVariable *compare)
{
    if (target->Declaration()->Type() != compare->Declaration()->Type()) {
        return false;
    }

    if ((target->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE) &&
         !compare->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE)) ||
        (!target->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE) &&
         compare->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE))) {
        return false;
    }

    return true;
}

void ETSChecker::AddBoxingFlagToPrimitiveType(TypeRelation *relation, Type *target)
{
    auto boxingResult = PrimitiveTypeAsETSBuiltinType(target);
    if (boxingResult != nullptr) {
        relation->GetNode()->AddBoxingUnboxingFlags(GetBoxingFlag(boxingResult));
        relation->Result(true);
    }
}

void ETSChecker::AddUnboxingFlagToPrimitiveType(TypeRelation *relation, Type *source, Type *self)
{
    auto unboxingResult = UnboxingConverter(this, relation, source, self).Result();
    if ((unboxingResult != nullptr) && relation->IsTrue()) {
        relation->GetNode()->AddBoxingUnboxingFlags(GetUnboxingFlag(unboxingResult));
    }
}

void ETSChecker::CheckUnboxedTypeWidenable(TypeRelation *relation, Type *target, Type *self)
{
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(
        relation, TypeRelationFlag::ONLY_CHECK_WIDENING |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE));
    // NOTE: vpukhov. handle union type
    auto unboxedType = ETSBuiltinTypeAsPrimitiveType(target);
    if (unboxedType == nullptr) {
        return;
    }
    NarrowingWideningConverter(this, relation, unboxedType, self);
    if (!relation->IsTrue()) {
        relation->Result(relation->IsAssignableTo(self, unboxedType));
    }
}

void ETSChecker::CheckUnboxedTypesAssignable(TypeRelation *relation, Type *source, Type *target)
{
    auto *unboxedSourceType = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(source);
    auto *unboxedTargetType = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(target);
    if (unboxedSourceType == nullptr || unboxedTargetType == nullptr) {
        return;
    }
    relation->IsAssignableTo(unboxedSourceType, unboxedTargetType);
    if (relation->IsTrue()) {
        relation->GetNode()->AddBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(unboxedSourceType));
    }
}

void ETSChecker::CheckBoxedSourceTypeAssignable(TypeRelation *relation, Type *source, Type *target)
{
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(
        relation, (relation->ApplyWidening() ? TypeRelationFlag::WIDENING : TypeRelationFlag::NONE) |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE));
    auto *boxedSourceType = relation->GetChecker()->AsETSChecker()->PrimitiveTypeAsETSBuiltinType(source);
    if (boxedSourceType == nullptr) {
        return;
    }
    // Do not box primitive in case of cast to dynamic types
    if (target->IsETSDynamicType()) {
        return;
    }
    relation->IsAssignableTo(boxedSourceType, target);
    if (relation->IsTrue() && !relation->OnlyCheckBoxingUnboxing()) {
        AddBoxingFlagToPrimitiveType(relation, boxedSourceType);
    } else {
        auto unboxedTargetType = ETSBuiltinTypeAsPrimitiveType(target);
        if (unboxedTargetType == nullptr) {
            return;
        }
        NarrowingWideningConverter(this, relation, unboxedTargetType, source);
        if (relation->IsTrue()) {
            AddBoxingFlagToPrimitiveType(relation, target);
        }
    }
}

void ETSChecker::CheckUnboxedSourceTypeWithWideningAssignable(TypeRelation *relation, Type *source, Type *target)
{
    auto *unboxedSourceType = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(source);
    if (unboxedSourceType == nullptr) {
        return;
    }
    relation->IsAssignableTo(unboxedSourceType, target);
    if (!relation->IsTrue() && relation->ApplyWidening()) {
        relation->GetChecker()->AsETSChecker()->CheckUnboxedTypeWidenable(relation, target, unboxedSourceType);
    }
    if (!relation->OnlyCheckBoxingUnboxing()) {
        relation->GetNode()->AddBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(unboxedSourceType));
    }
}

bool ETSChecker::CheckRethrowingParams(const ir::AstNode *ancestorFunction, const ir::AstNode *node)
{
    for (const auto param : ancestorFunction->AsScriptFunction()->Signature()->Function()->Params()) {
        if (node->AsCallExpression()->Callee()->AsIdentifier()->Name().Is(
                param->AsETSParameterExpression()->Ident()->Name().Mutf8())) {
            return true;
        }
    }
    return false;
}

void ETSChecker::CheckThrowingStatements(ir::AstNode *node)
{
    ir::AstNode *ancestorFunction = FindAncestorGivenByType(node, ir::AstNodeType::SCRIPT_FUNCTION);

    if (ancestorFunction == nullptr) {
        ThrowTypeError(
            "This statement can cause an exception, therefore it must be enclosed in a try statement with a default "
            "catch clause",
            node->Start());
    }

    if (ancestorFunction->AsScriptFunction()->IsThrowing() ||
        (ancestorFunction->AsScriptFunction()->IsRethrowing() &&
         (!node->IsThrowStatement() && CheckRethrowingParams(ancestorFunction, node)))) {
        return;
    }

    if (!CheckThrowingPlacement(node, ancestorFunction)) {
        if (ancestorFunction->AsScriptFunction()->IsRethrowing() && !node->IsThrowStatement()) {
            ThrowTypeError(
                "This statement can cause an exception, re-throwing functions can throw exception only by their "
                "parameters.",
                node->Start());
        }

        ThrowTypeError(
            "This statement can cause an exception, therefore it must be enclosed in a try statement with a default "
            "catch clause",
            node->Start());
    }
}

bool ETSChecker::CheckThrowingPlacement(ir::AstNode *node, const ir::AstNode *ancestorFunction)
{
    ir::AstNode *startPoint = node;
    ir::AstNode *enclosingCatchClause = nullptr;
    ir::BlockStatement *enclosingFinallyBlock = nullptr;
    ir::AstNode *p = startPoint->Parent();

    bool isHandled = false;
    const auto predicateFunc = [&enclosingCatchClause](ir::CatchClause *clause) {
        return clause == enclosingCatchClause;
    };

    do {
        if (p->IsTryStatement() && p->AsTryStatement()->HasDefaultCatchClause()) {
            enclosingCatchClause = FindAncestorGivenByType(startPoint, ir::AstNodeType::CATCH_CLAUSE, p);
            enclosingFinallyBlock = FindFinalizerOfTryStatement(startPoint, p);
            const auto catches = p->AsTryStatement()->CatchClauses();

            if (std::any_of(catches.begin(), catches.end(), predicateFunc)) {
                startPoint = enclosingCatchClause;
            } else if (enclosingFinallyBlock != nullptr &&
                       enclosingFinallyBlock == p->AsTryStatement()->FinallyBlock()) {
                startPoint = enclosingFinallyBlock;
            } else {
                isHandled = true;
                break;
            }
        }

        p = p->Parent();
    } while (p != ancestorFunction);

    return isHandled;
}

ir::BlockStatement *ETSChecker::FindFinalizerOfTryStatement(ir::AstNode *startFrom, const ir::AstNode *p)
{
    auto *iter = startFrom->Parent();

    do {
        if (iter->IsBlockStatement()) {
            ir::BlockStatement *finallyBlock = iter->AsBlockStatement();

            if (finallyBlock == p->AsTryStatement()->FinallyBlock()) {
                return finallyBlock;
            }
        }

        iter = iter->Parent();
    } while (iter != p);

    return nullptr;
}

void ETSChecker::CheckRethrowingFunction(ir::ScriptFunction *func)
{
    bool foundThrowingParam = false;

    // It doesn't support lambdas yet.
    for (auto item : func->Params()) {
        auto const *type = item->AsETSParameterExpression()->Ident()->TypeAnnotation();

        if (type->IsETSTypeReference()) {
            auto *typeDecl = type->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Variable()->Declaration();
            if (typeDecl->IsTypeAliasDecl()) {
                type = typeDecl->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation();
            }
        }

        if (type->IsETSFunctionType() && type->AsETSFunctionType()->IsThrowing()) {
            foundThrowingParam = true;
            break;
        }
    }

    if (!foundThrowingParam) {
        ThrowTypeError("A rethrowing function must have a throwing function parameter", func->Start());
    }
}

ETSObjectType *ETSChecker::GetRelevantArgumentedTypeFromChild(ETSObjectType *const child, ETSObjectType *const target)
{
    if (child->GetDeclNode() == target->GetDeclNode()) {
        auto *relevantType = CreateNewETSObjectType(child->Name(), child->GetDeclNode(), child->ObjectFlags());

        ArenaVector<Type *> params = child->TypeArguments();

        relevantType->SetTypeArguments(std::move(params));
        relevantType->SetEnclosingType(child->EnclosingType());
        relevantType->SetSuperType(child->SuperType());

        return relevantType;
    }

    ASSERT(child->SuperType() != nullptr);

    return GetRelevantArgumentedTypeFromChild(child->SuperType(), target);
}

static void TypeToString(std::stringstream &ss, Type *tp)
{
    if (tp->IsETSTypeParameter()) {
        ss << tp->AsETSTypeParameter()->GetDeclNode()->Start().index;
        ss << ".";
    }
    if (!tp->IsETSObjectType()) {
        tp->ToString(ss);
        return;
    }
    auto *const objType = tp->AsETSObjectType();
    ss << objType->Name();

    if (!objType->TypeArguments().empty()) {
        auto typeArgs = objType->TypeArguments();
        ss << "<";
        for (auto *ta : typeArgs) {
            TypeToString(ss, ta);
            ss << ";";
        }
        ss << ">";
    }

    if (tp->ContainsNull()) {
        ss << "|null";
    }

    if (tp->ContainsUndefined()) {
        ss << "|undefined";
    }
}

void ETSChecker::EmplaceSubstituted(Substitution *substitution, ETSTypeParameter *tparam, Type *typeArg)
{
    substitution->emplace(tparam, typeArg);
}

util::StringView ETSChecker::GetHashFromTypeArguments(const ArenaVector<Type *> &typeArgTypes)
{
    std::stringstream ss;

    for (auto *it : typeArgTypes) {
        TypeToString(ss, it);
        ss << compiler::Signatures::MANGLE_SEPARATOR;
    }

    return util::UString(ss.str(), Allocator()).View();
}

util::StringView ETSChecker::GetHashFromSubstitution(const Substitution *substitution)
{
    std::vector<std::string> fields;
    for (auto [k, v] : *substitution) {
        std::stringstream ss;
        TypeToString(ss, k);
        ss << ":";
        TypeToString(ss, v);
        fields.push_back(ss.str());
    }
    std::sort(fields.begin(), fields.end());

    std::stringstream ss;
    for (auto &fstr : fields) {
        ss << fstr;
        ss << ";";
    }
    return util::UString(ss.str(), Allocator()).View();
}

ETSObjectType *ETSChecker::GetOriginalBaseType(Type *const object)
{
    if (object == nullptr || !object->IsETSObjectType()) {
        return nullptr;
    }

    return object->AsETSObjectType()->GetOriginalBaseType();
}

Type *ETSChecker::GetTypeFromTypeAnnotation(ir::TypeNode *const typeAnnotation)
{
    auto *type = typeAnnotation->GetType(this);

    if (!typeAnnotation->IsNullAssignable() && !typeAnnotation->IsUndefinedAssignable()) {
        return type;
    }

    if (!IsReferenceType(type)) {
        ThrowTypeError("Non reference types cannot be nullish.", typeAnnotation->Start());
    }

    if (type->IsNullish()) {
        return type;
    }

    TypeFlag nullishFlags {0};
    if (typeAnnotation->IsNullAssignable()) {
        nullishFlags |= TypeFlag::NULL_TYPE;
    }
    if (typeAnnotation->IsUndefinedAssignable()) {
        nullishFlags |= TypeFlag::UNDEFINED;
    }
    return CreateNullishType(type, nullishFlags, Allocator(), Relation(), GetGlobalTypesHolder());
}

void ETSChecker::CheckValidGenericTypeParameter(Type *const argType, const lexer::SourcePosition &pos)
{
    if (!argType->IsETSEnumType() && !argType->IsETSStringEnumType()) {
        return;
    }
    std::stringstream ss;
    argType->ToString(ss);
    ThrowTypeError("Type '" + ss.str() + "' is not valid for generic type arguments", pos);
}

void ETSChecker::CheckNumberOfTypeArguments(ETSObjectType *const type, ir::TSTypeParameterInstantiation *const typeArgs,
                                            const lexer::SourcePosition &pos)
{
    auto const &typeParams = type->TypeArguments();
    if (typeParams.empty()) {
        if (typeArgs != nullptr) {
            ThrowTypeError({"Type '", type, "' is not generic."}, pos);
        }
        return;
    }

    size_t minimumTypeArgs = std::count_if(typeParams.begin(), typeParams.end(), [](Type *param) {
        return param->AsETSTypeParameter()->GetDefaultType() == nullptr;
    });
    if (typeArgs == nullptr && minimumTypeArgs > 0) {
        ThrowTypeError({"Type '", type, "' is generic but type argument were not provided."}, pos);
    }

    if (typeArgs != nullptr &&
        ((minimumTypeArgs > typeArgs->Params().size()) || (typeParams.size() < typeArgs->Params().size()))) {
        ThrowTypeError({"Type '", type, "' has ", minimumTypeArgs, " number of type parameters, but ",
                        typeArgs->Params().size(), " type arguments were provided."},
                       pos);
    }
}

bool ETSChecker::NeedTypeInference(const ir::ScriptFunction *lambda)
{
    if (lambda->ReturnTypeAnnotation() == nullptr) {
        return true;
    }
    for (auto *const param : lambda->Params()) {
        const auto *const lambdaParam = param->AsETSParameterExpression()->Ident();
        if (lambdaParam->TypeAnnotation() == nullptr) {
            return true;
        }
    }
    return false;
}

std::vector<bool> ETSChecker::FindTypeInferenceArguments(const ArenaVector<ir::Expression *> &arguments)
{
    std::vector<bool> argTypeInferenceRequired(arguments.size());
    size_t index = 0;
    for (ir::Expression *arg : arguments) {
        if (arg->IsArrowFunctionExpression()) {
            ir::ScriptFunction *const lambda = arg->AsArrowFunctionExpression()->Function();
            if (NeedTypeInference(lambda)) {
                argTypeInferenceRequired[index] = true;
            }
        }
        ++index;
    }
    return argTypeInferenceRequired;
}

static ir::AstNode *DerefETSTypeReference(ir::AstNode *node)
{
    ASSERT(node->IsETSTypeReference());
    do {
        auto *name = node->AsETSTypeReference()->Part()->Name();
        ASSERT(name->IsIdentifier());
        auto *var = name->AsIdentifier()->Variable();
        ASSERT(var != nullptr);
        auto *declNode = var->Declaration()->Node();
        if (!declNode->IsTSTypeAliasDeclaration()) {
            return declNode;
        }
        node = declNode->AsTSTypeAliasDeclaration()->TypeAnnotation();
    } while (node->IsETSTypeReference());
    return node;
}

bool ETSChecker::CheckLambdaAssignable(ir::Expression *param, ir::ScriptFunction *lambda)
{
    ASSERT(param->IsETSParameterExpression());
    ir::AstNode *typeAnn = param->AsETSParameterExpression()->Ident()->TypeAnnotation();
    if (typeAnn->IsETSTypeReference()) {
        typeAnn = DerefETSTypeReference(typeAnn);
    }
    if (!typeAnn->IsETSFunctionType()) {
        return false;
    }
    ir::ETSFunctionType *calleeType = typeAnn->AsETSFunctionType();
    return lambda->Params().size() == calleeType->Params().size();
}

void ETSChecker::InferTypesForLambda(ir::ScriptFunction *lambda, ir::ETSFunctionType *calleeType)
{
    for (size_t i = 0; i < calleeType->Params().size(); ++i) {
        const auto *const calleeParam = calleeType->Params()[i]->AsETSParameterExpression()->Ident();
        auto *const lambdaParam = lambda->Params()[i]->AsETSParameterExpression()->Ident();
        if (lambdaParam->TypeAnnotation() == nullptr) {
            lambdaParam->SetTsTypeAnnotation(calleeParam->TypeAnnotation());
        }
    }
    if (lambda->ReturnTypeAnnotation() == nullptr) {
        lambda->SetReturnTypeAnnotation(calleeType->ReturnType());
    }
}

bool ETSChecker::TypeInference(Signature *signature, const ArenaVector<ir::Expression *> &arguments,
                               TypeRelationFlag flags)
{
    bool invocable = true;
    auto const argumentCount = arguments.size();
    auto const parameterCount = signature->Params().size();
    auto const count = std::min(parameterCount, argumentCount);

    for (size_t index = 0U; index < count; ++index) {
        auto const &argument = arguments[index];
        if (!argument->IsArrowFunctionExpression()) {
            continue;
        }

        if (index == arguments.size() - 1 && (flags & TypeRelationFlag::NO_CHECK_TRAILING_LAMBDA) != 0) {
            continue;
        }

        auto *const arrowFuncExpr = argument->AsArrowFunctionExpression();
        ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
        if (!NeedTypeInference(lambda)) {
            continue;
        }

        auto const *const param = signature->Function()->Params()[index]->AsETSParameterExpression()->Ident();
        ir::AstNode *typeAnn = param->TypeAnnotation();

        if (typeAnn->IsETSTypeReference()) {
            typeAnn = DerefETSTypeReference(typeAnn);
        }

        ASSERT(typeAnn->IsETSFunctionType());
        InferTypesForLambda(lambda, typeAnn->AsETSFunctionType());
        Type *const argType = arrowFuncExpr->Check(this);

        checker::InvocationContext invokationCtx(
            Relation(), arguments[index], argType, signature->Params()[index]->TsType(), arrowFuncExpr->Start(),
            {"Call argument at index ", index, " is not compatible with the signature's type at that index"}, flags);

        invocable &= invokationCtx.IsInvocable();
    }
    return invocable;
}

void ETSChecker::AddUndefinedParamsForDefaultParams(const Signature *const signature,
                                                    ArenaVector<panda::es2panda::ir::Expression *> &arguments,
                                                    ETSChecker *checker)
{
    if (!signature->Function()->IsDefaultParamProxy() || signature->Function()->Params().size() <= arguments.size()) {
        return;
    }

    uint32_t num = 0;
    for (size_t i = arguments.size(); i != signature->Function()->Params().size() - 1; i++) {
        if (auto const *const param = signature->Function()->Params()[i]->AsETSParameterExpression();
            !param->IsRestParameter()) {
            auto const *const typeAnn = param->Ident()->TypeAnnotation();
            if (typeAnn->IsETSPrimitiveType()) {
                if (typeAnn->AsETSPrimitiveType()->GetPrimitiveType() == ir::PrimitiveType::BOOLEAN) {
                    arguments.push_back(checker->Allocator()->New<ir::BooleanLiteral>(false));
                } else {
                    arguments.push_back(checker->Allocator()->New<ir::NumberLiteral>(lexer::Number(0)));
                }
            } else {
                // A proxy-function is called, so default reference parameters
                // are initialized with null instead of undefined
                auto *const nullLiteral = checker->Allocator()->New<ir::NullLiteral>();
                nullLiteral->SetTsType(checker->GlobalETSNullType());
                arguments.push_back(nullLiteral);
            }
            num |= (1U << (arguments.size() - 1));
        }
    }
    arguments.push_back(checker->Allocator()->New<ir::NumberLiteral>(lexer::Number(num)));
}

bool ETSChecker::ExtensionETSFunctionType(checker::Type *type)
{
    if (!type->IsETSFunctionType()) {
        return false;
    }

    for (auto *signature : type->AsETSFunctionType()->CallSignatures()) {
        if (signature->Function()->IsExtensionMethod()) {
            return true;
        }
    }

    return false;
}

void ETSChecker::ValidateTupleMinElementSize(ir::ArrayExpression *const arrayExpr, ETSTupleType *tuple)
{
    if (arrayExpr->Elements().size() < static_cast<size_t>(tuple->GetMinTupleSize())) {
        ThrowTypeError({"Few elements in array initializer for tuple with size of ",
                        static_cast<size_t>(tuple->GetMinTupleSize())},
                       arrayExpr->Start());
    }
}

void ETSChecker::ModifyPreferredType(ir::ArrayExpression *const arrayExpr, Type *const newPreferredType)
{
    // After modifying the preferred type of an array expression, it needs to be rechecked at the call site
    arrayExpr->SetPreferredType(newPreferredType);
    arrayExpr->SetTsType(nullptr);

    for (auto *const element : arrayExpr->Elements()) {
        if (element->IsArrayExpression()) {
            ModifyPreferredType(element->AsArrayExpression(), nullptr);
        }
    }
}

bool ETSChecker::TryTransformingToStaticInvoke(ir::Identifier *const ident, const Type *resolvedType)
{
    ASSERT(ident->Parent()->IsCallExpression());
    ASSERT(ident->Parent()->AsCallExpression()->Callee() == ident);

    if (!resolvedType->IsETSObjectType()) {
        return false;
    }

    auto className = ident->Name();
    std::string_view propertyName;

    PropertySearchFlags searchFlag = PropertySearchFlags::SEARCH_IN_INTERFACES | PropertySearchFlags::SEARCH_IN_BASE |
                                     PropertySearchFlags::SEARCH_STATIC_METHOD;
    // clang-format off
    auto *instantiateMethod =
        resolvedType->AsETSObjectType()->GetProperty(compiler::Signatures::STATIC_INSTANTIATE_METHOD, searchFlag);
    if (instantiateMethod != nullptr) {
        propertyName = compiler::Signatures::STATIC_INSTANTIATE_METHOD;
    } else if (auto *invokeMethod =
                    resolvedType->AsETSObjectType()->GetProperty(compiler::Signatures::STATIC_INVOKE_METHOD, searchFlag);
                invokeMethod != nullptr) {
        propertyName = compiler::Signatures::STATIC_INVOKE_METHOD;
    } else {
        ThrowTypeError({"No static ", compiler::Signatures::STATIC_INVOKE_METHOD, " method and static ",
                        compiler::Signatures::STATIC_INSTANTIATE_METHOD, " method in ", className, ". ", className,
                        "() is not allowed."},
                       ident->Start());
    }
    // clang-format on

    auto *classId = AllocNode<ir::Identifier>(className, Allocator());
    auto *methodId = AllocNode<ir::Identifier>(propertyName, Allocator());
    auto *transformedCallee =
        AllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    classId->SetRange(ident->Range());
    methodId->SetRange(ident->Range());
    transformedCallee->SetRange(ident->Range());

    auto *callExpr = ident->Parent()->AsCallExpression();
    transformedCallee->SetParent(callExpr);
    callExpr->SetCallee(transformedCallee);

    if (instantiateMethod != nullptr) {
        std::string implicitInstantiateArgument = "()=>{return new " + std::string(className) + "()}";

        parser::Program program(Allocator(), VarBinder());
        es2panda::CompilerOptions options;
        auto parser = parser::ETSParser(&program, options, parser::ParserStatus::NO_OPTS);
        auto *argExpr = parser.CreateExpression(implicitInstantiateArgument);
        compiler::ScopesInitPhaseETS::RunExternalNode(argExpr, &program);

        argExpr->SetParent(callExpr);
        argExpr->SetRange(ident->Range());

        VarBinder()->AsETSBinder()->HandleCustomNodes(argExpr);

        auto &arguments = callExpr->Arguments();
        arguments.insert(arguments.begin(), argExpr);
    }

    return true;
}
}  // namespace panda::es2panda::checker
