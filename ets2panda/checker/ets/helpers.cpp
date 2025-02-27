/**
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

#include "checker/ETSchecker.h"

#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsTupleType.h"
#include "checker/ets/typeRelationContext.h"
#include "evaluate/scopedDebugInfoPlugin.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::checker {
varbinder::Variable *ETSChecker::FindVariableInFunctionScope(const util::StringView name,
                                                             const varbinder::ResolveBindingOptions options)
{
    return Scope() != nullptr ? Scope()->FindInFunctionScope(name, options).variable : nullptr;
}

std::pair<varbinder::Variable *, const ETSObjectType *> ETSChecker::FindVariableInClassOrEnclosing(
    const util::StringView name, const ETSObjectType *classType)
{
    // For Annotation, it doesnot have containing class, so classType will be nullptr.
    if (classType == nullptr) {
        return {nullptr, nullptr};
    }
    const auto searchFlags = PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE |
                             PropertySearchFlags::SEARCH_IN_INTERFACES;
    auto *resolved = classType->GetProperty(name, searchFlags);
    while (classType->EnclosingType() != nullptr && resolved == nullptr) {
        classType = classType->EnclosingType();
        resolved = classType->GetProperty(name, searchFlags);
    }

    return {resolved, classType};
}

varbinder::Variable *ETSChecker::FindVariableInGlobal(const ir::Identifier *const identifier,
                                                      const varbinder::ResolveBindingOptions options)
{
    return Scope()->FindInGlobal(identifier->Name(), options).variable;
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

void ETSChecker::LogUnresolvedReferenceError(ir::Identifier *const ident)
{
    if (!ident->IsErrorPlaceHolder()) {
        LogError(diagnostic::UNRESOLVED_REF, {ident->Name()}, ident->Start());
    }
}

void ETSChecker::WrongContextErrorClassifyByType(ir::Identifier *ident)
{
    if (ident->IsErrorPlaceHolder()) {
        return;
    }

    std::string identCategoryName {};
    switch (static_cast<varbinder::VariableFlags>(
        ident->Variable()->Flags() &
        (varbinder::VariableFlags::CLASS_OR_INTERFACE_OR_ENUM | varbinder::VariableFlags::METHOD |
         varbinder::VariableFlags::NAMESPACE | varbinder::VariableFlags::ANNOTATIONDECL |
         varbinder::VariableFlags::ANNOTATIONUSAGE | varbinder::VariableFlags::TYPE_ALIAS |
         varbinder::VariableFlags::TYPE))) {
        case varbinder::VariableFlags::CLASS:
            identCategoryName = "Class";
            break;

        case varbinder::VariableFlags::NAMESPACE:
            identCategoryName = "Namespace";
            break;

        case varbinder::VariableFlags::METHOD:
            identCategoryName = "Function";
            break;

        case varbinder::VariableFlags::INTERFACE:
            identCategoryName = "Interface";
            break;

        case varbinder::VariableFlags::ENUM_LITERAL:
            identCategoryName = "Enum";
            break;

        case varbinder::VariableFlags::ANNOTATIONDECL:
            [[fallthrough]];
        case varbinder::VariableFlags::ANNOTATIONUSAGE:
            identCategoryName = "Annotation";
            break;

        case varbinder::VariableFlags::TYPE:
            [[fallthrough]];
        case varbinder::VariableFlags::TYPE_ALIAS:
            identCategoryName = "Type";
            break;

        default:
            LogTypeError({"Identifier '", ident->Name(), "' is used in wrong context."}, ident->Start());
            return;
    }
    LogError(diagnostic::ID_IN_WRONG_CTX, {identCategoryName.c_str(), ident->Name()}, ident->Start());
}

void ETSChecker::NotResolvedError(ir::Identifier *const ident, const varbinder::Variable *classVar,
                                  const ETSObjectType *classType)
{
    if (classVar == nullptr) {
        LogUnresolvedReferenceError(ident);
        return;
    }

    if (IsVariableStatic(classVar)) {
        LogError(diagnostic::STATIC_PROP_INVALID_CTX, {ident->Name(), classType}, ident->Start());
    } else {
        LogError(diagnostic::PROP_ACCESS_WITHOUT_THIS, {ident->Name()}, ident->Start());
    }
}

std::pair<const ir::Identifier *, ir::TypeNode *> ETSChecker::GetTargetIdentifierAndType(ir::Identifier *const ident)
{
    if (ident->Parent()->IsClassProperty()) {
        const auto *const classProp = ident->Parent()->AsClassProperty();
        ES2PANDA_ASSERT(classProp->Value() && classProp->Value() == ident);
        return std::make_pair(classProp->Key()->AsIdentifier(), classProp->TypeAnnotation());
    }
    const auto *const variableDecl = ident->Parent()->AsVariableDeclarator();
    ES2PANDA_ASSERT(variableDecl->Init() && variableDecl->Init() == ident);
    return std::make_pair(variableDecl->Id()->AsIdentifier(), variableDecl->Id()->AsIdentifier()->TypeAnnotation());
}

varbinder::Variable *ETSChecker::ExtraCheckForResolvedError(ir::Identifier *const ident)
{
    const auto [class_var, class_type] = FindVariableInClassOrEnclosing(ident->Name(), Context().ContainingClass());
    auto *parentClass = FindAncestorGivenByType(ident, ir::AstNodeType::CLASS_DEFINITION);
    if (parentClass != nullptr && parentClass->AsClassDefinition()->IsLocal()) {
        if (parentClass != class_type->GetDeclNode()) {
            LogError(diagnostic::PROPERTY_CAPTURE,
                     {ident->Name(), class_type->Name(), parentClass->AsClassDefinition()->Ident()->Name()},
                     ident->Start());
        }
    }
    NotResolvedError(ident, class_var, class_type);
    return class_var;
}

bool ETSChecker::SaveCapturedVariableInLocalClass(varbinder::Variable *const var, ir::Identifier *ident)
{
    const auto &pos = ident->Start();

    if (!HasStatus(CheckerStatus::IN_LOCAL_CLASS)) {
        return false;
    }

    if (!var->HasFlag(varbinder::VariableFlags::LOCAL)) {
        return false;
    }

    LOG(DEBUG, ES2PANDA) << "Checking variable (line:" << pos.line << "): " << var->Name();
    auto *scopeIter = Scope();
    bool inStaticMethod = false;

    auto captureVariable = [this, var, ident, &scopeIter, &inStaticMethod, &pos]() {
        if (inStaticMethod) {
            LogError(diagnostic::PROPERTY_CAPTURE_IN_STATIC, {var->Name()}, pos);
            return false;
        }
        if (scopeIter->Node()->AsClassDefinition()->CaptureVariable(var)) {
            LOG(DEBUG, ES2PANDA) << "  Captured in class:" << scopeIter->Node()->AsClassDefinition()->Ident()->Name();
        }

        auto *parent = ident->Parent();

        if (parent->IsVariableDeclarator()) {
            parent = parent->Parent()->Parent();
        }

        if (!(parent->IsUpdateExpression() ||
              (parent->IsAssignmentExpression() && parent->AsAssignmentExpression()->Left() == ident)) ||
            var->Declaration() == nullptr) {
            return false;
        }

        if (var->Declaration()->IsParameterDecl()) {
            LOG(DEBUG, ES2PANDA) << "    - Modified parameter ";
            scopeIter->Node()->AsClassDefinition()->AddToLocalVariableIsNeeded(var);
        }
        return true;
    };

    while (scopeIter != var->GetScope()) {
        if (scopeIter->Node() != nullptr) {
            if (scopeIter->Node()->IsScriptFunction() && scopeIter->Node()->AsScriptFunction()->IsStatic()) {
                inStaticMethod = true;
            }

            if (scopeIter->Node()->IsClassDefinition()) {
                captureVariable();
                return true;
            }
        }
        scopeIter = scopeIter->Parent();
    }

    return false;
}

void ETSChecker::SaveCapturedVariable(varbinder::Variable *const var, ir::Identifier *ident)
{
    const auto &pos = ident->Start();

    if (!HasStatus(CheckerStatus::IN_LAMBDA)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PROPERTY)) {
        Context().AddCapturedVar(var, pos);
        return;
    }

    if ((!var->HasFlag(varbinder::VariableFlags::LOCAL) && !var->HasFlag(varbinder::VariableFlags::METHOD)) ||
        Context().ContainingLambda()->IsVarFromSubscope(var)) {
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

Type *ETSChecker::ResolveIdentifier(ir::Identifier *ident)
{
    if (ident->Variable() != nullptr) {
        auto *const resolved = ident->Variable();
        SaveCapturedVariable(resolved, ident);
        return GetTypeOfVariable(resolved);
    }

    auto options = ident->Parent()->IsTSTypeAliasDeclaration() ? varbinder::ResolveBindingOptions::TYPE_ALIASES
                                                               : varbinder::ResolveBindingOptions::ALL_NON_TYPE;

    auto *resolved = FindVariableInFunctionScope(ident->Name(), options);
    if (resolved == nullptr) {
        // If the reference is not found already in the current class, then it is not bound to the class, so we have to
        // find the reference in the global class first, then in the global scope
        resolved = FindVariableInGlobal(ident, options);
        if (UNLIKELY(resolved == nullptr && debugInfoPlugin_ != nullptr)) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            resolved = debugInfoPlugin_->FindIdentifier(ident);
        }
    }

    if (resolved == nullptr) {
        resolved = ExtraCheckForResolvedError(ident);
        if (resolved == nullptr) {
            auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(
                ident->Start(), !ident->IsErrorPlaceHolder() ? ident->Name() : compiler::GenName(Allocator()).View());
            var->SetScope(VarBinder()->GetScope());
            ident->SetVariable(var);
            decl->BindNode(ident);
            return ident->SetTsType(var->SetTsType(GlobalTypeError()));
        }
        ident->SetVariable(resolved);
        return GetTypeOfVariable(resolved);
    }

    ident->SetVariable(resolved);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ValidateResolvedIdentifier(ident);

    ValidatePropertyAccess(resolved, Context().ContainingClass(), ident->Start());
    SaveCapturedVariable(resolved, ident);

    return GetTypeOfVariable(resolved);
}

std::optional<checker::Type *> CheckLeftRightType(checker::ETSChecker *checker, checker::Type *unboxedL,
                                                  checker::Type *unboxedR)
{
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
    return std::nullopt;
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
                    return checker->GetNonConstantType(otherType);
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

    auto checkLeftRight = CheckLeftRightType(checker, unboxedL, unboxedR);
    if (checkLeftRight.has_value()) {
        return checkLeftRight.value();
    }
    UNREACHABLE();
}

Type *ETSChecker::ApplyUnaryOperatorPromotion(Type *type, const bool createConst, const bool doPromotion,
                                              const bool isCondExpr)
{
    Type *unboxedType = isCondExpr ? MaybeUnboxConditionalInRelation(type) : MaybeUnboxInRelation(type);

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
    // NOTE(vpukhov): #19701 void refactoring
    return expr->TsType()->DefinitelyETSNullish() || expr->TsType()->IsETSVoidType();
}

std::tuple<bool, bool> ETSChecker::IsResolvedAndValue(const ir::Expression *expr, Type *type) const
{
    auto [isResolve, isValue] =
        IsNullLikeOrVoidExpression(expr) ? std::make_tuple(true, false) : type->ResolveConditionExpr();

    const Type *tsType = expr->TsType();
    if (tsType->DefinitelyNotETSNullish() && !type->IsETSPrimitiveType()) {
        isResolve = true;
        isValue = true;
    }
    return std::make_tuple(isResolve, isValue);
}

Type *ETSChecker::HandleBooleanLogicalOperators(Type *leftType, Type *rightType, lexer::TokenType tokenType)
{
    using UType = typename ETSBooleanType::UType;
    ES2PANDA_ASSERT(leftType->IsETSBooleanType() && rightType->IsETSBooleanType());

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

bool ETSChecker::HandleLogicalPotentialResult(ir::Expression *left, ir::Expression *right, ir::BinaryExpression *expr,
                                              checker::Type *leftType)
{
    if (leftType->IsConstantType() && leftType->IsETSBooleanType()) {
        if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
            expr->SetResult(leftType->AsETSBooleanType()->GetValue() ? right : left);
            return true;
        }
        expr->SetResult(leftType->AsETSBooleanType()->GetValue() ? left : right);
        return true;
    }

    if (!leftType->IsETSPrimitiveType() && !leftType->PossiblyETSValueTyped()) {
        expr->SetResult(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND ? right : left);
        return true;
    }
    if (leftType->IsETSNullType() || leftType->IsETSUndefinedType()) {
        expr->SetResult(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND ? left : right);
        return true;
    }

    return false;
}

void ETSChecker::ResolveReturnStatement(checker::Type *funcReturnType, checker::Type *argumentType,
                                        ir::ScriptFunction *containingFunc, ir::ReturnStatement *st)
{
    if (funcReturnType->IsETSReferenceType() || argumentType->IsETSReferenceType()) {
        // function return type should be of reference (object) type
        Relation()->SetFlags(checker::TypeRelationFlag::NONE);

        if (!argumentType->IsETSReferenceType()) {
            argumentType = MaybeBoxInRelation(argumentType);
            if (argumentType == nullptr) {
                LogError(diagnostic::INVALID_EXPR_IN_RETURN, {}, st->Argument()->Start());
            } else {
                st->Argument()->AddBoxingUnboxingFlags(GetBoxingFlag(argumentType));
            }
        }

        if (!funcReturnType->IsETSReferenceType()) {
            funcReturnType = MaybeBoxInRelation(funcReturnType);
            if (funcReturnType == nullptr) {
                LogError(diagnostic::INVALID_RETURN_FUNC_EXPR, {}, st->Start());
            }
        }
        if (argumentType != nullptr && funcReturnType != nullptr) {
            funcReturnType = CreateETSUnionType({funcReturnType, argumentType});
            containingFunc->Signature()->SetReturnType(funcReturnType);
            containingFunc->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
        }
    } else if (funcReturnType->IsETSPrimitiveType() && argumentType->IsETSPrimitiveType()) {
        // function return type is of primitive type (including enums):
        Relation()->SetFlags(checker::TypeRelationFlag::DIRECT_RETURN |
                             checker::TypeRelationFlag::IN_ASSIGNMENT_CONTEXT |
                             checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
        if (Relation()->IsAssignableTo(funcReturnType, argumentType)) {
            funcReturnType = argumentType;
            containingFunc->Signature()->SetReturnType(funcReturnType);
            containingFunc->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
        } else if (!Relation()->IsAssignableTo(argumentType, funcReturnType)) {
            LogError(diagnostic::RETURN_DIFFERENT_PRIM, {funcReturnType, argumentType}, st->Argument()->Start());
        }
    } else {
        // Should never in this branch.
        UNREACHABLE();
        return;
    }
}

checker::Type *ETSChecker::CheckArrayElements(ir::ArrayExpression *init)
{
    ArenaVector<checker::Type *> elementTypes(Allocator()->Adapter());
    for (auto e : init->AsArrayExpression()->Elements()) {
        Type *eType = e->Check(this);
        if (eType->HasTypeFlag(TypeFlag::TYPE_ERROR)) {
            return eType;
        }
        elementTypes.push_back(GetNonConstantType(eType));
    }

    if (elementTypes.empty()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return Allocator()->New<ETSArrayType>(GlobalETSObjectType());
    }
    auto const isNumeric = [](checker::Type *ct) { return ct->HasTypeFlag(TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC); };
    auto const isChar = [](checker::Type *ct) { return ct->HasTypeFlag(TypeFlag::CHAR); };
    auto const elementType =
        std::all_of(elementTypes.begin(), elementTypes.end(), isNumeric)
            ? std::all_of(elementTypes.begin(), elementTypes.end(), isChar) ? GlobalCharType() : GlobalDoubleType()
            : CreateETSUnionType(std::move(elementTypes));

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return Allocator()->New<ETSArrayType>(elementType);
}

void ETSChecker::InferAliasLambdaType(ir::TypeNode *localTypeAnnotation, ir::ArrowFunctionExpression *init)
{
    ES2PANDA_ASSERT(localTypeAnnotation != nullptr);

    if (localTypeAnnotation->IsETSTypeReference()) {
        bool isAnnotationTypeAlias = true;
        while (localTypeAnnotation->IsETSTypeReference() && isAnnotationTypeAlias) {
            auto *nodeVar = localTypeAnnotation->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Variable();
            if (nodeVar == nullptr) {
                break;
            }

            auto *node = nodeVar->Declaration()->Node();

            isAnnotationTypeAlias = node->IsTSTypeAliasDeclaration();
            if (isAnnotationTypeAlias) {
                localTypeAnnotation = node->AsTSTypeAliasDeclaration()->TypeAnnotation();
            }
        }
    }

    if (localTypeAnnotation->IsETSFunctionType()) {
        auto *const arrowFuncExpr = init;
        ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
        if (lambda->Params().size() == localTypeAnnotation->AsETSFunctionType()->Params().size() &&
            NeedTypeInference(lambda)) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            InferTypesForLambda(lambda, localTypeAnnotation->AsETSFunctionType());
        }
    }
}

checker::Type *ETSChecker::FixOptionalVariableType(varbinder::Variable *const bindingVar, ir::ModifierFlags flags,
                                                   ir::Expression *init)
{
    if ((flags & ir::ModifierFlags::OPTIONAL) != 0) {
        if (init != nullptr && bindingVar->TsType()->IsETSPrimitiveType()) {
            init->SetBoxingUnboxingFlags(GetBoxingFlag(bindingVar->TsType()));
        }
        auto *variableType = bindingVar->TsType() != nullptr ? bindingVar->TsType() : GlobalTypeError();
        bindingVar->SetTsType(CreateETSUnionType({GlobalETSUndefinedType(), variableType}));
    }
    return bindingVar->TsType();
}

checker::Type *PreferredObjectTypeFromAnnotation(checker::Type *annotationType)
{
    if (!annotationType->IsETSUnionType()) {
        return annotationType;
    }

    checker::Type *resolvedType = nullptr;
    for (auto constituentType : annotationType->AsETSUnionType()->ConstituentTypes()) {
        if (constituentType->IsETSObjectType()) {
            if (resolvedType != nullptr) {
                return nullptr;
            }
            resolvedType = constituentType;
        }
    }

    return resolvedType;
}

bool ETSChecker::CheckInit(ir::Identifier *ident, ir::TypeNode *typeAnnotation, ir::Expression *init,
                           checker::Type *annotationType, varbinder::Variable *const bindingVar)
{
    if (typeAnnotation == nullptr) {
        if (init->IsArrayExpression()) {
            annotationType = CheckArrayElements(init->AsArrayExpression());
            if (bindingVar != nullptr) {
                bindingVar->SetTsType(annotationType);
            }
        }

        if (init->IsObjectExpression()) {
            LogError(diagnostic::CANNOT_INFER_OBJ_LIT, {ident->Name()}, ident->Start());
            return false;
        }
    }

    if (init->IsMemberExpression() && init->AsMemberExpression()->Object()->IsObjectExpression()) {
        LogError(diagnostic::MEMBER_OF_OBJECT_LIT, {}, ident->Start());
    }

    if (annotationType != nullptr && annotationType->HasTypeFlag(TypeFlag::TYPE_ERROR)) {
        return false;
    }

    if ((init->IsMemberExpression()) && (annotationType != nullptr)) {
        SetArrayPreferredTypeForNestedMemberExpressions(init->AsMemberExpression(), annotationType);
    }

    if (init->IsArrayExpression() && (annotationType != nullptr) && !annotationType->IsETSDynamicType()) {
        if (annotationType->IsETSTupleType() &&
            !IsArrayExprSizeValidForTuple(init->AsArrayExpression(), annotationType->AsETSTupleType())) {
            return false;
        }

        init->AsArrayExpression()->SetPreferredType(annotationType);
    }

    if (init->IsObjectExpression() && annotationType != nullptr) {
        init->AsObjectExpression()->SetPreferredType(PreferredObjectTypeFromAnnotation(annotationType));
    }

    if (typeAnnotation != nullptr && init->IsArrowFunctionExpression()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        InferAliasLambdaType(typeAnnotation, init->AsArrowFunctionExpression());
    }

    return true;
}

void ETSChecker::CheckEnumType(ir::Expression *init, checker::Type *initType, const util::StringView &varName)
{
    if (initType->IsETSObjectType() && initType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::ENUM) &&
        !init->IsMemberExpression()) {
        LogError(diagnostic::TYPE_MISMATCH_ENUM, {initType->AsETSObjectType()->Name(), varName}, init->Start());
    }
}

static bool IsOmitConstInit(ir::ModifierFlags const flags)
{
    return ((flags & ir::ModifierFlags::CONST) != 0) ||
           (((flags & ir::ModifierFlags::READONLY) != 0) && ((flags & ir::ModifierFlags::STATIC) != 0));
}

static bool NeedWidening(ir::Expression *e)
{
    // NOTE: need to be done by smart casts. Return true if we need to infer wider type.
    if (e->IsUnaryExpression()) {
        return NeedWidening(e->AsUnaryExpression()->Argument());
    }
    const bool isConstInit = e->IsIdentifier() && e->Variable()->Declaration()->IsConstDecl();

    return e->IsConditionalExpression() || e->IsLiteral() || isConstInit;
}

// Isolated until 'constant' types are tracked in some cases
static bool ShouldPreserveConstantTypeInVariableDeclaration(Type *annotation, Type *init)
{
    auto const isNumericWithConstTracking = [](Type *type) {
        return type->HasTypeFlag(TypeFlag::ETS_NUMERIC) || type->IsCharType();
    };

    return ((isNumericWithConstTracking(init) && isNumericWithConstTracking(annotation)) ||
            (init->IsETSStringType() && annotation->IsETSStringType()));
}

static void CheckAssignForDeclare(ir::Identifier *ident, ir::TypeNode *typeAnnotation, ir::Expression *init,
                                  ir::ModifierFlags const flags, ETSChecker *check)
{
    const bool isDeclare = (flags & ir::ModifierFlags::DECLARE) != 0;
    const bool isAbstract = (flags & ir::ModifierFlags::ABSTRACT) != 0;
    if (!isDeclare || isAbstract) {
        return;
    }
    if (typeAnnotation != nullptr && init != nullptr && !init->IsUndefinedLiteral()) {
        check->LogError(diagnostic::INIT_IN_AMBIENT, {ident->Name()}, init->Start());
        return;
    }
    const bool isConst = (flags & ir::ModifierFlags::CONST) != 0;
    bool numberLiteralButNotBigInt = init->IsNumberLiteral() && !init->IsBigIntLiteral();
    bool multilineLiteralWithNoEmbedding =
        init->IsTemplateLiteral() && init->AsTemplateLiteral()->Expressions().empty();
    if (isConst && !numberLiteralButNotBigInt && !init->IsStringLiteral() && !multilineLiteralWithNoEmbedding) {
        check->LogError(diagnostic::AMBIENT_CONST_INVALID_LIT, {ident->Name()}, init->Start());
    }
}

// CC-OFFNXT(huge_method,huge_cca_cyclomatic_complexity,huge_cyclomatic_complexity,G.FUN.01-CPP) solid logic
checker::Type *ETSChecker::CheckVariableDeclaration(ir::Identifier *ident, ir::TypeNode *typeAnnotation,
                                                    ir::Expression *init, ir::ModifierFlags const flags)
{
    varbinder::Variable *const bindingVar = ident->Variable();
    checker::Type *annotationType = nullptr;

    // We have to process possible parser errors when variable was not created and bind:
    if (bindingVar != nullptr) {
        if (typeAnnotation != nullptr) {
            annotationType = typeAnnotation->GetType(this);
            bindingVar->SetTsType(annotationType);
        }

        if (init == nullptr) {
            return FixOptionalVariableType(bindingVar, flags, init);
        }
        CheckAssignForDeclare(ident, typeAnnotation, init, flags, this);
    } else {
        ES2PANDA_ASSERT(IsAnyError());
    }

    checker::Type *initType = nullptr;
    if (init != nullptr) {
        TypeStackElement typeStackElement(this, init, {"Circular dependency detected for identifier: ", ident->Name()},
                                          init->Start());
        if (typeStackElement.HasTypeError()) {
            return init->SetTsType(GlobalTypeError());
        }

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        if (!CheckInit(ident, typeAnnotation, init, annotationType, bindingVar)) {
            init->SetTsType(GlobalTypeError());
        } else {
            initType = init->Check(this);
        }
    } else {
        ES2PANDA_ASSERT(IsAnyError());
    }

    // initType should not be nullptr. If an error occurs during check, set it to GlobalTypeError().
    if (bindingVar == nullptr || initType == nullptr || initType->IsTypeError()) {
        return annotationType != nullptr ? annotationType : GlobalTypeError();
    }

    if (typeAnnotation == nullptr && initType->IsETSFunctionType()) {
        annotationType = initType->AsETSFunctionType();
        bindingVar->SetTsType(annotationType);
    }

    if (annotationType != nullptr) {
        if (typeAnnotation != nullptr) {
            AssignmentContext(Relation(), init, initType, annotationType, init->Start(),
                              {"Type '", initType, "' cannot be assigned to type '", annotationType, "'"});
            if (!Relation()->IsTrue()) {
                return annotationType;
            }
        }

        if (IsOmitConstInit(flags) && ShouldPreserveConstantTypeInVariableDeclaration(annotationType, initType)) {
            bindingVar->SetTsType(init->TsType());
        }
    } else {
        CheckEnumType(init, initType, ident->Name());

        // NOTE: need to be done by smart casts
        auto needWidening = !IsOmitConstInit(flags) && typeAnnotation == nullptr && NeedWidening(init);
        bindingVar->SetTsType(needWidening ? GetNonConstantType(initType) : initType);
    }

    return FixOptionalVariableType(bindingVar, flags, init);
}

//==============================================================================//
// Smart cast support
//==============================================================================//

checker::Type *ETSChecker::ResolveSmartType(checker::Type *sourceType, checker::Type *targetType)
{
    //  For left-hand variable of primitive type leave it as is.
    if (targetType->IsETSPrimitiveType()) {
        return targetType;
    }

    //  For left-hand variable of tuple type leave it as is.
    if (targetType->IsETSTupleType()) {
        return targetType;
    }

    //  For left-hand invalid variable set smart type to right-hand type.
    if (targetType->IsTypeError()) {
        return sourceType;
    }

    //  For left-hand variable of builtin type leave it as is.
    if (targetType->IsETSObjectType() && targetType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE)) {
        return targetType;
    }

    // Nothing to do with identical types:
    auto *nonConstSourceType = GetNonConstantType(sourceType);
    auto *nonConstTargetType = GetNonConstantType(targetType);

    if (Relation()->IsIdenticalTo(nonConstSourceType, nonConstTargetType) ||
        Relation()->IsIdenticalTo(GlobalBuiltinJSValueType(), nonConstTargetType)) {
        return targetType;
    }

    //  For type parameter, null or undefined source type return it as is.
    if (sourceType->IsETSTypeParameter() || sourceType->DefinitelyETSNullish()) {
        return sourceType;
    }

    //  In case of Union left-hand type we have to select the proper type from the Union
    //  Because now we have logging of errors we have to continue analyze incorrect program, for
    //  this case we change typeError to source type.
    if (targetType->IsETSUnionType()) {
        auto component = targetType->AsETSUnionType()->GetAssignableType(this, sourceType);
        return component->IsTypeError() ? MaybeBoxType(sourceType) : component;
    }

    //  If source is reference type, set it as the current and use it for identifier smart cast
    if (sourceType->IsETSReferenceType()) {
        return sourceType;
    }

    //  For right-hand variable of primitive type apply boxing conversion (case: 'let x: Object = 5', then x => Int).
    if (sourceType->IsETSPrimitiveType() && !sourceType->IsETSVoidType() && targetType->IsETSObjectType()) {
        return MaybeBoxInRelation(sourceType);
    }

    //  NOTE - it seems that all the other possible cases are assignments like:
    //  'Object = ObjectLiteral' or smth similar ???
    //  thus for such cases also leave the target type as is.
    //  Possible errors in tests should clarify this hypothesis sooner or later :)
    return targetType;
}

// Auxiliary method to reduce the size of common 'CheckTestSmartCastConditions' function.
std::pair<Type *, Type *> ETSChecker::CheckTestNullishCondition(Type *testedType, Type *actualType, bool const strict)
{
    if (!strict) {
        return RemoveNullishTypes(actualType);
    }

    if (testedType->IsETSNullType()) {
        return {GlobalETSNullType(), RemoveNullType(actualType)};
    }

    if (testedType->IsETSUndefinedType()) {
        return {GlobalETSUndefinedType(), RemoveUndefinedType(actualType)};
    }

    return {GlobalETSNullishType(), GetNonNullishType(actualType)};
}

// Auxiliary method to reduce the size of common 'CheckTestSmartCastConditions' function.
std::pair<Type *, Type *> ETSChecker::CheckTestObjectCondition(ETSArrayType *testedType, Type *actualType)
{
    if (actualType->IsETSUnionType()) {
        return actualType->AsETSUnionType()->GetComplimentaryType(this, testedType);
    }

    // Both testing and actual (smart) types are arrays. Set types according to their relation.
    // NOTE: probably the rules of type extraction should be modified later on!
    if (actualType->IsETSArrayType()) {
        auto *const arrayType = actualType->AsETSArrayType();

        if (Relation()->IsIdenticalTo(arrayType, testedType)) {
            return {testedType, GetGlobalTypesHolder()->GlobalNeverType()};
        }

        if (Relation()->IsSupertypeOf(arrayType, testedType)) {
            return {testedType, actualType};
        }

        if (Relation()->IsSupertypeOf(testedType, arrayType)) {
            return {testedType, actualType};
        }
    } else if (actualType->IsETSObjectType() && actualType->AsETSObjectType()->IsGlobalETSObjectType()) {
        return {testedType, actualType};
    }

    return {GetGlobalTypesHolder()->GlobalNeverType(), actualType};
}

// Auxiliary method to reduce the size of common 'CheckTestSmartCastConditions' function.
std::pair<Type *, Type *> ETSChecker::CheckTestObjectCondition(ETSObjectType *testedType, Type *actualType,
                                                               bool const strict)
{
    if (actualType->IsETSUnionType()) {
        return actualType->AsETSUnionType()->GetComplimentaryType(this, testedType);
    }

    // Both testing and actual (smart) types are objects. Set types according to their relation.
    // NOTE: probably the rules of type extraction should be modified later on!
    if (actualType->IsETSObjectType()) {
        auto *const objectType = actualType->AsETSObjectType();

        if (Relation()->IsIdenticalTo(objectType, testedType) ||
            objectType->AssemblerName() == testedType->AssemblerName()) {
            return {testedType, strict ? GetGlobalTypesHolder()->GlobalNeverType() : actualType};
        }

        if (Relation()->IsSupertypeOf(objectType, testedType)) {
            return {testedType, actualType};
        }

        if (Relation()->IsSupertypeOf(testedType, objectType)) {
            return {testedType, actualType};
        }

        return {GetGlobalTypesHolder()->GlobalNeverType(), actualType};
    }

    return {testedType, actualType};
}

// Simple and conservative implementation unless smartcasts are not rewritten completely
static std::pair<Type *, Type *> ComputeConditionalSubtypes(TypeRelation *relation, Type *condition, Type *actual)
{
    if (relation->IsSupertypeOf(condition, actual)) {
        if (relation->IsIdenticalTo(condition, actual)) {
            return {condition, relation->GetChecker()->GetGlobalTypesHolder()->GlobalETSNeverType()};
        }
        return {actual, actual};
    }
    return {condition, actual};
}

static constexpr std::size_t const VARIABLE_POSITION = 0UL;
static constexpr std::size_t const CONSEQUENT_TYPE_POSITION = 1UL;
static constexpr std::size_t const ALTERNATE_TYPE_POSITION = 2UL;

void CheckerContext::CheckTestSmartCastCondition(lexer::TokenType operatorType)
{
    if (operatorType != lexer::TokenType::EOS && operatorType != lexer::TokenType::PUNCTUATOR_LOGICAL_AND &&
        operatorType != lexer::TokenType::PUNCTUATOR_LOGICAL_OR) {
        return;
    }

    auto types = ResolveSmartCastTypes();

    if (operatorType_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        if (types.has_value()) {
            auto const &variable = std::get<VARIABLE_POSITION>(*types);
            //  NOTE: now we support only cases like 'if (x != null && y == null)' but don't support different type
            //  checks for a single variable (like 'if (x != null && x instanceof string)'), because it seems that
            //  it doesn't make much sense.
            //  Can be implemented later on if the need arises.
            if (auto [_, inserted] =
                    testSmartCasts_.emplace(variable, std::make_pair(std::get<CONSEQUENT_TYPE_POSITION>(*types),
                                                                     std::get<ALTERNATE_TYPE_POSITION>(*types)));
                !inserted) {
                testSmartCasts_[variable] = {nullptr, nullptr};
            }
        }
        //  Clear alternate types, because now they become indefinite
        for (auto &smartCast : testSmartCasts_) {
            smartCast.second.second = nullptr;
        }
    } else if (operatorType_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR) {
        if (bool const cleanConsequent = types.has_value() ? CheckTestOrSmartCastCondition(*types) : true;
            cleanConsequent) {
            //  Clear consequent types, because now they become indefinite
            for (auto &smartCast : testSmartCasts_) {
                smartCast.second.first = nullptr;
            }
        }
    } else if (types.has_value()) {
        testSmartCasts_.emplace(
            std::get<VARIABLE_POSITION>(*types),
            std::make_pair(std::get<CONSEQUENT_TYPE_POSITION>(*types), std::get<ALTERNATE_TYPE_POSITION>(*types)));
    }

    testCondition_ = {};
    operatorType_ = operatorType;
}

std::optional<SmartCastTuple> CheckerContext::ResolveSmartCastTypes()
{
    if (testCondition_.variable == nullptr) {
        return std::nullopt;
    }

    // Exclude processing of global variables and those captured in lambdas and modified there
    auto const *const variableScope = testCondition_.variable->GetScope();
    auto const topLevelVariable =
        variableScope != nullptr ? variableScope->IsGlobalScope() ||
                                       (variableScope->Parent() != nullptr && variableScope->Parent()->IsGlobalScope())
                                 : false;
    if (topLevelVariable) {
        return std::nullopt;
    }

    ASSERT(testCondition_.testedType != nullptr);
    if (!testCondition_.testedType->IsETSReferenceType()) {
        return std::nullopt;
    }

    auto *smartType = GetSmartCast(testCondition_.variable);
    if (smartType == nullptr) {
        smartType = testCondition_.variable->TsType();
        if (smartType == nullptr) {
            return std::nullopt;
        }
    }

    auto *const checker = parent_->AsETSChecker();
    Type *consequentType = nullptr;
    Type *alternateType = nullptr;

    if (testCondition_.testedType->DefinitelyETSNullish()) {
        // In case of testing for 'null' and/or 'undefined' remove corresponding null-like types.
        std::tie(consequentType, alternateType) =
            checker->CheckTestNullishCondition(testCondition_.testedType, smartType, testCondition_.strict);
    } else if (testCondition_.testedType->IsETSObjectType()) {
        auto *const testedType = testCondition_.testedType->AsETSObjectType();
        std::tie(consequentType, alternateType) =
            checker->CheckTestObjectCondition(testedType, smartType, testCondition_.strict);
    } else if (testCondition_.testedType->IsETSArrayType()) {
        auto *const testedType = testCondition_.testedType->AsETSArrayType();
        std::tie(consequentType, alternateType) = checker->CheckTestObjectCondition(testedType, smartType);
    } else if (testCondition_.strict) {
        std::tie(consequentType, alternateType) =
            ComputeConditionalSubtypes(checker->Relation(), testCondition_.testedType, smartType);
    }

    return !testCondition_.negate
               ? std::make_optional(std::make_tuple(testCondition_.variable, consequentType, alternateType))
               : std::make_optional(std::make_tuple(testCondition_.variable, alternateType, consequentType));
}
bool ETSChecker::CheckVoidAnnotation(const ir::ETSPrimitiveType *typeAnnotation)
{
    // Void annotation is valid only when used as 'return type' , 'type parameter instantiation', 'default type'.
    if (typeAnnotation->GetPrimitiveType() != ir::PrimitiveType::VOID) {
        return true;
    }

    auto parent = typeAnnotation->Parent();
    if (parent->IsScriptFunction() && parent->AsScriptFunction()->ReturnTypeAnnotation() == typeAnnotation) {
        return true;
    }
    if (parent->IsETSFunctionType() && parent->AsETSFunctionType()->ReturnType() == typeAnnotation) {
        return true;
    }
    if (parent->IsTSTypeParameterInstantiation() || parent->IsTSTypeParameter()) {
        return true;
    }
    LogError(diagnostic::ANNOT_IS_VOID, {}, typeAnnotation->Start());
    return false;
}
void ETSChecker::ApplySmartCast(varbinder::Variable const *const variable, checker::Type *const smartType) noexcept
{
    ES2PANDA_ASSERT(variable != nullptr);
    if (smartType != nullptr) {
        auto *variableType = variable->TsType();

        if (Relation()->IsIdenticalTo(variableType, smartType)) {
            Context().RemoveSmartCast(variable);
        } else {
            Context().SetSmartCast(variable, smartType);
        }
    }
}

bool CheckerContext::CheckTestOrSmartCastCondition(SmartCastTuple const &types)
{
    auto *const &variable = std::get<VARIABLE_POSITION>(types);
    auto *const &consequentTypeNew = std::get<CONSEQUENT_TYPE_POSITION>(types);
    auto *const &alternateTypeNew = std::get<ALTERNATE_TYPE_POSITION>(types);

    if (auto const it = testSmartCasts_.find(variable); it != testSmartCasts_.end()) {
        auto *const consequentTypeOld = it->second.first;
        if (consequentTypeOld == nullptr) {
            return true;
        }

        if (consequentTypeNew != nullptr && !parent_->Relation()->IsIdenticalTo(consequentTypeOld, consequentTypeNew)) {
            it->second.first = parent_->AsETSChecker()->CreateETSUnionType({consequentTypeOld, consequentTypeNew});
        }

        if (auto *const alternateTypeOld = it->second.second; alternateTypeOld != nullptr) {
            if (alternateTypeNew != nullptr &&
                !parent_->Relation()->IsIdenticalTo(alternateTypeOld, alternateTypeNew)) {
                it->second.second = parent_->AsETSChecker()->CreateETSUnionType({alternateTypeOld, alternateTypeNew});
            }
        } else {
            it->second.second = alternateTypeNew;
        }

        return false;
    }

    //  NOTE: now we support only cases like 'if (x != null || y != null)' or 'if (x instanceof A || x instanceof B)'
    //  although it seems that the resulting variable type in the second case isn't used in subsequent code directly.
    //  More complex conditions can be implemented later on if the need arises.
    testSmartCasts_.emplace(variable, std::make_pair(consequentTypeNew, alternateTypeNew));
    return true;
}

//==============================================================================//

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

// 22955: type alias should be instantiated with Substitute
static void CollectAliasParametersForBoxing(Type *expandedAliasType, std::set<Type *> &parametersNeedToBeBoxed,
                                            bool needToBeBoxed)
{
    if (expandedAliasType->IsETSTypeParameter() && needToBeBoxed) {
        parametersNeedToBeBoxed.insert(expandedAliasType);
    } else if (expandedAliasType->IsETSObjectType()) {
        auto objectType = expandedAliasType->AsETSObjectType();
        needToBeBoxed =
            objectType->GetDeclNode()->IsClassDefinition() || objectType->GetDeclNode()->IsTSInterfaceDeclaration();
        for (const auto typeArgument : objectType->TypeArguments()) {
            CollectAliasParametersForBoxing(typeArgument, parametersNeedToBeBoxed, needToBeBoxed);
        }
    } else if (expandedAliasType->IsETSTupleType()) {
        auto tupleType = expandedAliasType->AsETSTupleType();
        needToBeBoxed = false;
        for (auto type : tupleType->GetTupleTypesList()) {
            CollectAliasParametersForBoxing(type, parametersNeedToBeBoxed, needToBeBoxed);
        }
    } else if (expandedAliasType->IsETSArrayType()) {
        auto arrayType = expandedAliasType->AsETSArrayType();
        needToBeBoxed = false;
        auto elementType = arrayType->ElementType();
        CollectAliasParametersForBoxing(elementType, parametersNeedToBeBoxed, needToBeBoxed);
    } else if (expandedAliasType->IsETSUnionType()) {
        auto unionType = expandedAliasType->AsETSUnionType();
        needToBeBoxed = false;
        for (auto type : unionType->ConstituentTypes()) {
            CollectAliasParametersForBoxing(type, parametersNeedToBeBoxed, needToBeBoxed);
        }
    } else if (expandedAliasType->IsETSFunctionType()) {
        auto functionType = expandedAliasType->AsETSFunctionType();
        needToBeBoxed = true;
        for (auto param : functionType->ArrowSignature()->Params()) {
            CollectAliasParametersForBoxing(param->TsType(), parametersNeedToBeBoxed, needToBeBoxed);
        }
        CollectAliasParametersForBoxing(functionType->ArrowSignature()->ReturnType(), parametersNeedToBeBoxed,
                                        needToBeBoxed);
    }
}

bool ETSChecker::CheckMinimumTypeArgsPresent(const ir::TSTypeAliasDeclaration *typeAliasNode,
                                             const ir::TSTypeParameterInstantiation *typeParams)
{
    size_t minNumberOfTypeParams =
        std::count_if(typeAliasNode->TypeParams()->Params().begin(), typeAliasNode->TypeParams()->Params().end(),
                      [](const ir::TSTypeParameter *param) { return param->DefaultType() == nullptr; });
    if (minNumberOfTypeParams > typeParams->Params().size() ||
        typeParams->Params().size() > typeAliasNode->TypeParams()->Params().size()) {
        LogError(diagnostic::EXPECTED_TYPE_ARGUMENTS, {minNumberOfTypeParams, typeParams->Params().size()},
                 typeParams->Start());
        return true;
    }

    return false;
}

ir::TypeNode *ETSChecker::ResolveTypeNodeForTypeArg(const ir::TSTypeAliasDeclaration *typeAliasNode,
                                                    const ir::TSTypeParameterInstantiation *typeParams, size_t idx)
{
    if (typeParams->Params().size() > idx) {
        return typeParams->Params().at(idx);
    }

    return typeAliasNode->TypeParams()->Params().at(idx)->DefaultType();
}

Type *ETSChecker::HandleTypeAlias(ir::Expression *const name, const ir::TSTypeParameterInstantiation *const typeParams)
{
    ES2PANDA_ASSERT(name->IsIdentifier() && name->AsIdentifier()->Variable() &&
                    name->AsIdentifier()->Variable()->Declaration()->IsTypeAliasDecl());

    auto *const typeAliasNode =
        name->AsIdentifier()->Variable()->Declaration()->AsTypeAliasDecl()->Node()->AsTSTypeAliasDeclaration();

    // NOTE (mmartin): modify for default params
    if ((typeParams == nullptr) != (typeAliasNode->TypeParams() == nullptr)) {
        if (typeParams == nullptr) {
            LogError(diagnostic::GENERIC_ALIAS_WITHOUT_PARAMS, {}, name->Start());
            return GlobalTypeError();
        }

        LogError(diagnostic::NON_GENERIC_ALIAS_WITH_PARAMS, {}, typeParams->Start());
        return GlobalTypeError();
    }

    if (typeParams == nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return GetReferencedTypeBase(name);
    }

    for (auto *const origTypeParam : typeParams->Params()) {
        origTypeParam->Check(this);
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    Type *const aliasType = GetReferencedTypeBase(name);
    auto *substitution = NewSubstitution();

    if (CheckMinimumTypeArgsPresent(typeAliasNode, typeParams)) {
        return GlobalTypeError();
    }

    std::set<Type *> parametersNeedToBeBoxed;
    auto expandedAliasType = aliasType->Substitute(Relation(), substitution);
    CollectAliasParametersForBoxing(expandedAliasType, parametersNeedToBeBoxed, false);

    for (std::size_t idx = 0; idx < typeAliasNode->TypeParams()->Params().size(); ++idx) {
        auto *typeAliasTypeName = typeAliasNode->TypeParams()->Params().at(idx)->Name();
        auto *typeAliasType = typeAliasTypeName->Variable()->TsType();
        if (!typeAliasType->IsETSTypeParameter()) {
            continue;
        }

        ir::TypeNode *typeNode = ResolveTypeNodeForTypeArg(typeAliasNode, typeParams, idx);
        auto paramType = typeNode->GetType(this);

        if (parametersNeedToBeBoxed.find(typeAliasType) != parametersNeedToBeBoxed.end()) {
            if (const auto boxedType = MaybeBoxInRelation(typeNode->GetType(this)); boxedType != nullptr) {
                paramType = boxedType;
            }
        }
        substitution->insert({typeAliasType->AsETSTypeParameter(), paramType});  // #21835: type argument is not boxed
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ValidateGenericTypeAliasForClonedNode(typeAliasNode->AsTSTypeAliasDeclaration(), typeParams);

    return aliasType->Substitute(Relation(), substitution);
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

std::pair<bool, util::StringView> FindSpecifierForModuleObject(ir::ETSImportDeclaration *importDecl,
                                                               util::StringView const &name)
{
    if (importDecl == nullptr) {
        return std::make_pair(true, util::StringView());
    }

    for (auto item : importDecl->Specifiers()) {
        if (item->IsImportSpecifier() && item->AsImportSpecifier()->Imported()->Name().Is(name.Mutf8())) {
            if (!item->AsImportSpecifier()->Imported()->Name().Is(item->AsImportSpecifier()->Local()->Name().Mutf8())) {
                return std::make_pair(true, item->AsImportSpecifier()->Local()->Name());
            }
            return std::make_pair(true, util::StringView());
        }
    }
    return std::make_pair(false, util::StringView());
}

template <checker::PropertyType TYPE>
void ETSChecker::BindingsModuleObjectAddProperty(checker::ETSObjectType *moduleObjType,
                                                 ir::ETSImportDeclaration *importDecl,
                                                 const varbinder::Scope::VariableMap &bindings,
                                                 const util::StringView &importPath)
{
    for (auto [_, var] : bindings) {
        (void)_;
        auto [found, aliasedName] = FindSpecifierForModuleObject(importDecl, var->AsLocalVariable()->Name());
        if ((var->AsLocalVariable()->Declaration()->Node()->IsExported() ||
             var->AsLocalVariable()->Declaration()->Node()->IsExportedType()) &&
            found) {
            if (!aliasedName.Empty()) {
                moduleObjType->AddReExportAlias(var->Declaration()->Name(), aliasedName);
            }
            moduleObjType->AddProperty<TYPE>(
                var->AsLocalVariable(), FindPropNameForNamespaceImport(var->AsLocalVariable()->Name(), importPath));
        }
    }
}

util::StringView ETSChecker::FindPropNameForNamespaceImport(const util::StringView &originalName,
                                                            const util::StringView &importPath)
{
    auto exportAliases = VarBinder()->AsETSBinder()->GetSelectiveExportAliasMultimap();
    auto relatedMapItem = exportAliases.find(importPath);
    if (relatedMapItem != exportAliases.end()) {
        if (auto result = std::find_if(relatedMapItem->second.begin(), relatedMapItem->second.end(),
                                       [originalName](const auto &item) { return item.second.first == originalName; });
            result != relatedMapItem->second.end()) {
            return result->first;
        }
    }

    return originalName;
}

// Helps to prevent searching for the imported file among external sources if it is the entry program
static parser::Program *SelectEntryOrExternalProgram(varbinder::ETSBinder *etsBinder,
                                                     const util::StringView &importPath)
{
    if (importPath.Is(etsBinder->GetGlobalRecordTable()->Program()->AbsoluteName().Mutf8())) {
        return etsBinder->GetGlobalRecordTable()->Program();
    }

    auto programList = etsBinder->GetProgramList(importPath);
    return !programList.empty() ? programList.front() : nullptr;
}

void ETSChecker::SetPropertiesForModuleObject(checker::ETSObjectType *moduleObjType, const util::StringView &importPath,
                                              ir::ETSImportDeclaration *importDecl)
{
    parser::Program *program =
        SelectEntryOrExternalProgram(static_cast<varbinder::ETSBinder *>(VarBinder()), importPath);
    // Check imported properties before assigning them to module object
    if (!program->IsASTChecked()) {
        // NOTE: helps to avoid endless loop in case of recursive imports that uses all bindings
        program->MarkASTAsChecked();
        program->Ast()->Check(this);
    }

    BindingsModuleObjectAddProperty<checker::PropertyType::STATIC_FIELD>(
        moduleObjType, importDecl, program->GlobalClassScope()->StaticFieldScope()->Bindings(), importPath);

    BindingsModuleObjectAddProperty<checker::PropertyType::STATIC_METHOD>(
        moduleObjType, importDecl, program->GlobalClassScope()->StaticMethodScope()->Bindings(), importPath);

    BindingsModuleObjectAddProperty<checker::PropertyType::STATIC_DECL>(
        moduleObjType, importDecl, program->GlobalClassScope()->StaticDeclScope()->Bindings(), importPath);

    BindingsModuleObjectAddProperty<checker::PropertyType::STATIC_DECL>(
        moduleObjType, importDecl, program->GlobalClassScope()->InstanceDeclScope()->Bindings(), importPath);

    BindingsModuleObjectAddProperty<checker::PropertyType::STATIC_DECL>(
        moduleObjType, importDecl, program->GlobalClassScope()->TypeAliasScope()->Bindings(), importPath);
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
    return TypeError(name, "Invalid type reference.", name->Start());
}

Type *ETSChecker::GetReferencedTypeBase(ir::Expression *name)
{
    if (name->IsTSQualifiedName()) {
        return name->Check(this);
    }

    ES2PANDA_ASSERT(name->IsIdentifier());

    auto *const var = name->AsIdentifier()->Variable();
    ES2PANDA_ASSERT(var != nullptr);

    if (var->TsType() != nullptr && var->TsType()->IsTypeError()) {
        return name->SetTsType(GlobalTypeError());
    }

    auto *importData = VarBinder()->AsETSBinder()->DynamicImportDataForVar(var);
    if (importData != nullptr && importData->import->IsPureDynamic()) {
        return name->SetTsType(GlobalBuiltinDynamicType(importData->import->Language()));
    }

    return name->SetTsType(ResolveReferencedType(var->AsLocalVariable(), name));
}

Type *ETSChecker::ResolveReferencedType(varbinder::LocalVariable *refVar, const ir::Expression *name)
{
    switch (refVar->Declaration()->Node()->Type()) {
        case ir::AstNodeType::TS_INTERFACE_DECLARATION:
            return GetTypeFromInterfaceReference(refVar);
        case ir::AstNodeType::CLASS_DECLARATION:
        case ir::AstNodeType::STRUCT_DECLARATION:
        case ir::AstNodeType::CLASS_DEFINITION:
            if (refVar->Declaration()->Node()->AsClassDefinition()->IsNamespaceTransformed()) {
                LogError(diagnostic::NAMESPACE_AS_TYPE, {refVar->Name()}, name->Start());
                return GlobalTypeError();
            }
            return GetTypeFromClassReference(refVar);
        case ir::AstNodeType::TS_ENUM_DECLARATION:
            return GetTypeFromEnumReference(refVar);
        case ir::AstNodeType::TS_TYPE_PARAMETER:
            return GetTypeFromTypeParameterReference(refVar, name->Start());
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
            return GetTypeFromTypeAliasReference(refVar);
        case ir::AstNodeType::ANNOTATION_DECLARATION:
            LogError(diagnostic::ANNOTATION_AS_TYPE, {}, name->Start());
            return GlobalTypeError();

        default:
            UNREACHABLE();
    }
}

void ETSChecker::ConcatConstantString(util::UString &target, Type *type)
{
    switch (ETSType(type)) {
        case TypeFlag::ETS_OBJECT: {
            ES2PANDA_ASSERT(type->IsETSStringType());
            target.Append(type->AsETSStringType()->GetValue());
            break;
        }
        case TypeFlag::ETS_BOOLEAN: {
            target.Append(type->AsETSBooleanType()->GetValue() ? "true" : "false");
            break;
        }
        case TypeFlag::BYTE: {
            target.Append(std::to_string(type->AsByteType()->GetValue()));
            break;
        }
        case TypeFlag::CHAR: {
            std::string s(1, type->AsCharType()->GetValue());
            target.Append(s);
            break;
        }
        case TypeFlag::SHORT: {
            target.Append(std::to_string(type->AsShortType()->GetValue()));
            break;
        }
        case TypeFlag::INT: {
            target.Append(std::to_string(type->AsIntType()->GetValue()));
            break;
        }
        case TypeFlag::LONG: {
            target.Append(std::to_string(type->AsLongType()->GetValue()));
            break;
        }
        case TypeFlag::FLOAT: {
            target.Append(std::to_string(type->AsFloatType()->GetValue()));
            break;
        }
        case TypeFlag::DOUBLE: {
            target.Append(std::to_string(type->AsDoubleType()->GetValue()));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

Type *ETSChecker::HandleStringConcatenation(Type *leftType, Type *rightType)
{
    ES2PANDA_ASSERT(leftType->IsETSStringType() || rightType->IsETSStringType());

    if (!leftType->HasTypeFlag(checker::TypeFlag::CONSTANT) || !rightType->HasTypeFlag(checker::TypeFlag::CONSTANT) ||
        leftType->IsETSBigIntType() || rightType->IsETSBigIntType()) {
        return GlobalETSStringLiteralType();
    }

    util::UString concatenated(Allocator());
    ConcatConstantString(concatenated, leftType);
    ConcatConstantString(concatenated, rightType);

    return CreateETSStringLiteralType(concatenated.View());
}

checker::ETSFunctionType *ETSChecker::FindFunctionInVectorGivenByName(util::StringView name,
                                                                      ArenaVector<checker::ETSFunctionType *> &list)
{
    for (auto *it : list) {
        if (it->Name() == name) {
            return it;
        }
    }

    return nullptr;
}

bool ETSChecker::IsFunctionContainsSignature(checker::ETSFunctionType *funcType, Signature *signature)
{
    for (auto *it : funcType->CallSignatures()) {
        Relation()->SignatureIsSupertypeOf(it, signature);
        if (Relation()->IsTrue()) {
            return true;
        }
    }

    return false;
}

bool ETSChecker::CheckFunctionContainsClashingSignature(const checker::ETSFunctionType *funcType, Signature *signature)
{
    for (auto *it : funcType->CallSignatures()) {
        SavedTypeRelationFlagsContext strfCtx(Relation(), TypeRelationFlag::NONE);
        Relation()->SignatureIsSupertypeOf(it, signature);
        if (Relation()->IsTrue() && it->Function()->Id()->Name() == signature->Function()->Id()->Name()) {
            std::stringstream ss;
            it->ToString(ss, nullptr, true);
            auto sigStr1 = ss.str();
            ss.str(std::string {});  // Clear buffer
            signature->ToString(ss, nullptr, true);
            auto sigStr2 = ss.str();
            LogError(
                diagnostic::FUNCTION_REDECLERATION,
                {it->Function()->Id()->Name(), sigStr1.c_str(), signature->Function()->Id()->Name(), sigStr2.c_str()},
                signature->Function()->ReturnTypeAnnotation()->Start());
            return false;
        }
    }
    return true;
}

void ETSChecker::MergeSignatures(checker::ETSFunctionType *target, checker::ETSFunctionType *source)
{
    for (auto *s : source->CallSignatures()) {
        if (IsFunctionContainsSignature(target, s)) {
            continue;
        }

        if (!CheckFunctionContainsClashingSignature(target, s)) {
            continue;
        }
        target->AddCallSignature(s);
    }
}

void ETSChecker::MergeComputedAbstracts(ArenaVector<checker::ETSFunctionType *> &merged,
                                        ArenaVector<checker::ETSFunctionType *> &current)
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
    ES2PANDA_ASSERT(signature->Function());
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

std::optional<const ir::AstNode *> ETSChecker::FindJumpTarget(ir::AstNode *node)
{
    ES2PANDA_ASSERT(node->IsBreakStatement() || node->IsContinueStatement());

    bool const isContinue = node->IsContinueStatement();

    // Look for label
    auto label = isContinue ? node->AsContinueStatement()->Ident() : node->AsBreakStatement()->Ident();
    if (label != nullptr) {
        if (auto var = label->Variable(); var == nullptr) {
            varbinder::LetDecl *decl;
            std::tie(decl, var) = VarBinder()->NewVarDecl<varbinder::LetDecl>(
                label->Start(), !label->IsErrorPlaceHolder() ? label->Name() : compiler::GenName(Allocator()).View());
            var->SetScope(VarBinder()->GetScope());
            label->SetVariable(var);
            decl->BindNode(label);
            label->SetTsType(var->SetTsType(GlobalTypeError()));
        } else if (var->Declaration()->IsLabelDecl()) {
            return var->Declaration()->Node();
        }

        // Failed to resolve variable for label
        LogUnresolvedReferenceError(label);
        return {};
    }

    // No label, find the nearest loop or switch statement
    const auto *iter = node->Parent();
    while (iter != nullptr) {
        switch (iter->Type()) {
            case ir::AstNodeType::DO_WHILE_STATEMENT:
            case ir::AstNodeType::WHILE_STATEMENT:
            case ir::AstNodeType::FOR_UPDATE_STATEMENT:
            case ir::AstNodeType::FOR_OF_STATEMENT:
            case ir::AstNodeType::SWITCH_STATEMENT: {
                return iter;
            }
            default: {
                break;
            }
        }

        iter = iter->Parent();
    }

    LogError(diagnostic::FLOW_REDIRECTION_INVALID_CTX, {}, node->Start());
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

Type *ETSChecker::CheckSwitchDiscriminant(ir::Expression *discriminant)
{
    discriminant->Check(this);
    auto *discriminantType = GetNonConstantType(MaybeUnboxExpression(discriminant));
    if (!discriminantType->HasTypeFlag(TypeFlag::VALID_SWITCH_TYPE)) {
        if (!(discriminantType->IsETSObjectType() &&
              discriminantType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_STRING |
                                                                 ETSObjectFlags::STRING | ETSObjectFlags::ENUM))) {
            LogError(diagnostic::ENUM_INVALID_DISCRIMINANT, {discriminantType}, discriminant->Start());
        }
    }

    return discriminantType;
}

void ETSChecker::AddBoxingUnboxingFlagsToNode(ir::AstNode *node, Type *boxingUnboxingType)
{
    if (boxingUnboxingType->IsETSObjectType()) {
        node->AddBoxingUnboxingFlags(GetBoxingFlag(boxingUnboxingType));
    } else if (!boxingUnboxingType->IsETSUnionType()) {
        node->AddBoxingUnboxingFlags(GetUnboxingFlag(boxingUnboxingType));
    }
}

Type *ETSChecker::MaybeBoxExpression(ir::Expression *expr)
{
    auto *promoted = MaybeBoxType(expr->TsType());
    if (promoted != expr->TsType()) {
        expr->AddBoxingUnboxingFlags(GetBoxingFlag(promoted));
    }
    return promoted;
}

Type *ETSChecker::MaybeUnboxExpression(ir::Expression *expr)
{
    auto *primitive = MaybeUnboxType(expr->TsType());
    if (primitive != expr->TsType()) {
        expr->AddBoxingUnboxingFlags(GetUnboxingFlag(primitive));
    }
    return primitive;
}

void ETSChecker::CheckForSameSwitchCases(ArenaVector<ir::SwitchCaseStatement *> const &cases)
{
    CheckItemCasesConstant(cases);
    CheckItemCasesDuplicate(cases);
}

std::string ETSChecker::GetStringFromIdentifierValue(checker::Type *caseType) const
{
    if (caseType->IsETSStringType()) {
        return std::string(caseType->AsETSStringType()->GetValue());
    }
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
            return "error";
        }
        default: {
            UNREACHABLE();
        }
    }
}

bool IsConstantMemberOrIdentifierExpression(ir::Expression *expression)
{
    varbinder::Variable *var = nullptr;
    if (expression->IsIdentifier()) {
        var = expression->AsIdentifier()->Variable();
    } else if (expression->IsMemberExpression()) {
        var = expression->AsMemberExpression()->PropVar();
    }
    return var != nullptr && (var->Declaration()->IsConstDecl() ||
                              (var->Declaration()->IsReadonlyDecl() && var->HasFlag(varbinder::VariableFlags::STATIC)));
}

static bool IsValidSwitchType(checker::Type *caseType)
{
    return caseType->HasTypeFlag(checker::TypeFlag::VALID_SWITCH_TYPE) || caseType->IsETSStringType();
}

void ETSChecker::CheckItemCasesConstant(ArenaVector<ir::SwitchCaseStatement *> const &cases)
{
    for (auto &it : cases) {
        auto *caseTest = it->Test();
        if (caseTest == nullptr) {
            continue;
        }
        auto *caseType = caseTest->TsType();
        if (caseType->HasTypeFlag(TypeFlag::TYPE_ERROR)) {
            continue;
        }
        if (caseTest->TsType()->IsETSEnumType()) {
            continue;
        }

        if (caseTest->IsIdentifier() || caseTest->IsMemberExpression()) {
            if (!IsConstantMemberOrIdentifierExpression(caseTest)) {
                LogError(diagnostic::NOT_CONSTANT, {}, it->Start());
                continue;
            }

            if (!IsValidSwitchType(caseType)) {
                LogError(diagnostic::SWITCH_CASE_INVALID_TYPE, {caseType}, it->Start());
            }
        }
    }
}

void CheckItemEnumType(ir::Expression const *const caseTest, ETSChecker *checker, ETSIntEnumType const *const type,
                       bool &isDup)
{
    if (caseTest->TsType()->AsETSIntEnumType()->IsSameEnumLiteralType(type)) {
        isDup = true;
        checker->LogError(diagnostic::SWITCH_CASE_DUPLICATE, {}, caseTest->Start());
    }
}

void CheckItemStringEnumType(ir::Expression const *const caseTest, ETSChecker *checker,
                             ETSStringEnumType const *const type, bool &isDup)
{
    if (caseTest->TsType()->AsETSStringEnumType()->IsSameEnumLiteralType(type)) {
        isDup = true;
        checker->LogError(diagnostic::SWITCH_CASE_DUPLICATE, {}, caseTest->Start());
    }
}

void ETSChecker::CheckItemCasesDuplicate(ArenaVector<ir::SwitchCaseStatement *> const &cases)
{
    for (size_t caseNum = 0; caseNum < cases.size(); caseNum++) {
        bool isItemDuplicate = false;
        for (size_t compareCase = caseNum + 1; compareCase < cases.size(); compareCase++) {
            auto *caseTest = cases.at(caseNum)->Test();
            auto *compareCaseTest = cases.at(compareCase)->Test();

            if (caseTest == nullptr || compareCaseTest == nullptr) {
                continue;
            }

            if (caseTest->TsType()->IsETSIntEnumType()) {
                CheckItemEnumType(caseTest, this, compareCaseTest->TsType()->AsETSIntEnumType(), isItemDuplicate);
                continue;
            }

            if (caseTest->TsType()->IsETSStringEnumType()) {
                CheckItemStringEnumType(caseTest, this, compareCaseTest->TsType()->AsETSStringEnumType(),
                                        isItemDuplicate);
                continue;
            }

            if (caseTest->IsIdentifier() || caseTest->IsMemberExpression()) {
                CheckIdentifierSwitchCase(caseTest, compareCaseTest, cases.at(caseNum)->Start());
                continue;
            }

            if (compareCaseTest->IsIdentifier() || compareCaseTest->IsMemberExpression()) {
                CheckIdentifierSwitchCase(compareCaseTest, caseTest, cases.at(compareCase)->Start());
                continue;
            }

            if (caseTest->IsLiteral() && compareCaseTest->IsLiteral() &&
                GetStringFromLiteral(caseTest) != GetStringFromLiteral(compareCaseTest)) {
                continue;
            }

            if (!(IsConstantExpression(caseTest, caseTest->TsType()) || caseTest->IsLiteral()) ||
                !(IsConstantExpression(compareCaseTest, compareCaseTest->TsType()) || compareCaseTest->IsLiteral())) {
                continue;
            }

            if (!isItemDuplicate) {
                isItemDuplicate = true;
                LogError(diagnostic::SWITCH_CASE_DUPLICATE, {}, cases.at(compareCase)->Start());
            }
        }
    }
}

bool ETSChecker::CompareIdentifiersValuesAreDifferent(ir::Expression *compareValue, const std::string &caseValue)
{
    checker::Type *compareCaseType = compareValue->TsType();

    if (compareCaseType->HasTypeFlag(TypeFlag::TYPE_ERROR)) {
        return true;
    }

    if (IsConstantMemberOrIdentifierExpression(compareValue)) {
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
        return;
    }

    checker::Type *caseType = currentCase->TsType();

    if (!IsValidSwitchType(caseType)) {
        return;
    }

    if (!CompareIdentifiersValuesAreDifferent(compareCase, GetStringFromIdentifierValue(caseType))) {
        LogError(diagnostic::SWITCH_CASE_VAR_DUPLICATE_VAL, {}, pos);
        return;
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
    return target->Declaration()->Type() == compare->Declaration()->Type();
}

bool ETSChecker::CheckRethrowingParams([[maybe_unused]] const ir::AstNode *ancestorFunction,
                                       [[maybe_unused]] const ir::AstNode *node)
{
    // #22954: the previous implementation compared different identifiers by string
    return true;
}

void ETSChecker::CheckThrowingStatements(ir::AstNode *node)
{
    ir::AstNode *ancestorFunction = FindAncestorGivenByType(node, ir::AstNodeType::SCRIPT_FUNCTION);

    if (ancestorFunction == nullptr) {
        LogError(diagnostic::MISSING_EXCEPTION_HANDLING, {}, node->Start());
        return;
    }

    if (ancestorFunction->AsScriptFunction()->IsThrowing() ||
        (ancestorFunction->AsScriptFunction()->IsRethrowing() &&
         (!node->IsThrowStatement() && CheckRethrowingParams(ancestorFunction, node)))) {
        return;
    }

    if (!CheckThrowingPlacement(node, ancestorFunction)) {
        if (ancestorFunction->AsScriptFunction()->IsRethrowing() && !node->IsThrowStatement()) {
            LogError(diagnostic::RETHROW_NOT_BY_PARAM, {}, node->Start());
            return;
        }

        if (auto interfaces =
                ancestorFunction->AsScriptFunction()->Signature()->Owner()->AsETSObjectType()->Interfaces();
            !(!interfaces.empty() &&
              interfaces[0]->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL_INTERFACE))) {
            LogError(diagnostic::MISSING_EXCEPTION_HANDLING, {}, node->Start());
            return;
        }
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
    if (func->Signature()->Owner()->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL_INTERFACE)) {
        return;
    }

    bool foundThrowingParam = false;

    // It doesn't support lambdas yet.
    for (auto item : func->Params()) {
        auto const *typeAnnotation = item->AsETSParameterExpression()->TypeAnnotation();

        if (typeAnnotation->IsETSTypeReference()) {
            auto *typeDecl =
                typeAnnotation->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Variable()->Declaration();
            if (typeDecl->IsTypeAliasDecl()) {
                typeAnnotation = typeDecl->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation();
            }
        }

        if (typeAnnotation->IsETSFunctionType() && typeAnnotation->AsETSFunctionType()->IsThrowing()) {
            foundThrowingParam = true;
            break;
        }
    }

    if (!foundThrowingParam) {
        LogError(diagnostic::RETHROW_WITHOUT_THROWING_FUNC_PARAM, {}, func->Start());
    }
}

ETSObjectType *ETSChecker::GetRelevantArgumentedTypeFromChild(ETSObjectType *const child, ETSObjectType *const target)
{
    if (child->GetDeclNode() == target->GetDeclNode()) {
        auto *relevantType = CreateETSObjectType(child->GetDeclNode(), child->ObjectFlags());

        ArenaVector<Type *> params = child->TypeArguments();

        relevantType->SetTypeArguments(std::move(params));
        relevantType->SetEnclosingType(child->EnclosingType());
        relevantType->SetSuperType(child->SuperType());

        return relevantType;
    }

    ES2PANDA_ASSERT(child->SuperType() != nullptr);

    return GetRelevantArgumentedTypeFromChild(child->SuperType(), target);
}

void ETSChecker::EmplaceSubstituted(Substitution *substitution, ETSTypeParameter *tparam, Type *typeArg)
{
    // *only* reference type may be substituted, no exceptions
    ES2PANDA_ASSERT(typeArg->IsETSReferenceType());
    substitution->emplace(tparam, typeArg);
}

util::StringView ETSChecker::GetHashFromTypeArguments(const ArenaVector<Type *> &typeArgTypes)
{
    std::stringstream ss;

    for (auto *it : typeArgTypes) {
        it->ToString(ss, true);
        ss << compiler::Signatures::MANGLE_SEPARATOR;

        // In case of ETSTypeParameters storing the name might not be sufficient as there can
        // be multiple different type parameters with the same name. For those we test identity based
        // on their memory address equality, so we store them in the hash to keep it unique.
        // To make it consistent we store it for every type.
        // NOTE (mmartin): change bare address to something more appropriate unique representation
        ss << it << compiler::Signatures::MANGLE_SEPARATOR;
    }

    return util::UString(ss.str(), Allocator()).View();
}

util::StringView ETSChecker::GetHashFromSubstitution(const Substitution *substitution, const bool extensionFuncFlag)
{
    std::vector<std::string> fields;
    for (auto [k, v] : *substitution) {
        std::stringstream ss;
        k->ToString(ss, true);
        ss << ":";
        v->ToString(ss, true);
        // NOTE (mmartin): change bare address to something more appropriate unique representation
        ss << ":" << k << ":" << v;
        fields.push_back(ss.str());
    }
    std::sort(fields.begin(), fields.end());

    std::stringstream ss;
    for (auto &fstr : fields) {
        ss << fstr;
        ss << ";";
    }

    if (extensionFuncFlag) {
        ss << "extensionFunctionType;";
    }
    return util::UString(ss.str(), Allocator()).View();
}

util::StringView ETSChecker::GetHashFromFunctionType(ir::ETSFunctionType *type)
{
    std::stringstream ss;
    for (auto *p : type->Params()) {
        auto *const param = p->AsETSParameterExpression();
        param->TypeAnnotation()->GetType(this)->ToString(ss, true);
        ss << ";";
    }

    if (type->IsExtensionFunction()) {
        if (type->ReturnType()->IsTSThisType()) {
            type->Params()[0]->AsETSParameterExpression()->TypeAnnotation()->TsType()->ToString(ss, true);
        } else {
            type->ReturnType()->GetType(this)->ToString(ss, true);
        }
        ss << "extensionFunction;";
    } else {
        type->ReturnType()->GetType(this)->ToString(ss, true);
    }

    ss << ";";

    if (type->IsThrowing()) {
        ss << "throws;";
    }

    if (type->IsRethrowing()) {
        ss << "rethrows;";
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

void ETSChecker::CheckValidGenericTypeParameter(Type *const argType, const lexer::SourcePosition &pos)
{
    std::stringstream ss;
    argType->ToString(ss);
    LogError(diagnostic::INVALID_TYPE_PARAM, {ss.str()}, pos);
}

bool ETSChecker::CheckNumberOfTypeArguments(ETSObjectType *const type, ir::TSTypeParameterInstantiation *const typeArgs,
                                            const lexer::SourcePosition &pos)
{
    auto const &typeParams = type->TypeArguments();
    if (typeParams.empty()) {
        if (typeArgs != nullptr) {
            LogError(diagnostic::NOT_GENERIC, {type}, pos);
            return false;
        }
        return true;
    }

    size_t minimumTypeArgs = std::count_if(typeParams.begin(), typeParams.end(), [](Type *param) {
        return param->IsETSTypeParameter() && param->AsETSTypeParameter()->GetDefaultType() == nullptr;
    });
    if (typeArgs == nullptr && minimumTypeArgs > 0) {
        LogError(diagnostic::GENERIC_WITHOUT_TYPE_PARAMS, {type}, pos);
        return false;
    }

    if (typeArgs != nullptr &&
        ((minimumTypeArgs > typeArgs->Params().size()) || (typeParams.size() < typeArgs->Params().size()))) {
        LogError(diagnostic::GENERIC_TYPE_PARAM_COUNT_MISMATCH, {type, minimumTypeArgs, typeArgs->Params().size()},
                 pos);
        return false;
    }
    return true;
}

bool ETSChecker::NeedTypeInference(const ir::ScriptFunction *lambda)
{
    if (lambda->ReturnTypeAnnotation() == nullptr) {
        return true;
    }
    for (auto *const param : lambda->Params()) {
        if (param->AsETSParameterExpression()->TypeAnnotation() == nullptr) {
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

// #22952: optional arrow leftovers
bool ETSChecker::CheckLambdaAssignableUnion(ir::AstNode *typeAnn, ir::ScriptFunction *lambda)
{
    for (auto *type : typeAnn->AsETSUnionType()->Types()) {
        if (type->IsETSFunctionType()) {
            return lambda->Params().size() == type->AsETSFunctionType()->Params().size();
        }
    }

    return false;
}

void ETSChecker::InferTypesForLambda(ir::ScriptFunction *lambda, ir::ETSFunctionType *calleeType,
                                     Signature *maybeSubstitutedFunctionSig)
{
    for (size_t i = 0; i < lambda->Params().size(); ++i) {
        const auto *const calleeParam = calleeType->Params()[i]->AsETSParameterExpression()->Ident();
        auto *const lambdaParam = lambda->Params().at(i)->AsETSParameterExpression()->Ident();
        if (lambdaParam->TypeAnnotation() == nullptr) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *const typeAnnotation = calleeParam->TypeAnnotation()->Clone(Allocator(), lambdaParam);
            if (maybeSubstitutedFunctionSig != nullptr) {
                ES2PANDA_ASSERT(maybeSubstitutedFunctionSig->Params().size() == calleeType->Params().size());
                typeAnnotation->SetTsType(maybeSubstitutedFunctionSig->Params()[i]->TsType());
            }
            lambdaParam->SetTsTypeAnnotation(typeAnnotation);
        }
    }

    if (lambda->ReturnTypeAnnotation() == nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const returnTypeAnnotation = calleeType->ReturnType()->Clone(Allocator(), lambda);
        if (maybeSubstitutedFunctionSig != nullptr) {
            returnTypeAnnotation->SetTsType(maybeSubstitutedFunctionSig->ReturnType());
        }

        // Return type can be ETSFunctionType
        // Run varbinder to set scopes for cloned node
        compiler::InitScopesPhaseETS::RunExternalNode(returnTypeAnnotation, VarBinder());
        lambda->SetReturnTypeAnnotation(returnTypeAnnotation);
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

bool ETSChecker::IsInLocalClass(const ir::AstNode *node) const
{
    while (node != nullptr) {
        if (node->Type() == ir::AstNodeType::CLASS_DEFINITION) {
            return node->AsClassDefinition()->IsLocal();
        }
        node = node->Parent();
    }

    return false;
}

ir::Expression *ETSChecker::GenerateImplicitInstantiateArg(const std::string &className)
{
    std::string implicitInstantiateArgument = "()=>{return new " + className + "()}";
    parser::Program program(Allocator(), VarBinder());
    auto parser = parser::ETSParser(&program, nullptr, DiagnosticEngine());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *argExpr = parser.CreateExpression(implicitInstantiateArgument);
    // NOTE(kaskov): #23399 We temporary delete SourceRange of all artificially created nodes (not from original
    // Lexer()), because all errors, which created by this code, will got a segfault. That caused because Program exist
    // till the end this function, and not avaible in diagnosticEngine. Now errors printed, but whitout position
    // because it doesn't actually exist). PS.Previously written competely wrong positons and file, so situation
    // isn't changed.
    compiler::SetSourceRangesRecursively(argExpr, lexer::SourceRange());
    argExpr->IterateRecursively([](ir::AstNode *node) -> void { node->SetRange(lexer::SourceRange()); });
    compiler::InitScopesPhaseETS::RunExternalNode(argExpr, &program);

    return argExpr;
}

ir::ClassProperty *ETSChecker::ClassPropToImplementationProp(ir::ClassProperty *classProp, varbinder::ClassScope *scope)
{
    classProp->Key()->AsIdentifier()->SetName(
        util::UString(std::string(compiler::Signatures::PROPERTY) + classProp->Key()->AsIdentifier()->Name().Mutf8(),
                      Allocator())
            .View());
    classProp->AddModifier(ir::ModifierFlags::PRIVATE);

    auto *fieldDecl = Allocator()->New<varbinder::LetDecl>(classProp->Key()->AsIdentifier()->Name());
    fieldDecl->BindNode(classProp);

    auto fieldVar = scope->InstanceFieldScope()->AddDecl(Allocator(), fieldDecl, ScriptExtension::STS);
    fieldVar->AddFlag(varbinder::VariableFlags::PROPERTY);
    classProp->Key()->SetVariable(fieldVar);
    fieldVar->SetTsType(classProp->TsType());

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), scope);
    compiler::InitScopesPhaseETS::RunExternalNode(classProp->Value(), VarBinder());

    return classProp;
}

void ETSChecker::GenerateGetterSetterBody(ArenaVector<ir::Statement *> &stmts, ArenaVector<ir::Expression *> &params,
                                          ir::ClassProperty *const field, varbinder::FunctionParamScope *paramScope,
                                          bool isSetter)
{
    auto *classDef = field->Parent()->AsClassDefinition();

    ir::Expression *baseExpression;
    if ((field->Modifiers() & ir::ModifierFlags::SUPER_OWNER) != 0U) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        baseExpression = Allocator()->New<ir::SuperExpression>();
    } else {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        baseExpression = Allocator()->New<ir::ThisExpression>();
    }
    baseExpression->SetParent(classDef);
    baseExpression->SetTsType(classDef->TsType());

    auto *memberExpression =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::MemberExpression>(baseExpression, field->Key()->AsIdentifier()->Clone(Allocator(), nullptr),
                                        ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    memberExpression->SetTsType(field->TsType());
    memberExpression->SetPropVar(field->Key()->Variable()->AsLocalVariable());
    memberExpression->SetRange(classDef->Range());
    if (memberExpression->ObjType() == nullptr && classDef->TsType() != nullptr) {
        memberExpression->SetObjectType(classDef->TsType()->AsETSObjectType());
    }

    if (!isSetter) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        stmts.push_back(AllocNode<ir::ReturnStatement>(memberExpression));
        return;
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *paramIdent = field->Key()->AsIdentifier()->Clone(Allocator(), nullptr);
    if (field->TypeAnnotation() != nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const typeAnnotation = field->TypeAnnotation()->Clone(Allocator(), paramIdent);
        paramIdent->SetTsTypeAnnotation(typeAnnotation);
    } else {
        paramIdent->SetTsType(field->TsType());
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *paramExpression = AllocNode<ir::ETSParameterExpression>(paramIdent, false, Allocator());
    paramExpression->SetRange(paramIdent->Range());

    auto [paramVar, node] = paramScope->AddParamDecl(Allocator(), paramExpression);
    if (node != nullptr) {
        VarBinder()->ThrowRedeclaration(node->Start(), paramVar->Name());
    }

    paramExpression->SetVariable(paramVar);
    params.push_back(paramExpression);

    auto *assignmentExpression = AllocNode<ir::AssignmentExpression>(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        memberExpression, paramExpression->Clone(Allocator(), nullptr), lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignmentExpression->SetTsType(paramVar->TsType());

    assignmentExpression->SetRange({field->Start(), field->End()});
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    stmts.push_back(AllocNode<ir::ExpressionStatement>(assignmentExpression));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    stmts.push_back(Allocator()->New<ir::ReturnStatement>(nullptr));
}

ir::MethodDefinition *ETSChecker::GenerateDefaultGetterSetter(ir::ClassProperty *const property,
                                                              ir::ClassProperty *const field,
                                                              varbinder::ClassScope *classScope, bool isSetter,
                                                              ETSChecker *checker)
{
    auto *paramScope = checker->Allocator()->New<varbinder::FunctionParamScope>(checker->Allocator(), classScope);
    auto *functionScope = checker->Allocator()->New<varbinder::FunctionScope>(checker->Allocator(), paramScope);

    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);

    ArenaVector<ir::Expression *> params(checker->Allocator()->Adapter());
    ArenaVector<ir::Statement *> stmts(checker->Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    checker->GenerateGetterSetterBody(stmts, params, field, paramScope, isSetter);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = checker->AllocNode<ir::BlockStatement>(checker->Allocator(), std::move(stmts));
    auto funcFlags = isSetter ? ir::ScriptFunctionFlags::SETTER : ir::ScriptFunctionFlags::GETTER;
    auto *const returnTypeAnn = isSetter || field->TypeAnnotation() == nullptr
                                    ? nullptr
                                    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                    : field->TypeAnnotation()->Clone(checker->Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = checker->AllocNode<ir::ScriptFunction>(
        checker->Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), returnTypeAnn),
                                                funcFlags, ir::ModifierFlags::PUBLIC});

    if (!isSetter) {
        func->AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);
    }
    func->SetRange(field->Range());
    func->SetScope(functionScope);
    body->SetScope(functionScope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *methodIdent = property->Key()->AsIdentifier()->Clone(checker->Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = checker->AllocNode<ir::FunctionExpression>(func);
    funcExpr->SetRange(func->Range());
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *method = checker->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, methodIdent, funcExpr,
                                                            ir::ModifierFlags::PUBLIC, checker->Allocator(), false);

    auto *decl = checker->Allocator()->New<varbinder::FunctionDecl>(checker->Allocator(),
                                                                    property->Key()->AsIdentifier()->Name(), method);
    auto *var = checker->Allocator()->New<varbinder::LocalVariable>(decl, varbinder::VariableFlags::VAR);
    var->AddFlag(varbinder::VariableFlags::METHOD);

    methodIdent->SetVariable(var);

    method->Id()->SetMutator();
    method->SetRange(field->Range());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    method->Function()->SetIdent(method->Id()->Clone(checker->Allocator(), nullptr));
    method->Function()->AddModifier(method->Modifiers());
    method->SetVariable(var);
    method->SetParent(field->Parent());

    paramScope->BindNode(func);
    functionScope->BindNode(func);

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(checker->VarBinder(), classScope);
    checker->VarBinder()->AsETSBinder()->ResolveMethodDefinition(method);

    functionScope->BindName(classScope->Node()->AsClassDefinition()->InternalName());
    method->Check(checker);

    return method;
}

ir::ClassProperty *GetImplementationClassProp(ETSChecker *checker, ir::ClassProperty *interfaceProp,
                                              ir::ClassProperty *originalProp, ETSObjectType *classType)
{
    bool isSuperOwner = ((originalProp->Modifiers() & ir::ModifierFlags::SUPER_OWNER) != 0U);
    if (!isSuperOwner) {
        auto *const classDef = classType->GetDeclNode()->AsClassDefinition();
        auto *const scope = checker->Scope()->AsClassScope();
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const classProp = checker->ClassPropToImplementationProp(
            interfaceProp->Clone(checker->Allocator(), originalProp->Parent()), scope);
        classType->AddProperty<PropertyType::INSTANCE_FIELD>(classProp->Key()->Variable()->AsLocalVariable());
        classDef->Body().push_back(classProp);
        return classProp;
    }

    auto *const classProp = classType
                                ->GetProperty(interfaceProp->Key()->AsIdentifier()->Name(),
                                              PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE)
                                ->Declaration()
                                ->Node()
                                ->AsClassProperty();
    classProp->AddModifier(ir::ModifierFlags::SUPER_OWNER);
    return classProp;
}

static void SetupGetterSetterFlags(ir::ClassProperty *originalProp, ETSObjectType *classType,
                                   ir::MethodDefinition *getter, ir::MethodDefinition *setter, const bool inExternal)
{
    auto *const classDef = classType->GetDeclNode()->AsClassDefinition();
    for (auto &method : {getter, setter}) {
        if (method == nullptr) {
            continue;
        }

        const auto mflag = method == getter ? ir::ModifierFlags::GETTER : ir::ModifierFlags::SETTER;
        const auto tflag = method == getter ? TypeFlag::GETTER : TypeFlag::SETTER;

        method->TsType()->AddTypeFlag(tflag);
        method->Variable()->SetTsType(method->TsType());
        if (((originalProp->Modifiers() & mflag) != 0U)) {
            method->Function()->AddModifier(ir::ModifierFlags::OVERRIDE);
        }

        if (inExternal) {
            method->Function()->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
        }
        method->SetParent(classDef);
        classType->AddProperty<checker::PropertyType::INSTANCE_METHOD>(method->Variable()->AsLocalVariable());
    }
}

void ETSChecker::GenerateGetterSetterPropertyAndMethod(ir::ClassProperty *originalProp, ETSObjectType *classType)
{
    auto *const classDef = classType->GetDeclNode()->AsClassDefinition();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *interfaceProp = originalProp->Clone(Allocator(), originalProp->Parent());
    interfaceProp->ClearModifier(ir::ModifierFlags::GETTER_SETTER);

    auto *const scope = Scope()->AsClassScope();
    scope->InstanceFieldScope()->EraseBinding(interfaceProp->Key()->AsIdentifier()->Name());
    interfaceProp->SetRange(originalProp->Range());

    auto classCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(VarBinder(), scope);
    compiler::InitScopesPhaseETS::RunExternalNode(interfaceProp->Value(), VarBinder());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const classProp = GetImplementationClassProp(this, interfaceProp, originalProp, classType);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ir::MethodDefinition *getter = GenerateDefaultGetterSetter(interfaceProp, classProp, scope, false, this);
    classDef->Body().push_back(getter);

    const auto &name = getter->Key()->AsIdentifier()->Name();

    ir::MethodDefinition *setter =
        !classProp->IsConst()
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ? GenerateDefaultGetterSetter(interfaceProp, classProp, Scope()->AsClassScope(), true, this)
            : nullptr;

    auto *const methodScope = scope->InstanceMethodScope();
    auto *const decl = Allocator()->New<varbinder::FunctionDecl>(Allocator(), name, getter);

    auto *var = methodScope->AddDecl(Allocator(), decl, ScriptExtension::STS);
    if (var == nullptr) {
        auto *const prevDecl = methodScope->FindDecl(name);
        for (const auto &method : {getter, setter}) {
            if (method != nullptr) {
                prevDecl->Node()->AsMethodDefinition()->AddOverload(method);
            }
        }
        var = methodScope->FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS);
        var->AddFlag(varbinder::VariableFlags::METHOD);
    }

    getter->Function()->Id()->SetVariable(var);

    SetupGetterSetterFlags(originalProp, classType, getter, setter, HasStatus(CheckerStatus::IN_EXTERNAL));

    if (setter != nullptr && !setter->TsType()->IsTypeError()) {
        getter->Variable()->TsType()->AsETSFunctionType()->AddCallSignature(
            setter->TsType()->AsETSFunctionType()->CallSignatures()[0]);
        getter->AddOverload(setter);
    }
}

bool ETSChecker::TryTransformingToStaticInvoke(ir::Identifier *const ident, const Type *resolvedType)
{
    ES2PANDA_ASSERT(ident->Parent()->IsCallExpression());
    ES2PANDA_ASSERT(ident->Parent()->AsCallExpression()->Callee() == ident);

    if (!resolvedType->IsETSObjectType()) {
        return false;
    }

    auto className = ident->Name();
    std::string_view propertyName;

    PropertySearchFlags searchFlag = PropertySearchFlags::SEARCH_IN_INTERFACES | PropertySearchFlags::SEARCH_IN_BASE |
                                     PropertySearchFlags::SEARCH_STATIC_METHOD;
    auto *instantiateMethod =
        resolvedType->AsETSObjectType()->GetProperty(compiler::Signatures::STATIC_INSTANTIATE_METHOD, searchFlag);
    auto *invokeMethod =
        resolvedType->AsETSObjectType()->GetProperty(compiler::Signatures::STATIC_INVOKE_METHOD, searchFlag);
    if (instantiateMethod != nullptr) {
        propertyName = compiler::Signatures::STATIC_INSTANTIATE_METHOD;
    } else if (invokeMethod != nullptr) {
        propertyName = compiler::Signatures::STATIC_INVOKE_METHOD;
    } else {
        LogError(diagnostic::NO_STATIC_INVOKE,
                 {compiler::Signatures::STATIC_INVOKE_METHOD, compiler::Signatures::STATIC_INSTANTIATE_METHOD,
                  className, className},
                 ident->Start());
        return true;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *classId = AllocNode<ir::Identifier>(className, Allocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *methodId = AllocNode<ir::Identifier>(propertyName, Allocator());
    if (propertyName == compiler::Signatures::STATIC_INSTANTIATE_METHOD) {
        methodId->SetVariable(instantiateMethod);
    } else if (propertyName == compiler::Signatures::STATIC_INVOKE_METHOD) {
        methodId->SetVariable(invokeMethod);
    }

    auto *transformedCallee =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    classId->SetRange(ident->Range());
    methodId->SetRange(ident->Range());
    transformedCallee->SetRange(ident->Range());

    auto *callExpr = ident->Parent()->AsCallExpression();
    transformedCallee->SetParent(callExpr);
    callExpr->SetCallee(transformedCallee);

    if (instantiateMethod != nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *argExpr = GenerateImplicitInstantiateArg(std::string(className));

        argExpr->SetParent(callExpr);
        argExpr->SetRange(ident->Range());

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->AsETSBinder()->HandleCustomNodes(argExpr);

        auto &arguments = callExpr->Arguments();
        arguments.insert(arguments.begin(), argExpr);
    }

    return true;
}

void ETSChecker::ImportNamespaceObjectTypeAddReExportType(ir::ETSImportDeclaration *importDecl,
                                                          checker::ETSObjectType *lastObjectType, ir::Identifier *ident)
{
    for (auto item : VarBinder()->AsETSBinder()->ReExportImports()) {
        if (!importDecl->ResolvedSource()->Str().Is(item->GetProgramPath().Mutf8())) {
            continue;
        }
        auto *reExportType = GetImportSpecifierObjectType(item->GetETSImportDeclarations(), ident);
        if (reExportType->IsTypeError()) {
            continue;
        }
        lastObjectType->AddReExports(reExportType->AsETSObjectType());
        for (auto node : importDecl->Specifiers()) {
            if (node->IsImportSpecifier()) {
                auto specifier = node->AsImportSpecifier();
                lastObjectType->AddReExportAlias(specifier->Imported()->Name(), specifier->Local()->Name());
            }
        }
    }
}

Type *ETSChecker::GetImportSpecifierObjectType(ir::ETSImportDeclaration *importDecl, ir::Identifier *ident)
{
    auto importPath = importDecl->ResolvedSource()->Str();
    parser::Program *program =
        SelectEntryOrExternalProgram(static_cast<varbinder::ETSBinder *>(VarBinder()), importPath);
    if (program == nullptr) {
        return GlobalTypeError();
    }

    auto const moduleName = program->ModuleName();
    auto const internalName =
        util::UString(
            moduleName.Mutf8().append(compiler::Signatures::METHOD_SEPARATOR).append(compiler::Signatures::ETS_GLOBAL),
            Allocator())
            .View();

    auto *moduleObjectType = Allocator()->New<ETSObjectType>(
        Allocator(), moduleName, internalName, std::make_tuple(ident, checker::ETSObjectFlags::CLASS, Relation()));

    auto *rootDecl = Allocator()->New<varbinder::ClassDecl>(moduleName);
    varbinder::LocalVariable *rootVar =
        Allocator()->New<varbinder::LocalVariable>(rootDecl, varbinder::VariableFlags::NONE);
    rootVar->SetTsType(moduleObjectType);

    ImportNamespaceObjectTypeAddReExportType(importDecl, moduleObjectType, ident);
    SetPropertiesForModuleObject(moduleObjectType, importPath,
                                 importDecl->Specifiers()[0]->IsImportNamespaceSpecifier() ? nullptr : importDecl);
    SetrModuleObjectTsType(ident, moduleObjectType);

    return moduleObjectType;
}

ETSChecker::NamedAccessMeta ETSChecker::FormNamedAccessMetadata(varbinder::Variable const *prop)
{
    const auto *field = prop->Declaration()->Node()->AsClassProperty();
    const auto *owner = field->Parent()->AsClassDefinition();
    return {owner->TsType()->AsETSObjectType(), field->TsType(), field->Id()->Name()};
}

void ETSChecker::ETSObjectTypeDeclNode(ETSChecker *checker, ETSObjectType *const objectType)
{
    auto *declNode = objectType->AsETSObjectType()->GetDeclNode();
    if (declNode == nullptr) {
        return;
    }

    if (declNode->IsClassDefinition() && !declNode->AsClassDefinition()->IsClassDefinitionChecked()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        checker->CheckClassDefinition(declNode->AsClassDefinition());
    }
}

checker::Type *ETSChecker::TryGetTypeFromExtensionAccessor(ir::Expression *expr)
{
    if (expr->TsType() == nullptr) {
        expr->Check(this);
    }

    if (!expr->IsMemberExpression() ||
        !expr->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::EXTENSION_ACCESSOR)) {
        return expr->TsType();
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return expr->AsMemberExpression()->GetExtensionAccessorReturnType(this);
}

ir::CallExpression *ETSChecker::CreateExtensionAccessorCall(ETSChecker *checker, ir::MemberExpression *expr,
                                                            ArenaVector<ir::Expression *> &&args)
{
    ir::Expression *callExpr = nullptr;
    if (expr->Object()->IsETSNewClassInstanceExpression()) {
        args.insert(args.begin(), expr->Object());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        callExpr = checker->AllocNode<ir::CallExpression>(expr->Property(), std::move(args), nullptr, false, false);
    } else {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        callExpr = checker->AllocNode<ir::CallExpression>(expr, std::move(args), nullptr, false, false);
    }
    callExpr->SetRange(expr->Range());
    return callExpr->AsCallExpression();
}

void ETSChecker::CheckTypeParameterVariance(ir::ClassDefinition *classDef)
{
    if (classDef->TypeParams() == nullptr) {
        return;
    }

    Context().SetContainingClass(classDef->TsType()->AsETSObjectType());
    auto checkVariance = [this](VarianceFlag varianceFlag, ir::Expression *expression, Type *type) {
        Relation()->Result(RelationResult::TRUE);
        Relation()->SetNode(expression);
        Relation()->CheckVarianceRecursively(type, varianceFlag);
        Relation()->SetNode(nullptr);
    };

    for (auto *it : classDef->Body()) {
        if (!it->IsClassProperty() || it->AsClassProperty()->TypeAnnotation() == nullptr) {
            continue;
        }
        // Readonly Fields may have out type parameters, otherwise fields should be invariant type parameters
        checkVariance(it->AsClassProperty()->IsReadonly() ? VarianceFlag::COVARIANT : VarianceFlag::INVARIANT,
                      it->AsClassProperty()->TypeAnnotation(), it->AsClassProperty()->TsType());
    }

    for (auto *it : classDef->Body()) {
        if (!it->IsMethodDefinition() || it->AsMethodDefinition()->IsConstructor()) {
            continue;
        }
        // Methods may have out type parameters as return types, and in type parameters as parameter types，(in)=>out
        checkVariance(VarianceFlag::COVARIANT, it->AsMethodDefinition()->Id(), it->Check(this));
    }

    if (classDef->Super() != nullptr) {
        checkVariance(VarianceFlag::COVARIANT, classDef->Super(), classDef->Super()->Check(this));
    }

    for (auto *implement : classDef->Implements()) {
        checkVariance(VarianceFlag::COVARIANT, implement, implement->Expr()->AsTypeNode()->Check(this));
    }
}

void ETSChecker::SetPreferredTypeIfPossible(ir::Expression *const expr, Type *const targetType)
{
    // Object expression requires that its type be set by the context before checking. in this case, the target type
    // provides that context.
    if (expr->IsObjectExpression()) {
        expr->AsObjectExpression()->SetPreferredType(targetType);
    }

    if (expr->IsArrayExpression()) {
        expr->AsArrayExpression()->SetPreferredType(targetType);
    }
}

}  // namespace ark::es2panda::checker
