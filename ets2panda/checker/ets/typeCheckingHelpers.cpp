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

#include "checker/checker.h"
#include "checker/ets/narrowingWideningConverter.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/types/ets/etsPartialTypeParameter.h"
#include "ir/base/catchClause.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/switchCaseStatement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsTuple.h"
#include "varbinder/declaration.h"
#include "checker/ETSchecker.h"
#include "varbinder/ETSBinder.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/ets/boxingConverter.h"
#include "checker/ets/unboxingConverter.h"
#include "util/helpers.h"
#include "generated/diagnostic.h"

namespace ark::es2panda::checker {
void ETSChecker::CheckTruthinessOfType(ir::Expression *expr)
{
    auto const testType = expr->Check(this);
    auto *const conditionType = MaybeUnboxConditionalInRelation(testType);

    expr->SetTsType(conditionType);

    if (conditionType == nullptr || (!conditionType->IsTypeError() && !conditionType->IsConditionalExprType())) {
        LogError(diagnostic::NOT_COND_TYPE, {}, expr->Start());
        return;
    }

    if (conditionType->IsETSVoidType()) {
        LogError(diagnostic::VOID_IN_LOGIC, {}, expr->Start());
        return;
    }

    if (conditionType->IsETSPrimitiveType()) {
        FlagExpressionWithUnboxing(testType, conditionType, expr);
    }

    // For T_S compatibility
    if (conditionType->IsETSEnumType()) {
        expr->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
    }
}

bool ETSChecker::CheckNonNullish(ir::Expression const *expr)
{
    if (!expr->TsType()->PossiblyETSNullish()) {
        return true;
    }

    if (HasStatus(checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK)) {
        return false;
    }

    LogError(diagnostic::POSSIBLY_NULLISH, {}, expr->Start());
    return false;
}

Type *ETSChecker::GetNonNullishType(Type *type)
{
    if (type->DefinitelyNotETSNullish()) {
        return type;
    }
    if (type->IsETSTypeParameter()) {
        return Allocator()->New<ETSNonNullishType>(type->AsETSTypeParameter());
    }
    if (type->IsETSPartialTypeParameter()) {
        return type->AsETSPartialTypeParameter()->GetUnderlying();
    }
    if (type->IsETSNullType() || type->IsETSUndefinedType()) {
        return GetGlobalTypesHolder()->GlobalETSNeverType();
    }

    ArenaVector<Type *> copied(Allocator()->Adapter());
    for (auto const &t : type->AsETSUnionType()->ConstituentTypes()) {
        if (t->IsETSNullType() || t->IsETSUndefinedType()) {
            continue;
        }
        copied.push_back(GetNonNullishType(t));
    }
    return copied.empty() ? GetGlobalTypesHolder()->GlobalETSNeverType() : CreateETSUnionType(std::move(copied));
}

Type *ETSChecker::RemoveNullType(Type *const type)
{
    if (type->DefinitelyNotETSNullish() || type->IsETSUndefinedType()) {
        return type;
    }

    if (type->IsETSTypeParameter()) {
        // Strict equality produces incorrect NonNullish types #21526
        return type;
    }

    if (type->IsETSNullType()) {
        return GetGlobalTypesHolder()->GlobalETSNeverType();
    }

    ES2PANDA_ASSERT(type->IsETSUnionType());
    ArenaVector<Type *> copiedTypes(Allocator()->Adapter());

    for (auto *constituentType : type->AsETSUnionType()->ConstituentTypes()) {
        if (!constituentType->IsETSNullType()) {
            copiedTypes.push_back(RemoveNullType(constituentType));
        }
    }

    return copiedTypes.empty() ? GetGlobalTypesHolder()->GlobalETSNeverType()
                               : CreateETSUnionType(std::move(copiedTypes));
}

Type *ETSChecker::RemoveUndefinedType(Type *const type)
{
    if (type->DefinitelyNotETSNullish() || type->IsETSNullType()) {
        return type;
    }

    if (type->IsETSTypeParameter()) {
        // Strict equality produces incorrect NonNullish types #21526
        return type;
    }

    if (type->IsETSUndefinedType()) {
        return GetGlobalTypesHolder()->GlobalETSNeverType();
    }

    ES2PANDA_ASSERT(type->IsETSUnionType());
    ArenaVector<Type *> copiedTypes(Allocator()->Adapter());

    for (auto *constituentType : type->AsETSUnionType()->ConstituentTypes()) {
        if (!constituentType->IsETSUndefinedType()) {
            copiedTypes.push_back(RemoveUndefinedType(constituentType));
        }
    }

    return copiedTypes.empty() ? GetGlobalTypesHolder()->GlobalETSNeverType()
                               : CreateETSUnionType(std::move(copiedTypes));
}

std::pair<Type *, Type *> ETSChecker::RemoveNullishTypes(Type *type)
{
    if (type->DefinitelyNotETSNullish()) {
        return {GetGlobalTypesHolder()->GlobalETSNeverType(), type};
    }

    if (type->IsETSTypeParameter()) {
        return {GetGlobalTypesHolder()->GlobalETSNullishType(),
                Allocator()->New<ETSNonNullishType>(type->AsETSTypeParameter())};
    }

    if (type->IsETSUndefinedType() || type->IsETSNullType()) {
        return {type, GetGlobalTypesHolder()->GlobalETSNeverType()};
    }

    ES2PANDA_ASSERT(type->IsETSUnionType());
    ArenaVector<Type *> nullishTypes(Allocator()->Adapter());
    ArenaVector<Type *> notNullishTypes(Allocator()->Adapter());

    for (auto *constituentType : type->AsETSUnionType()->ConstituentTypes()) {
        if (constituentType->IsETSUndefinedType() || constituentType->IsETSNullType()) {
            nullishTypes.push_back(constituentType);
        } else {
            notNullishTypes.push_back(!constituentType->IsETSTypeParameter()
                                          ? constituentType
                                          : Allocator()->New<ETSNonNullishType>(constituentType->AsETSTypeParameter()));
        }
    }

    Type *nullishType = nullishTypes.empty() ? GetGlobalTypesHolder()->GlobalETSNeverType()
                                             : CreateETSUnionType(std::move(nullishTypes));
    Type *notNullishType = notNullishTypes.empty() ? GetGlobalTypesHolder()->GlobalETSNeverType()
                                                   : CreateETSUnionType(std::move(notNullishTypes));
    return {nullishType, notNullishType};
}

// NOTE(vpukhov): can be implemented with relation if etscompiler will support it
template <typename Pred, typename Trv>
static bool MatchConstituentOrConstraint(const Type *type, Pred const &pred, Trv const &trv)
{
    auto const traverse = [&pred, &trv](const Type *ttype) {
        return MatchConstituentOrConstraint<Pred, Trv>(ttype, pred, trv);
    };
    if (pred(type)) {
        return true;
    }
    if (!trv(type)) {
        return false;
    }
    if (type->IsETSUnionType()) {
        for (auto const &ctype : type->AsETSUnionType()->ConstituentTypes()) {
            if (traverse(ctype)) {
                return true;
            }
        }
        return false;
    }
    if (type->IsETSTypeParameter()) {
        return traverse(type->AsETSTypeParameter()->GetConstraintType());
    }
    if (type->IsETSNonNullishType()) {
        auto tparam = type->AsETSNonNullishType()->GetUnderlying();
        return traverse(tparam->GetConstraintType());
    }
    if (type->IsETSPartialTypeParameter()) {
        auto tparam = type->AsETSPartialTypeParameter()->GetUnderlying();
        return traverse(tparam->GetConstraintType());
    }
    return false;
}

template <typename Pred>
static bool MatchConstituentOrConstraint(const Type *type, Pred const &pred)
{
    return MatchConstituentOrConstraint(type, pred, []([[maybe_unused]] const Type *t) { return true; });
}

bool Type::PossiblyETSNull() const
{
    return MatchConstituentOrConstraint(
        this, [](const Type *t) { return t->IsETSNullType(); },
        [](const Type *t) { return !t->IsETSNonNullishType(); });
}

bool Type::PossiblyETSUndefined() const
{
    return MatchConstituentOrConstraint(
        this, [](const Type *t) { return t->IsETSUndefinedType(); },
        [](const Type *t) { return !t->IsETSNonNullishType(); });
}

bool Type::PossiblyETSNullish() const
{
    return MatchConstituentOrConstraint(
        this, [](const Type *t) { return t->IsETSNullType() || t->IsETSUndefinedType(); },
        [](const Type *t) { return !t->IsETSNonNullishType(); });
}

bool Type::DefinitelyETSNullish() const
{
    return !MatchConstituentOrConstraint(
        this,
        [](const Type *t) {
            return !(t->IsTypeParameter() || t->IsETSUnionType() || t->IsETSNullType() || t->IsETSUndefinedType());
        },
        [](const Type *t) { return !t->IsETSNonNullishType(); });
}

bool Type::DefinitelyNotETSNullish() const
{
    return !PossiblyETSNullish();
}

bool Type::PossiblyETSString() const
{
    return MatchConstituentOrConstraint(this, [](const Type *t) {
        return t->IsETSStringType() || (t->IsETSObjectType() && t->AsETSObjectType()->IsGlobalETSObjectType());
    });
}

static bool IsValueTypedObjectType(ETSObjectType const *t)
{
    return t->IsGlobalETSObjectType() || t->HasObjectFlag(ETSObjectFlags::VALUE_TYPED) ||
           t->HasObjectFlag(ETSObjectFlags::ENUM_OBJECT);
}

bool Type::PossiblyETSValueTyped() const
{
    return MatchConstituentOrConstraint(this, [](const Type *t) {
        return t->IsETSNullType() || t->IsETSUndefinedType() ||
               (t->IsETSObjectType() && IsValueTypedObjectType(t->AsETSObjectType()));
    });
}

bool Type::PossiblyETSValueTypedExceptNullish() const
{
    return MatchConstituentOrConstraint(
        this, [](const Type *t) { return t->IsETSObjectType() && IsValueTypedObjectType(t->AsETSObjectType()); });
}

bool Type::IsETSArrowType() const
{
    // Arrow types (in form `(p: A) => B`) will be isolated from Methods
    return IsETSFunctionType() && !IsETSMethodType();
}

bool Type::IsETSMethodType() const
{
    return HasTypeFlag(TypeFlag::ETS_METHOD);
}

[[maybe_unused]] static bool IsSaneETSReferenceType(Type const *type)
{
    static constexpr TypeFlag ETS_SANE_REFERENCE_TYPE =
        TypeFlag::TYPE_ERROR | TypeFlag::ETS_NULL | TypeFlag::ETS_UNDEFINED | TypeFlag::ETS_OBJECT |
        TypeFlag::ETS_TYPE_PARAMETER | TypeFlag::WILDCARD | TypeFlag::ETS_NONNULLISH |
        TypeFlag::ETS_REQUIRED_TYPE_PARAMETER | TypeFlag::ETS_NEVER | TypeFlag::ETS_UNION | TypeFlag::ETS_ARRAY |
        TypeFlag::FUNCTION | TypeFlag::ETS_PARTIAL_TYPE_PARAMETER | TypeFlag::ETS_TUPLE | TypeFlag::ETS_ENUM;

    // Issues
    if (type->IsETSVoidType()) {  // NOTE(vpukhov): #19701 void refactoring
        return true;
    }
    if (type->IsETSTypeAliasType()) {  // NOTE(vpukhov): #20561
        return true;
    }
    if (type->IsNeverType()) {  // NOTE(vpukhov): #20562 We use ets/never and ts/never simultaneously
        return true;
    }
    return type->HasTypeFlag(ETS_SANE_REFERENCE_TYPE);
}

bool Type::IsETSPrimitiveType() const
{
    static constexpr TypeFlag ETS_PRIMITIVE = TypeFlag::ETS_NUMERIC | TypeFlag::CHAR | TypeFlag::ETS_BOOLEAN;

    // Do not modify
    ES2PANDA_ASSERT(!HasTypeFlag(ETS_PRIMITIVE) == IsSaneETSReferenceType(this));
    return HasTypeFlag(ETS_PRIMITIVE);
}

bool Type::IsETSResizableArrayType() const
{
    return IsETSObjectType() && AsETSObjectType()->Name() == compiler::Signatures::ARRAY;
}

bool Type::IsETSPrimitiveOrEnumType() const
{
    return IsETSPrimitiveType() || IsETSEnumType();
}

bool Type::IsETSReferenceType() const
{
    // Do not modify
    return !IsETSPrimitiveType();
}

bool Type::IsETSUnboxableObject() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE);
}

bool ETSChecker::IsConstantExpression(ir::Expression *expr, Type *type)
{
    return (type->HasTypeFlag(TypeFlag::CONSTANT) && (expr->IsIdentifier() || expr->IsMemberExpression()));
}

Type *ETSChecker::GetNonConstantType(Type *type)
{
    if (type->IsETSStringType()) {
        return GlobalBuiltinETSStringType();
    }

    if (type->IsETSBigIntType()) {
        return GlobalETSBigIntType();
    }

    if (type->IsETSUnionType()) {
        return CreateETSUnionType(ETSUnionType::GetNonConstantTypes(this, type->AsETSUnionType()->ConstituentTypes()));
    }

    if (!type->IsETSPrimitiveType()) {
        return type;
    }

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

Type *ETSChecker::GetTypeOfSetterGetter(varbinder::Variable *const var)
{
    auto *propType = var->TsType()->AsETSFunctionType();
    if (propType->HasTypeFlag(checker::TypeFlag::GETTER)) {
        return propType->FindGetter()->ReturnType();
    }

    return propType->FindSetter()->Params()[0]->TsType();
}

void ETSChecker::IterateInVariableContext(varbinder::Variable *const var)
{
    // Before computing the given variables type, we have to make a new checker context frame so that the checking is
    // done in the proper context, and have to enter the scope where the given variable is declared, so reference
    // resolution works properly
    auto *iter = var->Declaration()->Node()->Parent();
    while (iter != nullptr) {
        if (iter->IsMethodDefinition()) {
            auto *methodDef = iter->AsMethodDefinition();
            ES2PANDA_ASSERT(methodDef->TsType());
            Context().SetContainingSignature(methodDef->Function()->Signature());
        } else if (iter->IsClassDefinition()) {
            auto *classDef = iter->AsClassDefinition();
            Type *containingClass {};

            if (classDef->TsType() == nullptr) {
                containingClass = BuildBasicClassProperties(classDef);
                ResolveDeclaredMembersOfObject(containingClass->AsETSObjectType());
            } else {
                containingClass = classDef->TsType()->AsETSObjectType();
            }

            ES2PANDA_ASSERT(classDef->TsType());
            if (!containingClass->IsTypeError()) {
                Context().SetContainingClass(containingClass->AsETSObjectType());
            }
        }

        iter = iter->Parent();
    }
}

static Type *GetTypeFromVarLikeVariableDeclaration(ETSChecker *checker, varbinder::Variable *const var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *declNode = var->Declaration()->Node();
    if (var->Declaration()->Node()->IsIdentifier()) {
        declNode = declNode->Parent();
    }
    TypeStackElement tse(
        checker, var->Declaration(),
        // OHOS CC thinks initializer lists are statement blocks...
        // CC-OFFNXT(G.FMT.03-CPP) project code style
        {{diagnostic::CIRCULAR_DEPENDENCY, util::DiagnosticMessageParams {var->Declaration()->Name()}}},
        declNode->Start());
    if (tse.HasTypeError()) {
        var->SetTsType(checker->GlobalTypeError());
        return checker->GlobalTypeError();
    }
    return declNode->Check(checker);
}

Type *ETSChecker::GetTypeFromVariableDeclaration(varbinder::Variable *const var)
{
    Type *variableType = nullptr;

    switch (var->Declaration()->Type()) {
        case varbinder::DeclType::CLASS: {
            auto *classDef = var->Declaration()->Node()->AsClassDefinition();
            BuildBasicClassProperties(classDef);
            variableType = classDef->TsType();
            break;
        }
        case varbinder::DeclType::CONST:
            [[fallthrough]];
        case varbinder::DeclType::READONLY:
            [[fallthrough]];
        case varbinder::DeclType::LET:
            [[fallthrough]];
        case varbinder::DeclType::VAR: {
            variableType = GetTypeFromVarLikeVariableDeclaration(this, var);
            break;
        }

        case varbinder::DeclType::FUNC:
            [[fallthrough]];
        case varbinder::DeclType::IMPORT:
            variableType = var->Declaration()->Node()->Check(this);
            break;

        case varbinder::DeclType::TYPE_ALIAS:
            variableType = GetTypeFromTypeAliasReference(var);
            break;

        case varbinder::DeclType::INTERFACE:
            variableType = BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
            break;

        case varbinder::DeclType::ANNOTATIONUSAGE:
            [[fallthrough]];
        case varbinder::DeclType::ANNOTATIONDECL:
            break;

        default:
            ES2PANDA_ASSERT(IsAnyError());
            break;
    }

    return variableType != nullptr ? variableType : GlobalTypeError();
}

Type *ETSChecker::GetTypeOfVariable(varbinder::Variable *const var)
{
    if (IsVariableExtensionAccessor(var)) {
        return var->TsType();
    }

    if (IsVariableGetterSetter(var)) {
        return GetTypeOfSetterGetter(var);
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

    checker::SavedCheckerContext savedContext(this, CheckerStatus::NO_OPTS);
    checker::ScopeContext scopeCtx(this, var->GetScope());
    IterateInVariableContext(var);

    return GetTypeFromVariableDeclaration(var);
}

// Determine if unchecked cast is needed and yield guaranteed source type
Type *ETSChecker::GuaranteedTypeForUncheckedCast(Type *base, Type *substituted)
{
    // Apparent type acts as effective representation for type.
    //  For T extends SomeClass|undefined
    //  Apparent(Int|T|null) is Int|SomeClass|undefined|null
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *appBase = GetApparentType(base);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *appSubst = GetApparentType(substituted);
    // Base is supertype of Substituted AND Substituted is supertype of Base
    return Relation()->IsIdenticalTo(appSubst, appBase) ? nullptr : appBase;
}

// Determine if substituted property access requires cast from erased type
Type *ETSChecker::GuaranteedTypeForUncheckedPropertyAccess(varbinder::Variable *const prop)
{
    if (IsVariableStatic(prop)) {
        return nullptr;
    }

    if (prop->TsType() != nullptr && prop->TsType()->IsTypeError()) {
        return nullptr;
    }

    if (IsVariableGetterSetter(prop)) {
        auto *method = prop->TsType()->AsETSFunctionType();
        if (!method->HasTypeFlag(checker::TypeFlag::GETTER)) {
            return nullptr;
        }
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return GuaranteedTypeForUncheckedCallReturn(method->FindGetter());
    }
    // NOTE(vpukhov): mark ETSDynamicType properties
    if (prop->Declaration() == nullptr || prop->Declaration()->Node() == nullptr) {
        return nullptr;
    }

    switch (auto node = prop->Declaration()->Node(); node->Type()) {
        case ir::AstNodeType::CLASS_PROPERTY: {
            auto baseProp = node->AsClassProperty()->Id()->Variable();
            if (baseProp == prop) {
                return nullptr;
            }
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            return GuaranteedTypeForUncheckedCast(GetTypeOfVariable(baseProp), GetTypeOfVariable(prop));
        }
        case ir::AstNodeType::METHOD_DEFINITION:
        case ir::AstNodeType::CLASS_DEFINITION:
            return GetTypeOfVariable(prop);
        case ir::AstNodeType::TS_ENUM_DECLARATION:
            return nullptr;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

// Determine if substituted method cast requires cast from erased type
Type *ETSChecker::GuaranteedTypeForUncheckedCallReturn(Signature *sig)
{
    ES2PANDA_ASSERT(sig->HasFunction());
    if (sig->HasSignatureFlag(SignatureFlags::THIS_RETURN_TYPE)) {
        return sig->ReturnType();
    }
    auto *const baseSig = sig->Function() != nullptr ? sig->Function()->Signature() : nullptr;
    if (baseSig == nullptr || baseSig == sig) {
        return nullptr;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return GuaranteedTypeForUncheckedCast(MaybeBoxType(baseSig->ReturnType()), MaybeBoxType(sig->ReturnType()));
}

Type *ETSChecker::ResolveUnionUncheckedType(ArenaVector<checker::Type *> &&apparentTypes)
{
    if (apparentTypes.empty()) {
        return nullptr;
    }
    auto *unionType = CreateETSUnionType(std::move(apparentTypes));
    if (unionType->IsETSUnionType()) {
        checker::Type *typeLUB = unionType->AsETSUnionType()->GetAssemblerLUB();
        return typeLUB;
    }
    // Is case of single apparent type, just return itself
    return unionType;
}

Type *ETSChecker::GuaranteedTypeForUnionFieldAccess(ir::MemberExpression *memberExpression, ETSUnionType *etsUnionType)
{
    const auto &types = etsUnionType->ConstituentTypes();
    ArenaVector<checker::Type *> apparentTypes {Allocator()->Adapter()};
    const auto &propertyName = memberExpression->Property()->AsIdentifier()->Name();
    for (auto *type : types) {
        auto searchFlags = PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_METHOD |
                           PropertySearchFlags::SEARCH_IN_BASE;
        if (!type->IsETSObjectType()) {
            return nullptr;
        }
        auto *fieldVar = type->AsETSObjectType()->GetProperty(propertyName, searchFlags);
        if (fieldVar == nullptr) {
            return nullptr;
        }
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *fieldType = GuaranteedTypeForUncheckedPropertyAccess(fieldVar);
        if (fieldType != nullptr) {
            apparentTypes.push_back(fieldType);
        }
    }
    return ResolveUnionUncheckedType(std::move(apparentTypes));
}

bool ETSChecker::IsAllowedTypeAliasRecursion(const ir::TSTypeAliasDeclaration *typeAliasNode,
                                             std::unordered_set<const ir::TSTypeAliasDeclaration *> &typeAliases)
{
    bool isAllowedRerursiveType = true;

    RecursionPreserver<const ir::TSTypeAliasDeclaration> recursionPreserver(typeAliases, typeAliasNode);

    if (*recursionPreserver) {
        return false;
    }

    auto typeAliasDeclarationCheck = [this, &typeAliases](ir::ETSTypeReferencePart *part) {
        if (!part->Name()->IsIdentifier()) {
            return false;
        }

        if (part->Name()->Variable() == nullptr) {
            return true;
        }

        auto const *const decl = part->Name()->Variable()->Declaration();
        if (auto const *const node = decl->Node(); node != nullptr && node->IsTSTypeAliasDeclaration()) {
            return IsAllowedTypeAliasRecursion(node->AsTSTypeAliasDeclaration(), typeAliases);
        }

        return true;
    };

    if (typeAliasNode->TypeAnnotation()->IsETSTypeReference()) {
        isAllowedRerursiveType &=
            typeAliasDeclarationCheck(typeAliasNode->TypeAnnotation()->AsETSTypeReference()->Part());
    }

    if (isAllowedRerursiveType && typeAliasNode->TypeAnnotation()->IsETSUnionType()) {
        for (auto &type : typeAliasNode->TypeAnnotation()->AsETSUnionType()->Types()) {
            if (type->IsETSTypeReference()) {
                isAllowedRerursiveType &= typeAliasDeclarationCheck(type->AsETSTypeReference()->Part());
            }
        }
    }

    return isAllowedRerursiveType;
}

Type *ETSChecker::GetTypeFromTypeAliasReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *const aliasTypeNode = var->Declaration()->Node()->AsTSTypeAliasDeclaration();
    std::unordered_set<const ir::TSTypeAliasDeclaration *> typeAliases;
    auto isAllowedRecursion = IsAllowedTypeAliasRecursion(aliasTypeNode, typeAliases);

    TypeStackElement tse(this, aliasTypeNode, {{diagnostic::CYCLIC_ALIAS}}, aliasTypeNode->Start(), isAllowedRecursion);

    if (tse.HasTypeError()) {
        var->SetTsType(GlobalTypeError());
        return GlobalTypeError();
    }

    auto *typeAliasType = tse.GetElementType();

    if (typeAliasType != nullptr) {
        typeAliasType->AsETSTypeAliasType()->SetRecursive();
        return typeAliasType;
    }

    typeAliasType = CreateETSTypeAliasType(aliasTypeNode->Id()->Name(), aliasTypeNode);
    if (aliasTypeNode->TypeParams() != nullptr) {
        auto [typeParamTypes, ok] = CreateUnconstrainedTypeParameters(aliasTypeNode->TypeParams());
        typeAliasType->AsETSTypeAliasType()->SetTypeArguments(std::move(typeParamTypes));
        if (ok) {
            AssignTypeParameterConstraints(aliasTypeNode->TypeParams());
        }
    }
    tse.SetElementType(typeAliasType);

    aliasTypeNode->Check(this);
    Type *targetType = aliasTypeNode->TypeAnnotation()->GetType(this);
    typeAliasType->AsETSTypeAliasType()->SetTargetType(targetType);
    typeAliasType->AsETSTypeAliasType()->ApplySubstitution(Relation());

    var->SetTsType(targetType);
    return targetType;
}

Type *ETSChecker::GetTypeFromInterfaceReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *interfaceType = BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    var->SetTsType(interfaceType);
    return interfaceType;
}

Type *ETSChecker::GetTypeFromClassReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto classDef = var->Declaration()->Node()->AsClassDefinition();

    auto *classType = BuildBasicClassProperties(classDef);
    var->SetTsType(classType);
    return classType;
}

Type *ETSChecker::GetTypeFromTypeParameterReference(varbinder::LocalVariable *var, const lexer::SourcePosition &pos)
{
    ES2PANDA_ASSERT(var->Declaration()->Node()->IsTSTypeParameter());
    if ((var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsClassDefinition() ||
         var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsTSInterfaceDeclaration()) &&
        HasStatus(CheckerStatus::IN_STATIC_CONTEXT)) {
        return TypeError(var, diagnostic::STATIC_REF_TO_NONSTATIC, {var->Name()}, pos);
    }

    return var->TsType();
}

bool ETSChecker::CheckAmbientAnnotationFieldInitializer(ir::Expression *init, ir::Expression *expected)
{
    if (init->Type() != expected->Type()) {
        return false;
    }

    switch (init->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL:
        case ir::AstNodeType::BOOLEAN_LITERAL:
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::ARRAY_EXPRESSION:
        case ir::AstNodeType::MEMBER_EXPRESSION:
        case ir::AstNodeType::UNARY_EXPRESSION: {
            if (CheckAmbientAnnotationFieldInitializerValue(init, expected)) {
                break;
            }
            LogError(diagnostic::AMBIENT_ANNOT_FIELD_INIT_MISMATCH, {}, init->Start());
            return false;
        }
        default:
            ES2PANDA_UNREACHABLE();
    }

    return true;
}

static bool IsValidateUnaryExpression(lexer::TokenType operatorType)
{
    return operatorType == lexer::TokenType::PUNCTUATOR_PLUS || operatorType == lexer::TokenType::PUNCTUATOR_MINUS;
}

bool ETSChecker::CheckAmbientAnnotationFieldInitializerValue(ir::Expression *init, ir::Expression *expected)
{
    switch (init->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL: {
            return init->AsNumberLiteral()->Number().GetDouble() == expected->AsNumberLiteral()->Number().GetDouble();
        }
        case ir::AstNodeType::BOOLEAN_LITERAL: {
            return init->AsBooleanLiteral()->Value() == expected->AsBooleanLiteral()->Value();
        }
        case ir::AstNodeType::STRING_LITERAL: {
            return init->AsStringLiteral()->Str() == expected->AsStringLiteral()->Str();
        }
        case ir::AstNodeType::ARRAY_EXPRESSION: {
            const auto &elements = init->AsArrayExpression()->Elements();
            const auto &expectedElements = expected->AsArrayExpression()->Elements();
            if (elements.size() != expectedElements.size()) {
                return false;
            }
            for (size_t i = 0; i < elements.size(); ++i) {
                if (!CheckAmbientAnnotationFieldInitializer(elements[i], expectedElements[i])) {
                    return false;
                }
            }
            return true;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            if (!Relation()->IsIdenticalTo(init->TsType(), expected->TsType())) {
                return false;
            }
            auto elem = init->AsMemberExpression()->Property()->AsIdentifier()->Name();
            auto expectedElem = expected->AsMemberExpression()->Property()->AsIdentifier()->Name();
            return elem == expectedElem;
        }
        case ir::AstNodeType::UNARY_EXPRESSION: {
            if (!IsValidateUnaryExpression(init->AsUnaryExpression()->OperatorType()) ||
                !IsValidateUnaryExpression(expected->AsUnaryExpression()->OperatorType())) {
                LogError(diagnostic::ILLEGAL_UNARY_OP, {}, init->Start());
                return false;
            }
            if (init->AsUnaryExpression()->OperatorType() != expected->AsUnaryExpression()->OperatorType()) {
                return false;
            }
            return CheckAmbientAnnotationFieldInitializer(init->AsUnaryExpression()->Argument(),
                                                          expected->AsUnaryExpression()->Argument());
        }
        default:
            ES2PANDA_UNREACHABLE();
    }
}

void ETSChecker::CheckAmbientAnnotation(ir::AnnotationDeclaration *annoImpl, ir::AnnotationDeclaration *annoDecl)
{
    std::unordered_map<util::StringView, ir::ClassProperty *> fieldMap;

    for (auto *prop : annoDecl->Properties()) {
        auto *field = prop->AsClassProperty();
        fieldMap[field->Id()->Name()] = field;
    }

    for (auto *prop : annoImpl->Properties()) {
        auto *field = prop->AsClassProperty();
        auto fieldName = field->Id()->Name();
        auto fieldDeclIter = fieldMap.find(fieldName);
        if (fieldDeclIter == fieldMap.end()) {
            LogError(diagnostic::AMBIENT_ANNOT_IMPL_OF_UNDEFINED_FIELD, {fieldName, annoDecl->GetBaseName()->Name()},
                     field->Start());
            continue;
        }

        auto *fieldDecl = fieldDeclIter->second;
        fieldDecl->Check(this);
        if (!Relation()->IsIdenticalTo(field->TsType(), fieldDecl->TsType())) {
            LogError(diagnostic::AMBIENT_ANNOT_FIELD_TYPE_MISMATCH, {fieldName, annoDecl->GetBaseName()->Name()},
                     field->TypeAnnotation()->Start());
        }

        bool hasValueMismatch = (field->Value() == nullptr) != (fieldDecl->Value() == nullptr);
        bool initializerInvalid = field->Value() != nullptr && fieldDecl->Value() != nullptr &&
                                  !CheckAmbientAnnotationFieldInitializer(field->Value(), fieldDecl->Value());
        if (hasValueMismatch || initializerInvalid) {
            LogError(diagnostic::AMBIENT_ANNOT_FIELD_MISMATCH, {fieldName, annoDecl->GetBaseName()->Name()},
                     field->Start());
        }
        fieldMap.erase(fieldDeclIter);
    }

    for (auto it : fieldMap) {
        LogError(diagnostic::AMBIENT_ANNOT_FIELD_MISSING_IMPL,
                 {it.second->Key()->AsIdentifier()->Name(), annoDecl->GetBaseName()->Name()}, annoImpl->Start());
    }
}

void ETSChecker::CheckFunctionSignatureAnnotations(const ArenaVector<ir::Expression *> &params,
                                                   ir::TSTypeParameterDeclaration *typeParams,
                                                   ir::TypeNode *returnTypeAnnotation)
{
    for (auto *param : params) {
        if (param->IsETSParameterExpression()) {
            CheckAnnotations(param->AsETSParameterExpression()->Annotations());
            if (param->AsETSParameterExpression()->TypeAnnotation() != nullptr) {
                param->AsETSParameterExpression()->TypeAnnotation()->Check(this);
            }
        }
    }

    if (typeParams != nullptr) {
        for (auto *typeParam : typeParams->Params()) {
            CheckAnnotations(typeParam->Annotations());
        }
    }

    if (returnTypeAnnotation != nullptr) {
        ValidateThisUsage(returnTypeAnnotation);
        CheckAnnotations(returnTypeAnnotation->Annotations());
    }
}

bool ETSChecker::CheckAndLogInvalidThisUsage(const ir::TypeNode *type, const diagnostic::DiagnosticKind &diagnostic)
{
    if (type->IsTSThisType()) {
        LogError(diagnostic, {}, type->Start());
        return true;
    }
    return false;
}

void ETSChecker::ValidateThisUsage(const ir::TypeNode *returnTypeAnnotation)
{
    if (returnTypeAnnotation->IsETSUnionType()) {
        auto types = returnTypeAnnotation->AsETSUnionType()->Types();
        for (auto type : types) {
            if (CheckAndLogInvalidThisUsage(type, diagnostic::NOT_ALLOWED_THIS_IN_UNION_TYPE)) {
                return;
            }
            ValidateThisUsage(type);
        }
        return;
    }
    if (returnTypeAnnotation->IsETSTuple()) {
        auto types = returnTypeAnnotation->AsETSTuple()->GetTupleTypeAnnotationsList();
        for (auto type : types) {
            if (CheckAndLogInvalidThisUsage(type, diagnostic::NOT_ALLOWED_THIS_IN_TUPLE_TYPE)) {
                return;
            }
            ValidateThisUsage(type);
        }
        return;
    }
    if (returnTypeAnnotation->IsTSArrayType()) {
        auto elementType = returnTypeAnnotation->AsTSArrayType()->ElementType();
        if (CheckAndLogInvalidThisUsage(elementType, diagnostic::NOT_ALLOWED_THIS_IN_ARRAY_TYPE)) {
            return;
        }
        ValidateThisUsage(elementType);
        return;
    }
}

void ETSChecker::CheckAnnotations(const ArenaVector<ir::AnnotationUsage *> &annotations)
{
    if (annotations.empty()) {
        return;
    }
    std::unordered_set<util::StringView> seenAnnotations;
    for (const auto &anno : annotations) {
        anno->Check(this);
        CheckAnnotationRetention(anno);
        auto annoName = anno->GetBaseName()->Name();
        if (seenAnnotations.find(annoName) != seenAnnotations.end()) {
            LogError(diagnostic::ANNOT_DUPLICATE, {annoName}, anno->Start());
        }
        seenAnnotations.insert(annoName);
    }
}

static bool IsValidSourceRetentionUsage(ir::AnnotationUsage *anno, ir::AnnotationDeclaration *annoDecl)
{
    bool isTransformedClassProperty = anno->Parent()->IsClassProperty() &&
                                      anno->Parent()->Parent()->IsClassDefinition() &&
                                      anno->Parent()->Parent()->AsClassDefinition()->IsModule();
    return (!anno->Parent()->IsClassDefinition() && !anno->Parent()->IsScriptFunction() &&
            !anno->Parent()->IsETSModule() && !anno->Parent()->IsTSInterfaceDeclaration() &&
            !anno->Parent()->IsETSParameterExpression() && !anno->Parent()->IsClassProperty() &&
            !annoDecl->IsSourceRetention()) ||
           (isTransformedClassProperty && !annoDecl->IsSourceRetention());
}

void ETSChecker::CheckAnnotationRetention(ir::AnnotationUsage *anno)
{
    if (anno->GetBaseName()->Name().Mutf8() == compiler::Signatures::BUILTIN_RETENTION &&
        !anno->Parent()->IsAnnotationDeclaration()) {
        LogError(diagnostic::INVALID_ANNOTATION_RETENTION, {}, anno->Start());
        return;
    }
    if (anno->GetBaseName()->Variable() == nullptr ||
        !anno->GetBaseName()->Variable()->Declaration()->Node()->IsAnnotationDeclaration()) {
        return;
    }
    auto *annoDecl = anno->GetBaseName()->Variable()->Declaration()->Node()->AsAnnotationDeclaration();
    annoDecl->Check(this);
    if (IsValidSourceRetentionUsage(anno, annoDecl)) {
        LogError(diagnostic::ANNOTATION_ON_LAMBDA_LOCAL_TYPE, {}, anno->Start());
    }
}

void ETSChecker::HandleAnnotationRetention(ir::AnnotationUsage *anno, ir::AnnotationDeclaration *annoDecl)
{
    if (anno->Properties().size() != 1) {
        return;
    }
    auto policyStr = anno->Properties()[0]->AsClassProperty()->Value()->AsStringLiteral()->Str().Mutf8();
    if (policyStr == compiler::Signatures::SOURCE_POLICY) {
        annoDecl->SetSourceRetention();
    } else if (policyStr == compiler::Signatures::BYTECODE_POLICY) {
        annoDecl->SetBytecodeRetention();
    } else if (policyStr == compiler::Signatures::RUNTIME_POLICY) {
        annoDecl->SetRuntimeRetention();
    } else {
        LogError(diagnostic::ANNOTATION_POLICY_INVALID, {}, anno->Properties()[0]->Start());
    }
}

void ETSChecker::CheckStandardAnnotation(ir::AnnotationUsage *anno)
{
    if (anno->GetBaseName()->Variable() == nullptr) {
        return;
    }
    ES2PANDA_ASSERT(anno->GetBaseName()->Variable()->Declaration()->Node()->AsAnnotationDeclaration() != nullptr);
    auto *annoDecl = anno->GetBaseName()->Variable()->Declaration()->Node()->AsAnnotationDeclaration();
    auto annoName = annoDecl->InternalName().Mutf8();
    if (annoName.rfind(compiler::Signatures::STD_ANNOTATIONS) != 0) {
        LogError(diagnostic::STANDARD_ANNOTATION_REQUIRED, {}, anno->Start());
    }
    if (annoName == compiler::Signatures::STD_ANNOTATIONS_RETENTION) {
        HandleAnnotationRetention(anno, anno->Parent()->AsAnnotationDeclaration());
    }
}

void ETSChecker::CheckAnnotationPropertyType(ir::ClassProperty *property)
{
    // typeAnnotation check
    if (!ValidateAnnotationPropertyType(property->TsType())) {
        LogError(diagnostic::ANNOT_FIELD_INVALID_TYPE, {}, property->Start());
    }

    // The type of the Initializer has been check in the parser,
    // except for the enumeration type, because it is a member expression,
    // so here is an additional check to the enumeration type.
    if (property->Value() != nullptr &&
        ((property->Value()->IsMemberExpression() && !property->TsType()->IsETSEnumType()) ||
         property->Value()->IsIdentifier())) {
        LogError(diagnostic::ANNOTATION_FIELD_NONLITERAL, {}, property->Value()->Start());
    }
}

void ETSChecker::CheckSinglePropertyAnnotation(ir::AnnotationUsage *st, ir::AnnotationDeclaration *annoDecl)
{
    auto *param = st->Properties().at(0)->AsClassProperty();
    if (annoDecl->Properties().size() > 1) {
        LogError(diagnostic::ANNOT_MULTIPLE_FIELD, {st->GetBaseName()->Name()}, st->Start());
    }
    auto singleField = annoDecl->Properties().at(0)->AsClassProperty();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto clone = singleField->TypeAnnotation()->Clone(Allocator(), param);
    param->SetTypeAnnotation(clone);
    ScopeContext scopeCtx(this, st->Scope());
    param->Check(this);
    CheckAnnotationPropertyType(param);
}

void ETSChecker::ProcessRequiredFields(ArenaUnorderedMap<util::StringView, ir::ClassProperty *> &fieldMap,
                                       ir::AnnotationUsage *st, ETSChecker *checker) const
{
    for (const auto &entry : fieldMap) {
        if (entry.second->Value() == nullptr) {
            checker->LogError(diagnostic::ANNOT_FIELD_NO_VAL, {entry.first}, st->Start());
            continue;
        }
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *clone = entry.second->Clone(checker->Allocator(), st);
        st->AddProperty(clone);
    }
}

void ETSChecker::CheckMultiplePropertiesAnnotation(ir::AnnotationUsage *st, util::StringView const &baseName,
                                                   ArenaUnorderedMap<util::StringView, ir::ClassProperty *> &fieldMap)
{
    for (auto *it : st->Properties()) {
        auto *param = it->AsClassProperty();
        auto result = fieldMap.find(param->Id()->Name());
        if (result == fieldMap.end()) {
            LogError(diagnostic::ANNOT_PROP_UNDEFINED, {param->Id()->Name(), baseName}, param->Start());
            continue;
        }

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto clone = result->second->TypeAnnotation()->Clone(Allocator(), param);
        param->SetTypeAnnotation(clone);
        ScopeContext scopeCtx(this, st->Scope());
        param->Check(this);
        CheckAnnotationPropertyType(param);
        fieldMap.erase(result);
    }
}

Type *ETSChecker::MaybeUnboxInRelation(Type *type)
{
    if (type == nullptr) {
        return nullptr;
    }

    if (type->IsETSPrimitiveType()) {
        return type;
    }

    if (!type->IsETSUnboxableObject()) {
        return nullptr;
    }

    auto savedResult = Relation()->IsTrue();
    Relation()->Result(false);

    UnboxingConverter converter = UnboxingConverter(AsETSChecker(), Relation(), type, type);
    Relation()->Result(savedResult);
    return converter.Result();
}

Type *ETSChecker::MaybeUnboxConditionalInRelation(Type *const objectType)
{
    if (objectType != nullptr && objectType->IsTypeError()) {
        return objectType;
    }

    if ((objectType == nullptr) || !objectType->IsConditionalExprType()) {
        return nullptr;
    }

    if (auto *unboxed = MaybeUnboxInRelation(objectType); unboxed != nullptr) {
        return unboxed;
    }

    return objectType;
}

Type *ETSChecker::MaybeBoxInRelation(Type *objectType)
{
    if (objectType == nullptr) {
        return nullptr;
    }

    if (objectType->IsETSUnboxableObject()) {
        return objectType;
    }

    if (!objectType->IsETSPrimitiveType()) {
        return nullptr;
    }

    auto savedResult = Relation()->IsTrue();
    Relation()->Result(false);

    BoxingConverter converter = BoxingConverter(AsETSChecker(), Relation(), objectType,
                                                Checker::GetGlobalTypesHolder()->GlobalIntegerBuiltinType());
    Relation()->Result(savedResult);
    return converter.Result();
}

Type *ETSChecker::MaybeBoxType(Type *type) const
{
    return type->IsETSPrimitiveType() ? BoxingConverter::Convert(this, type) : type;
}

Type *ETSChecker::MaybeUnboxType(Type *type) const
{
    return type->IsETSUnboxableObject() ? UnboxingConverter::Convert(this, type->AsETSObjectType()) : type;
}

Type const *ETSChecker::MaybeBoxType(Type const *type) const
{
    return MaybeBoxType(const_cast<Type *>(type));
}

Type const *ETSChecker::MaybeUnboxType(Type const *type) const
{
    return MaybeUnboxType(const_cast<Type *>(type));
}

ir::BoxingUnboxingFlags ETSChecker::GetBoxingFlag(Type *const boxingType)
{
    auto typeKind = TypeKind(MaybeUnboxInRelation(boxingType));
    switch (typeKind) {
        case TypeFlag::ETS_BOOLEAN:
            return ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN;
        case TypeFlag::BYTE:
            return ir::BoxingUnboxingFlags::BOX_TO_BYTE;
        case TypeFlag::CHAR:
            return ir::BoxingUnboxingFlags::BOX_TO_CHAR;
        case TypeFlag::SHORT:
            return ir::BoxingUnboxingFlags::BOX_TO_SHORT;
        case TypeFlag::INT:
            return ir::BoxingUnboxingFlags::BOX_TO_INT;
        case TypeFlag::LONG:
            return ir::BoxingUnboxingFlags::BOX_TO_LONG;
        case TypeFlag::FLOAT:
            return ir::BoxingUnboxingFlags::BOX_TO_FLOAT;
        case TypeFlag::DOUBLE:
            return ir::BoxingUnboxingFlags::BOX_TO_DOUBLE;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

ir::BoxingUnboxingFlags ETSChecker::GetUnboxingFlag(Type const *const unboxingType) const
{
    auto typeKind = TypeKind(unboxingType);
    switch (typeKind) {
        case TypeFlag::ETS_BOOLEAN:
            return ir::BoxingUnboxingFlags::UNBOX_TO_BOOLEAN;
        case TypeFlag::BYTE:
            return ir::BoxingUnboxingFlags::UNBOX_TO_BYTE;
        case TypeFlag::CHAR:
            return ir::BoxingUnboxingFlags::UNBOX_TO_CHAR;
        case TypeFlag::SHORT:
            return ir::BoxingUnboxingFlags::UNBOX_TO_SHORT;
        case TypeFlag::INT:
            return ir::BoxingUnboxingFlags::UNBOX_TO_INT;
        case TypeFlag::LONG:
            return ir::BoxingUnboxingFlags::UNBOX_TO_LONG;
        case TypeFlag::FLOAT:
            return ir::BoxingUnboxingFlags::UNBOX_TO_FLOAT;
        case TypeFlag::DOUBLE:
            return ir::BoxingUnboxingFlags::UNBOX_TO_DOUBLE;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

void ETSChecker::MaybeAddBoxingFlagInRelation(TypeRelation *relation, Type *target)
{
    auto boxingResult = MaybeBoxInRelation(target);
    if ((boxingResult != nullptr) && !relation->OnlyCheckBoxingUnboxing()) {
        relation->GetNode()->RemoveBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOXING_FLAG);
        relation->GetNode()->AddBoxingUnboxingFlags(GetBoxingFlag(boxingResult));
        relation->Result(true);
    }
}

void ETSChecker::MaybeAddUnboxingFlagInRelation(TypeRelation *relation, Type *source, Type *self)
{
    auto unboxingResult = UnboxingConverter(this, relation, source, self).Result();
    if ((unboxingResult != nullptr) && relation->IsTrue() && !relation->OnlyCheckBoxingUnboxing()) {
        relation->GetNode()->AddBoxingUnboxingFlags(GetUnboxingFlag(unboxingResult));
    }
}

void ETSChecker::CheckUnboxedTypeWidenable(TypeRelation *relation, Type *target, Type *self)
{
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(
        relation, TypeRelationFlag::ONLY_CHECK_WIDENING |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE));
    // NOTE: vpukhov. handle union type
    auto unboxedType = MaybeUnboxInRelation(target);
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
    auto *unboxedSourceType = relation->GetChecker()->AsETSChecker()->MaybeUnboxInRelation(source);
    auto *unboxedTargetType = relation->GetChecker()->AsETSChecker()->MaybeUnboxInRelation(target);
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
    ES2PANDA_ASSERT(relation != nullptr);
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(
        relation, (relation->ApplyWidening() ? TypeRelationFlag::WIDENING : TypeRelationFlag::NONE) |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE) |
                      (relation->OnlyCheckBoxingUnboxing() ? TypeRelationFlag::ONLY_CHECK_BOXING_UNBOXING
                                                           : TypeRelationFlag::NONE));

    auto *boxedSourceType = relation->GetChecker()->AsETSChecker()->MaybeBoxInRelation(source);
    if (boxedSourceType == nullptr) {
        return;
    }
    ES2PANDA_ASSERT(target != nullptr);
    // Do not box primitive in case of cast to dynamic types
    if (target->IsETSDynamicType()) {
        return;
    }
    relation->IsAssignableTo(boxedSourceType, target);
    if (relation->IsTrue()) {
        MaybeAddBoxingFlagInRelation(relation, boxedSourceType);
    } else {
        auto unboxedTargetType = MaybeUnboxInRelation(target);
        if (unboxedTargetType == nullptr) {
            return;
        }
        NarrowingWideningConverter(this, relation, unboxedTargetType, source);
        if (relation->IsTrue()) {
            MaybeAddBoxingFlagInRelation(relation, target);
        }
    }
}

void ETSChecker::CheckUnboxedSourceTypeWithWideningAssignable(TypeRelation *relation, Type *source, Type *target)
{
    auto *unboxedSourceType = relation->GetChecker()->AsETSChecker()->MaybeUnboxInRelation(source);
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

static ir::AstNode *DerefETSTypeReference(ir::AstNode *node)
{
    ES2PANDA_ASSERT(node->IsETSTypeReference());
    do {
        auto *name = node->AsETSTypeReference()->Part()->GetIdent();

        ES2PANDA_ASSERT(name->IsIdentifier());
        auto *var = name->AsIdentifier()->Variable();
        ES2PANDA_ASSERT(var != nullptr);
        auto *declNode = var->Declaration()->Node();
        if (!declNode->IsTSTypeAliasDeclaration()) {
            return declNode;
        }
        node = declNode->AsTSTypeAliasDeclaration()->TypeAnnotation();
    } while (node->IsETSTypeReference());
    return node;
}

// #22952: optional arrow leftovers
bool ETSChecker::CheckLambdaAssignable(ir::Expression *param, ir::ScriptFunction *lambda)
{
    ES2PANDA_ASSERT(param->IsETSParameterExpression());
    ir::AstNode *typeAnn = param->AsETSParameterExpression()->Ident()->TypeAnnotation();
    if (typeAnn == nullptr) {
        return false;
    }
    if (typeAnn->IsETSTypeReference()) {
        typeAnn = DerefETSTypeReference(typeAnn);
    }

    if (!typeAnn->IsETSFunctionType()) {
        // the surrounding function is made so we can *bypass* the typecheck in the "inference" context,
        // however the body of the function has to be checked in any case
        if (typeAnn->IsETSUnionType()) {
            lambda->Parent()->Check(this);
            return CheckLambdaAssignableUnion(typeAnn, lambda);
        }

        Type *paramType = param->AsETSParameterExpression()->Ident()->TsType();
        if (paramType->IsETSObjectType() && Relation()->IsSupertypeOf(paramType, GlobalBuiltinFunctionType())) {
            lambda->Parent()->Check(this);
            return true;
        }
        return false;
    }

    ir::ETSFunctionType *calleeType = typeAnn->AsETSFunctionType();
    return lambda->Params().size() <= calleeType->Params().size();
}

bool ETSChecker::CheckLambdaInfer(ir::AstNode *typeAnnotation, ir::ArrowFunctionExpression *const arrowFuncExpr,
                                  Type *const subParameterType)
{
    if (typeAnnotation->IsETSTypeReference()) {
        typeAnnotation = DerefETSTypeReference(typeAnnotation);
    }

    if (!typeAnnotation->IsETSFunctionType()) {
        return false;
    }

    ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
    auto calleeType = typeAnnotation->AsETSFunctionType();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    InferTypesForLambda(lambda, calleeType, subParameterType->AsETSFunctionType()->ArrowSignature());

    return true;
}

bool ETSChecker::CheckLambdaTypeAnnotation(ir::AstNode *typeAnnotation,
                                           ir::ArrowFunctionExpression *const arrowFuncExpr, Type *const parameterType,
                                           TypeRelationFlag flags)
{
    auto checkInvocable = [&arrowFuncExpr, &parameterType, this](TypeRelationFlag functionFlags) {
        Type *const argumentType = arrowFuncExpr->Check(this);
        functionFlags |= TypeRelationFlag::NO_THROW;

        checker::InvocationContext invocationCtx(Relation(), arrowFuncExpr, argumentType, parameterType,
                                                 arrowFuncExpr->Start(), std::nullopt, functionFlags);
        return invocationCtx.IsInvocable();
    };

    //  process `single` type as usual.
    if (!typeAnnotation->IsETSUnionType()) {
        auto param = typeAnnotation->Parent()->Parent()->AsETSParameterExpression();
        // #22952: infer optional parameter heuristics
        auto nonNullishParam = param->IsOptional() ? GetNonNullishType(parameterType) : parameterType;
        if (!nonNullishParam->IsETSFunctionType()) {
            return true;
        }
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return CheckLambdaInfer(typeAnnotation, arrowFuncExpr, nonNullishParam) && checkInvocable(flags);
    }

    // Preserve actual lambda types
    ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
    ArenaVector<ir::TypeNode *> lambdaParamTypes {Allocator()->Adapter()};
    for (auto *const lambdaParam : lambda->Params()) {
        lambdaParamTypes.emplace_back(lambdaParam->AsETSParameterExpression()->Ident()->TypeAnnotation());
    }
    auto *const lambdaReturnTypeAnnotation = lambda->ReturnTypeAnnotation();

    Type *const argumentType = arrowFuncExpr->Check(this);
    if (Relation()->IsSupertypeOf(parameterType, argumentType)) {
        return true;
    }

    ES2PANDA_ASSERT(parameterType->AsETSUnionType()->ConstituentTypes().size() ==
                    typeAnnotation->AsETSUnionType()->Types().size());
    const auto typeAnnsOfUnion = typeAnnotation->AsETSUnionType()->Types();
    const auto typeParamOfUnion = parameterType->AsETSUnionType()->ConstituentTypes();
    for (size_t ix = 0; ix < typeAnnsOfUnion.size(); ++ix) {
        auto *typeNode = typeAnnsOfUnion[ix];
        auto *paramNode = typeParamOfUnion[ix];
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        if (CheckLambdaInfer(typeNode, arrowFuncExpr, paramNode) && checkInvocable(flags)) {
            return true;
        }

        //  Restore inferring lambda types:
        for (std::size_t i = 0U; i < lambda->Params().size(); ++i) {
            if (lambdaParamTypes[i] == nullptr) {
                lambda->Params()[i]->AsETSParameterExpression()->Ident()->SetTsTypeAnnotation(nullptr);
            }
        }
        if (lambdaReturnTypeAnnotation == nullptr) {
            lambda->SetReturnTypeAnnotation(nullptr);
        }
    }

    return false;
}

bool ETSChecker::TypeInference(Signature *signature, const ArenaVector<ir::Expression *> &arguments,
                               TypeRelationFlag flags)
{
    bool invocable = true;
    auto const argumentCount = arguments.size();
    auto const commonArity = std::min(signature->ArgCount(), argumentCount);

    for (size_t index = 0U; index < commonArity; ++index) {
        auto const &argument = arguments[index];
        if (!argument->IsArrowFunctionExpression()) {
            continue;
        }

        if (index == argumentCount - 1 && (flags & TypeRelationFlag::NO_CHECK_TRAILING_LAMBDA) != 0) {
            continue;
        }

        auto *const arrowFuncExpr = argument->AsArrowFunctionExpression();
        ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
        if (!NeedTypeInference(lambda)) {
            continue;
        }

        arrowFuncExpr->SetTsType(nullptr);

        // Note: If the signatures are from lambdas, then they have no `Function`.
        auto const *const param =
            signature->GetSignatureInfo()->params[index]->Declaration()->Node()->AsETSParameterExpression();
        ir::AstNode *typeAnn = param->Ident()->TypeAnnotation();
        Type *const parameterType = signature->Params()[index]->TsType();

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        bool rc = CheckLambdaTypeAnnotation(typeAnn, arrowFuncExpr, parameterType, flags);
        if (!rc && (flags & TypeRelationFlag::NO_THROW) == 0) {
            Type *const argumentType = arrowFuncExpr->Check(this);
            LogError(diagnostic::TYPE_MISMATCH_AT_IDX, {argumentType, parameterType, index + 1},
                     arrowFuncExpr->Start());
            rc = false;
        } else if ((lambda->Signature() != nullptr) && !lambda->HasReturnStatement()) {
            //  Need to check void return type here if there are no return statement(s) in the body.
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            if (!AssignmentContext(Relation(), AllocNode<ir::Identifier>(Allocator()), GlobalVoidType(),
                                   lambda->Signature()->ReturnType(), lambda->Start(), std::nullopt,
                                   checker::TypeRelationFlag::DIRECT_RETURN | checker::TypeRelationFlag::NO_THROW)
                     .IsAssignable()) {  // CC-OFF(G.FMT.02-CPP) project code style
                LogError(diagnostic::ARROW_TYPE_MISMATCH, {GlobalVoidType(), lambda->Signature()->ReturnType()},
                         lambda->Body()->Start());
                rc = false;
            }
        }

        invocable &= rc;
    }

    return invocable;
}

// #22951 requires complete refactoring
bool ETSChecker::IsExtensionETSFunctionType(const checker::Type *type)
{
    if (type == nullptr || (!type->IsETSFunctionType() && !type->IsETSObjectType())) {
        return false;
    }

    if (type->IsETSObjectType()) {
        return type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::EXTENSION_FUNCTION);
    }

    if (type->IsETSArrowType()) {
        return type->AsETSFunctionType()->ArrowSignature()->IsExtensionFunction();
    }

    return type->AsETSFunctionType()->IsExtensionFunctionType();
}

// #22951 requires complete refactoring
bool ETSChecker::IsExtensionAccessorFunctionType(const checker::Type *type)
{
    if (type == nullptr || !type->IsETSFunctionType()) {
        return false;
    }

    if (type->IsETSArrowType()) {
        return type->AsETSFunctionType()->ArrowSignature()->IsExtensionAccessor();
    }

    return type->AsETSFunctionType()->IsExtensionAccessorType();
}

void ETSChecker::CheckExceptionClauseType(const std::vector<checker::ETSObjectType *> &exceptions,
                                          ir::CatchClause *catchClause, checker::Type *clauseType)
{
    for (auto *exception : exceptions) {
        this->Relation()->IsIdenticalTo(clauseType, exception);
        if (this->Relation()->IsTrue()) {
            LogError(diagnostic::EXCEPTION_REDECLARATION, {}, catchClause->Start());
        }
    }
}
}  // namespace ark::es2panda::checker
