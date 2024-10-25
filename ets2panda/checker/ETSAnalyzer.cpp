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

#include "ETSAnalyzer.h"

#include "types/signature.h"
#include "util/helpers.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsTupleType.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"
#include "evaluate/scopedDebugInfoPlugin.h"
#include "types/ts/undefinedType.h"
#include "ir/statements/namespaceDeclaration.h"

namespace ark::es2panda::checker {

ETSChecker *ETSAnalyzer::GetETSChecker() const
{
    return static_cast<ETSChecker *>(GetChecker());
}

// from base folder
checker::Type *ETSAnalyzer::Check(ir::CatchClause *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ETSObjectType *exceptionType = checker->GlobalETSObjectType();

    ir::Identifier *paramIdent = st->Param()->AsIdentifier();

    if (paramIdent->TypeAnnotation() != nullptr) {
        checker::Type *catchParamAnnotationType = paramIdent->TypeAnnotation()->GetType(checker);

        exceptionType = checker->CheckExceptionOrErrorType(catchParamAnnotationType, st->Param()->Start());
    }

    paramIdent->Variable()->SetTsType(exceptionType);

    st->Body()->Check(checker);

    st->SetTsType(exceptionType);
    return exceptionType;
}

checker::Type *ETSAnalyzer::Check(ir::ClassDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();

    if (node->TsTypeOrError() == nullptr) {
        checker->BuildBasicClassProperties(node);
    }

    if (!node->IsClassDefinitionChecked()) {
        checker->CheckClassDefinition(node);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ClassProperty *st) const
{
    ASSERT(st->Id() != nullptr);
    ETSChecker *checker = GetETSChecker();

    if (st->TsTypeOrError() != nullptr) {
        return st->TsTypeOrError();
    }

    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass(),
                                              checker->Context().ContainingSignature());

    if (st->IsStatic()) {
        checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    st->SetTsType(checker->CheckVariableDeclaration(st->Id(), st->TypeAnnotation(), st->Value(), st->Modifiers()));

    return st->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::ClassStaticBlock *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(checker::CheckerStatus::INNER_CLASS)) {
        checker->LogTypeError("Static initializer is not allowed in inner class.", st->Start());
        st->SetTsType(checker->GlobalTypeError());
        return st->TsTypeOrError();
    }

    auto *func = st->Function();
    checker->BuildFunctionSignature(func);
    if (func->Signature() == nullptr) {
        st->SetTsType(checker->GlobalTypeError());
        return st->TsTypeOrError();
    }
    st->SetTsType(checker->BuildNamedFunctionType(func));
    checker::ScopeContext scopeCtx(checker, func->Scope());
    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_STATIC_BLOCK | checker::CheckerStatus::IN_STATIC_CONTEXT);
    func->Body()->Check(checker);
    return st->TsType();
}

// Satisfy the Chinese code checker
static void HandleNativeAndAsyncMethods(ETSChecker *checker, ir::MethodDefinition *node)
{
    auto *scriptFunc = node->Function();
    if (node->IsNative()) {
        if (scriptFunc->ReturnTypeAnnotation() == nullptr) {
            checker->LogTypeError("'Native' method should have explicit return type", scriptFunc->Start());
            node->SetTsType(checker->GlobalTypeError());
        }
        ASSERT(!scriptFunc->IsGetter() && !scriptFunc->IsSetter());
    }

    if (IsAsyncMethod(node)) {
        if (scriptFunc->ReturnTypeAnnotation() != nullptr) {
            auto *asyncFuncReturnType = scriptFunc->Signature()->ReturnType();

            if (!asyncFuncReturnType->IsETSObjectType() ||
                asyncFuncReturnType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
                checker->LogTypeError("Return type of async function must be 'Promise'.", scriptFunc->Start());
                scriptFunc->Signature()->SetReturnType(checker->GlobalTypeError());
                return;
            }
        }

        if (node->Function()->HasBody()) {
            ComposeAsyncImplMethod(checker, node);
        }
    }
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();

    auto *scriptFunc = node->Function();

    if (scriptFunc == nullptr) {
        checker->LogTypeError("Invalid function expression", node->Start());
        node->SetTsType(checker->GlobalTypeError());
        return node->TsTypeOrError();
    }

    if (scriptFunc->IsProxy()) {
        return nullptr;
    }

    // NOTE: aszilagyi. make it correctly check for open function not have body
    if (!scriptFunc->HasBody() && !(node->IsAbstract() || node->IsNative() || node->IsDeclare() ||
                                    checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->LogTypeError("Only abstract or native methods can't have body.", scriptFunc->Start());
        node->SetTsType(checker->GlobalTypeError());
        return node->TsTypeOrError();
    }

    if (scriptFunc->ReturnTypeAnnotation() == nullptr &&
        (node->IsNative() || (node->IsDeclare() && !node->IsConstructor()))) {
        checker->LogTypeError("Native and Declare methods should have explicit return type.", scriptFunc->Start());
        node->SetTsType(checker->GlobalTypeError());
        return node->TsTypeOrError();
    }

    if (node->TsTypeOrError() == nullptr) {
        node->SetTsType(checker->BuildMethodSignature(node));
    }

    this->CheckMethodModifiers(node);
    HandleNativeAndAsyncMethods(checker, node);
    DoBodyTypeChecking(checker, node, scriptFunc);
    CheckPredefinedMethodReturnType(checker, scriptFunc);
    if (node->TsTypeOrError()->IsTypeError()) {
        return node->TsTypeOrError();
    }
    // NOTE(gogabr): temporary, until we have proper bridges, see #16485
    // Don't check overriding for synthetic functional classes.
    if ((node->Parent()->Modifiers() & ir::ModifierFlags::FUNCTIONAL) == 0) {
        checker->CheckOverride(node->TsType()->AsETSFunctionType()->FindSignature(node->Function()));
    }

    for (auto *overload : node->Overloads()) {
        overload->Check(checker);
    }

    if (scriptFunc->IsRethrowing()) {
        checker->CheckRethrowingFunction(scriptFunc);
    }

    return node->TsType();
}

void ETSAnalyzer::CheckMethodModifiers(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto const notValidInAbstract = ir::ModifierFlags::NATIVE | ir::ModifierFlags::PRIVATE |
                                    ir::ModifierFlags::OVERRIDE | ir::ModifierFlags::FINAL | ir::ModifierFlags::STATIC;

    if (node->IsAbstract() && (node->flags_ & notValidInAbstract) != 0U) {
        checker->LogTypeError(
            "Invalid method modifier(s): an abstract method can't have private, override, static, final or native "
            "modifier.",
            node->Start());
        node->SetTsType(checker->GlobalTypeError());
        return;
    }

    if (node->Function() == nullptr) {
        checker->LogTypeError("Invalid function expression", node->Start());
        node->SetTsType(checker->GlobalTypeError());
        return;
    }

    if ((node->IsAbstract() || (!node->Function()->HasBody() && !node->IsNative() && !node->IsDeclare())) &&
        !(checker->HasStatus(checker::CheckerStatus::IN_ABSTRACT) ||
          checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->LogTypeError("Non abstract class has abstract method.", node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }

    auto const notValidInFinal = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::STATIC | ir::ModifierFlags::NATIVE;

    if (node->IsFinal() && (node->flags_ & notValidInFinal) != 0U) {
        checker->LogTypeError(
            "Invalid method modifier(s): a final method can't have abstract, static or native modifier.",
            node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }

    auto const notValidInStatic = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::FINAL | ir::ModifierFlags::OVERRIDE;

    if (node->IsStatic() && (node->flags_ & notValidInStatic) != 0U) {
        checker->LogTypeError(
            "Invalid method modifier(s): a static method can't have abstract, final or override modifier.",
            node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Property *expr) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SpreadElement *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *elementType =
        expr->AsSpreadElement()->Argument()->AsIdentifier()->Check(checker)->AsETSArrayType()->ElementType();
    expr->SetTsType(elementType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateElement *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->SetTsType(checker->CreateETSStringLiteralType(expr->Raw()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSClassLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    auto *const literal = expr->Expr();

    checker->LogTypeError("Class literal is not yet supported.", literal->Start());
    expr->SetTsType(checker->GlobalTypeError());
    return expr->TsTypeOrError();

    auto *exprType = literal->Check(checker);

    if (exprType->IsETSVoidType()) {
        checker->LogTypeError("Invalid .class reference", literal->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    ArenaVector<checker::Type *> typeArgTypes(checker->Allocator()->Adapter());
    typeArgTypes.push_back(exprType);  // NOTE: Box it if it's a primitive type

    checker::InstantiationContext ctx(checker, checker->GlobalBuiltinTypeType(), std::move(typeArgTypes),
                                      expr->Range().start);
    expr->SetTsType(ctx.Result());

    return expr->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    if (node->TsType() != nullptr) {
        return node->TsType();
    }
    ETSChecker *checker = GetETSChecker();

    size_t optionalParameterIndex = node->DefaultParamIndex();
    auto *genericInterfaceType = checker->GlobalBuiltinFunctionType(node->Params().size(), node->Flags());
    node->SetFunctionalInterface(genericInterfaceType->GetDeclNode()->AsTSInterfaceDeclaration());

    auto *tsType = checker->GetCachedFunctionalInterface(node);
    node->SetTsType(tsType);
    if (tsType != nullptr) {
        return tsType;
    }

    auto *substitution = checker->NewSubstitution();
    ETSObjectType *interfaceType;

    if (optionalParameterIndex == node->Params().size()) {
        interfaceType = CreateInterfaceTypeForETSFunctionType(checker, node, genericInterfaceType, substitution);
    } else {
        interfaceType = CreateOptionalSignaturesForFunctionalType(checker, node, genericInterfaceType, substitution,
                                                                  optionalParameterIndex);
    }

    node->SetTsType(interfaceType);
    return interfaceType;
}

checker::Type *ETSAnalyzer::Check(ir::ETSLaunchExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->expr_->Check(checker);
    auto *const launchPromiseType =
        checker->GlobalBuiltinPromiseType()
            ->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder())
            ->AsETSObjectType();
    launchPromiseType->AddTypeFlag(checker::TypeFlag::GENERIC);

    // Launch expression returns a Promise<T> type, so we need to insert the expression's type
    // as type parameter for the Promise class.

    auto exprType = [&checker](auto *tsType) {
        if (tsType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            return checker->PrimitiveTypeAsETSBuiltinType(tsType);
        }

        return tsType;
    }(expr->expr_->TsType());

    checker::Substitution *substitution = checker->NewSubstitution();
    ASSERT(launchPromiseType->TypeArguments().size() == 1);
    checker::ETSChecker::EmplaceSubstituted(
        substitution, launchPromiseType->TypeArguments()[0]->AsETSTypeParameter()->GetOriginal(), exprType);

    expr->SetTsType(launchPromiseType->Substitute(checker->Relation(), substitution));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewArrayInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    auto *elementType = expr->TypeReference()->GetType(checker);
    checker->ValidateArrayIndex(expr->Dimension(), true);
    if (!elementType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        if (elementType->IsETSUnionType() && !elementType->AsETSUnionType()->HasNullishType(checker)) {
            checker->LogTypeError({"Union types in array declaration must include a nullish type."}, expr->Start());
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsTypeOrError();
        }
        if (elementType->IsETSObjectType()) {
            auto *calleeObj = elementType->AsETSObjectType();
            const auto flags = checker::ETSObjectFlags::ABSTRACT | checker::ETSObjectFlags::INTERFACE;
            if (!calleeObj->HasObjectFlag(flags)) {
                // A workaround check for new Interface[...] in test cases
                expr->SetSignature(
                    checker->CollectParameterlessConstructor(calleeObj->ConstructSignatures(), expr->Start()));
                checker->ValidateSignatureAccessibility(calleeObj, nullptr, expr->Signature(), expr->Start());
            } else {
                checker->LogTypeError("Cannot use array creation expression with abstract classes and interfaces.",
                                      expr->Start());
                expr->SetTsType(checker->GlobalTypeError());
                return expr->TsTypeOrError();
            }
        }
    }
    expr->SetTsType(checker->CreateETSArrayType(elementType));
    checker->CreateBuiltinArraySignature(expr->TsType()->AsETSArrayType(), 1);
    return expr->TsType();
}

void ETSAnalyzer::CheckInstantatedClass(ir::ETSNewClassInstanceExpression *expr, ETSObjectType *&calleeObj) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->ClassDefinition() != nullptr) {
        if (calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT) && calleeObj->GetDeclNode()->IsFinal()) {
            checker->LogTypeError({"Class ", calleeObj->Name(), " cannot be both 'abstract' and 'final'."},
                                  calleeObj->GetDeclNode()->Start());
            expr->SetTsType(checker->GlobalTypeError());
            return;
        }

        bool fromInterface = calleeObj->HasObjectFlag(checker::ETSObjectFlags::INTERFACE);
        auto *classType = checker->BuildAnonymousClassProperties(
            expr->ClassDefinition(), fromInterface ? checker->GlobalETSObjectType() : calleeObj);
        if (fromInterface) {
            classType->AddInterface(calleeObj);
            calleeObj = checker->GlobalETSObjectType();
        }
        expr->ClassDefinition()->SetTsType(classType);
        checker->CheckClassDefinition(expr->ClassDefinition());
        checker->CheckInnerClassMembers(classType);
        expr->SetTsType(classType);
    } else if (calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
        checker->LogTypeError({calleeObj->Name(), " is abstract therefore cannot be instantiated."}, expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
    }

    if (calleeObj->HasObjectFlag(ETSObjectFlags::REQUIRED) &&
        !expr->HasAstNodeFlags(ir::AstNodeFlags::ALLOW_REQUIRED_INSTANTIATION)) {
        checker->LogTypeError("Required type can be instantiated only with object literal",
                              expr->GetTypeRef()->Start());
        expr->SetTsType(checker->GlobalTypeError());
    }
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    auto *calleeType = GetCalleeType(checker, expr);
    if (calleeType == nullptr) {
        return expr->TsType();
    }

    if (calleeType->IsTypeError()) {
        expr->SetTsType(calleeType);
        return expr->TsTypeOrError();
    }
    auto *calleeObj = calleeType->AsETSObjectType();
    expr->SetTsType(calleeObj);

    CheckInstantatedClass(expr, calleeObj);

    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->GetTypeRef(), expr->GetArguments(), lang, true));
    } else {
        auto *signature = checker->ResolveConstructExpression(calleeObj, expr->GetArguments(), expr->Start());

        if (signature == nullptr) {
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsTypeOrError();
        }

        checker->CheckObjectLiteralArguments(signature, expr->GetArguments());

        checker->ValidateSignatureAccessibility(calleeObj, nullptr, signature, expr->Start());

        ASSERT(signature->Function() != nullptr);

        if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
            checker->CheckThrowingStatements(expr);
        }

        if (calleeType->IsETSDynamicType()) {
            ASSERT(signature->Function()->IsDynamic());
            auto lang = calleeType->AsETSDynamicType()->Language();
            expr->SetSignature(
                checker->ResolveDynamicCallExpression(expr->GetTypeRef(), signature->Params(), lang, true));
        } else {
            ASSERT(!signature->Function()->IsDynamic());
            expr->SetSignature(signature);
        }
    }

    return expr->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    auto *elementType = expr->TypeReference()->GetType(checker);

    for (auto *dim : expr->Dimensions()) {
        checker->ValidateArrayIndex(dim, true);
        elementType = checker->CreateETSArrayType(elementType);
    }

    expr->SetTsType(elementType);
    expr->SetSignature(checker->CreateBuiltinArraySignature(elementType->AsETSArrayType(), expr->Dimensions().size()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSPackageDeclaration *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ETSParameterExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() == nullptr) {
        checker::Type *paramType;

        if (expr->Ident()->TsTypeOrError() != nullptr) {
            paramType = expr->Ident()->TsTypeOrError();
        } else {
            paramType = !expr->IsRestParameter() ? expr->Ident()->Check(checker) : expr->spread_->Check(checker);
            if (expr->IsDefault()) {
                std::cout << __LINE__ << std::endl;
                [[maybe_unused]] auto *const initType = expr->Initializer()->Check(checker);
            }
        }

        expr->SetTsType(paramType);
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSPrimitiveType *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSStructDeclaration *node) const
{
    ETSChecker *checker = GetETSChecker();
    node->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReference *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReferencePart *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSNullType *node) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSUndefinedType *node) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSStringLiteralType *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

// compile methods for EXPRESSIONS in alphabetical order

checker::Type *ETSAnalyzer::GetPreferredType(ir::ArrayExpression *expr) const
{
    return expr->preferredType_;
}

static bool CheckArrayElement(ETSChecker *checker, checker::Type *elementType,
                              std::vector<checker::Type *> targetElementType, ir::Expression *currentElement,
                              bool &isSecondaryChosen)
{
    if ((targetElementType[0]->IsETSArrayType() &&
         targetElementType[0]->AsETSArrayType()->ElementType()->IsETSArrayType() &&
         !(targetElementType[0]->AsETSArrayType()->ElementType()->IsETSTupleType() &&
           targetElementType[1] == nullptr)) ||
        (!checker::AssignmentContext(checker->Relation(), currentElement, elementType, targetElementType[0],
                                     currentElement->Start(),
                                     {"Array element type '", elementType, "' is not assignable to explicit type '",
                                      targetElementType[0], "'"},
                                     TypeRelationFlag::NO_THROW)
              .IsAssignable() &&
         !(targetElementType[0]->IsETSArrayType() && currentElement->IsArrayExpression()))) {
        if (targetElementType[1] == nullptr) {
            checker->LogTypeError({"Array element type '", elementType, "' is not assignable to explicit type '",
                                   targetElementType[0], "'"},
                                  currentElement->Start());
            return false;
        }

        if (!(targetElementType[0]->IsETSArrayType() && currentElement->IsArrayExpression()) &&
            !checker::AssignmentContext(checker->Relation(), currentElement, elementType, targetElementType[1],
                                        currentElement->Start(),
                                        {"Array element type '", elementType, "' is not assignable to explicit type '",
                                         targetElementType[1], "'"},
                                        TypeRelationFlag::NO_THROW)
                 .IsAssignable()) {
            checker->LogTypeError({"Array element type '", elementType, "' is not assignable to explicit type '",
                                   targetElementType[1], "'"},
                                  currentElement->Start());
            return false;
        }
        isSecondaryChosen = true;
    }
    return true;
}

static bool CheckElement(ir::ArrayExpression *expr, ETSChecker *checker, std::vector<checker::Type *> targetElementType,
                         bool isPreferredTuple)
{
    bool isSecondaryChosen = false;
    bool ok = true;

    for (std::size_t idx = 0; idx < expr->Elements().size(); ++idx) {
        auto *const currentElement = expr->Elements()[idx];

        if (currentElement->IsArrayExpression()) {
            if (!expr->HandleNestedArrayExpression(checker, currentElement->AsArrayExpression(), isPreferredTuple,
                                                   idx)) {
                continue;
            }
        }

        if (currentElement->IsObjectExpression()) {
            currentElement->AsObjectExpression()->SetPreferredType(
                expr->GetPreferredType()->AsETSArrayType()->ElementType());
        }

        checker::Type *elementType = currentElement->Check(checker);

        if (!elementType->IsETSArrayType() && isPreferredTuple) {
            auto const *const tupleType = expr->GetPreferredType()->AsETSTupleType();

            auto *compareType = tupleType->GetTypeAtIndex(idx);
            if (compareType == nullptr) {
                checker->LogTypeError({"Too many elements in array initializer for tuple with size of ",
                                       static_cast<uint32_t>(tupleType->GetTupleSize())},
                                      currentElement->Start());
                ok = false;
                continue;
            }
            // clang-format off
            if (!AssignmentContext(checker->Relation(), currentElement, elementType, compareType,
                                   currentElement->Start(), {}, TypeRelationFlag::NO_THROW).IsAssignable()) {
                checker->LogTypeError({"Array initializer's type is not assignable to tuple type at index: ", idx},
                                      currentElement->Start());
                                      ok=false;
                continue;
            }
            // clang-format on

            elementType = compareType;
        }

        if (targetElementType[0] == elementType) {
            continue;
        }

        if (!CheckArrayElement(checker, elementType, targetElementType, currentElement, isSecondaryChosen)) {
            ok = false;
            continue;
        }
    }

    return ok;
}

checker::Type *ETSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    if (expr->preferredType_ != nullptr && !expr->preferredType_->IsETSArrayType() &&
        !checker->Relation()->IsSupertypeOf(expr->preferredType_, checker->GlobalETSObjectType())) {
        checker->LogTypeError({"Expected type for array literal should be an array type, got ", expr->preferredType_},
                              expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    const bool isArray = (expr->preferredType_ != nullptr) && expr->preferredType_->IsETSArrayType() &&
                         !expr->preferredType_->IsETSTupleType();

    if (!expr->Elements().empty()) {
        if (expr->preferredType_ == nullptr || expr->preferredType_ == checker->GlobalETSObjectType()) {
            expr->preferredType_ = checker->CreateETSArrayType(expr->Elements()[0]->Check(checker));
        }

        const bool isPreferredTuple = expr->preferredType_->IsETSTupleType();
        // NOTE(aakmaev): Need to rework type inference of array literal (#19096 internal issue)
        auto *targetElementType =
            checker->GetNonConstantType(expr->GetPreferredType()->AsETSArrayType()->ElementType());
        Type *targetElementTypeSecondary = nullptr;
        if (isPreferredTuple && !isArray) {
            targetElementTypeSecondary = expr->GetPreferredType()->AsETSTupleType()->ElementType();
        }

        if (!CheckElement(expr, checker, {targetElementType, targetElementTypeSecondary}, isPreferredTuple)) {
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsTypeOrError();
        }
    }

    if (expr->preferredType_ == nullptr) {
        checker->LogTypeError("Can't resolve array type", expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    expr->SetTsType(expr->preferredType_);
    auto *const arrayType = expr->TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    return expr->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }
    checker::ScopeContext scopeCtx(checker, expr->Function()->Scope());

    if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
        /*
        example code:
        ```
            class A {
                prop:number
            }
            function A.method() {
                let a = () => {
                    console.println(this.prop)
                }
            }
        ```
        here the enclosing class of arrow function should be Class A
        */
        checker->Context().SetContainingClass(
            checker->Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS).variable->TsType()->AsETSObjectType());
    }

    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass());

    checker->AddStatus(checker::CheckerStatus::IN_LAMBDA);
    checker->Context().SetContainingLambda(expr);

    checker->BuildFunctionSignature(expr->Function(), false);
    if (expr->Function()->Signature() == nullptr) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }
    auto *signature = expr->Function()->Signature();

    checker->Context().SetContainingSignature(signature);
    expr->Function()->Body()->Check(checker);

    ArenaVector<Signature *> signatures(checker->Allocator()->Adapter());
    signatures.push_back(signature);
    for (auto &sigInfo : checker->ComposeSignatureInfosForArrowFunction(expr)) {
        auto sig = checker->ComposeSignature(expr->Function(), sigInfo, signature->ReturnType(), nullptr);
        sig->AddSignatureFlag(signature->GetFlags());
        signatures.push_back(sig);
    }

    auto *funcType = checker->CreateETSFunctionType(expr->Function(), std::move(signatures), nullptr);
    checker->Context().SetContainingSignature(nullptr);

    if (expr->Function()->IsAsyncFunc()) {
        auto *retType = signature->ReturnType();
        if (!retType->IsETSObjectType() ||
            retType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
            checker->LogTypeError("Return type of async lambda must be 'Promise'", expr->Function()->Start());
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsTypeOrError();
        }
    }

    expr->SetTsType(funcType);
    return expr->TsType();
}

static bool IsInvalidArrayLengthAssignment(ir::AssignmentExpression *const expr, ETSChecker *checker)
{
    if (expr->Left()->IsMemberExpression() &&
        expr->Left()->AsMemberExpression()->Object()->TsType()->IsETSArrayType() &&
        expr->Left()->AsMemberExpression()->Property()->IsIdentifier() &&
        expr->Left()->AsMemberExpression()->Property()->AsIdentifier()->Name().Is("length")) {
        checker->LogTypeError("Setting the length of an array is not permitted", expr->Left()->Start());
        return true;
    }
    return false;
}

checker::Type *ETSAnalyzer::GetSmartType(ir::AssignmentExpression *expr, checker::Type *leftType,
                                         checker::Type *rightType) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *smartType = leftType;

    if (expr->Left()->IsIdentifier()) {
        //  Now try to define the actual type of Identifier so that smart cast can be used in further checker processing
        smartType = checker->ResolveSmartType(rightType, leftType);
        auto const *const variable = expr->Target();

        //  Add/Remove/Modify smart cast for identifier
        //  (excluding the variables defined at top-level scope or captured in lambda-functions!)
        auto const *const variableScope = variable->GetScope();
        auto const topLevelVariable =
            variableScope != nullptr && (variableScope->IsGlobalScope() || (variableScope->Parent() != nullptr &&
                                                                            variableScope->Parent()->IsGlobalScope()));
        if (!topLevelVariable) {
            if (checker->Relation()->IsIdenticalTo(leftType, smartType)) {
                checker->Context().RemoveSmartCast(variable);
            } else {
                expr->Left()->SetTsType(smartType);
                checker->Context().SetSmartCast(variable, smartType);
            }
        }
    }
    return smartType;
}

checker::Type *ETSAnalyzer::Check(ir::AssignmentExpression *const expr) const
{
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    ETSChecker *checker = GetETSChecker();
    auto *const leftType = expr->Left()->Check(checker);

    if (IsInvalidArrayLengthAssignment(expr, checker)) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (expr->Left()->IsIdentifier()) {
        expr->target_ = expr->Left()->AsIdentifier()->Variable();
    } else if (expr->Left()->IsMemberExpression()) {
        expr->target_ = expr->Left()->AsMemberExpression()->PropVar();
    } else {
        checker->LogTypeError("Invalid left-hand side of assignment expression", expr->Left()->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (expr->target_ != nullptr && !expr->IsIgnoreConstAssign()) {
        checker->ValidateUnaryOperatorOperand(expr->target_);
    }

    auto [rightType, relationNode] = CheckAssignmentExprOperatorType(expr, leftType);
    if (rightType == nullptr) {
        expr->SetTsType(checker->GlobalTypeError());
        return checker->GlobalTypeError();
    }

    const checker::Type *targetType = checker->TryGettingFunctionTypeFromInvokeFunction(leftType);
    const checker::Type *sourceType = checker->TryGettingFunctionTypeFromInvokeFunction(rightType);

    checker::AssignmentContext(checker->Relation(), relationNode, rightType, leftType, expr->Right()->Start(),
                               {"Type '", sourceType, "' cannot be assigned to type '", targetType, "'"});

    checker::Type *smartType = GetSmartType(expr, leftType, rightType);

    expr->SetTsType(smartType);
    return expr->TsTypeOrError();
}

std::tuple<Type *, ir::Expression *> ETSAnalyzer::CheckAssignmentExprOperatorType(ir::AssignmentExpression *expr,
                                                                                  Type *const leftType) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *sourceType {};
    ir::Expression *relationNode = expr->Right();
    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            std::tie(std::ignore, expr->operationType_) = checker->CheckBinaryOperator(
                expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start(), true);

            auto unboxedLeft = checker->ETSBuiltinTypeAsPrimitiveType(leftType);
            sourceType = unboxedLeft == nullptr ? leftType : unboxedLeft;

            relationNode = expr;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            if (leftType->IsETSArrayType() && expr->Right()->IsArrayExpression()) {
                checker->ModifyPreferredType(expr->Right()->AsArrayExpression(), leftType);
            }

            if (expr->Right()->IsObjectExpression()) {
                expr->Right()->AsObjectExpression()->SetPreferredType(leftType);
            }

            sourceType = expr->Right()->Check(checker);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return {sourceType, relationNode};
}

checker::Type *ETSAnalyzer::Check(ir::AwaitExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    checker::Type *argType = checker->GetApparentType(expr->argument_->Check(checker));
    // Check the argument type of await expression
    if (!argType->IsETSObjectType() ||
        (argType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType())) {
        checker->LogTypeError("'await' expressions require Promise object as argument.", expr->Argument()->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    Type *type = argType->AsETSObjectType()->TypeArguments().at(0);
    expr->SetTsType(UnwrapPromiseType(type));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::UnwrapPromiseType(checker::Type *type) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *promiseType = checker->GlobalBuiltinPromiseType();
    while (type->IsETSObjectType() && type->AsETSObjectType()->GetOriginalBaseType() == promiseType) {
        type = type->AsETSObjectType()->TypeArguments().at(0);
    }
    if (!type->IsETSUnionType()) {
        return type;
    }
    const auto &ctypes = type->AsETSUnionType()->ConstituentTypes();
    auto it = std::find_if(ctypes.begin(), ctypes.end(), [promiseType](checker::Type *t) {
        return t == promiseType || (t->IsETSObjectType() && t->AsETSObjectType()->GetBaseType() == promiseType);
    });
    if (it == ctypes.end()) {
        return type;
    }
    ArenaVector<Type *> newCTypes(ctypes);
    do {
        size_t index = it - ctypes.begin();
        newCTypes[index] = UnwrapPromiseType(ctypes[index]);
        ++it;
        it = std::find_if(it, ctypes.end(), [promiseType](checker::Type *t) {
            return t == promiseType || t->AsETSObjectType()->GetBaseType() == promiseType;
        });
    } while (it != ctypes.end());
    return checker->CreateETSUnionType(std::move(newCTypes));
}

checker::Type *ETSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    ETSChecker *checker = GetETSChecker();
    checker::Type *newTsType {nullptr};
    std::tie(newTsType, expr->operationType_) =
        checker->CheckBinaryOperator(expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start());
    expr->SetTsType(newTsType);

    checker->Context().CheckBinarySmartCastCondition(expr);

    return expr->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::BlockExpression *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    if (st->TsTypeOrError() == nullptr) {
        // NOLINTNEXTLINE(modernize-loop-convert)
        for (std::size_t idx = 0; idx < st->Statements().size(); idx++) {
            st->Statements()[idx]->Check(checker);
        }

        auto lastStmt = st->Statements().back();
        ASSERT(lastStmt->IsExpressionStatement());
        st->SetTsType(lastStmt->AsExpressionStatement()->GetExpression()->TsType());
    }

    return st->TsTypeOrError();
}

checker::Signature *ETSAnalyzer::ResolveSignature(ETSChecker *checker, ir::CallExpression *expr,
                                                  checker::Type *calleeType, bool isFunctionalInterface,
                                                  bool isUnionTypeWithFunctionalInterface) const
{
    bool extensionFunctionType = expr->Callee()->IsMemberExpression() && checker->ExtensionETSFunctionType(calleeType);

    if (calleeType->IsETSExtensionFuncHelperType()) {
        return ResolveCallForETSExtensionFuncHelperType(calleeType->AsETSExtensionFuncHelperType(), checker, expr);
    }
    if (extensionFunctionType) {
        return ResolveCallExtensionFunction(calleeType->AsETSFunctionType(), checker, expr);
    }
    auto &signatures = ChooseSignatures(checker, calleeType, expr->IsETSConstructorCall(), isFunctionalInterface,
                                        isUnionTypeWithFunctionalInterface);
    // Remove static signatures if the callee is a member expression and the object is initialized
    if (expr->Callee()->IsMemberExpression() &&
        !expr->Callee()->AsMemberExpression()->Object()->TsType()->IsETSEnumType() &&
        (expr->Callee()->AsMemberExpression()->Object()->IsSuperExpression() ||
         (expr->Callee()->AsMemberExpression()->Object()->IsIdentifier() &&
          expr->Callee()->AsMemberExpression()->Object()->AsIdentifier()->Variable()->HasFlag(
              varbinder::VariableFlags::INITIALIZED)))) {
        signatures.erase(
            std::remove_if(signatures.begin(), signatures.end(),
                           [](checker::Signature *signature) { return signature->Function()->IsStatic(); }),
            signatures.end());
    }

    checker::Signature *signature = checker->ResolveCallExpressionAndTrailingLambda(signatures, expr, expr->Start());
    if (signature == nullptr) {
        return nullptr;
    }

    if (signature->Function()->IsExtensionMethod()) {
        checker->LogTypeError({"No matching call signature"}, expr->Start());
        return nullptr;
    }
    return signature;
}

checker::Type *ETSAnalyzer::GetReturnType(ir::CallExpression *expr, checker::Type *calleeType) const
{
    ETSChecker *checker = GetETSChecker();

    if (calleeType->IsTypeError()) {
        return checker->GlobalTypeError();
    }

    bool isConstructorCall = expr->IsETSConstructorCall();
    bool isUnionTypeWithFunctionalInterface =
        calleeType->IsETSUnionType() &&
        calleeType->AsETSUnionType()->HasObjectType(checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    bool isFunctionalInterface = calleeType->IsETSObjectType() && calleeType->AsETSObjectType()->HasObjectFlag(
                                                                      checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    bool etsExtensionFuncHelperType = calleeType->IsETSExtensionFuncHelperType();

    if (expr->Callee()->IsArrowFunctionExpression()) {
        calleeType = InitAnonymousLambdaCallee(checker, expr->Callee(), calleeType);
        isFunctionalInterface = true;
    }

    if (!isFunctionalInterface && !calleeType->IsETSFunctionType() && !isConstructorCall &&
        !etsExtensionFuncHelperType && !isUnionTypeWithFunctionalInterface) {
        checker->LogTypeError({"Type '", calleeType, "' has no call signatures."}, expr->Start());
        return checker->GlobalTypeError();
    }

    checker::Signature *signature =
        ResolveSignature(checker, expr, calleeType, isFunctionalInterface, isUnionTypeWithFunctionalInterface);
    if (signature == nullptr) {
        return checker->GlobalTypeError();
    }

    checker->CheckObjectLiteralArguments(signature, expr->Arguments());

    if (!isFunctionalInterface) {
        checker::ETSObjectType *calleeObj = ChooseCalleeObj(checker, expr, calleeType, isConstructorCall);
        checker->ValidateSignatureAccessibility(calleeObj, expr, signature, expr->Start());
    }

    ASSERT(signature->Function() != nullptr);
    if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
        checker->CheckThrowingStatements(expr);
    }

    if (signature->Function()->IsDynamic()) {
        ASSERT(signature->Function()->IsDynamic());
        auto lang = signature->Function()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->Callee(), signature->Params(), lang, false));
    } else {
        ASSERT(!signature->Function()->IsDynamic());
        expr->SetSignature(signature);
    }

    auto *returnType = signature->ReturnType();

    if (signature->HasSignatureFlag(SignatureFlags::THIS_RETURN_TYPE)) {
        returnType = ChooseCalleeObj(checker, expr, calleeType, isConstructorCall);
    }

    return returnType;
}

static void CheckAbstractCall(ETSChecker *checker, ir::CallExpression *expr)
{
    if (expr->Callee()->IsMemberExpression()) {
        auto obj = expr->Callee()->AsMemberExpression()->Object();
        if (obj != nullptr && obj->IsSuperExpression()) {
            if ((expr->Signature() != nullptr) && (expr->Signature()->HasSignatureFlag(SignatureFlags::ABSTRACT))) {
                checker->LogTypeError("Cannot call abstract method!", expr->Start());
                expr->SetTsType(checker->GlobalTypeError());
            }
        }
    }
}

static void CheckCallee(ETSChecker *checker, ir::CallExpression *expr)
{
    checker->CheckNonNullish(expr->Callee());
    if (expr->Callee()->IsMemberExpression() && expr->Callee()->AsMemberExpression()->Object() != nullptr &&
        expr->Callee()->AsMemberExpression()->Object()->TsType()->IsETSObjectType() &&
        expr->Callee()->AsMemberExpression()->Object()->TsType()->AsETSObjectType()->HasObjectFlag(
            ETSObjectFlags::READONLY)) {
        checker->LogTypeError("Cannot call readonly type methods.", expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
    }
}

checker::Type *ETSAnalyzer::GetCallExpressionReturnType(ir::CallExpression *expr, checker::Type *calleeType) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *returnType = nullptr;
    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        // Trailing lambda for js function call is not supported, check the correctness of `foo() {}`
        checker->EnsureValidCurlyBrace(expr);
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->Callee(), expr->Arguments(), lang, false));
        returnType = expr->Signature()->ReturnType();
    } else {
        returnType = GetReturnType(expr, calleeType);
    }

    if (returnType->IsTypeError()) {
        return checker->GlobalTypeError();
    }

    if (expr->Signature()->RestVar() != nullptr) {
        auto *const elementType = expr->Signature()->RestVar()->TsType()->AsETSArrayType()->ElementType();
        auto *const arrayType = checker->CreateETSArrayType(elementType)->AsETSArrayType();
        checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
        checker::SavedCheckerContext savedCtx(checker, checker->Context().Status(), expr->Signature()->Owner());
        expr->Signature()->OwnerVar()->Declaration()->Node()->Check(checker);
        if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE) &&
            expr->Signature()->Function()->HasBody()) {
            checker::ScopeContext scopeCtx(checker, expr->Signature()->Function()->Body()->Scope());
            checker->CollectReturnStatements(expr->Signature()->Function());
        }
        returnType = expr->Signature()->ReturnType();
        // NOTE(vpukhov): #14902 substituted signature is not updated
    }

    return returnType;
}

checker::Type *ETSAnalyzer::Check(ir::CallExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }
    ASSERT(!expr->IsOptional());

    auto *oldCallee = expr->Callee();
    checker::Type *calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    if (calleeType->IsTypeError()) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (expr->Callee() != oldCallee) {
        // If it is a static invoke, the callee will be transformed from an identifier to a member expression
        // Type check the callee again for member expression
        calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    }

    CheckCallee(checker, expr);

    checker::Type *returnType = GetCallExpressionReturnType(expr, calleeType);
    if (returnType->IsTypeError()) {
        expr->SetTsType(returnType);
        return returnType;
    }

    expr->SetTsType(returnType);
    expr->SetUncheckedType(checker->GuaranteedTypeForUncheckedCallReturn(expr->Signature()));
    if (expr->UncheckedType() != nullptr) {
        checker->ComputeApparentType(returnType);
    }

    if (returnType->IsTypeError()) {
        expr->SetTsType(returnType);
        return expr->TsTypeOrError();
    }

    CheckVoidTypeExpression(checker, expr);
    CheckAbstractCall(checker, expr);
    return expr->TsTypeOrError();
}

static void HandleTestedTypes(SmartCastTypes testedTypes, ETSChecker *checker)
{
    if (testedTypes.has_value()) {
        for (auto [variable, consequentType, _] : *testedTypes) {
            checker->ApplySmartCast(variable, consequentType);
        }
    }
}

checker::Type *ETSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    ETSChecker *const checker = GetETSChecker();

    SmartCastArray smartCasts = checker->Context().EnterTestExpression();
    checker->CheckTruthinessOfType(expr->Test());
    SmartCastTypes testedTypes = checker->Context().ExitTestExpression();
    HandleTestedTypes(testedTypes, checker);

    auto *consequent = expr->Consequent();
    auto *consequentType = consequent->Check(checker);

    if (consequentType->IsETSEnumType()) {
        consequent->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
        consequentType = consequentType->AsETSEnumType()->GetDecl()->BoxedClass()->TsType();
    }
    SmartCastArray consequentSmartCasts = checker->Context().CloneSmartCasts();
    checker->Context().RestoreSmartCasts(smartCasts);

    if (testedTypes.has_value()) {
        for (auto [variable, _, alternateType] : *testedTypes) {
            checker->ApplySmartCast(variable, alternateType);
        }
    }

    auto *alternate = expr->Alternate();
    auto *alternateType = alternate->Check(checker);

    if (alternateType->IsETSEnumType()) {
        alternate->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
        alternateType = alternateType->AsETSEnumType()->GetDecl()->BoxedClass()->TsType();
    }

    // Here we need to combine types from consequent and alternate if blocks.
    checker->Context().CombineSmartCasts(consequentSmartCasts);

    if (checker->IsTypeIdenticalTo(consequentType, alternateType)) {
        expr->SetTsType(checker->GetNonConstantType(consequentType));
    } else {
        //  If possible and required update number literal type to the proper value (identical to left-side type)
        if (alternate->IsNumberLiteral() &&
            checker->AdjustNumberLiteralType(alternate->AsNumberLiteral(), alternateType, consequentType)) {
            expr->SetTsType(consequentType);
        } else if (consequent->IsNumberLiteral() &&
                   checker->AdjustNumberLiteralType(consequent->AsNumberLiteral(), consequentType, alternateType)) {
            expr->SetTsType(alternateType);
        } else {
            expr->SetTsType(checker->CreateETSUnionType({consequentType, alternateType}));
            if (expr->TsType()->IsETSReferenceType()) {
                checker->MaybeBoxExpression(expr->Consequent());
                checker->MaybeBoxExpression(expr->Alternate());
            }
        }
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::Identifier *expr) const
{
    if (expr->TsTypeOrError() == nullptr) {
        ETSChecker *checker = GetETSChecker();

        auto *identType = checker->ResolveIdentifier(expr);
        if (expr->Variable() != nullptr && (expr->Parent() == nullptr || !expr->Parent()->IsAssignmentExpression() ||
                                            expr != expr->Parent()->AsAssignmentExpression()->Left())) {
            if (auto *const smartType = checker->Context().GetSmartCast(expr->Variable()); smartType != nullptr) {
                identType = smartType;
            }
        }
        expr->SetTsType(identType);

        checker->Context().CheckIdentifierSmartCastCondition(expr);
    }
    return expr->TsTypeOrError();
}

std::pair<checker::Type *, util::StringView> SearchReExportsType(ETSObjectType *baseType, ir::MemberExpression *expr,
                                                                 util::StringView &aliasName, ETSChecker *checker)
{
    std::pair<ETSObjectType *, util::StringView> ret {};

    for (auto *const item : baseType->ReExports()) {
        auto name = item->GetReExportAliasValue(aliasName);
        if (name == aliasName && item->IsReExportHaveAliasValue(name)) {
            break;
        }

        if (item->GetProperty(name, PropertySearchFlags::SEARCH_ALL) != nullptr) {
            if (ret.first != nullptr) {
                checker->LogTypeError({"Ambiguous reference to '", aliasName, "'"}, expr->Start());
                expr->SetTsType(checker->GlobalTypeError());
                return ret;
            }
            ret = {item, name};
        }

        if (auto reExportType = SearchReExportsType(item, expr, name, checker); reExportType.first != nullptr) {
            return reExportType;
        }
    }

    return ret;
}

static void TypeErrorOnMissingProperty(ir::MemberExpression *expr, checker::Type *baseType,
                                       checker::ETSChecker *checker)
{
    checker->LogTypeError(
        {"Property '", expr->Property()->AsIdentifier()->Name(), "' does not exist on type '", baseType, "'"},
        expr->Object()->Start());
    expr->SetTsType(checker->GlobalTypeError());
}

checker::Type *ETSAnalyzer::Check(ir::MemberExpression *expr) const
{
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }
    ASSERT(!expr->IsOptional());

    ETSChecker *checker = GetETSChecker();
    auto *baseType = checker->GetNonConstantType(checker->GetApparentType(expr->Object()->Check(checker)));
    //  Note: don't use possible smart cast to null-like types.
    //        Such situation should be correctly resolved in the subsequent lowering.
    if (baseType->DefinitelyETSNullish() && expr->Object()->IsIdentifier()) {
        baseType = expr->Object()->AsIdentifier()->Variable()->TsType();
    }

    if (baseType->IsETSObjectType() && !baseType->AsETSObjectType()->ReExports().empty() &&
        baseType->AsETSObjectType()->GetProperty(expr->Property()->AsIdentifier()->Name(),
                                                 PropertySearchFlags::SEARCH_ALL) == nullptr) {
        if (auto reExportType = SearchReExportsType(baseType->AsETSObjectType(), expr,
                                                    expr->Property()->AsIdentifier()->Name(), checker);
            reExportType.first != nullptr) {
            baseType = reExportType.first;
            expr->object_->AsIdentifier()->SetTsType(baseType);
            expr->property_->AsIdentifier()->SetName(reExportType.second);
        }
    }

    if (!checker->CheckNonNullish(expr->Object())) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    if (expr->IsComputed()) {
        return expr->AdjustType(checker, expr->CheckComputed(checker, baseType));
    }

    if (baseType->IsETSArrayType()) {
        if (expr->Property()->AsIdentifier()->Name().Is("length")) {
            return expr->AdjustType(checker, checker->GlobalIntType());
        }

        return expr->SetAndAdjustType(checker, checker->GlobalETSObjectType());
    }

    if (baseType->IsETSObjectType()) {
        return expr->SetAndAdjustType(checker, baseType->AsETSObjectType());
    }

    if (baseType->IsETSEnumType()) {
        auto [memberType, memberVar] = expr->ResolveEnumMember(checker, baseType);
        expr->SetPropVar(memberVar);
        expr->Property()->SetTsType(memberType == nullptr ? checker->GlobalTypeError() : memberType);
        return expr->AdjustType(checker, expr->Property()->TsTypeOrError());
    }

    if (baseType->IsETSUnionType()) {
        return expr->AdjustType(checker, expr->CheckUnionMember(checker, baseType));
    }
    TypeErrorOnMissingProperty(expr, baseType, checker);
    return expr->TsTypeOrError();
}

checker::Type *ETSAnalyzer::PreferredType(ir::ObjectExpression *expr) const
{
    return expr->preferredType_;
}

static bool ValidatePreferredType(ir::ObjectExpression *expr, ETSChecker *checker)
{
    auto preferredType = expr->PreferredType();
    if (preferredType == nullptr) {
        checker->LogTypeError({"need to specify target type for class composite"}, expr->Start());
        return false;
    }

    if (!preferredType->IsETSObjectType()) {
        checker->LogTypeError(
            {"Target type for class composite needs to be an object type, found '", preferredType, "'"}, expr->Start());
        return false;
    }

    return true;
}

checker::Type *ETSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    if (!ValidatePreferredType(expr, checker)) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (expr->PreferredType()->IsETSDynamicType()) {
        for (ir::Expression *propExpr : expr->Properties()) {
            ASSERT(propExpr->IsProperty());
            ir::Property *prop = propExpr->AsProperty();
            ir::Expression *value = prop->Value();
            value->Check(checker);
            ASSERT(value->TsType());
        }

        expr->SetTsType(expr->PreferredType());
        return expr->PreferredType();
    }

    checker::ETSObjectType *objType = expr->PreferredType()->AsETSObjectType();
    if (objType->HasObjectFlag(checker::ETSObjectFlags::INTERFACE)) {
        // Object literal of interface tpye
        // Further interfaceObjectLiteralLowering phase will resolve interface type
        // and create corresponding anonymous class and class type
        // Here we just set the type to pass the checker
        CheckObjectExprProps(expr, checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                       checker::PropertySearchFlags::SEARCH_IN_INTERFACES);
        expr->SetTsType(objType);
        return objType;
    }

    if (objType->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
        checker->LogTypeError({"target type for class composite ", objType->Name(), " is not instantiable"},
                              expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (expr->PreferredType()->ToAssemblerName().str() == "escompat.Record" ||
        expr->PreferredType()->ToAssemblerName().str() == "escompat.Map") {
        // 7.6.3 Object Literal of Record Type
        // Record is an alias to Map
        // Here we just set the type to pass the checker
        // See Record Lowering for details
        expr->SetTsType(objType);
        return objType;
    }

    bool haveEmptyConstructor = false;
    for (checker::Signature *sig : objType->ConstructSignatures()) {
        if (sig->Params().empty()) {
            haveEmptyConstructor = true;
            checker->ValidateSignatureAccessibility(objType, nullptr, sig, expr->Start());
            break;
        }
    }
    if (!haveEmptyConstructor) {
        checker->LogTypeError({"type ", objType->Name(), " has no parameterless constructor"}, expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    CheckObjectExprProps(expr, checker::PropertySearchFlags::SEARCH_INSTANCE_FIELD |
                                   checker::PropertySearchFlags::SEARCH_IN_BASE |
                                   checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD);

    expr->SetTsType(objType);
    return objType;
}

void ETSAnalyzer::CheckObjectExprProps(const ir::ObjectExpression *expr, checker::PropertySearchFlags searchFlags) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ETSObjectType *objType = expr->PreferredType()->AsETSObjectType();

    for (ir::Expression *propExpr : expr->Properties()) {
        ASSERT(propExpr->IsProperty());
        ir::Property *prop = propExpr->AsProperty();
        ir::Expression *key = prop->Key();
        ir::Expression *value = prop->Value();

        util::StringView pname;
        if (key->IsStringLiteral()) {
            pname = key->AsStringLiteral()->Str();
        } else if (key->IsIdentifier()) {
            pname = key->AsIdentifier()->Name();
        } else {
            checker->LogTypeError({"key in class composite should be either identifier or string literal"},
                                  expr->Start());
            return;
        }
        varbinder::LocalVariable *lv = objType->GetProperty(pname, searchFlags);
        if (lv == nullptr) {
            checker->LogTypeError({"type ", objType->Name(), " has no property named ", pname}, propExpr->Start());
            return;
        }
        checker->ValidatePropertyAccess(lv, objType, propExpr->Start());

        if (key->IsIdentifier()) {
            key->AsIdentifier()->SetVariable(lv);
        }

        auto *propType = checker->GetTypeOfVariable(lv);
        key->SetTsType(propType);

        if (value->IsObjectExpression()) {
            value->AsObjectExpression()->SetPreferredType(propType);
        }
        value->SetTsType(value->Check(checker));

        auto *const valueType = value->TsType();
        const checker::Type *sourceType = checker->TryGettingFunctionTypeFromInvokeFunction(valueType);
        const checker::Type *targetType = checker->TryGettingFunctionTypeFromInvokeFunction(propType);

        checker::AssignmentContext(
            checker->Relation(), value, valueType, propType, value->Start(),
            {"Type '", sourceType, "' is not compatible with type '", targetType, "' at property '", pname, "'"});
    }

    if (objType->HasObjectFlag(ETSObjectFlags::REQUIRED)) {
        checker->ValidateObjectLiteralForRequiredType(objType, expr);
    }
}

checker::Type *ETSAnalyzer::Check(ir::OpaqueTypeNode *expr) const
{
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::SequenceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    for (auto *it : expr->Sequence()) {
        it->Check(checker);
    }
    ASSERT(!expr->Sequence().empty());
    expr->SetTsType(expr->Sequence().back()->TsType());
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::SuperExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    expr->SetTsType(checker->CheckThisOrSuperAccess(expr, checker->Context().ContainingClass()->SuperType(), "super"));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    if (expr->Quasis().size() != expr->Expressions().size() + 1U) {
        checker->LogTypeError("Invalid string template expression", expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    for (auto *it : expr->Expressions()) {
        it->Check(checker);
    }

    for (auto *it : expr->Quasis()) {
        it->Check(checker);
    }

    expr->SetTsType(checker->GlobalBuiltinETSStringType());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ThisExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    /*
    example code:
    ```
        class A {
            prop
        }
        function A.method() {
            let a = () => {
                console.println(this.prop)
            }
        }
        is identical to
        function method(this: A) {
            let a = () => {
                console.println(this.prop)
            }
        }
    ```
    here when "this" is used inside an extension function, we need to bind "this" to the first
    parameter(MANDATORY_PARAM_THIS), and capture the parameter's variable other than containing class's variable
    */
    auto *variable = checker->AsETSChecker()->Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS).variable;
    if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
        ASSERT(variable != nullptr);
        expr->SetTsType(variable->TsType());
    } else {
        expr->SetTsType(checker->CheckThisOrSuperAccess(expr, checker->Context().ContainingClass(), "this"));
    }

    return expr->TsType();
}

// Get string literal type as potential typeof result type with respect to spec p.7.17
static checker::Type *GetTypeOfStringType(checker::Type *argType, ETSChecker *checker)
{
    if (auto unboxed = checker->MaybePrimitiveBuiltinType(argType);
        unboxed->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        switch (checker->TypeKind(unboxed)) {
            case TypeFlag::ETS_BOOLEAN: {
                return checker->CreateETSStringLiteralType("boolean");
            }
            case TypeFlag::BYTE:
            case TypeFlag::CHAR:
            case TypeFlag::SHORT:
            case TypeFlag::INT:
            case TypeFlag::LONG:
            case TypeFlag::FLOAT:
            case TypeFlag::DOUBLE: {
                return checker->CreateETSStringLiteralType("number");
            }
            default:
                UNREACHABLE();
        }
    }
    if (argType->IsETSUndefinedType()) {
        return checker->CreateETSStringLiteralType(util::StringView("undefined"));
    }
    if (argType->IsETSArrayType() || argType->IsETSNullType()) {
        return checker->CreateETSStringLiteralType(util::StringView("object"));
    }
    if (argType->IsETSIntEnumType()) {
        return checker->CreateETSStringLiteralType(util::StringView("number"));
    }
    if (argType->IsETSStringType() || argType->IsETSStringEnumType()) {
        return checker->CreateETSStringLiteralType(util::StringView("string"));
    }
    if (argType->IsETSBigIntType()) {
        return checker->CreateETSStringLiteralType(util::StringView("bigint"));
    }
    if (argType->IsETSFunctionType()) {
        return checker->CreateETSStringLiteralType(util::StringView("function"));
    }

    return checker->GlobalBuiltinETSStringType();
}

static checker::Type *ComputeTypeOfType(ETSChecker *checker, checker::Type *argType)
{
    checker::Type *ret = nullptr;
    ArenaVector<checker::Type *> types(checker->Allocator()->Adapter());
    if (argType->IsETSUnionType()) {
        for (auto *it : argType->AsETSUnionType()->ConstituentTypes()) {
            checker::Type *elType = ComputeTypeOfType(checker, it);
            types.push_back(elType);
        }
        ret = checker->CreateETSUnionType(std::move(types));
    } else {
        ret = GetTypeOfStringType(argType, checker);
    }
    return ret;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TypeofExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    expr->Argument()->Check(checker);
    expr->SetTsType(ComputeTypeOfType(checker, expr->Argument()->TsType()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    auto argType = expr->argument_->Check(checker);
    const auto isCondExpr = expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK;
    checker::Type *operandType = checker->ApplyUnaryOperatorPromotion(argType, true, true, isCondExpr);
    auto unboxedOperandType = isCondExpr ? checker->ETSBuiltinTypeAsConditionalType(argType)
                                         : checker->ETSBuiltinTypeAsPrimitiveType(argType);

    if (argType != nullptr && argType->IsETSBigIntType() && argType->HasTypeFlag(checker::TypeFlag::BIGINT_LITERAL)) {
        switch (expr->OperatorType()) {
            case lexer::TokenType::PUNCTUATOR_MINUS: {
                checker::Type *type = checker->CreateETSBigIntLiteralType(argType->AsETSBigIntType()->GetValue());

                // We do not need this const anymore as we are negating the bigint object in runtime
                type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
                expr->argument_->SetTsType(type);
                expr->SetTsType(type);
                return expr->TsType();
            }
            default:
                // Handled below
                // NOTE(kkonsw): handle other unary operators for bigint literals
                break;
        }
    }

    if (argType != nullptr && argType->IsETSBigIntType()) {
        switch (expr->OperatorType()) {
            case lexer::TokenType::PUNCTUATOR_MINUS:
            case lexer::TokenType::PUNCTUATOR_PLUS:
            case lexer::TokenType::PUNCTUATOR_TILDE: {
                expr->SetTsType(argType);
                return expr->TsType();
            }
            default:
                break;
        }
    }

    if (argType != nullptr && argType->IsETSEnumType()) {
        expr->Argument()->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
    }
    SetTsTypeForUnaryExpression(checker, expr, operandType);

    if ((argType != nullptr) && argType->IsETSObjectType() && (unboxedOperandType != nullptr) &&
        unboxedOperandType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedOperandType));
    }

    checker->Context().CheckUnarySmartCastCondition(expr);

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::UpdateExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    checker::Type *operandType = expr->argument_->Check(checker);
    if (expr->Argument()->IsIdentifier()) {
        checker->ValidateUnaryOperatorOperand(expr->Argument()->AsIdentifier()->Variable());
    } else if (expr->Argument()->IsTSAsExpression()) {
        if (auto *const asExprVar = expr->Argument()->AsTSAsExpression()->Variable(); asExprVar != nullptr) {
            checker->ValidateUnaryOperatorOperand(asExprVar);
        }
    } else if (expr->Argument()->IsTSNonNullExpression()) {
        if (auto *const nonNullExprVar = expr->Argument()->AsTSNonNullExpression()->Variable();
            nonNullExprVar != nullptr) {
            checker->ValidateUnaryOperatorOperand(nonNullExprVar);
        }
    } else {
        ASSERT(expr->Argument()->IsMemberExpression());
        varbinder::LocalVariable *propVar = expr->argument_->AsMemberExpression()->PropVar();
        if (propVar != nullptr) {
            checker->ValidateUnaryOperatorOperand(propVar);
        }
    }

    if (operandType->IsETSBigIntType()) {
        expr->SetTsType(operandType);
        return expr->TsType();
    }

    auto unboxedType = checker->ETSBuiltinTypeAsPrimitiveType(operandType);
    if (unboxedType == nullptr || !unboxedType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        checker->LogTypeError("Bad operand type, the type of the operand must be numeric type.",
                              expr->Argument()->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (operandType->IsETSObjectType()) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedType) |
                                                 checker->GetBoxingFlag(unboxedType));
    }

    expr->SetTsType(operandType);
    return expr->TsType();
}

// compile methods for LITERAL EXPRESSIONS in alphabetical order
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::BigIntLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->SetTsType(checker->CreateETSBigIntLiteralType(expr->Str()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::BooleanLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() == nullptr) {
        expr->SetTsType(checker->CreateETSBooleanType(expr->Value()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::CharLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() == nullptr) {
        expr->SetTsType(checker->Allocator()->New<checker::CharType>(expr->Char()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::NullLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() == nullptr) {
        expr->SetTsType(checker->GlobalETSNullType());
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::NamespaceDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NamespaceDefinition *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::NumberLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->Number().IsInt()) {
        expr->SetTsType(checker->CreateIntType(expr->Number().GetInt()));
        return expr->TsType();
    }

    if (expr->Number().IsLong()) {
        expr->SetTsType(checker->CreateLongType(expr->Number().GetLong()));
        return expr->TsType();
    }

    if (expr->Number().IsFloat()) {
        expr->SetTsType(checker->CreateFloatType(expr->Number().GetFloat()));
        return expr->TsType();
    }

    expr->SetTsType(checker->CreateDoubleType(expr->Number().GetDouble()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::StringLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsTypeOrError() == nullptr) {
        expr->SetTsType(checker->CreateETSStringLiteralType(expr->Str()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ImportDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *type = nullptr;
    for (auto *spec : st->Specifiers()) {
        if (spec->IsImportNamespaceSpecifier()) {
            type = spec->AsImportNamespaceSpecifier()->Check(checker);
        }
    }

    return type;
}

checker::Type *ETSAnalyzer::Check(ir::ImportNamespaceSpecifier *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (st->Local()->Name().Empty()) {
        return nullptr;
    }

    if (st->Local()->AsIdentifier()->TsTypeOrError() != nullptr) {
        return st->Local()->TsTypeOrError();
    }

    auto *importDecl = st->Parent()->AsETSImportDeclaration();

    if (importDecl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(importDecl->Language());
        checker->SetrModuleObjectTsType(st->Local(), type);
        return type;
    }

    return checker->GetImportSpecifierObjectType(importDecl, st->Local()->AsIdentifier());
}

// compile methods for STATEMENTS in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::AssertStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (!(st->Test()->Check(checker)->HasTypeFlag(TypeFlag::ETS_BOOLEAN | TypeFlag::BOOLEAN_LIKE) ||
          st->Test()->Check(checker)->ToString() == "Boolean")) {
        checker->LogTypeError("Bad operand type, the type of the operand must be boolean type.", st->Test()->Start());
    }

    if (st->Second() != nullptr) {
        auto *msgType = st->second_->Check(checker);

        if (!msgType->IsETSStringType()) {
            checker->LogTypeError("Assert message must be string", st->Second()->Start());
        }
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::BlockStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    // Iterator type checking of statements is modified to index type, to allow modifying the statement list during
    // checking without invalidating the iterator
    //---- Don't modify this to iterator, as it may break things during checking
    for (std::size_t idx = 0; idx < st->Statements().size(); ++idx) {
        auto *stmt = st->Statements()[idx];
        stmt->Check(checker);

        //  NOTE! Processing of trailing blocks was moved here so that smart casts could be applied correctly
        if (auto const tb = st->trailingBlocks_.find(stmt); tb != st->trailingBlocks_.end()) {
            auto *const trailingBlock = tb->second;
            trailingBlock->Check(checker);
            st->Statements().emplace(std::next(st->Statements().begin() + idx), trailingBlock);
            ++idx;
        }
    }
    if (UNLIKELY(checker->GetDebugInfoPlugin() != nullptr)) {
        // Compilation in eval-mode might require to create additional statements.
        // In this case, they must be created after iteration through statements ends.
        checker->GetDebugInfoPlugin()->AddPrologueEpilogue(st);
    }

    //  Remove possible smart casts for variables declared in inner scope:
    if (auto const *const scope = st->Scope();
        scope->IsFunctionScope() && st->Parent()->Parent()->Parent()->IsMethodDefinition()) {
        // When exiting method definition, just clear all smart casts
        checker->Context().ClearSmartCasts();
    } else if (!scope->IsGlobalScope()) {
        // otherwise only check inner declarations
        for (auto const *const decl : scope->Decls()) {
            if (decl->IsLetOrConstDecl() && decl->Node()->IsIdentifier()) {
                checker->Context().RemoveSmartCast(decl->Node()->AsIdentifier()->Variable());
            }
        }
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::BreakStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    auto node = checker->FindJumpTarget(st);
    if (!node.has_value()) {
        return checker->GlobalTypeError();
    }
    st->SetTarget(*node);

    checker->Context().OnBreakStatement(st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ClassDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::AnnotationDeclaration *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::AnnotationUsage *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ContinueStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    auto node = checker->FindJumpTarget(st);
    if (!node.has_value()) {
        return checker->GlobalTypeError();
    }
    st->SetTarget(*node);

    checker->AddStatus(CheckerStatus::MEET_CONTINUE);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::DoWhileStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st);

    checker->CheckTruthinessOfType(st->Test());
    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::EmptyStatement *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ExpressionStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    return st->GetExpression()->Check(checker);
}

static bool ValidateAndProcessIteratorType(ETSChecker *checker, Type *elemType, ir::ForOfStatement *const st)
{
    checker::Type *iterType = GetIteratorType(checker, elemType, st->Left());
    if (iterType->IsTypeError()) {
        return false;
    }
    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(st->Left()->IsVariableDeclaration()
                          ? st->Left()->AsVariableDeclaration()->Declarators().front()->Id()
                          : st->Left()->AsIdentifier());

    if (!relation->IsAssignableTo(elemType, iterType)) {
        std::stringstream ss {};
        ss << "Source element type '" << elemType->ToString() << "' is not assignable to the loop iterator type '"
           << iterType->ToString() << "'.";
        checker->LogTypeError(ss.str(), st->Start());
        return false;
    }

    relation->SetNode(nullptr);
    relation->SetFlags(checker::TypeRelationFlag::NONE);

    if (iterType->Variable() == nullptr && !iterType->IsETSObjectType() && elemType->IsETSObjectType() &&
        st->Left()->IsVariableDeclaration()) {
        for (auto &declarator : st->Left()->AsVariableDeclaration()->Declarators()) {
            checker->AddBoxingUnboxingFlagsToNode(declarator->Id(), iterType);
        }
    }
    return true;
}
// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const MISSING_SOURCE_EXPR_TYPE[] =
    "Cannot determine source expression type in the 'for-of' statement.";
static constexpr char const INVALID_SOURCE_EXPR_TYPE[] =
    "'For-of' statement source expression is not of iterable type.";
// NOLINTEND(modernize-avoid-c-arrays)

checker::Type *ETSAnalyzer::Check(ir::ForOfStatement *const st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st);

    checker::Type *const exprType = st->Right()->Check(checker);
    if (exprType == nullptr) {
        checker->LogTypeError(MISSING_SOURCE_EXPR_TYPE, st->Right()->Start());
        return checker->GlobalTypeError();
    }

    checker::Type *elemType = nullptr;

    if (exprType->IsETSStringType()) {
        elemType = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else if (exprType->IsETSArrayType()) {
        elemType = exprType->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                          checker->GetGlobalTypesHolder());
        if (elemType != nullptr) {
            elemType->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        }
    } else if (exprType->IsETSObjectType() || exprType->IsETSUnionType() || exprType->IsETSTypeParameter()) {
        elemType = st->CheckIteratorMethod(checker);
    }

    if (elemType == nullptr) {
        checker->LogTypeError(INVALID_SOURCE_EXPR_TYPE, st->Right()->Start());
        return checker->GlobalTypeError();
    }

    st->Left()->Check(checker);

    if (!ValidateAndProcessIteratorType(checker, elemType, st)) {
        return checker->GlobalTypeError();
    };

    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st);

    if (st->Init() != nullptr) {
        st->Init()->Check(checker);
    }

    if (st->Test() != nullptr) {
        checker->CheckTruthinessOfType(st->Test());
    }

    if (st->Update() != nullptr) {
        st->Update()->Check(checker);
    }

    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::IfStatement *st) const
{
    ETSChecker *const checker = GetETSChecker();

    SmartCastArray smartCasts = checker->Context().EnterTestExpression();
    checker->CheckTruthinessOfType(st->Test());
    SmartCastTypes testedTypes = checker->Context().ExitTestExpression();
    if (testedTypes.has_value()) {
        for (auto [variable, consequentType, _] : *testedTypes) {
            checker->ApplySmartCast(variable, consequentType);
        }
    }

    checker->Context().EnterPath();
    st->Consequent()->Check(checker);
    bool const consequentTerminated = checker->Context().ExitPath();
    SmartCastArray consequentSmartCasts = checker->Context().CloneSmartCasts();

    // Restore smart casts to initial state.
    checker->Context().RestoreSmartCasts(smartCasts);
    //  Apply the alternate smart casts
    if (testedTypes.has_value()) {
        for (auto [variable, _, alternateType] : *testedTypes) {
            checker->ApplySmartCast(variable, alternateType);
        }
    }

    if (st->Alternate() != nullptr) {
        checker->Context().EnterPath();
        st->Alternate()->Check(checker);
        bool const alternateTerminated = checker->Context().ExitPath();
        if (alternateTerminated) {
            if (!consequentTerminated) {
                // Here we need to restore types from consequent if block.
                checker->Context().RestoreSmartCasts(consequentSmartCasts);
            } else {
                // Here we need to restore initial smart types.
                checker->Context().RestoreSmartCasts(smartCasts);
            }
        } else if (!consequentTerminated) {
            // Here we need to combine types from consequent and alternate if blocks.
            checker->Context().CombineSmartCasts(consequentSmartCasts);
        }
    } else {
        if (!consequentTerminated) {
            // Here we need to combine types from consequent if block and initial.
            checker->Context().CombineSmartCasts(consequentSmartCasts);
        }
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::LabelledStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->body_->Check(checker);
    return nullptr;
}

bool ETSAnalyzer::CheckInferredFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc,
                                                  checker::Type *&funcReturnType, ir::TypeNode *returnTypeAnnotation,
                                                  ETSChecker *checker) const
{
    funcReturnType = returnTypeAnnotation->GetType(checker);
    if (returnTypeAnnotation->IsTSThisType() && (st->Argument() == nullptr || !st->Argument()->IsThisExpression())) {
        checker->LogTypeError("The only allowed return value is 'this' if the method's return type is the 'this' type",
                              st->Start());
        return false;
    }

    // Case when function's return type is defined explicitly:

    if (st->argument_ == nullptr) {
        if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalVoidType() &&
            !funcReturnType->IsETSAsyncFuncReturnType()) {
            checker->LogTypeError("Missing return value.", st->Start());
            return false;
        }
        funcReturnType = checker->GlobalVoidType();
    } else {
        const auto name = containingFunc->Scope()->InternalName().Mutf8();
        if (!CheckArgumentVoidType(funcReturnType, checker, name, st)) {
            return false;
        }

        if (st->argument_->IsObjectExpression()) {
            st->argument_->AsObjectExpression()->SetPreferredType(funcReturnType);
        }
        if (st->argument_->IsMemberExpression()) {
            checker->SetArrayPreferredTypeForNestedMemberExpressions(st->argument_->AsMemberExpression(),
                                                                     funcReturnType);
        }

        if (st->argument_->IsArrayExpression()) {
            st->argument_->AsArrayExpression()->SetPreferredType(funcReturnType);
        }

        checker::Type *argumentType = st->argument_->Check(checker);
        return CheckReturnType(checker, funcReturnType, argumentType, st->argument_, containingFunc->IsAsyncFunc());
    }
    return true;
}

checker::Type *ETSAnalyzer::GetFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc) const
{
    ASSERT(containingFunc->ReturnTypeAnnotation() != nullptr || containingFunc->Signature()->ReturnType() != nullptr);

    ETSChecker *checker = GetETSChecker();
    checker::Type *funcReturnType = nullptr;

    if (auto *const returnTypeAnnotation = containingFunc->ReturnTypeAnnotation(); returnTypeAnnotation != nullptr) {
        if (!CheckInferredFunctionReturnType(st, containingFunc, funcReturnType, returnTypeAnnotation, checker)) {
            return checker->GlobalTypeError();
        }
    } else {
        //  Case when function's return type should be inferred from return statement(s):
        if (containingFunc->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
            InferReturnType(checker, containingFunc, funcReturnType,
                            st->argument_);  // This removes the NEED_RETURN_TYPE flag, so only the first return
                                             // statement going to land here...
        } else {
            //  All subsequent return statements:
            ProcessReturnStatements(checker, containingFunc, funcReturnType, st,
                                    st->argument_);  // and the remaining return statements will get processed here.
        }
    }

    if ((st->argument_ != nullptr) && st->argument_->IsArrayExpression() && funcReturnType->IsArrayType()) {
        checker->ModifyPreferredType(st->argument_->AsArrayExpression(), funcReturnType);
        st->argument_->Check(checker);
    }

    return funcReturnType;
}

checker::Type *ETSAnalyzer::Check(ir::ReturnStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(st, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containingFunc = ancestor->AsScriptFunction();

    checker->AddStatus(CheckerStatus::MEET_RETURN);

    if (containingFunc->IsConstructor()) {
        if (st->argument_ != nullptr) {
            checker->LogTypeError("Return statement with expression isn't allowed in constructor.", st->Start());
            return checker->GlobalTypeError();
        }
        return nullptr;
    }

    st->returnType_ = GetFunctionReturnType(st, containingFunc);

    if (containingFunc->ReturnTypeAnnotation() == nullptr) {
        containingFunc->AddReturnStatement(st);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::SwitchStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(checker->Relation(),
                                                                    checker::TypeRelationFlag::NONE);

    auto *comparedExprType = checker->CheckSwitchDiscriminant(st->Discriminant());
    auto unboxedDiscType = (st->Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
                               ? checker->ETSBuiltinTypeAsPrimitiveType(comparedExprType)
                               : comparedExprType;

    SmartCastArray smartCasts = checker->Context().CloneSmartCasts();
    bool hasDefaultCase = false;

    for (auto &it : st->Cases()) {
        checker->Context().EnterPath();
        it->CheckAndTestCase(checker, comparedExprType, unboxedDiscType, st->Discriminant(), hasDefaultCase);
        bool const caseTerminated = checker->Context().ExitPath();

        if (it != st->Cases().back()) {
            if (!caseTerminated) {
                checker->Context().CombineSmartCasts(smartCasts);
            } else {
                checker->Context().RestoreSmartCasts(smartCasts);
            }
        } else {
            if (!caseTerminated) {
                //  if the recent switch case isn't terminated in any way, copy actual smart casts to the array of
                //  smart casts for the other case blocks so that it can be processed in unified way
                checker->Context().AddBreakSmartCasts(st, checker->Context().CloneSmartCasts());
            }
            checker->Context().ClearSmartCasts();
        }
    }

    // If default case is absent initial smart casts should be also applied here
    if (!hasDefaultCase) {
        checker->Context().AddBreakSmartCasts(st, std::move(smartCasts));
    }

    // Combine smart casts from all [non-terminated] case blocks with 'break'
    checker->Context().CombineBreakSmartCasts(st);

    checker->CheckForSameSwitchCases(st->Cases());
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ThrowStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    auto *argType = st->argument_->Check(checker);
    checker->CheckExceptionOrErrorType(argType, st->Start());

    if (checker->Relation()->IsAssignableTo(argType, checker->GlobalBuiltinExceptionType())) {
        checker->CheckThrowingStatements(st);
    }

    checker->AddStatus(CheckerStatus::MEET_THROW);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TryStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    std::vector<checker::ETSObjectType *> exceptions {};

    std::vector<SmartCastArray> casts {};
    auto smartCasts = checker->Context().CheckTryBlock(*st->Block());
    st->Block()->Check(checker);

    bool defaultCatchFound = false;
    for (auto *catchClause : st->CatchClauses()) {
        if (defaultCatchFound) {
            checker->LogTypeError("Default catch clause should be the last in the try statement", catchClause->Start());
            return checker->GlobalTypeError();
        }

        checker->Context().RestoreSmartCasts(smartCasts);

        if (auto const exceptionType = catchClause->Check(checker);
            exceptionType != nullptr && catchClause->Param() != nullptr) {
            auto *clauseType = exceptionType->AsETSObjectType();
            checker->CheckExceptionClauseType(exceptions, catchClause, clauseType);
            exceptions.emplace_back(clauseType);
        }

        defaultCatchFound = catchClause->IsDefaultCatchClause();

        casts.emplace_back(checker->Context().CloneSmartCasts());
    }

    checker->Context().RestoreSmartCasts(smartCasts);
    if (!casts.empty()) {
        for (auto const &cast : casts) {
            checker->Context().CombineSmartCasts(cast);
        }
    }

    if (st->HasFinalizer()) {
        st->FinallyBlock()->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    if (st->TsTypeOrError() != nullptr) {
        return st->TsTypeOrError();
    }

    ETSChecker *checker = GetETSChecker();
    ASSERT(st->Id()->IsIdentifier());
    auto *const ident = st->Id()->AsIdentifier();
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (ident->Parent()->Parent()->AsVariableDeclaration()->Kind() ==
        ir::VariableDeclaration::VariableDeclarationKind::CONST) {
        flags |= ir::ModifierFlags::CONST;
    }

    if (ident->IsOptionalDeclaration()) {
        flags |= ir::ModifierFlags::OPTIONAL;
    }

    auto *const variableType = checker->CheckVariableDeclaration(ident, ident->TypeAnnotation(), st->Init(), flags);
    auto *smartType = variableType;

    //  Now try to define the actual type of Identifier so that smart cast can be used in further checker processing
    //  NOTE: T_S and K_o_t_l_i_n don't act in such way, but we can try - why not? :)
    if (auto *const initType = st->Init() != nullptr ? st->Init()->TsTypeOrError() : nullptr; initType != nullptr) {
        smartType = checker->ResolveSmartType(initType, variableType);
        //  Set smart type for identifier if it differs from annotated type
        //  Top-level and captured variables are not processed here!
        if (!checker->Relation()->IsIdenticalTo(variableType, smartType)) {
            ident->SetTsType(smartType);
            checker->Context().SetSmartCast(ident->Variable(), smartType);
        }
    }

    st->SetTsType(smartType);
    return smartType;
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    for (auto *it : st->Declarators()) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::WhileStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st);

    checker->CheckTruthinessOfType(st->Test());
    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TSArrayType *node) const
{
    ETSChecker *checker = GetETSChecker();
    node->elementType_->Check(checker);
    node->SetTsType(node->GetType(checker));

    const auto arrayType = node->TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsTypeOrError() != nullptr) {
        return expr->TsTypeOrError();
    }

    auto *const targetType = expr->TypeAnnotation()->AsTypeNode()->GetType(checker);
    // Object expression requires that its type be set by the context before checking. in this case, the target type
    // provides that context.
    if (expr->Expr()->IsObjectExpression()) {
        expr->Expr()->AsObjectExpression()->SetPreferredType(targetType);
    }

    if (expr->Expr()->IsArrayExpression()) {
        expr->Expr()->AsArrayExpression()->SetPreferredType(targetType);
    }

    auto *const sourceType = expr->Expr()->Check(checker);
    if (sourceType->IsTypeError()) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    if (targetType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) && sourceType->IsETSReferenceType()) {
        auto *const boxedTargetType = checker->PrimitiveTypeAsETSBuiltinType(targetType);
        if (!checker->Relation()->IsIdenticalTo(sourceType, boxedTargetType)) {
            expr->Expr()->AddAstNodeFlags(ir::AstNodeFlags::CHECKCAST);
        }
    }

    if (sourceType->DefinitelyETSNullish() && !targetType->PossiblyETSNullish()) {
        checker->LogTypeError("Cannot cast 'null' or 'undefined' to non-nullish type.", expr->Expr()->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    const checker::CastingContext ctx(
        checker->Relation(),
        std::initializer_list<TypeErrorMessageElement> {"Cannot cast type '", sourceType, "' to '", targetType, "'"},
        checker::CastingContext::ConstructorData {expr->Expr(), sourceType, targetType, expr->Expr()->Start()});

    if (sourceType->IsETSDynamicType() && targetType->IsLambdaObject()) {
        // NOTE: itrubachev. change targetType to created lambdaobject type.
        // Now targetType is not changed, only construct signature is added to it
        checker->BuildLambdaObjectClass(targetType->AsETSObjectType(),
                                        expr->TypeAnnotation()->AsETSFunctionType()->ReturnType());
    }
    expr->isUncheckedCast_ = ctx.UncheckedCast();

    // Make sure the array type symbol gets created for the assembler to be able to emit checkcast.
    // Because it might not exist, if this particular array type was never created explicitly.
    if (!expr->isUncheckedCast_ && targetType->IsETSArrayType()) {
        auto *const targetArrayType = targetType->AsETSArrayType();
        checker->CreateBuiltinArraySignature(targetArrayType, targetArrayType->Rank());
    }

    if (targetType == checker->GetGlobalTypesHolder()->GlobalBuiltinNeverType()) {
        checker->LogTypeError("Cast to 'never' is prohibited", expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsTypeOrError();
    }

    checker->ComputeApparentType(targetType);
    expr->SetTsType(targetType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TSEnumDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    varbinder::Variable *enumVar = st->Key()->Variable();
    ASSERT(enumVar != nullptr);

    if (enumVar->TsTypeOrError() == nullptr) {
        checker::Type *etsEnumType = nullptr;
        Check(st->BoxedClass());
        if (auto *const itemInit = st->Members().front()->AsTSEnumMember()->Init(); itemInit->IsNumberLiteral()) {
            etsEnumType = checker->CreateEnumIntTypeFromEnumDeclaration(st);
        } else if (itemInit->IsStringLiteral()) {
            etsEnumType = checker->CreateEnumStringTypeFromEnumDeclaration(st);
        } else {
            checker->LogTypeError("Invalid enumeration value type.", st->Start());
            st->SetTsType(checker->GlobalTypeError());
            return st->TsTypeOrError();
        }
        st->SetTsType(etsEnumType);
        etsEnumType->SetVariable(enumVar);
        enumVar->SetTsType(etsEnumType);
    } else if (st->TsTypeOrError() == nullptr) {
        st->SetTsType(enumVar->TsTypeOrError());
    }

    return st->TsTypeOrError();
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();

    checker::ETSObjectType *interfaceType {};

    if (st->TsTypeOrError() != nullptr) {
        return st->TsTypeOrError();
    }

    interfaceType = checker->BuildBasicInterfaceProperties(st);
    ASSERT(interfaceType != nullptr);
    interfaceType->SetSuperType(checker->GlobalETSObjectType());
    checker->CheckInvokeMethodsLegitimacy(interfaceType);
    st->SetTsType(interfaceType);

    checker::ScopeContext scopeCtx(checker, st->Scope());
    auto savedContext = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_INTERFACE, interfaceType);

    for (auto *it : st->Body()->Body()) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TSNonNullExpression *expr) const
{
    if (expr->TsTypeOrError() == nullptr) {
        ETSChecker *checker = GetETSChecker();
        auto exprType = expr->expr_->Check(checker);
        //  If the actual [smart] type is definitely 'null' or 'undefined' then probably CTE should be thrown.
        //  Anyway we'll definitely obtain NullPointerException at runtime.
        if (exprType->DefinitelyETSNullish()) {
            checker->LogTypeError(
                "Bad operand type, the operand of the non-nullish expression is 'null' or 'undefined'.",
                expr->Expr()->Start());
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsTypeOrError();
        }
        expr->SetTsType(checker->GetNonNullishType(exprType));
    }
    expr->SetOriginalType(expr->TsType());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TSQualifiedName *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *baseType = expr->Left()->Check(checker);

    if (baseType->IsETSObjectType()) {
        auto importDecl = baseType->AsETSObjectType()->GetDeclNode()->Parent()->Parent();
        // clang-format off
        auto searchName =
            importDecl->IsETSImportDeclaration()
                ? checker->VarBinder()->AsETSBinder()->FindNameInAliasMap(
                    importDecl->AsETSImportDeclaration()->ResolvedSource()->Str(), expr->Right()->Name())
                : expr->Right()->Name();
        // clang-format on
        // NOTE (oeotvos) This should be done differently in the follow-up patch.
        if (searchName.Empty()) {
            searchName = expr->Right()->Name();
        }
        varbinder::Variable *prop =
            baseType->AsETSObjectType()->GetProperty(searchName, checker::PropertySearchFlags::SEARCH_DECL);
        // NOTE(dslynko): in debugger evaluation mode must lazily generate module's properties here.

        if (prop == nullptr) {
            checker->LogTypeError({"'", expr->Right()->Name(), "' type does not exist."}, expr->Right()->Start());
            return checker->GlobalTypeError();
        }

        if (expr->Right()->Name().Is(searchName.Mutf8()) && prop->Declaration()->Node()->HasExportAlias()) {
            checker->LogTypeError({"Cannot find imported element '", searchName, "' exported with alias"},
                                  expr->Right()->Start());
            return checker->GlobalTypeError();
        }

        expr->Right()->SetVariable(prop);
        return checker->GetTypeOfVariable(prop);
    }

    checker->LogTypeError({"'", expr->Right()->Name(), "' type does not exist."}, expr->Right()->Start());
    return checker->GlobalTypeError();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (st->TypeParams() == nullptr) {
        const checker::SavedTypeRelationFlagsContext savedFlagsCtx(
            checker->Relation(), checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

        if (st->TypeAnnotation()->TsTypeOrError() == nullptr) {
            st->TypeAnnotation()->Check(checker);
        }

        return nullptr;
    }

    if (st->TypeParameterTypes().empty()) {
        auto [typeParamTypes, ok] = checker->CreateUnconstrainedTypeParameters(st->TypeParams());
        st->SetTypeParameterTypes(std::move(typeParamTypes));
        if (ok) {
            checker->AssignTypeParameterConstraints(st->TypeParams());
        }
    }

    for (auto *const param : st->TypeParams()->Params()) {
        const auto *const res = st->TypeAnnotation()->FindChild([&param](const ir::AstNode *const node) {
            if (!node->IsIdentifier()) {
                return false;
            }

            return param->Name()->AsIdentifier()->Variable() == node->AsIdentifier()->Variable();
        });

        if (res == nullptr) {
            checker->LogTypeError(
                {"Type alias generic parameter '", param->Name()->Name(), "' is not used in type annotation"},
                param->Start());
            return checker->GlobalTypeError();
        }
    }

    const checker::SavedTypeRelationFlagsContext savedFlagsCtx(checker->Relation(),
                                                               checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

    if (st->TypeAnnotation()->TsTypeOrError() == nullptr) {
        st->TypeAnnotation()->Check(checker);
    }

    return nullptr;
}
}  // namespace ark::es2panda::checker
