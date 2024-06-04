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

#include "util/helpers.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsTupleType.h"

namespace ark::es2panda::checker {

ETSChecker *ETSAnalyzer::GetETSChecker() const
{
    return static_cast<ETSChecker *>(GetChecker());
}

// from as folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NamedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
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
    if (node->TsType() == nullptr) {
        checker->BuildBasicClassProperties(node);
    }

    checker->CheckClassDefinition(node);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ClassProperty *st) const
{
    ASSERT(st->Id() != nullptr);
    ETSChecker *checker = GetETSChecker();

    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass(),
                                              checker->Context().ContainingSignature());

    if (st->IsStatic()) {
        checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    st->SetTsType(checker->CheckVariableDeclaration(st->Id(), st->TypeAnnotation(), st->Value(), st->Modifiers()));

    return st->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ClassStaticBlock *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(checker::CheckerStatus::INNER_CLASS)) {
        checker->ThrowTypeError("Static initializer is not allowed in inner class.", st->Start());
    }

    auto *func = st->Function();
    st->SetTsType(checker->BuildFunctionSignature(func));
    checker::ScopeContext scopeCtx(checker, func->Scope());
    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_STATIC_BLOCK | checker::CheckerStatus::IN_STATIC_CONTEXT);
    func->Body()->Check(checker);
    return st->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Decorator *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::MetaProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();

    auto *scriptFunc = node->Function();

    if (scriptFunc == nullptr) {
        checker->ThrowTypeError("Invalid function expression", node->Start());
    }

    if (scriptFunc->IsProxy()) {
        return nullptr;
    }

    // NOTE: aszilagyi. make it correctly check for open function not have body
    if (!scriptFunc->HasBody() && !(node->IsAbstract() || node->IsNative() || node->IsDeclare() ||
                                    checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->ThrowTypeError("Only abstract or native methods can't have body.", scriptFunc->Start());
    }

    if (scriptFunc->ReturnTypeAnnotation() == nullptr &&
        (node->IsNative() || (node->IsDeclare() && !node->IsConstructor()))) {
        checker->ThrowTypeError("Native and Declare methods should have explicit return type.", scriptFunc->Start());
    }

    if (node->TsType() == nullptr) {
        node->SetTsType(checker->BuildMethodSignature(node));
    }

    this->CheckMethodModifiers(node);

    if (node->IsNative()) {
        if (scriptFunc->ReturnTypeAnnotation() == nullptr) {
            checker->ThrowTypeError("'Native' method should have explicit return type", scriptFunc->Start());
        }
        if (scriptFunc->IsGetter() || scriptFunc->IsSetter()) {
            checker->ThrowTypeError("'Native' modifier is invalid for Accessors", scriptFunc->Start());
        }
    }

    DoBodyTypeChecking(checker, node, scriptFunc);
    CheckPredefinedMethodReturnType(checker, scriptFunc);

    checker->CheckOverride(node->TsType()->AsETSFunctionType()->FindSignature(node->Function()));

    for (auto *it : node->Overloads()) {
        it->Check(checker);
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
        checker->ThrowTypeError(
            "Invalid method modifier(s): an abstract method can't have private, override, static, final or native "
            "modifier.",
            node->Start());
    }

    if (node->Function() == nullptr) {
        checker->ThrowTypeError("Invalid function expression", node->Start());
    }

    if ((node->IsAbstract() || (!node->Function()->HasBody() && !node->IsNative() && !node->IsDeclare())) &&
        !(checker->HasStatus(checker::CheckerStatus::IN_ABSTRACT) ||
          checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->ThrowTypeError("Non abstract class has abstract method.", node->Start());
    }

    auto const notValidInFinal = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::STATIC | ir::ModifierFlags::NATIVE;

    if (node->IsFinal() && (node->flags_ & notValidInFinal) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): a final method can't have abstract, static or native modifier.",
            node->Start());
    }

    auto const notValidInStatic = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::FINAL | ir::ModifierFlags::OVERRIDE;

    if (node->IsStatic() && (node->flags_ & notValidInStatic) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): a static method can't have abstract, final or override modifier.",
            node->Start());
    }
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Property *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ScriptFunction *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SpreadElement *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateElement *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->SetTsType(checker->CreateETSStringLiteralType(expr->Raw()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIndexSignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSMethodSignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSPropertySignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSSignatureDeclaration *node) const
{
    UNREACHABLE();
}
// from ets folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSScript *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSClassLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker->ThrowTypeError("Class literal is not yet supported.", expr->expr_->Start());

    expr->expr_->Check(checker);
    auto *exprType = expr->expr_->GetType(checker);

    if (exprType->IsETSVoidType()) {
        checker->ThrowTypeError("Invalid .class reference", expr->expr_->Start());
    }

    ArenaVector<checker::Type *> typeArgTypes(checker->Allocator()->Adapter());
    typeArgTypes.push_back(exprType);  // NOTE: Box it if it's a primitive type

    checker::InstantiationContext ctx(checker, checker->GlobalBuiltinTypeType(), typeArgTypes, expr->range_.start);
    expr->SetTsType(ctx.Result());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto *genericInterfaceType = checker->GlobalBuiltinFunctionType(node->Params().size());
    node->SetFunctionalInterface(genericInterfaceType->GetDeclNode()->AsTSInterfaceDeclaration());

    auto *tsType = checker->GetCachedFunctionlInterface(node);
    node->SetTsType(tsType);
    if (tsType != nullptr) {
        return tsType;
    }

    auto *substitution = checker->NewSubstitution();

    auto maxParamsNum = checker->GlobalBuiltinFunctionTypeVariadicThreshold();

    auto const &params = node->Params();
    size_t i = 0;
    if (params.size() < maxParamsNum) {
        for (; i < params.size(); i++) {
            auto *paramType = params[i]->AsETSParameterExpression()->TypeAnnotation()->GetType(checker);
            if (paramType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
                checker->Relation()->SetNode(params[i]);
                auto *const boxedTypeArg = checker->PrimitiveTypeAsETSBuiltinType(paramType);
                ASSERT(boxedTypeArg);
                paramType = boxedTypeArg->Instantiate(checker->Allocator(), checker->Relation(),
                                                      checker->GetGlobalTypesHolder());
            }

            checker::ETSChecker::EmplaceSubstituted(
                substitution, genericInterfaceType->TypeArguments()[i]->AsETSTypeParameter()->GetOriginal(), paramType);
        }
    }

    auto *returnType = node->ReturnType()->GetType(checker);
    if (returnType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        checker->Relation()->SetNode(node->ReturnType());
        auto *const boxedTypeRet = checker->PrimitiveTypeAsETSBuiltinType(returnType);
        returnType =
            boxedTypeRet->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
    }

    checker::ETSChecker::EmplaceSubstituted(
        substitution, genericInterfaceType->TypeArguments()[i]->AsETSTypeParameter()->GetOriginal(), returnType);

    auto *interfaceType = genericInterfaceType->Substitute(checker->Relation(), substitution)->AsETSObjectType();

    node->SetTsType(interfaceType);
    return interfaceType;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
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

    auto *exprType =
        expr->expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) && !expr->expr_->TsType()->IsETSVoidType()
            ? checker->PrimitiveTypeAsETSBuiltinType(expr->expr_->TsType())
            : expr->expr_->TsType();
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
        if (elementType->IsETSObjectType()) {
            auto *calleeObj = elementType->AsETSObjectType();
            if (!calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
                // A workaround check for new Interface[...] in test cases
                expr->SetSignature(
                    checker->CollectParameterlessConstructor(calleeObj->ConstructSignatures(), expr->Start()));
                checker->ValidateSignatureAccessibility(calleeObj, nullptr, expr->Signature(), expr->Start());
            }
        }
    }
    expr->SetTsType(checker->CreateETSArrayType(elementType));
    checker->CreateBuiltinArraySignature(expr->TsType()->AsETSArrayType(), 1);
    return expr->TsType();
}

void ETSAnalyzer::CheckLocalClassInstantiation(ir::ETSNewClassInstanceExpression *expr, ETSObjectType *calleeObj) const
{
    ETSChecker *checker = GetETSChecker();
    ASSERT(calleeObj->GetDeclNode()->IsClassDefinition());
    if (calleeObj->GetDeclNode()->AsClassDefinition()->IsLocal()) {
        checker->AddToLocalClassInstantiationList(expr);
    }
}

void ETSAnalyzer::CheckInstantatedClass(ir::ETSNewClassInstanceExpression *expr, ETSObjectType *&calleeObj) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->ClassDefinition() != nullptr) {
        if (!calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT) && calleeObj->GetDeclNode()->IsFinal()) {
            checker->ThrowTypeError({"Class ", calleeObj->Name(), " cannot be both 'abstract' and 'final'."},
                                    calleeObj->GetDeclNode()->Start());
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
        checker->ThrowTypeError({calleeObj->Name(), " is abstract therefore cannot be instantiated."}, expr->Start());
    }
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    auto *calleeType = GetCalleeType(checker, expr);
    auto *calleeObj = calleeType->AsETSObjectType();
    expr->SetTsType(calleeObj);

    CheckLocalClassInstantiation(expr, calleeObj);
    CheckInstantatedClass(expr, calleeObj);

    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->GetTypeRef(), expr->GetArguments(), lang, true));
    } else {
        auto *signature = checker->ResolveConstructExpression(calleeObj, expr->GetArguments(), expr->Start());

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

    return expr->TsType();
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
    if (expr->TsType() == nullptr) {
        checker::Type *paramType;

        if (expr->Ident()->TsType() != nullptr) {
            paramType = expr->Ident()->TsType();
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

checker::Type *ETSAnalyzer::Check(ir::ETSTuple *node) const
{
    (void)node;
    UNREACHABLE();
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

checker::Type *ETSAnalyzer::Check(ir::ETSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSWildcardType *node) const
{
    UNREACHABLE();
}

// compile methods for EXPRESSIONS in alphabetical order

checker::Type *ETSAnalyzer::GetPreferredType(ir::ArrayExpression *expr) const
{
    return expr->preferredType_;
}

static void CheckArrayElement(ETSChecker *checker, checker::Type *elementType,
                              std::vector<checker::Type *> targetElementType, ir::Expression *currentElement,
                              bool &isSecondaryChosen)
{
    // clang-format off
    if ((targetElementType[0]->IsETSArrayType() &&
         targetElementType[0]->AsETSArrayType()->ElementType()->IsETSArrayType() &&
         !(targetElementType[0]->AsETSArrayType()->ElementType()->IsETSTupleType() &&
           targetElementType[1] == nullptr)) ||
        (!checker::AssignmentContext(checker->Relation(), currentElement, elementType, targetElementType[0],
                                     currentElement->Start(),
                                     {"Array element type '", elementType, "' is not assignable to explicit type '",
                                      targetElementType[0], "'"},
                                     TypeRelationFlag::NO_THROW).IsAssignable() &&
         !(targetElementType[0]->IsETSArrayType() && currentElement->IsArrayExpression()))) {
        if (targetElementType[1] == nullptr) {
            checker->ThrowTypeError({"Array element type '", elementType, "' is not assignable to explicit type '",
                                     targetElementType[1], "'"},
                                    currentElement->Start());
        } else if (!(targetElementType[0]->IsETSArrayType() && currentElement->IsArrayExpression()) &&
                   !checker::AssignmentContext(checker->Relation(), currentElement, elementType, targetElementType[1],
                                               currentElement->Start(),
                                               {"Array element type '", elementType,
                                                "' is not assignable to explicit type '", targetElementType[1], "'"},
                                               TypeRelationFlag::NO_THROW).IsAssignable()) {
            checker->ThrowTypeError({"Array element type '", elementType, "' is not assignable to explicit type '",
                                     targetElementType[1], "'"},
                                    currentElement->Start());
            // clang-format on
        } else {
            isSecondaryChosen = true;
        }
    }
}

static void CheckElement(ir::ArrayExpression *expr, ETSChecker *checker, std::vector<checker::Type *> targetElementType,
                         bool isPreferredTuple, bool isArray)
{
    bool isSecondaryChosen = false;

    for (std::size_t idx = 0; idx < expr->Elements().size(); ++idx) {
        auto *const currentElement = expr->Elements()[idx];

        if (currentElement->IsArrayExpression()) {
            expr->HandleNestedArrayExpression(checker, currentElement->AsArrayExpression(), isArray, isPreferredTuple,
                                              idx);
        }

        if (currentElement->IsObjectExpression()) {
            currentElement->AsObjectExpression()->SetPreferredType(expr->GetPreferredType());
        }

        checker::Type *elementType = currentElement->Check(checker);

        if (!elementType->IsETSArrayType() && isPreferredTuple) {
            auto const *const tupleType = expr->GetPreferredType()->AsETSTupleType();

            auto *compareType = tupleType->GetTypeAtIndex(idx);
            if (compareType == nullptr) {
                checker->ThrowTypeError({"Too many elements in array initializer for tuple with size of ",
                                         static_cast<uint32_t>(tupleType->GetTupleSize())},
                                        currentElement->Start());
            }

            checker::AssignmentContext(checker->Relation(), currentElement, elementType, compareType,
                                       currentElement->Start(),
                                       {"Array initializer's type is not assignable to tuple type at index: ", idx});

            elementType = compareType;
        }

        if (targetElementType[0] == elementType) {
            continue;
        }

        CheckArrayElement(checker, elementType, targetElementType, currentElement, isSecondaryChosen);
    }

    expr->SetPreferredType(isSecondaryChosen ? targetElementType[1] : targetElementType[0]);
}

checker::Type *ETSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    const bool isArray = (expr->preferredType_ != nullptr) && expr->preferredType_->IsETSArrayType() &&
                         !expr->preferredType_->IsETSTupleType();
    if (isArray) {
        expr->preferredType_ = expr->preferredType_->AsETSArrayType()->ElementType();
    }

    if (!expr->Elements().empty()) {
        if (expr->preferredType_ == nullptr) {
            expr->preferredType_ = expr->Elements()[0]->Check(checker);
        }

        const bool isPreferredTuple = expr->preferredType_->IsETSTupleType();
        auto *targetElementType = expr->GetPreferredType();
        Type *targetElementTypeSecondary = nullptr;
        if (isPreferredTuple && !isArray) {
            targetElementTypeSecondary = targetElementType->AsETSTupleType()->ElementType();
        }

        CheckElement(expr, checker, {targetElementType, targetElementTypeSecondary}, isPreferredTuple, isArray);
    }

    if (expr->preferredType_ == nullptr) {
        checker->ThrowTypeError("Can't resolve array type", expr->Start());
    }

    expr->SetTsType(checker->CreateETSArrayType(expr->preferredType_));
    auto *const arrayType = expr->TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(checker::CheckerStatus::IN_LAMBDA)) {
        ASSERT(checker->Context().ContainingLambda() != nullptr);
        checker->Context().ContainingLambda()->AddChildLambda(expr);
        expr->SetParentLambda(checker->Context().ContainingLambda());
    }

    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *funcType = checker->BuildFunctionSignature(expr->Function(), false);

    if (expr->Function()->IsAsyncFunc()) {
        auto *retType = expr->Function()->Signature()->ReturnType();
        if (!retType->IsETSObjectType() ||
            retType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
            checker->ThrowTypeError("Return type of async lambda must be 'Promise'", expr->Function()->Start());
        }
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
    checker->Context().SetContainingSignature(funcType->CallSignatures()[0]);
    checker->Context().SetContainingLambda(expr);

    expr->Function()->Body()->Check(checker);

    checker->Context().SetContainingSignature(nullptr);
    checker->CheckCapturedVariables();

    for (auto [var, _] : checker->Context().CapturedVars()) {
        (void)_;
        expr->AddCapturedVar(var);
    }

    expr->SetTsType(funcType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::AssignmentExpression *const expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    auto *const leftType = expr->Left()->Check(checker);

    if (expr->Left()->IsMemberExpression() &&
        expr->Left()->AsMemberExpression()->Object()->TsType()->IsETSArrayType() &&
        expr->Left()->AsMemberExpression()->Property()->IsIdentifier() &&
        expr->Left()->AsMemberExpression()->Property()->AsIdentifier()->Name().Is("length")) {
        checker->ThrowTypeError("Setting the length of an array is not permitted", expr->Left()->Start());
    }

    if (expr->Left()->IsIdentifier()) {
        expr->target_ = expr->Left()->AsIdentifier()->Variable();
    } else if (expr->Left()->IsMemberExpression()) {
        expr->target_ = expr->Left()->AsMemberExpression()->PropVar();
    } else {
        checker->ThrowTypeError("Invalid left-hand side of assignment expression", expr->Left()->Start());
    }

    if (expr->target_ != nullptr) {
        checker->ValidateUnaryOperatorOperand(expr->target_);
    }

    auto [rightType, relationNode] = CheckAssignmentExprOperatorType(expr, leftType);

    const checker::Type *targetType = checker->TryGettingFunctionTypeFromInvokeFunction(leftType);
    const checker::Type *sourceType = checker->TryGettingFunctionTypeFromInvokeFunction(rightType);

    checker::AssignmentContext(checker->Relation(), relationNode, rightType, leftType, expr->Right()->Start(),
                               {"Type '", sourceType, "' cannot be assigned to type '", targetType, "'"});

    checker::Type *smartType = leftType;

    if (expr->Left()->IsIdentifier()) {
        //  Now try to define the actual type of Identifier so that smart cast can be used in further checker processing
        smartType = checker->ResolveSmartType(rightType, leftType);
        auto const *const variable = expr->Target();

        //  Add/Remove/Modify smart cast for identifier
        //  (excluding the variables defined at top-level scope or captured in lambda-functions!)
        auto const *const variableScope = variable->GetScope();
        auto const topLevelVariable = variableScope != nullptr
                                          ? variableScope->IsGlobalScope() || (variableScope->Parent() != nullptr &&
                                                                               variableScope->Parent()->IsGlobalScope())
                                          : false;
        if (!topLevelVariable && !variable->HasFlag(varbinder::VariableFlags::BOXED)) {
            if (checker->Relation()->IsIdenticalTo(leftType, smartType)) {
                checker->Context().RemoveSmartCast(variable);
            } else {
                expr->Left()->SetTsType(smartType);
                checker->Context().SetSmartCast(variable, smartType);
            }
        }
    }

    expr->SetTsType(smartType);
    return expr->TsType();
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker::Type *argType = checker->GetApparentType(expr->argument_->Check(checker));
    // Check the argument type of await expression
    if (!argType->IsETSObjectType() ||
        (argType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType())) {
        checker->ThrowTypeError("'await' expressions require Promise object as argument.", expr->Argument()->Start());
    }

    expr->SetTsType(argType->AsETSObjectType()->TypeArguments().at(0));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    checker::Type *newTsType {nullptr};
    std::tie(newTsType, expr->operationType_) =
        checker->CheckBinaryOperator(expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start());
    expr->SetTsType(newTsType);

    checker->Context().CheckBinarySmartCastCondition(expr);

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::BlockExpression *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    if (st->TsType() == nullptr) {
        for (auto *const node : st->Statements()) {
            node->Check(checker);
        }

        auto lastStmt = st->Statements().back();
        ASSERT(lastStmt->IsExpressionStatement());
        st->SetTsType(lastStmt->AsExpressionStatement()->GetExpression()->TsType());
    }

    return st->TsType();
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
    if (signature->Function()->IsExtensionMethod()) {
        checker->ThrowTypeError({"No matching call signature"}, expr->Start());
    }
    return signature;
}

checker::Type *ETSAnalyzer::GetReturnType(ir::CallExpression *expr, checker::Type *calleeType) const
{
    ETSChecker *checker = GetETSChecker();
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
        checker->ThrowTypeError("This expression is not callable.", expr->Start());
    }

    checker::Signature *signature =
        ResolveSignature(checker, expr, calleeType, isFunctionalInterface, isUnionTypeWithFunctionalInterface);

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

checker::Type *ETSAnalyzer::Check(ir::CallExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ASSERT(!expr->IsOptional());
    auto *oldCallee = expr->Callee();
    checker::Type *calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    if (expr->Callee() != oldCallee) {
        // If it is a static invoke, the callee will be transformed from an identifier to a member expression
        // Type check the callee again for member expression
        calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    }
    checker->CheckNonNullish(expr->Callee());
    checker::Type *returnType;
    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        // Trailing lambda for js function call is not supported, check the correctness of `foo() {}`
        checker->EnsureValidCurlyBrace(expr);
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->Callee(), expr->Arguments(), lang, false));
        returnType = expr->Signature()->ReturnType();
    } else {
        returnType = GetReturnType(expr, calleeType);
    }

    if (expr->Signature()->RestVar() != nullptr) {
        auto *const elementType = expr->Signature()->RestVar()->TsType()->AsETSArrayType()->ElementType();
        auto *const arrayType = checker->CreateETSArrayType(elementType)->AsETSArrayType();
        checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
        checker::SavedCheckerContext savedCtx(checker, checker->Context().Status(), expr->Signature()->Owner());
        expr->Signature()->OwnerVar()->Declaration()->Node()->Check(checker);
        returnType = expr->Signature()->ReturnType();
        // NOTE(vpukhov): #14902 substituted signature is not updated
    }
    expr->SetTsType(returnType);
    expr->SetUncheckedType(checker->GuaranteedTypeForUncheckedCallReturn(expr->Signature()));
    if (expr->UncheckedType() != nullptr) {
        checker->ComputeApparentType(returnType);
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ChainExpression *expr) const
{
    UNREACHABLE();  // eliminated in OptionalLowering
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSReExportDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *const checker = GetETSChecker();

    SmartCastArray smartCasts = checker->Context().EnterTestExpression();
    checker->CheckTruthinessOfType(expr->Test());
    SmartCastTypes testedTypes = checker->Context().ExitTestExpression();
    if (testedTypes.has_value()) {
        for (auto [variable, consequentType, _] : *testedTypes) {
            checker->ApplySmartCast(variable, consequentType);
        }
    }

    auto *const consequentType = expr->Consequent()->Check(checker);

    SmartCastArray consequentSmartCasts = checker->Context().CloneSmartCasts();
    checker->Context().RestoreSmartCasts(smartCasts);

    if (testedTypes.has_value()) {
        for (auto [variable, _, alternateType] : *testedTypes) {
            checker->ApplySmartCast(variable, alternateType);
        }
    }

    auto *const alternateType = expr->Alternate()->Check(checker);

    // Here we need to combine types from consequent and alternate if blocks.
    checker->Context().CombineSmartCasts(consequentSmartCasts);

    if (checker->IsTypeIdenticalTo(consequentType, alternateType)) {
        expr->SetTsType(checker->GetNonConstantTypeFromPrimitiveType(consequentType));
    } else {
        expr->SetTsType(checker->CreateETSUnionType({consequentType, alternateType}));
        if (expr->TsType()->IsETSReferenceType()) {
            checker->MaybeBoxExpression(expr->Consequent());
            checker->MaybeBoxExpression(expr->Alternate());
        }
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DirectEvalExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::Identifier *expr) const
{
    if (expr->TsType() == nullptr) {
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
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::SetAndAdjustType(ETSChecker *checker, ir::MemberExpression *expr,
                                             ETSObjectType *objectType) const
{
    expr->SetObjectType(objectType);
    auto [resType, resVar] = expr->ResolveObjectMember(checker);
    expr->SetPropVar(resVar);
    return expr->AdjustType(checker, resType);
}

std::pair<checker::Type *, util::StringView> SearchReExportsType(Type *baseType, ir::MemberExpression *expr,
                                                                 util::StringView aliasName)
{
    for (auto item : baseType->AsETSObjectType()->ReExports()) {
        auto name = item->AsETSObjectType()->GetReExportAliasValue(aliasName);
        if (item->GetProperty(name, PropertySearchFlags::SEARCH_ALL) != nullptr) {
            return std::make_pair(item, name);
        }
        if (auto reExportType = SearchReExportsType(item, expr, name); reExportType.first != nullptr) {
            return reExportType;
        }
    }
    return std::make_pair(nullptr, util::StringView());
}

checker::Type *ETSAnalyzer::Check(ir::MemberExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ASSERT(!expr->IsOptional());

    ETSChecker *checker = GetETSChecker();
    auto *baseType = checker->GetApparentType(expr->Object()->Check(checker));
    //  Note: don't use possible smart cast to null-like types.
    //        Such situation should be correctly resolved in the subsequent lowering.
    if (baseType->DefinitelyETSNullish() && expr->Object()->IsIdentifier()) {
        baseType = expr->Object()->AsIdentifier()->Variable()->TsType();
    }

    if (baseType->IsETSObjectType() && !baseType->AsETSObjectType()->ReExports().empty() &&
        baseType->AsETSObjectType()->GetProperty(expr->Property()->AsIdentifier()->Name(),
                                                 PropertySearchFlags::SEARCH_ALL) == nullptr) {
        if (auto reExportType = SearchReExportsType(baseType, expr, expr->Property()->AsIdentifier()->Name());
            reExportType.first != nullptr) {
            baseType = reExportType.first;
            expr->object_->AsIdentifier()->SetTsType(baseType);
            expr->property_->AsIdentifier()->SetName(reExportType.second);
        }
    }

    checker->CheckNonNullish(expr->Object());

    if (expr->IsComputed()) {
        return expr->AdjustType(checker, expr->CheckComputed(checker, baseType));
    }

    if (baseType->IsETSArrayType()) {
        if (expr->Property()->AsIdentifier()->Name().Is("length")) {
            return expr->AdjustType(checker, checker->GlobalIntType());
        }

        return SetAndAdjustType(checker, expr, checker->GlobalETSObjectType());
    }

    if (baseType->IsETSObjectType()) {
        return SetAndAdjustType(checker, expr, baseType->AsETSObjectType());
    }

    if (baseType->IsETSEnumType() || baseType->IsETSStringEnumType()) {
        auto [memberType, memberVar] = expr->ResolveEnumMember(checker, baseType);
        expr->SetPropVar(memberVar);
        return expr->AdjustType(checker, memberType);
    }

    if (baseType->IsETSUnionType()) {
        return expr->AdjustType(checker, expr->CheckUnionMember(checker, baseType));
    }

    if (baseType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        checker->ThrowTypeError(
            {"Property '", expr->Property()->AsIdentifier()->Name(), "' does not exist on type '", baseType, "'"},
            expr->Object()->Start());
    }

    checker->ThrowTypeError({"Cannot access property of non-object or non-enum type"}, expr->Object()->Start());
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NewExpression *expr) const
{
    UNREACHABLE();
}
checker::Type *ETSAnalyzer::PreferredType(ir::ObjectExpression *expr) const
{
    return expr->preferredType_;
}

checker::Type *ETSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    if (expr->PreferredType() == nullptr) {
        checker->ThrowTypeError({"need to specify target type for class composite"}, expr->Start());
    }
    if (!expr->PreferredType()->IsETSObjectType()) {
        checker->ThrowTypeError(
            {"Target type for class composite needs to be an object type, found '", expr->PreferredType(), "'"},
            expr->Start());
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
    if (objType->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT | checker::ETSObjectFlags::INTERFACE)) {
        checker->ThrowTypeError({"target type for class composite ", objType->Name(), " is not instantiable"},
                                expr->Start());
    }

    if (expr->PreferredType()->ToAssemblerName().str() == "escompat.Map") {
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
        checker->ThrowTypeError({"type ", objType->Name(), " has no parameterless constructor"}, expr->Start());
    }

    CheckObjectExprProps(expr);

    expr->SetTsType(objType);
    return objType;
}

void ETSAnalyzer::CheckObjectExprProps(const ir::ObjectExpression *expr) const
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
            checker->ThrowTypeError({"key in class composite should be either identifier or string literal"},
                                    expr->Start());
        }
        varbinder::LocalVariable *lv = objType->GetProperty(
            pname, checker::PropertySearchFlags::SEARCH_INSTANCE_FIELD | checker::PropertySearchFlags::SEARCH_IN_BASE |
                       checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD);
        if (lv == nullptr) {
            checker->ThrowTypeError({"type ", objType->Name(), " has no property named ", pname}, propExpr->Start());
        }
        checker->ValidatePropertyAccess(lv, objType, propExpr->Start());
        if (lv->HasFlag(varbinder::VariableFlags::READONLY)) {
            checker->ThrowTypeError({"cannot assign to readonly property ", pname}, propExpr->Start());
        }

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
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::OmittedExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::OpaqueTypeNode *expr) const
{
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::SequenceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    expr->SetTsType(checker->CheckThisOrSuperAccess(expr, checker->Context().ContainingClass()->SuperType(), "super"));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TaggedTemplateExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    if (expr->Quasis().size() != expr->Expressions().size() + 1U) {
        checker->ThrowTypeError("Invalid string template expression", expr->Start());
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
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

    if (checker->HasStatus(checker::CheckerStatus::IN_LAMBDA)) {
        if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
            checker->Context().AddCapturedVar(variable, expr->Start());
        } else {
            checker->Context().AddCapturedVar(checker->Context().ContainingClass()->Variable(), expr->Start());
        }
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TypeofExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    expr->Argument()->Check(checker);
    expr->SetTsType(GetETSChecker()->GlobalBuiltinETSStringType());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsType() != nullptr) {
        return expr->TsType();
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker::Type *operandType = expr->argument_->Check(checker);
    if (expr->Argument()->IsIdentifier()) {
        checker->ValidateUnaryOperatorOperand(expr->Argument()->AsIdentifier()->Variable());
    } else if (expr->Argument()->IsTSAsExpression()) {
        if (auto *const asExprVar = expr->Argument()->AsTSAsExpression()->Variable(); asExprVar != nullptr) {
            checker->ValidateUnaryOperatorOperand(asExprVar);
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
    if (unboxedType == nullptr || !unboxedType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
        checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                expr->Argument()->Start());
    }

    if (operandType->IsETSObjectType()) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedType) |
                                                 checker->GetBoxingFlag(unboxedType));
    }

    expr->SetTsType(operandType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::YieldExpression *expr) const
{
    UNREACHABLE();
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
    if (expr->TsType() == nullptr) {
        expr->SetTsType(checker->CreateETSBooleanType(expr->Value()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::CharLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() == nullptr) {
        expr->SetTsType(checker->Allocator()->New<checker::CharType>(expr->Char()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::NullLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() == nullptr) {
        expr->SetTsType(checker->GlobalETSNullType());
    }
    return expr->TsType();
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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::RegExpLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::StringLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() == nullptr) {
        expr->SetTsType(checker->CreateETSStringLiteralType(expr->Str()));
    }
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::UndefinedLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportAllDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportDefaultDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportNamedDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportSpecifier *st) const
{
    UNREACHABLE();
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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ImportNamespaceSpecifier *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (st->Local()->Name().Empty()) {
        return nullptr;
    }

    if (st->Local()->AsIdentifier()->TsType() != nullptr) {
        return st->Local()->TsType();
    }

    auto *importDecl = st->Parent()->AsETSImportDeclaration();

    if (importDecl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(importDecl->Language());
        checker->SetrModuleObjectTsType(st->Local(), type);
        return type;
    }

    return checker->GetImportSpecifierObjectType(importDecl, st->Local()->AsIdentifier());
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}

// compile methods for STATEMENTS in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::AssertStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckTruthinessOfType(st->test_);

    if (st->Second() != nullptr) {
        auto *msgType = st->second_->Check(checker);

        if (!msgType->IsETSStringType()) {
            checker->ThrowTypeError("Assert message must be string", st->Second()->Start());
        }
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::BlockStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    for (size_t i = 0; i < st->Statements().size(); i++) {
        auto el = st->Statements()[i];
        el->Check(checker);

        //  NOTE! Processing of trailing blocks was moved here so that smart casts could be applied correctly
        if (auto const tb = st->trailingBlocks_.find(el); tb != st->trailingBlocks_.end()) {
            auto *const trailingBlock = tb->second;
            trailingBlock->Check(checker);
            st->Statements().emplace(std::next(st->Statements().begin() + i), trailingBlock);
        }
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
    st->SetTarget(checker->FindJumpTarget(st));

    checker->Context().OnBreakStatement(st);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ClassDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ContinueStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->SetTarget(checker->FindJumpTarget(st));

    checker->AddStatus(CheckerStatus::MEET_CONTINUE);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DebuggerStatement *st) const
{
    UNREACHABLE();
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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ForInStatement *st) const
{
    UNREACHABLE();
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
        checker->ThrowTypeError(MISSING_SOURCE_EXPR_TYPE, st->Right()->Start());
    }

    checker::Type *elemType = nullptr;

    if (exprType->IsETSStringType()) {
        elemType = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else if (exprType->IsETSArrayType()) {
        elemType = exprType->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                          checker->GetGlobalTypesHolder());
        elemType->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    } else if (exprType->IsETSObjectType() || exprType->IsETSUnionType() || exprType->IsETSTypeParameter()) {
        elemType = st->CheckIteratorMethod(checker);
    }

    if (elemType == nullptr) {
        checker->ThrowTypeError(INVALID_SOURCE_EXPR_TYPE, st->Right()->Start());
    }

    st->Left()->Check(checker);
    checker::Type *iterType = GetIteratorType(checker, elemType, st->Left());
    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(checker->AllocNode<ir::SuperExpression>());  // Dummy node to avoid assertion!

    if (!relation->IsAssignableTo(elemType, iterType)) {
        std::stringstream ss {};
        ss << "Source element type '";
        elemType->ToString(ss);
        ss << "' is not assignable to the loop iterator type '";
        iterType->ToString(ss);
        ss << "'.";
        checker->ThrowTypeError(ss.str(), st->Start());
    }

    relation->SetNode(nullptr);
    relation->SetFlags(checker::TypeRelationFlag::NONE);

    if (iterType->Variable() == nullptr && !iterType->IsETSObjectType() && elemType->IsETSObjectType() &&
        st->Left()->IsVariableDeclaration()) {
        for (auto &declarator : st->Left()->AsVariableDeclaration()->Declarators()) {
            checker->AddBoxingUnboxingFlagsToNode(declarator->Id(), iterType);
        }
    }

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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionDeclaration *st) const
{
    UNREACHABLE();
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

checker::Type *ETSAnalyzer::GetFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc) const
{
    ASSERT(containingFunc->ReturnTypeAnnotation() != nullptr || containingFunc->Signature()->ReturnType() != nullptr);

    ETSChecker *checker = GetETSChecker();
    checker::Type *funcReturnType = nullptr;

    if (auto *const returnTypeAnnotation = containingFunc->ReturnTypeAnnotation(); returnTypeAnnotation != nullptr) {
        if (returnTypeAnnotation->IsTSThisType() &&
            (st->Argument() == nullptr || !st->Argument()->IsThisExpression())) {
            checker->ThrowTypeError(
                "The only allowed return value is 'this' if the method's return type is the 'this' type", st->Start());
        }

        // Case when function's return type is defined explicitly:
        funcReturnType = returnTypeAnnotation->GetType(checker);

        if (st->argument_ == nullptr) {
            if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalVoidType() &&
                !funcReturnType->IsETSAsyncFuncReturnType()) {
                checker->ThrowTypeError("Missing return value.", st->Start());
            }
            funcReturnType = checker->GlobalVoidType();
        } else {
            const auto name = containingFunc->Scope()->InternalName().Mutf8();
            CheckArgumentVoidType(funcReturnType, checker, name, st);

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
            CheckReturnType(checker, funcReturnType, argumentType, st->argument_, containingFunc->IsAsyncFunc());
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

    if ((st->argument_ != nullptr) && st->argument_->IsArrayExpression()) {
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
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", st->Start());
        }
        return nullptr;
    }

    st->returnType_ = GetFunctionReturnType(st, containingFunc);

    if (containingFunc->ReturnTypeAnnotation() == nullptr) {
        containingFunc->AddReturnStatement(st);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
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

    st->Block()->Check(checker);
    auto smartCasts = checker->Context().CloneSmartCasts(true);

    bool defaultCatchFound = false;
    for (auto *catchClause : st->CatchClauses()) {
        if (defaultCatchFound) {
            checker->ThrowTypeError("Default catch clause should be the last in the try statement",
                                    catchClause->Start());
        }

        if (auto const exceptionType = catchClause->Check(checker);
            exceptionType != nullptr && catchClause->Param() != nullptr) {
            auto *clauseType = exceptionType->AsETSObjectType();
            checker->CheckExceptionClauseType(exceptions, catchClause, clauseType);
            exceptions.emplace_back(clauseType);
        }

        defaultCatchFound = catchClause->IsDefaultCatchClause();

        checker->Context().CombineSmartCasts(smartCasts);
        smartCasts = checker->Context().CloneSmartCasts(true);
    }

    if (st->HasFinalizer()) {
        st->finalizer_->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    if (st->TsType() != nullptr) {
        return st->TsType();
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
    if (auto *const initType = st->Init() != nullptr ? st->Init()->TsType() : nullptr; initType != nullptr) {
        smartType = checker->ResolveSmartType(initType, variableType);
        //  Set smart type for identifier if it differs from annotated type
        //  Top-level and captured variables are not processed here!
        if (!checker->Relation()->IsIdenticalTo(variableType, smartType)) {
            //  Add constness to the smart type if required (initializer type usually is not const)
            if (ident->Variable()->Declaration()->IsConstDecl() && !smartType->HasTypeFlag(TypeFlag::CONSTANT) &&
                !smartType->DefinitelyETSNullish()) {
                smartType = smartType->Clone(checker);
                smartType->AddTypeFlag(TypeFlag::CONSTANT);
            }

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

// from ts folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSAnyKeyword *node) const
{
    UNREACHABLE();
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

    if (expr->TsType() != nullptr) {
        return expr->TsType();
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

    if (targetType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) && sourceType->IsETSReferenceType()) {
        auto *const boxedTargetType = checker->PrimitiveTypeAsETSBuiltinType(targetType);
        if (!checker->Relation()->IsIdenticalTo(sourceType, boxedTargetType)) {
            expr->Expr()->AddAstNodeFlags(ir::AstNodeFlags::CHECKCAST);
        }
    }

    if (sourceType->DefinitelyETSNullish() && !targetType->PossiblyETSNullish()) {
        checker->ThrowTypeError("Cannot cast 'null' or 'undefined' to non-nullish type.", expr->Expr()->Start());
    }

    const checker::CastingContext ctx(checker->Relation(), expr->Expr(), sourceType, targetType, expr->Expr()->Start(),
                                      {"Cannot cast type '", sourceType, "' to '", targetType, "'"});

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
        checker->ThrowTypeError("Cast to 'never' is prohibited", expr->Start());
    }

    checker->ComputeApparentType(targetType);
    expr->SetTsType(targetType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSBigintKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSBooleanKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSClassImplements *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSConditionalType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSConstructorType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSEnumDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    varbinder::Variable *enumVar = st->Key()->Variable();
    ASSERT(enumVar != nullptr);

    if (enumVar->TsType() == nullptr) {
        checker::Type *etsEnumType;
        if (auto *const itemInit = st->Members().front()->AsTSEnumMember()->Init(); itemInit->IsNumberLiteral()) {
            etsEnumType = checker->CreateETSEnumType(st);
        } else if (itemInit->IsStringLiteral()) {
            etsEnumType = checker->CreateETSStringEnumType(st);
        } else {
            checker->ThrowTypeError("Invalid enumeration value type.", st->Start());
        }
        st->SetTsType(etsEnumType);
        etsEnumType->SetVariable(enumVar);
        enumVar->SetTsType(etsEnumType);
    } else if (st->TsType() == nullptr) {
        st->SetTsType(enumVar->TsType());
    }

    return st->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSFunctionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSImportEqualsDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSImportType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIndexedAccessType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInferType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceBody *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();

    checker::ETSObjectType *interfaceType {};

    if (st->TsType() == nullptr) {
        interfaceType = checker->BuildBasicInterfaceProperties(st);
        ASSERT(interfaceType != nullptr);
        interfaceType->SetSuperType(checker->GlobalETSObjectType());
        checker->CheckInvokeMethodsLegitimacy(interfaceType);
        st->SetTsType(interfaceType);
    }

    checker::ScopeContext scopeCtx(checker, st->Scope());
    auto savedContext = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_INTERFACE, interfaceType);

    for (auto *it : st->Body()->Body()) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceHeritage *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIntersectionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSLiteralType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSMappedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSModuleBlock *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSModuleDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNamedTupleMember *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNeverKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSNonNullExpression *expr) const
{
    if (expr->TsType() == nullptr) {
        ETSChecker *checker = GetETSChecker();
        auto exprType = expr->expr_->Check(checker);
        if (!exprType->PossiblyETSNullish()) {
            checker->ThrowTypeError(
                "Bad operand type, the operand of the non-nullish expression must be a nullish type",
                expr->Expr()->Start());
        }

        //  If the actual [smart] type is definitely 'null' or 'undefined' then probably CTE should be thrown.
        //  Anyway we'll definitely obtain NullPointerException at runtime.
        if (exprType->DefinitelyETSNullish()) {
            checker->ThrowTypeError(
                "Bad operand type, the operand of the non-nullish expression is 'null' or 'undefined'.",
                expr->Expr()->Start());
        }

        expr->SetTsType(checker->GetNonNullishType(exprType));
    }
    expr->SetOriginalType(expr->TsType());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNullKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNumberKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSParameterProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSParenthesizedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSQualifiedName *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *baseType = expr->Left()->Check(checker);
    if (baseType->IsETSObjectType()) {
        varbinder::Variable *prop =
            baseType->AsETSObjectType()->GetProperty(expr->Right()->Name(), checker::PropertySearchFlags::SEARCH_DECL);

        if (prop != nullptr) {
            return checker->GetTypeOfVariable(prop);
        }
    }

    checker->ThrowTypeError({"'", expr->Right()->Name(), "' type does not exist."}, expr->Right()->Start());
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSStringKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSThisType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTupleType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (st->TypeParams() == nullptr) {
        const checker::SavedTypeRelationFlagsContext savedFlagsCtx(
            checker->Relation(), checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

        if (st->TypeAnnotation()->TsType() == nullptr) {
            st->TypeAnnotation()->Check(checker);
        }

        return nullptr;
    }

    if (st->TypeParameterTypes().empty()) {
        st->SetTypeParameterTypes(checker->CreateTypeForTypeParameters(st->TypeParams()));
    }

    for (auto *const param : st->TypeParams()->Params()) {
        const auto *const res = st->TypeAnnotation()->FindChild([&param](const ir::AstNode *const node) {
            if (!node->IsIdentifier()) {
                return false;
            }

            return param->Name()->AsIdentifier()->Variable() == node->AsIdentifier()->Variable();
        });

        if (res == nullptr) {
            checker->ThrowTypeError(
                {"Type alias generic parameter '", param->Name()->Name(), "' is not used in type annotation"},
                param->Start());
        }
    }

    const checker::SavedTypeRelationFlagsContext savedFlagsCtx(checker->Relation(),
                                                               checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

    if (st->TypeAnnotation()->TsType() == nullptr) {
        st->TypeAnnotation()->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeAssertion *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeLiteral *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeOperator *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameter *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterInstantiation *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypePredicate *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeQuery *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeReference *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUndefinedKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUnionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUnknownKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSVoidKeyword *node) const
{
    UNREACHABLE();
}

}  // namespace ark::es2panda::checker
