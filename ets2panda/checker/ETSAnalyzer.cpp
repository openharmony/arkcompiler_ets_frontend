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

#include "ETSAnalyzer.h"

#include "generated/diagnostic.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsTupleType.h"
#include "evaluate/scopedDebugInfoPlugin.h"
#include "types/signature.h"
#include "compiler/lowering/ets/setJumpTarget.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"
namespace ark::es2panda::checker {

ETSChecker *ETSAnalyzer::GetETSChecker() const
{
    return static_cast<ETSChecker *>(GetChecker());
}

// from base folder
checker::Type *ETSAnalyzer::Check(ir::CatchClause *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *exceptionType = checker->GlobalTypeError();

    if (st->Param() != nullptr) {
        ES2PANDA_ASSERT(st->Param()->IsIdentifier());

        ir::Identifier *paramIdent = st->Param()->AsIdentifier();
        if (!paramIdent->IsErrorPlaceHolder()) {
            if (paramIdent->TypeAnnotation() != nullptr) {
                checker::Type *catchParamAnnotationType = paramIdent->TypeAnnotation()->GetType(checker);
                exceptionType = checker->CheckExceptionOrErrorType(catchParamAnnotationType, st->Param()->Start());
            } else {
                exceptionType = checker->GlobalETSObjectType();
            }
            paramIdent->Variable()->SetTsType(exceptionType);
        }
        paramIdent->SetTsType(exceptionType);
    } else {
        ES2PANDA_ASSERT(checker->IsAnyError());
    }

    st->Body()->Check(checker);

    return st->SetTsType(exceptionType);
}

checker::Type *ETSAnalyzer::Check(ir::ClassDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();

    if (node->TsType() == nullptr) {
        checker->BuildBasicClassProperties(node);
    }

    if (!node->IsClassDefinitionChecked()) {
        checker->CheckClassDefinition(node);
    }

    return node->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ClassProperty *st) const
{
    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    ES2PANDA_ASSERT(st->Id() != nullptr);

    ETSChecker *checker = GetETSChecker();

    if (st->Id()->Variable() == nullptr) {
        st->Id()->Check(checker);
    }

    ES2PANDA_ASSERT(st->Id()->Variable() != nullptr);

    checker->CheckAnnotations(st->Annotations());
    if (st->TypeAnnotation() != nullptr) {
        st->TypeAnnotation()->Check(checker);
    }
    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass(),
                                              checker->Context().ContainingSignature());

    if (st->IsStatic()) {
        checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    checker::Type *propertyType =
        checker->CheckVariableDeclaration(st->Id(), st->TypeAnnotation(), st->Value(), st->Modifiers());

    return st->SetTsType(propertyType != nullptr ? propertyType : checker->GlobalTypeError());
}

checker::Type *ETSAnalyzer::Check(ir::ClassStaticBlock *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(checker::CheckerStatus::INNER_CLASS)) {
        checker->LogError(diagnostic::STATIC_INIT_IN_NESTED_CLASS, {}, st->Start());
        st->SetTsType(checker->GlobalTypeError());
        return st->TsType();
    }

    auto *func = st->Function();
    checker->BuildFunctionSignature(func);

    if (func->Signature() == nullptr) {
        st->SetTsType(checker->GlobalTypeError());
    } else {
        st->SetTsType(checker->BuildMethodType(func));
    }
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
    if (node->IsNative() && !node->IsConstructor() && !scriptFunc->IsSetter()) {
        if (scriptFunc->ReturnTypeAnnotation() == nullptr) {
            checker->LogError(diagnostic::NATIVE_WITHOUT_RETURN, {}, scriptFunc->Start());
            node->SetTsType(checker->GlobalTypeError());
        }
    }

    if (util::Helpers::IsAsyncMethod(node)) {
        if (scriptFunc->ReturnTypeAnnotation() != nullptr) {
            auto *asyncFuncReturnType = scriptFunc->Signature()->ReturnType();

            if (!asyncFuncReturnType->IsETSObjectType() ||
                asyncFuncReturnType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
                checker->LogError(diagnostic::ASYNC_FUNCTION_RETURN_TYPE, {}, scriptFunc->Start());
                scriptFunc->Signature()->SetReturnType(checker->GlobalTypeError());
                return;
            }
        }
    }
}

//  Extacted from 'ETSAnalyzer::Check(ir::MethodDefinition *node)' to reduce its size
static checker::Type *CheckMethodDefinitionHelper(ETSChecker *checker, ir::MethodDefinition *node) noexcept
{
    // NOTE(gogabr): temporary, until we have proper bridges, see #16485
    // Don't check overriding for synthetic functional classes.
    if ((node->Parent()->Modifiers() & ir::ModifierFlags::FUNCTIONAL) == 0) {
        checker->CheckOverride(node->TsType()->AsETSFunctionType()->FindSignature(node->Function()));
    }

    for (auto *overload : node->Overloads()) {
        overload->Check(checker);
    }

    return node->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto *scriptFunc = node->Function();

    // CC-OFFNXT(G.FMT.14-CPP) project code style
    auto const returnErrorType = [checker, node]() -> checker::Type * {
        node->SetTsType(checker->GlobalTypeError());
        return node->TsType();
    };

    if (scriptFunc == nullptr) {
        checker->LogError(diagnostic::FUNC_EXPR_INVALID, {}, node->Start());
        return returnErrorType();
    }
    checker->CheckAnnotations(scriptFunc->Annotations());
    checker->CheckFunctionSignatureAnnotations(scriptFunc->Params(), scriptFunc->TypeParams(),
                                               scriptFunc->ReturnTypeAnnotation());

    if (scriptFunc->IsProxy()) {
        return ReturnTypeForStatement(node);
    }

    ES2PANDA_ASSERT(!(scriptFunc->IsGetter() && scriptFunc->IsSetter()));
    if (scriptFunc->IsGetter() || scriptFunc->IsSetter()) {
        auto status = scriptFunc->IsGetter() ? CheckerStatus::IN_GETTER : CheckerStatus::IN_SETTER;
        checker->AddStatus(status);
    }

    // NOTE: aszilagyi. make it correctly check for open function not have body
    if (!scriptFunc->HasBody() && !(node->IsAbstract() || node->IsNative() || node->IsDeclare() ||
                                    checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->LogError(diagnostic::FUNCTION_WITHOUT_BODY, {}, scriptFunc->Start());
        return returnErrorType();
    }

    if (CheckReturnTypeNecessity(node) && scriptFunc->ReturnTypeAnnotation() == nullptr) {
        checker->LogError(diagnostic::MISSING_RETURN_TYPE, {}, scriptFunc->Start());
        return returnErrorType();
    }

    if (node->TsType() == nullptr) {
        node->SetTsType(checker->BuildMethodSignature(node));
    }

    this->CheckMethodModifiers(node);
    HandleNativeAndAsyncMethods(checker, node);
    DoBodyTypeChecking(checker, node, scriptFunc);
    CheckPredefinedMethodReturnType(checker, scriptFunc);
    if (node->TsType()->IsTypeError()) {
        return node->TsType();
    }

    return CheckMethodDefinitionHelper(checker, node);
}

void ETSAnalyzer::CheckMethodModifiers(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto const notValidInAbstract = ir::ModifierFlags::NATIVE | ir::ModifierFlags::PRIVATE |
                                    ir::ModifierFlags::OVERRIDE | ir::ModifierFlags::FINAL | ir::ModifierFlags::STATIC;

    if (node->IsAbstract() && (node->flags_ & notValidInAbstract) != 0U) {
        checker->LogError(diagnostic::ABSTRACT_METHOD_INVALID_MODIFIER, {}, node->Start());
        node->SetTsType(checker->GlobalTypeError());
        return;
    }

    if (node->Function() == nullptr) {
        checker->LogError(diagnostic::FUNC_EXPR_INVALID, {}, node->Start());
        node->SetTsType(checker->GlobalTypeError());
        return;
    }

    if ((node->IsAbstract() || (!node->Function()->HasBody() && !node->IsNative() && !node->IsDeclare())) &&
        !(checker->HasStatus(checker::CheckerStatus::IN_ABSTRACT) ||
          checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->LogError(diagnostic::ABSTRACT_IN_CONCRETE, {}, node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }

    auto const notValidInFinal = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::STATIC;

    if (node->IsFinal() && (node->flags_ & notValidInFinal) != 0U) {
        checker->LogError(diagnostic::FINAL_METHOD_INVALID_MODIFIER, {}, node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }

    auto const notValidInStatic = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::FINAL | ir::ModifierFlags::OVERRIDE;

    if (node->IsStatic() && (node->flags_ & notValidInStatic) != 0U) {
        checker->LogError(diagnostic::STATIC_METHOD_INVALID_MODIFIER, {}, node->Start());
        node->SetTsType(checker->GlobalTypeError());
    }
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Property *expr) const
{
    ETSChecker *checker = GetETSChecker();
    return checker->GlobalTypeError();
}

checker::Type *ETSAnalyzer::Check(ir::SpreadElement *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    Type *exprType = expr->AsSpreadElement()->Argument()->Check(checker);

    if (exprType->IsETSResizableArrayType()) {
        return expr->SetTsType(exprType->AsETSObjectType()->TypeArguments().front());
    }

    if (!exprType->IsETSArrayType() && !exprType->IsETSTupleType()) {
        if (!exprType->IsTypeError()) {
            // Don't duplicate error messages for the same error
            checker->LogError(diagnostic::SPREAD_OF_INVALID_TYPE, {exprType}, expr->Start());
        }
        return checker->InvalidateType(expr);
    }

    checker::Type *const elementType =
        exprType->IsETSArrayType() ? exprType->AsETSArrayType()->ElementType() : exprType;
    return expr->SetTsType(elementType);
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

    checker->LogError(diagnostic::UNSUPPORTED_CLASS_LITERAL, {}, literal->Start());
    expr->SetTsType(checker->GlobalTypeError());
    return expr->TsType();

    auto exprType = literal->Check(checker);
    if (exprType->IsETSVoidType()) {
        checker->LogError(diagnostic::INVALID_DOT_CLASS, {}, literal->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    ArenaVector<checker::Type *> typeArgTypes(checker->Allocator()->Adapter());
    typeArgTypes.push_back(exprType);  // NOTE: Box it if it's a primitive type

    checker::InstantiationContext ctx(checker, checker->GlobalBuiltinTypeType(), std::move(typeArgTypes),
                                      expr->Range().start);
    expr->SetTsType(ctx.Result());

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    if (node->TsType() != nullptr) {
        return node->TsType();
    }
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    checker->CheckFunctionSignatureAnnotations(node->Params(), node->TypeParams(), node->ReturnType());

    auto *signatureInfo = checker->ComposeSignatureInfo(node->TypeParams(), node->Params());
    auto *returnType = node->IsExtensionFunction() && node->ReturnType()->IsTSThisType()
                           ? signatureInfo->params.front()->TsType()
                           : checker->ComposeReturnType(node->ReturnType(), node->IsAsync());

    auto *const signature =
        checker->CreateSignature(signatureInfo, returnType, node->Flags(), node->IsExtensionFunction());
    if (signature == nullptr) {  // #23134
        ES2PANDA_ASSERT(GetChecker()->IsAnyError());
        return node->SetTsType(checker->GlobalTypeError());
    }

    signature->SetOwner(checker->Context().ContainingClass());

    return node->SetTsType(checker->CreateETSArrowType(signature));
}

checker::Type *ETSAnalyzer::Check(ir::ETSLaunchExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->expr_->Check(checker);

    // Launch expression returns a Promise<T> type, so we need to insert the expression's type
    // as type parameter for the Promise class.

    auto exprType = [&checker](auto *tsType) {
        if (tsType->IsETSPrimitiveType()) {
            return checker->MaybeBoxInRelation(tsType);
        }

        return tsType;
    }(expr->expr_->TsType());

    expr->SetTsType(checker->CreatePromiseOf(exprType));
    return expr->TsType();
}

template <typename T, typename = typename std::enable_if_t<std::is_base_of_v<ir::Expression, T>>>
static bool CheckArrayElementType(ETSChecker *checker, T *newArrayInstanceExpr)
{
    ES2PANDA_ASSERT(checker != nullptr);
    ES2PANDA_ASSERT(newArrayInstanceExpr != nullptr);

    checker::Type *elementType = newArrayInstanceExpr->TypeReference()->GetType(checker);
    if (elementType->IsETSPrimitiveType()) {
        return true;
    }

    if (elementType->IsETSObjectType()) {
        auto *calleeObj = elementType->AsETSObjectType();
        const auto flags = checker::ETSObjectFlags::ABSTRACT | checker::ETSObjectFlags::INTERFACE;
        if (!calleeObj->HasObjectFlag(flags)) {
            // A workaround check for new Interface[...] in test cases
            newArrayInstanceExpr->SetSignature(checker->CollectParameterlessConstructor(
                calleeObj->ConstructSignatures(), newArrayInstanceExpr->Start()));
            checker->ValidateSignatureAccessibility(calleeObj, newArrayInstanceExpr->Signature(),
                                                    newArrayInstanceExpr->Start());
        } else {
            checker->LogError(diagnostic::ABSTRACT_CLASS_AS_ARRAY_ELEMENT_TYPE, {}, newArrayInstanceExpr->Start());
            return false;
        }
    } else {
        if (!checker->Relation()->IsSupertypeOf(elementType, checker->GlobalETSUndefinedType()) &&
            !checker->Relation()->IsIdenticalTo(checker->GetApparentType(elementType), elementType)) {
            checker->LogError(diagnostic::TYPE_PARAMETER_AS_ARRAY_ELEMENT_TYPE, {}, newArrayInstanceExpr->Start());
            return false;
        }
        if (!checker->Relation()->IsSupertypeOf(elementType, checker->GlobalETSUndefinedType())) {
            checker->LogError(diagnostic::NON_SUPERTYPE_OF_UNDEFINED_AS_ARRAY_ELEMENT_TYPE, {},
                              newArrayInstanceExpr->Start());
            return false;
        }
    }
    return true;
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewArrayInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    auto *elementType = expr->TypeReference()->GetType(checker);
    checker->ValidateArrayIndex(expr->Dimension(), true);

    CheckArrayElementType(checker, expr);
    expr->SetTsType(checker->CreateETSArrayType(elementType));
    checker->CreateBuiltinArraySignature(expr->TsType()->AsETSArrayType(), 1);

    return expr->TsType();
}

static checker::Type *CheckInstantiatedNewType(ETSChecker *checker, ir::ETSNewClassInstanceExpression *expr)
{
    checker::Type *calleeType = expr->GetTypeRef()->Check(checker);
    if (calleeType->IsTypeError()) {
        return checker->InvalidateType(expr->GetTypeRef());
    }
    if (calleeType->IsETSUnionType()) {
        return checker->TypeError(expr->GetTypeRef(), diagnostic::UNION_NONCONSTRUCTIBLE, expr->Start());
    }
    if (!ir::ETSNewClassInstanceExpression::TypeIsAllowedForInstantiation(calleeType)) {
        return checker->TypeError(expr->GetTypeRef(), diagnostic::CALLEE_NONCONSTRUCTIBLE, {calleeType}, expr->Start());
    }
    if (!calleeType->IsETSObjectType()) {
        return checker->TypeError(expr->GetTypeRef(), diagnostic::EXPR_NONCONSTRUCTIBLE, {}, expr->Start());
    }

    auto calleeObj = calleeType->AsETSObjectType();
    if (calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
        checker->LogError(diagnostic::ABSTRACT_INSTANTIATION, {calleeObj->Name()}, expr->Start());
        return checker->GlobalTypeError();
    }

    if (calleeObj->HasObjectFlag(checker::ETSObjectFlags::INTERFACE)) {
        checker->LogError(diagnostic::INTERFACE_INSTANTIATION, {calleeObj->Name()}, expr->Start());
        return checker->GlobalTypeError();
    }

    if (calleeObj->HasObjectFlag(ETSObjectFlags::REQUIRED) &&
        !expr->HasAstNodeFlags(ir::AstNodeFlags::ALLOW_REQUIRED_INSTANTIATION)) {
        checker->LogError(diagnostic::NONLITERAL_INSTANTIATION, {}, expr->GetTypeRef()->Start());
        return checker->GlobalTypeError();
    }

    return calleeType;
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ETSChecker *checker = GetETSChecker();
    auto *calleeType = CheckInstantiatedNewType(checker, expr);
    if (calleeType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }
    auto *calleeObj = calleeType->AsETSObjectType();
    expr->SetTsType(calleeObj);

    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->GetTypeRef(), expr->GetArguments(), lang, true));
    } else {
        auto *signature = checker->ResolveConstructExpression(calleeObj, expr->GetArguments(), expr->Start());

        if (signature == nullptr) {
            return checker->InvalidateType(expr);
        }

        checker->CheckObjectLiteralArguments(signature, expr->GetArguments());

        checker->ValidateSignatureAccessibility(calleeObj, signature, expr->Start());

        if (calleeType->IsETSDynamicType()) {
            ES2PANDA_ASSERT(signature->Function()->IsDynamic());
            auto lang = calleeType->AsETSDynamicType()->Language();
            expr->SetSignature(
                checker->ResolveDynamicCallExpression(expr->GetTypeRef(), signature->Params(), lang, true));
        } else {
            expr->SetSignature(signature);
        }
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    CheckArrayElementType(checker, expr);
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
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::ETSParameterExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ASSERT_PRINT(expr->Initializer() == nullptr, "default parameter was not lowered");

    if (expr->Ident()->TsType() != nullptr) {
        expr->SetTsType(expr->Ident()->TsType());
    } else if (expr->IsRestParameter()) {
        expr->SetTsType(expr->RestParameter()->Check(checker));
    } else {
        expr->SetTsType(expr->Ident()->Check(checker));
    }
    ES2PANDA_ASSERT(!expr->IsOptional() ||
                    checker->Relation()->IsSupertypeOf(expr->TsType(), checker->GlobalETSUndefinedType()));
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
    return ReturnTypeForStatement(node);
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReference *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReferencePart *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSNullType *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    return checker->GlobalETSNullType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSUndefinedType *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    return checker->GlobalETSUndefinedType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSNeverType *node) const
{
    ETSChecker *checker = GetETSChecker();
    return checker->GlobalETSNeverType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSStringLiteralType *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSKeyofType *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

// compile methods for EXPRESSIONS in alphabetical order

checker::Type *ETSAnalyzer::GetPreferredType(ir::ArrayExpression *expr) const
{
    return expr->preferredType_;
}

static void AddSpreadElementTypes(ETSChecker *checker, ir::SpreadElement *const element,
                                  ArenaVector<std::pair<Type *, ir::Expression *>> &elementTypes)
{
    Type *const spreadType = element->Check(checker);

    if (spreadType->IsTypeError()) {
        // error recovery
        return;
    }

    Type *const spreadArgumentType = element->Argument()->TsType();

    if (spreadArgumentType->IsETSTupleType()) {
        for (Type *type : spreadArgumentType->AsETSTupleType()->GetTupleTypesList()) {
            elementTypes.emplace_back(type, element);
        }
    } else if (spreadArgumentType->IsETSArrayType()) {
        elementTypes.emplace_back(spreadArgumentType->AsETSArrayType()->ElementType(), element);
    } else {
        ES2PANDA_ASSERT(spreadArgumentType->IsETSResizableArrayType());
        elementTypes.emplace_back(spreadArgumentType->AsETSObjectType()->TypeArguments().front(), element);
    }
}

static bool ValidArrayExprSizeForTupleSize(ETSChecker *checker, Type *possibleTupleType,
                                           ir::Expression *possibleArrayExpr)
{
    if (!possibleArrayExpr->IsArrayExpression() || !possibleTupleType->IsETSTupleType()) {
        return true;
    }

    return checker->IsArrayExprSizeValidForTuple(possibleArrayExpr->AsArrayExpression(),
                                                 possibleTupleType->AsETSTupleType());
}

static ArenaVector<std::pair<Type *, ir::Expression *>> GetElementTypes(ETSChecker *checker, ir::ArrayExpression *expr)
{
    ArenaVector<std::pair<Type *, ir::Expression *>> elementTypes(checker->Allocator()->Adapter());

    for (std::size_t idx = 0; idx < expr->Elements().size(); ++idx) {
        ir::Expression *const element = expr->Elements()[idx];

        if (element->IsSpreadElement()) {
            AddSpreadElementTypes(checker, element->AsSpreadElement(), elementTypes);
            continue;
        }

        auto *const exprPreferredType = expr->GetPreferredType();

        if (expr->GetPreferredType()->IsETSTupleType() &&
            idx < expr->GetPreferredType()->AsETSTupleType()->GetTupleSize() &&
            !ValidArrayExprSizeForTupleSize(checker, exprPreferredType->AsETSTupleType()->GetTypeAtIndex(idx),
                                            element)) {
            elementTypes.emplace_back(checker->GlobalTypeError(), element);
            continue;
        }

        if (element->IsArrayExpression() || element->IsObjectExpression()) {
            auto *const targetPreferredType = exprPreferredType->IsETSTupleType()
                                                  ? exprPreferredType->AsETSTupleType()->GetTypeAtIndex(idx)
                                                  : exprPreferredType->AsETSArrayType()->ElementType();
            ETSChecker::SetPreferredTypeIfPossible(element, targetPreferredType);
        }

        elementTypes.emplace_back(element->Check(checker), element);
    }

    return elementTypes;
}

static bool CheckElement(ETSChecker *checker, Type *const preferredType,
                         ArenaVector<std::pair<Type *, ir::Expression *>> arrayExprElementTypes, std::size_t idx)
{
    auto [elementType, currentElement] = arrayExprElementTypes[idx];

    if (elementType->IsTypeError()) {
        return true;
    }

    Type *targetType = nullptr;

    if (preferredType->IsETSTupleType()) {
        const auto *const tupleType = preferredType->AsETSTupleType();
        if (tupleType->GetTupleSize() != arrayExprElementTypes.size()) {
            return false;
        }

        auto *const compareType = tupleType->GetTypeAtIndex(idx);
        if (compareType == nullptr) {
            checker->LogError(diagnostic::TUPLE_SIZE_MISMATCH, {tupleType->GetTupleSize()}, currentElement->Start());
            return false;
        }

        auto ctx = AssignmentContext(checker->Relation(), currentElement, elementType, compareType,
                                     currentElement->Start(), std::nullopt, TypeRelationFlag::NO_THROW);
        if (!ctx.IsAssignable()) {
            checker->LogError(diagnostic::TUPLE_UNASSIGNABLE_ARRAY, {idx}, currentElement->Start());
            return false;
        }

        const CastingContext castCtx(
            checker->Relation(), diagnostic::CAST_FAIL_UNREACHABLE, {},
            CastingContext::ConstructorData {currentElement, compareType, checker->MaybeBoxType(compareType),
                                             currentElement->Start(), TypeRelationFlag::NO_THROW});

        targetType = compareType;
    } else {
        targetType = preferredType->AsETSArrayType()->ElementType();
    }

    auto ctx = AssignmentContext(checker->Relation(), currentElement, elementType, targetType, currentElement->Start(),
                                 {}, TypeRelationFlag::NO_THROW);
    if (!ctx.IsAssignable()) {
        checker->LogError(diagnostic::ARRAY_ELEMENT_INIT_TYPE_INCOMPAT, {idx, elementType, targetType},
                          currentElement->Start());
        return false;
    }

    return true;
}

static ETSArrayType *InferPreferredTypeFromElements(ETSChecker *checker, ir::ArrayExpression *arrayExpr)
{
    ArenaVector<Type *> arrayExpressionElementTypes(checker->Allocator()->Adapter());
    for (auto *const element : arrayExpr->Elements()) {
        auto *elementType = *element->Check(checker);
        if (element->IsSpreadElement() && elementType->IsETSTupleType()) {
            for (auto *typeFromTuple : elementType->AsETSTupleType()->GetTupleTypesList()) {
                arrayExpressionElementTypes.emplace_back(typeFromTuple);
            }

            continue;
        }

        if (element->IsSpreadElement() && elementType->IsETSArrayType()) {
            elementType = elementType->AsETSArrayType()->ElementType();
        }

        arrayExpressionElementTypes.emplace_back(elementType);
    }

    // NOTE (smartin): fix union type normalization. Currently for primitive types like a 'char | char' type, it will be
    // normalized to 'Char'. However it shouldn't be boxed, and be kept as 'char'. For a quick fix, if all types are
    // primitive, then after making the union type, explicitly unbox it.
    if (std::all_of(arrayExpressionElementTypes.begin(), arrayExpressionElementTypes.end(),
                    [](Type *const typeOfElement) { return typeOfElement->IsETSPrimitiveType(); })) {
        return checker->CreateETSArrayType(checker->GetNonConstantType(
            checker->MaybeUnboxType(checker->CreateETSUnionType(std::move(arrayExpressionElementTypes)))));
    }

    // NOTE (smartin): optimize element access on constant array expressions (note is here, because the constant value
    // will be present on the type)
    return checker->CreateETSArrayType(
        checker->GetNonConstantType(checker->CreateETSUnionType(std::move(arrayExpressionElementTypes))));
}

static bool CheckArrayExpressionElements(ETSChecker *checker, ir::ArrayExpression *arrayExpr)
{
    const ArenaVector<std::pair<Type *, ir::Expression *>> arrayExprElementTypes = GetElementTypes(checker, arrayExpr);

    bool allElementsAssignable = !std::any_of(arrayExprElementTypes.begin(), arrayExprElementTypes.end(),
                                              [](auto &pair) { return pair.first->IsTypeError(); });

    for (std::size_t idx = 0; idx < arrayExprElementTypes.size(); ++idx) {
        allElementsAssignable &= CheckElement(checker, arrayExpr->GetPreferredType(), arrayExprElementTypes, idx);
    }

    return allElementsAssignable;
}

void ETSAnalyzer::GetUnionPreferredType(ir::ArrayExpression *expr) const
{
    ES2PANDA_ASSERT(expr->preferredType_->IsETSUnionType());
    checker::Type *preferredType = nullptr;
    for (auto &type : expr->preferredType_->AsETSUnionType()->ConstituentTypes()) {
        if (type->IsETSArrayType() || type->IsETSTupleType()) {
            if (preferredType != nullptr) {
                preferredType = nullptr;
                break;
            }
            preferredType = type;
        }
    }

    expr->preferredType_ = preferredType;
}

checker::Type *ETSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    if (expr->GetPreferredType() != nullptr) {
        if (expr->GetPreferredType()->IsETSTypeAliasType()) {
            expr->SetPreferredType(expr->GetPreferredType()->AsETSTypeAliasType()->GetTargetType());
        }

        if (expr->GetPreferredType()->IsETSUnionType()) {
            GetUnionPreferredType(expr);
        }
    }

    if (!IsArrayExpressionValidInitializerForType(checker, expr->GetPreferredType())) {
        checker->LogError(diagnostic::UNEXPECTED_ARRAY, {expr->GetPreferredType()}, expr->Start());
        return checker->InvalidateType(expr);
    }

    if (!expr->Elements().empty()) {
        if (expr->GetPreferredType() == nullptr || expr->GetPreferredType() == checker->GlobalETSObjectType()) {
            expr->SetPreferredType(InferPreferredTypeFromElements(checker, expr));
        }

        if (!CheckArrayExpressionElements(checker, expr)) {
            return checker->InvalidateType(expr);
        }
    }

    if (expr->GetPreferredType() == nullptr) {
        return checker->TypeError(expr, diagnostic::UNRESOLVABLE_ARRAY, expr->Start());
    }

    expr->SetTsType(expr->GetPreferredType());

    if (!expr->TsType()->IsETSTupleType()) {
        ES2PANDA_ASSERT(expr->TsType()->IsETSArrayType());
        const auto *const arrayType = expr->TsType()->AsETSArrayType();
        checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    return expr->TsType();
}

void TryInferPreferredType(ir::ArrowFunctionExpression *expr, checker::Type *preferredType, ETSChecker *checker)
{
    if (!preferredType->IsETSUnionType()) {
        if (preferredType->IsETSArrowType() &&
            !preferredType->AsETSFunctionType()->CallSignaturesOfMethodOrArrow().empty()) {
            checker->TryInferTypeForLambdaTypeAlias(expr, preferredType->AsETSFunctionType());
            checker->BuildFunctionSignature(expr->Function(), false);
        }
        return;
    }

    for (auto &ct : preferredType->AsETSUnionType()->ConstituentTypes()) {
        if (!ct->IsETSArrowType() || ct->AsETSFunctionType()->CallSignaturesOfMethodOrArrow().empty()) {
            continue;
        }
        checker->TryInferTypeForLambdaTypeAlias(expr, ct->AsETSFunctionType());
        checker->BuildFunctionSignature(expr->Function(), false);
        if (expr->Function()->Signature() != nullptr) {
            return;
        }
    }
}

checker::Type *ETSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(expr->Annotations());
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    checker::ScopeContext scopeCtx(checker, expr->Function()->Scope());

    if (checker->HasStatus(checker::CheckerStatus::IN_EXTENSION_METHOD) && !expr->Function()->HasReceiver()) {
        /*
        example code:
        ```
            class A {
                prop:number
            }
            function method(this: A) {
                let a = () => {
                    console.log(this.prop)
                }
            }
        ```
        here the enclosing class of arrow function should be Class A
        */
        checker->Context().SetContainingClass(
            checker->Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS).variable->TsType()->AsETSObjectType());
    }

    auto lambdaSavedSmartCasts = checker->Context().CloneSmartCasts();
    checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                              checker->Context().ContainingClass());

    if (expr->Parent()->IsCallExpression() && !expr->Function()->IsAsyncFunc()) {
        checker->Context().RestoreSmartCasts(lambdaSavedSmartCasts);
    }

    checker->AddStatus(checker::CheckerStatus::IN_LAMBDA);
    checker->Context().SetContainingLambda(expr);

    auto preferredType = expr->GetPreferredType();
    if (preferredType != nullptr) {
        TryInferPreferredType(expr, preferredType, checker);
    } else {
        checker->BuildFunctionSignature(expr->Function(), false);
    }

    if (expr->Function()->Signature() == nullptr) {
        return checker->InvalidateType(expr);
    }

    if (expr->Function()->HasReceiver()) {
        checker->AddStatus(checker::CheckerStatus::IN_EXTENSION_METHOD);
        CheckExtensionMethod(checker, expr->Function(), expr);
    }
    auto *signature = expr->Function()->Signature();

    checker->Context().SetContainingSignature(signature);
    expr->Function()->Body()->Check(checker);

    auto *funcType = checker->CreateETSArrowType(signature);
    checker->Context().SetContainingSignature(nullptr);

    if (expr->Function()->IsAsyncFunc()) {
        auto *retType = signature->ReturnType();
        if (!retType->IsETSObjectType() ||
            retType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
            checker->LogError(diagnostic::ASYNC_DOESNT_PROMISE, {}, expr->Function()->Start());
            expr->SetTsType(checker->GlobalTypeError());
            return expr->TsType();
        }
    }
    expr->SetTsType(funcType);
    return expr->TsType();
}

static bool IsInvalidArrayMemberAssignment(const ir::AssignmentExpression *const expr, ETSChecker *checker)
{
    if (!expr->Left()->IsMemberExpression()) {
        return false;
    }

    const auto *const leftExpr = expr->Left()->AsMemberExpression();
    if (leftExpr->Object()->TsType()->IsETSArrayType() || leftExpr->Object()->TsType()->IsETSTupleType() ||
        leftExpr->Object()->TsType()->IsETSResizableArrayType()) {
        if (leftExpr->Object()->TsType()->IsETSArrayType() && leftExpr->Property()->IsIdentifier() &&
            leftExpr->Property()->AsIdentifier()->Name().Is("length")) {
            checker->LogError(diagnostic::ARRAY_LENGTH_MODIFICATION, {}, expr->Left()->Start());
            return true;
        }

        if (leftExpr->Object()->TsType()->HasTypeFlag(TypeFlag::READONLY)) {
            checker->LogError(diagnostic::READONLY_ARRAYLIKE_MODIFICATION, {}, expr->Left()->Start());
            return true;
        }
    }

    return false;
}

checker::Type *ETSAnalyzer::GetSmartType(ir::AssignmentExpression *expr, checker::Type *leftType,
                                         checker::Type *rightType) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *smartType = leftType;

    if (expr->Left()->IsIdentifier() && expr->Target() != nullptr) {
        //  Now try to define the actual type of Identifier so that smart cast can be used in further checker
        //  processing
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(CheckerStatus::IN_SETTER) && expr->Left()->IsMemberExpression()) {
        checker->WarnForEndlessLoopInGetterSetter(expr->Left()->AsMemberExpression());
    }

    const auto leftType = expr->Left()->Check(checker);

    if (IsInvalidArrayMemberAssignment(expr, checker)) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    if (expr->Left()->IsIdentifier()) {
        expr->target_ = expr->Left()->AsIdentifier()->Variable();
    } else if (expr->Left()->IsMemberExpression()) {
        expr->target_ = expr->Left()->AsMemberExpression()->PropVar();
    } else {
        checker->LogError(diagnostic::ASSIGNMENT_INVALID_LHS, {}, expr->Left()->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    if (expr->target_ != nullptr && !expr->IsIgnoreConstAssign()) {
        checker->ValidateUnaryOperatorOperand(expr->target_);
    }

    auto [rightType, relationNode] = CheckAssignmentExprOperatorType(expr, leftType);
    if (rightType->IsTypeError()) {
        return expr->SetTsType(leftType);
    }

    CastPossibleTupleOnRHS(checker, expr);

    checker::Type *smartType = rightType;
    if (!leftType->IsTypeError()) {
        if (const auto ctx = checker::AssignmentContext(checker->Relation(), relationNode, rightType, leftType,
                                                        expr->Right()->Start(),
                                                        {{diagnostic::INVALID_ASSIGNMNENT, {rightType, leftType}}});
            ctx.IsAssignable()) {
            smartType = GetSmartType(expr, leftType, rightType);
        }
    }

    return expr->SetTsType(smartType);
}

static checker::Type *HandleSubstitution(ETSChecker *checker, ir::AssignmentExpression *expr, Type *const leftType)
{
    bool possibleInferredTypeOfArray = leftType->IsETSArrayType() || leftType->IsETSResizableArrayType() ||
                                       leftType->IsETSTupleType() || leftType->IsETSUnionType();
    if (expr->Right()->IsArrayExpression() && possibleInferredTypeOfArray) {
        checker->ModifyPreferredType(expr->Right()->AsArrayExpression(), leftType);
    }

    if (expr->Right()->IsETSNewArrayInstanceExpression()) {
        expr->Right()->AsETSNewArrayInstanceExpression()->SetPreferredType(leftType);
    }

    if (expr->Right()->IsETSNewMultiDimArrayInstanceExpression()) {
        expr->Right()->AsETSNewMultiDimArrayInstanceExpression()->SetPreferredType(leftType);
    }

    if (expr->Right()->IsObjectExpression()) {
        expr->Right()->AsObjectExpression()->SetPreferredType(leftType);
    }

    if (expr->Right()->IsArrowFunctionExpression() && (leftType->IsETSArrowType() || leftType->IsETSUnionType())) {
        expr->Right()->AsArrowFunctionExpression()->SetPreferredType(leftType);
    }

    return expr->Right()->Check(checker);
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

            auto unboxedLeft = checker->MaybeUnboxInRelation(leftType);
            sourceType = unboxedLeft == nullptr ? leftType : unboxedLeft;

            relationNode = expr;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            sourceType = HandleSubstitution(checker, expr, leftType);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
            break;
        }
    }

    return {sourceType, relationNode};
}

static bool IsPromiseType(checker::Type *type, ETSChecker *checker)
{
    return type->IsETSObjectType() &&
           type->AsETSObjectType()->GetOriginalBaseType() == checker->GlobalBuiltinPromiseType();
}

checker::Type *ETSAnalyzer::Check(ir::AwaitExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker::Type *argType = checker->GetApparentType(expr->argument_->Check(checker));
    ArenaVector<Type *> awaitedTypes(checker->Allocator()->Adapter());

    if (argType->IsETSUnionType()) {
        for (Type *type : argType->AsETSUnionType()->ConstituentTypes()) {
            if (!IsPromiseType(type, checker)) {
                return checker->TypeError(expr, diagnostic::AWAITED_NOT_PROMISE, expr->Argument()->Start());
            }

            Type *typeArg = type->AsETSObjectType()->TypeArguments().at(0);
            awaitedTypes.push_back(UnwrapPromiseType(typeArg));
        }
    } else {
        if (!IsPromiseType(argType, checker)) {
            return checker->TypeError(expr, diagnostic::AWAITED_NOT_PROMISE, expr->Argument()->Start());
        }

        Type *typeArg = argType->AsETSObjectType()->TypeArguments().at(0);
        awaitedTypes.push_back(UnwrapPromiseType(typeArg));
    }

    expr->SetTsType(argType->IsETSUnionType() ? checker->CreateETSUnionType(std::move(awaitedTypes)) : awaitedTypes[0]);
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
    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    // NOLINTNEXTLINE(modernize-loop-convert)
    for (std::size_t idx = 0; idx < st->Statements().size(); idx++) {
        st->Statements()[idx]->Check(checker);
    }

    auto lastStmt = st->Statements().back();
    ES2PANDA_ASSERT(lastStmt->IsExpressionStatement());
    st->SetTsType(lastStmt->AsExpressionStatement()->GetExpression()->TsType());
    return st->TsType();
}

checker::Signature *ETSAnalyzer::ResolveSignature(ETSChecker *checker, ir::CallExpression *expr,
                                                  checker::Type *calleeType) const
{
    if (calleeType->IsETSFunctionType() && calleeType->AsETSFunctionType()->HasHelperSignature() &&
        expr->Signature() != nullptr) {
        // Note: Only works when rechecking in DeclareOveloadLowering phase
        auto *helperSignature = calleeType->AsETSFunctionType()->GetHelperSignature();
        checker->ReportWarning({"Detect duplicate signatures, use '", helperSignature->Function()->Id()->Name(),
                                helperSignature, "' to replace"},
                               expr->Start());
        checker->CreateOverloadSigContainer(helperSignature);
        return checker->ResolveCallExpressionAndTrailingLambda(checker->GetOverloadSigContainer(), expr, expr->Start());
    }

    if (calleeType->IsETSExtensionFuncHelperType()) {
        auto *signature =
            ResolveCallForETSExtensionFuncHelperType(calleeType->AsETSExtensionFuncHelperType(), checker, expr);
        GetChecker()->AsETSChecker()->UpdateDeclarationFromSignature(expr, signature);
        return signature;
    }

    if (checker->IsExtensionETSFunctionType(calleeType)) {
        auto *signature = ResolveCallExtensionFunction(calleeType, checker, expr);
        if (signature != nullptr && signature->IsExtensionAccessor() &&
            !checker->HasStatus(CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK)) {
            checker->LogError(diagnostic::EXTENSION_ACCESSOR_INVALID_CALL, {}, expr->Start());
            return nullptr;
        }
        return signature;
    }
    auto &signatures = expr->IsETSConstructorCall() ? calleeType->AsETSObjectType()->ConstructSignatures()
                                                    : calleeType->AsETSFunctionType()->CallSignaturesOfMethodOrArrow();

    return checker->ResolveCallExpressionAndTrailingLambda(signatures, expr, expr->Start());
}

static ETSObjectType *GetCallExpressionCalleeObject(ETSChecker *checker, ir::CallExpression *expr, Type *calleeType)
{
    if (expr->IsETSConstructorCall()) {
        return calleeType->AsETSObjectType();
    }
    auto callee = expr->Callee();
    if (callee->IsMemberExpression()) {
        return callee->AsMemberExpression()->ObjType();
    }
    ES2PANDA_ASSERT(callee->IsIdentifier());
    return checker->Context().ContainingClass();
}

Type *ETSAnalyzer::GetReturnType(ir::CallExpression *expr, Type *calleeType) const
{
    ETSChecker *checker = GetETSChecker();

    if (calleeType->IsTypeError()) {
        return checker->GlobalTypeError();
    }

    if (!calleeType->IsETSFunctionType() && !expr->IsETSConstructorCall() &&
        !calleeType->IsETSExtensionFuncHelperType()) {
        checker->LogError(diagnostic::NO_CALL_SIGNATURE, {calleeType}, expr->Start());
        return checker->GlobalTypeError();
    }

    Signature *const signature = ResolveSignature(checker, expr, calleeType);
    if (signature == nullptr) {
        return checker->GlobalTypeError();
    }

    checker->CheckObjectLiteralArguments(signature, expr->Arguments());

    if (calleeType->IsETSMethodType()) {
        ETSObjectType *calleeObj = GetCallExpressionCalleeObject(checker, expr, calleeType);
        checker->ValidateSignatureAccessibility(calleeObj, signature, expr->Start());
    }

    if (calleeType->IsETSMethodType() && signature->Function()->IsDynamic()) {
        ES2PANDA_ASSERT(signature->Function()->IsDynamic());
        auto lang = signature->Function()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->Callee(), signature->Params(), lang, false));
    } else {
        expr->SetSignature(signature);
    }

    // #22951: this type should not be encoded as a signature flag
    if (signature->HasSignatureFlag(SignatureFlags::THIS_RETURN_TYPE)) {
        return signature->HasSignatureFlag(SignatureFlags::EXTENSION_FUNCTION)
                   ? expr->Arguments()[0]->TsType()
                   : GetCallExpressionCalleeObject(checker, expr, calleeType);
    }
    return signature->ReturnType();
}

static void CheckAbstractCall(ETSChecker *checker, ir::CallExpression *expr)
{
    if (expr->Callee()->IsMemberExpression()) {
        auto obj = expr->Callee()->AsMemberExpression()->Object();
        if (obj != nullptr && obj->IsSuperExpression()) {
            if ((expr->Signature() != nullptr) && (expr->Signature()->HasSignatureFlag(SignatureFlags::ABSTRACT))) {
                checker->LogError(diagnostic::ABSTRACT_CALL, {}, expr->Start());
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
        checker->LogError(diagnostic::READONLY_CALL, {}, expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
    }
}

// Restore CheckerContext of the owner class if we want to perform checking
static checker::SavedCheckerContext ReconstructOwnerClassContext(ETSChecker *checker, ETSObjectType *owner)
{
    if (owner == nullptr) {
        return SavedCheckerContext(checker, CheckerStatus::NO_OPTS, nullptr);
    }
    ES2PANDA_ASSERT(!owner->HasObjectFlag(ETSObjectFlags::ENUM));
    CheckerStatus const status =
        (owner->HasObjectFlag(ETSObjectFlags::CLASS) ? CheckerStatus::IN_CLASS : CheckerStatus::IN_INTERFACE) |
        (owner->HasObjectFlag(ETSObjectFlags::ABSTRACT) ? CheckerStatus::IN_ABSTRACT : CheckerStatus::NO_OPTS) |
        (owner->HasObjectFlag(ETSObjectFlags::INNER) ? CheckerStatus::INNER_CLASS : CheckerStatus::NO_OPTS) |
        (owner->GetDeclNode()->IsClassDefinition() && owner->GetDeclNode()->AsClassDefinition()->IsLocal()
             ? CheckerStatus::IN_LOCAL_CLASS
             : CheckerStatus::NO_OPTS);

    return SavedCheckerContext(checker, status, owner);
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

    auto *const signature = expr->Signature();
    if (signature->RestVar() != nullptr && signature->RestVar()->TsType()->IsETSArrayType()) {
        auto *elementType = signature->RestVar()->TsType()->AsETSArrayType()->ElementType();
        auto *const arrayType = checker->CreateETSArrayType(elementType)->AsETSArrayType();
        checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    if (!signature->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE) ||
        (signature->HasSignatureFlag(checker::SignatureFlags::CONSTRUCTOR))) {
        return returnType;
    }

    auto owner = const_cast<ETSObjectType *>(util::Helpers::GetContainingObjectType(signature->Function()));
    SavedCheckerContext savedCtx(ReconstructOwnerClassContext(checker, owner));

    ir::AstNode *methodDef = signature->Function();
    while (!methodDef->IsMethodDefinition()) {
        methodDef = methodDef->Parent();
        ES2PANDA_ASSERT(methodDef != nullptr);
    }
    ES2PANDA_ASSERT(methodDef->IsMethodDefinition());
    methodDef->Check(checker);

    if (!signature->Function()->HasBody()) {
        return signature->ReturnType();
    }

    if (signature->Function()->IsExternal()) {
        checker->VarBinder()->AsETSBinder()->ResolveReferencesForScopeWithContext(signature->Function()->Body(),
                                                                                  signature->Function()->Scope());
    }
    checker::ScopeContext scopeCtx(checker, signature->Function()->Body()->Scope());
    checker->CollectReturnStatements(signature->Function());
    return signature->ReturnType();
    // NOTE(vpukhov): #14902 substituted signature is not updated
}

checker::Type *ETSAnalyzer::Check(ir::CallExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ES2PANDA_ASSERT(!expr->IsOptional());

    auto *oldCallee = expr->Callee();
    checker::Type *calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    if (calleeType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }

    if (expr->Callee() != oldCallee) {
        // If it is a static invoke, the callee will be transformed from an identifier to a member expression
        // Type check the callee again for member expression
        calleeType = checker->GetApparentType(expr->Callee()->Check(checker));
    }

    CheckCallee(checker, expr);

    checker::TypeStackElement tse(checker, expr, {{diagnostic::CYCLIC_CALLEE, {}}}, expr->Start());
    if (tse.HasTypeError()) {
        expr->SetTsType(checker->GlobalTypeError());
        return checker->GlobalTypeError();
    }

    checker::Type *const returnType = GetCallExpressionReturnType(expr, calleeType);
    expr->SetTsType(returnType);
    if (returnType->IsTypeError()) {
        return returnType;
    }
    if (calleeType->IsETSArrowType()) {
        expr->SetUncheckedType(checker->GuaranteedTypeForUncheckedCast(
            checker->GlobalETSNullishObjectType(), checker->MaybeBoxType(expr->Signature()->ReturnType())));
    } else {
        expr->SetUncheckedType(checker->GuaranteedTypeForUncheckedCallReturn(expr->Signature()));
    }

    if (expr->UncheckedType() != nullptr) {
        ES2PANDA_ASSERT(expr->UncheckedType()->IsETSReferenceType());
        checker->ComputeApparentType(returnType);
    }

    if (returnType->IsTypeError()) {
        expr->SetTsType(returnType);
        return expr->TsType();
    }

    CheckVoidTypeExpression(checker, expr);
    CheckAbstractCall(checker, expr);
    return expr->TsType();
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

    auto *consequent = expr->Consequent();
    Type *consequentType = consequent->Check(checker);

    SmartCastArray consequentSmartCasts = checker->Context().CloneSmartCasts();
    checker->Context().RestoreSmartCasts(smartCasts);

    if (testedTypes.has_value()) {
        for (auto [variable, _, alternateType] : *testedTypes) {
            checker->ApplySmartCast(variable, alternateType);
        }
    }

    auto *alternate = expr->Alternate();
    Type *alternateType = alternate->Check(checker);

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

// Convert method references to Arrow type if method is used as value
static Type *TransformTypeForMethodReference(ETSChecker *checker, ir::Expression *const use, Type *type)
{
    ES2PANDA_ASSERT(use->IsIdentifier() || use->IsMemberExpression());
    if (!type->IsETSMethodType()) {
        return type;
    }
    auto const getUseSite = [use]() {
        return use->IsIdentifier() ? use->Start() : use->AsMemberExpression()->Property()->Start();
    };

    ir::Expression *expr = use;
    while (expr->Parent()->IsMemberExpression() && expr->Parent()->AsMemberExpression()->Property() == expr) {
        expr = expr->Parent()->AsMemberExpression();
    }
    if (expr->Parent()->IsCallExpression() && expr->Parent()->AsCallExpression()->Callee() == expr) {
        return type;  // type is actually used as method
    }

    if (type->AsETSFunctionType()->CallSignatures().at(0)->HasSignatureFlag(SignatureFlags::PRIVATE)) {
        checker->LogError(diagnostic::PRIVATE_METHOD_AS_VALUE, getUseSite());
        return checker->GlobalTypeError();
    }

    if (type->AsETSFunctionType()->CallSignatures().size() > 1) {
        checker->LogError(diagnostic::OVERLOADED_METHOD_AS_VALUE, getUseSite());
        return checker->GlobalTypeError();
    }
    return type->AsETSFunctionType()->MethodToArrow(checker);
}

checker::Type *ETSAnalyzer::Check(ir::Identifier *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    ETSChecker *checker = GetETSChecker();

    auto *identType = TransformTypeForMethodReference(checker, expr, checker->ResolveIdentifier(expr));

    ES2PANDA_ASSERT(expr->Variable() != nullptr);
    if (expr->Parent() == nullptr || !expr->Parent()->IsAssignmentExpression() ||
        expr != expr->Parent()->AsAssignmentExpression()->Left()) {
        auto *const smartType = checker->Context().GetSmartCast(expr->Variable());
        if (smartType != nullptr) {
            identType = smartType;
        }
    }

    expr->SetTsType(identType);
    if (!identType->IsTypeError()) {
        checker->Context().CheckIdentifierSmartCastCondition(expr);
    }
    return expr->TsType();
}

std::pair<checker::Type *, util::StringView> SearchReExportsType(ETSObjectType *baseType, ir::MemberExpression *expr,
                                                                 util::StringView &aliasName, ETSChecker *checker)
{
    std::pair<ETSObjectType *, util::StringView> ret {};

    for (auto *const item : baseType->ReExports()) {
        auto name = item->GetReExportAliasValue(aliasName);
        if (name == aliasName && item->IsReExportHaveAliasValue(name)) {
            continue;
        }

        if (item->GetProperty(name, PropertySearchFlags::SEARCH_ALL) != nullptr) {
            if (ret.first != nullptr) {
                checker->LogError(diagnostic::AMBIGUOUS_REFERENCE, {aliasName}, expr->Start());
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
    std::ignore = checker->TypeError(expr, diagnostic::PROPERTY_NONEXISTENT,
                                     {expr->Property()->AsIdentifier()->Name(), baseType}, expr->Object()->Start());
}

checker::Type *ETSAnalyzer::ResolveMemberExpressionByBaseType(ETSChecker *checker, checker::Type *baseType,
                                                              ir::MemberExpression *expr) const
{
    if (baseType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }

    if (baseType->IsETSArrayType()) {
        if (expr->Property()->AsIdentifier()->Name().Is("length")) {
            return expr->AdjustType(checker, checker->GlobalIntType());
        }

        return expr->SetAndAdjustType(checker, checker->GlobalETSObjectType());
    }

    if (baseType->IsETSFunctionType() || baseType->IsETSTupleType()) {
        return expr->SetAndAdjustType(checker, checker->GlobalETSObjectType());
    }

    if (baseType->IsETSObjectType()) {
        checker->ETSObjectTypeDeclNode(checker, baseType->AsETSObjectType());
        return expr->SetTsType(TransformTypeForMethodReference(
            checker, expr, expr->SetAndAdjustType(checker, baseType->AsETSObjectType())));
    }

    if (baseType->IsETSUnionType()) {
        return expr->AdjustType(checker, expr->CheckUnionMember(checker, baseType));
    }
    TypeErrorOnMissingProperty(expr, baseType, checker);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::MemberExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ES2PANDA_ASSERT(!expr->IsOptional());
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
        auto *invalidType = checker->HasStatus(checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK)
                                ? checker->GlobalETSNullishType()
                                : checker->InvalidateType(expr);
        return invalidType;
    }

    if (expr->IsComputed()) {
        return expr->AdjustType(checker, expr->CheckComputed(checker, baseType));
    }

    return ResolveMemberExpressionByBaseType(checker, baseType, expr);
}

checker::Type *ETSAnalyzer::PreferredType(ir::ObjectExpression *expr) const
{
    return expr->preferredType_;
}

checker::Type *ETSAnalyzer::CheckDynamic(ir::ObjectExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    for (ir::Expression *propExpr : expr->Properties()) {
        ES2PANDA_ASSERT(propExpr->IsProperty());
        ir::Property *prop = propExpr->AsProperty();
        ir::Expression *value = prop->Value();
        value->Check(checker);
        ES2PANDA_ASSERT(value->TsType());
    }

    expr->SetTsType(expr->PreferredType());
    return expr->PreferredType();
}

static bool ValidatePreferredType(ETSChecker *checker, ir::ObjectExpression *expr)
{
    auto preferredType = expr->PreferredType();
    if (preferredType == nullptr) {
        checker->LogError(diagnostic::CLASS_COMPOSITE_UNKNOWN_TYPE, {}, expr->Start());
        return false;
    }

    if (preferredType->IsTypeError()) {
        //  Don't need to duplicate error message for a single error.
        return false;
    }

    if (!preferredType->IsETSObjectType()) {
        checker->LogError(diagnostic::CKASS_COMPOSITE_INVALID_TARGET, {preferredType}, expr->Start());
        return false;
    }

    return true;
}

static void SetTypeforRecordProperties(const ir::ObjectExpression *expr, checker::ETSObjectType *objType,
                                       ETSChecker *checker)
{
    const auto &recordProperties = expr->Properties();
    auto typeArguments = objType->TypeArguments();
    auto *const valueType = typeArguments[1];  //  Record<K, V>  type arguments

    for (auto *const recordProperty : recordProperties) {
        auto *const recordPropertyExpr = recordProperty->AsProperty()->Value();
        ETSChecker::SetPreferredTypeIfPossible(recordPropertyExpr, valueType);
        recordPropertyExpr->Check(checker);
    }
}

checker::Type *ETSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    if (!ValidatePreferredType(checker, expr)) {
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    if (expr->PreferredType()->IsETSDynamicType()) {
        return CheckDynamic(expr);
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

    if (expr->PreferredType()->ToAssemblerName().str() == "escompat.Record" ||
        expr->PreferredType()->ToAssemblerName().str() == "escompat.Map") {
        // 7.6.3 Object Literal of Record Type
        // Record is an alias to Map
        // Here we just set the type to pass the checker
        // See Record Lowering for details
        expr->SetTsType(objType);
        SetTypeforRecordProperties(expr, objType, checker);
        return objType;
    }

    bool haveEmptyConstructor = false;
    for (checker::Signature *sig : objType->ConstructSignatures()) {
        if (sig->Params().empty()) {
            haveEmptyConstructor = true;
            checker->ValidateSignatureAccessibility(objType, sig, expr->Start());
            break;
        }
    }
    if (!haveEmptyConstructor) {
        return checker->TypeError(expr, diagnostic::NO_PARAMLESS_CTOR, {objType->Name()}, expr->Start());
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
        if (!propExpr->IsProperty()) {
            checker->LogError(diagnostic::OBJECT_LITERAL_NOT_KV, {}, expr->Start());
            return;
        }
        ir::Expression *key = propExpr->AsProperty()->Key();
        ir::Expression *value = propExpr->AsProperty()->Value();

        util::StringView pname;
        if (key->IsStringLiteral()) {
            pname = key->AsStringLiteral()->Str();
        } else if (key->IsIdentifier()) {
            pname = key->AsIdentifier()->Name();
        } else {
            checker->LogError(diagnostic::CLASS_COMPOSITE_INVALID_KEY, {}, expr->Start());
            return;
        }
        varbinder::LocalVariable *lv = objType->GetProperty(pname, searchFlags);
        if (lv == nullptr) {
            checker->LogError(diagnostic::UNDEFINED_PROPERTY, {objType->Name(), pname}, propExpr->Start());
            return;
        }
        checker->ValidatePropertyAccess(lv, objType, propExpr->Start());

        if (key->IsIdentifier()) {
            key->AsIdentifier()->SetVariable(lv);
        }

        auto *propType = checker->GetTypeOfVariable(lv);
        if (propType->IsETSMethodType()) {
            checker->LogError(diagnostic::OBJECT_LITERAL_METHOD_KEY, {pname}, propExpr->Start());
            return;
        }

        ETSChecker::SetPreferredTypeIfPossible(value, propType);
        key->SetTsType(propType);
        value->SetTsType(value->Check(checker));

        checker::AssignmentContext(checker->Relation(), value, value->TsType(), propType, value->Start(),
                                   {{diagnostic::PROP_INCOMPAT, {value->TsType(), propType, pname}}});
    }

    if (objType->HasObjectFlag(ETSObjectFlags::REQUIRED)) {
        checker->ValidateObjectLiteralForRequiredType(objType, expr);
    }
}

checker::Type *ETSAnalyzer::Check(ir::OpaqueTypeNode *expr) const
{
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::BrokenTypeNode *expr) const
{
    return GetETSChecker()->GlobalTypeError();
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
    ES2PANDA_ASSERT(!expr->Sequence().empty());
    expr->SetTsType(expr->Sequence().back()->TsType());
    return expr->TsType();
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

checker::Type *ETSAnalyzer::Check(ir::TemplateLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    if (expr->Quasis().size() != expr->Expressions().size() + 1U) {
        checker->LogError(diagnostic::TEMPLATE_COUNT_MISMATCH, {}, expr->Start());
        expr->SetTsType(checker->GlobalTypeError());
        return expr->TsType();
    }

    for (auto *it : expr->Expressions()) {
        it->Check(checker);
    }

    for (auto *it : expr->Quasis()) {
        it->Check(checker);
    }

    expr->SetTsType(checker->CreateETSStringLiteralType(expr->GetMultilineString()));
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
    if (checker->HasStatus(checker::CheckerStatus::IN_EXTENSION_METHOD)) {
        ES2PANDA_ASSERT(variable != nullptr);
        expr->SetTsType(variable->TsType());
    } else {
        expr->SetTsType(checker->CheckThisOrSuperAccess(expr, checker->Context().ContainingClass(), "this"));
    }

    return expr->TsType();
}

// Get string literal type as potential typeof result type with respect to spec p.7.17
static checker::Type *GetTypeOfStringType(checker::Type *argType, ETSChecker *checker)
{
    if (auto unboxed = checker->MaybeUnboxType(argType); unboxed->IsETSPrimitiveType()) {
        switch (checker->TypeKind(unboxed)) {
            case TypeFlag::ETS_BOOLEAN:
                return checker->CreateETSStringLiteralType("boolean");
            case TypeFlag::BYTE:
            case TypeFlag::CHAR:
            case TypeFlag::SHORT:
            case TypeFlag::INT:
            case TypeFlag::LONG:
            case TypeFlag::FLOAT:
            case TypeFlag::DOUBLE:
                return checker->CreateETSStringLiteralType("number");
            default:
                ES2PANDA_UNREACHABLE();
        }
    }
    if (argType->IsETSUndefinedType()) {
        return checker->CreateETSStringLiteralType("undefined");
    }
    if (argType->IsETSArrayType() || argType->IsETSNullType()) {
        return checker->CreateETSStringLiteralType("object");
    }
    if (argType->IsETSStringType()) {
        return checker->CreateETSStringLiteralType("string");
    }
    if (argType->IsETSBigIntType()) {
        return checker->CreateETSStringLiteralType("bigint");
    }
    if (argType->IsETSFunctionType()) {
        return checker->CreateETSStringLiteralType("function");
    }
    if (argType->IsETSIntEnumType()) {
        return checker->CreateETSStringLiteralType("number");
    }
    if (argType->IsETSStringEnumType()) {
        return checker->CreateETSStringLiteralType("string");
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    expr->Argument()->Check(checker);
    expr->SetTsType(ComputeTypeOfType(checker, expr->Argument()->TsType()));
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
    auto unboxedOperandType =
        isCondExpr ? checker->MaybeUnboxConditionalInRelation(argType) : checker->MaybeUnboxInRelation(argType);

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

    if ((argType != nullptr) && argType->IsETSObjectType() && (unboxedOperandType != nullptr) &&
        unboxedOperandType->IsETSPrimitiveType()) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedOperandType));
    }

    SetTsTypeForUnaryExpression(checker, expr, operandType);

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
    if (operandType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }

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
    } else if (expr->Argument()->IsMemberExpression()) {
        varbinder::LocalVariable *propVar = expr->argument_->AsMemberExpression()->PropVar();
        if (propVar != nullptr) {
            checker->ValidateUnaryOperatorOperand(propVar);
        }
    } else {
        ES2PANDA_ASSERT(checker->IsAnyError());
        expr->Argument()->SetTsType(checker->GlobalTypeError());
        return expr->SetTsType(checker->GlobalTypeError());
    }

    if (operandType->IsETSBigIntType()) {
        return expr->SetTsType(operandType);
    }

    auto unboxedType = checker->MaybeUnboxInRelation(operandType);
    if (unboxedType == nullptr || !unboxedType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        checker->LogError(diagnostic::OPERAND_NOT_NUMERIC, {}, expr->Argument()->Start());
        return expr->SetTsType(checker->GlobalTypeError());
    }

    if (operandType->IsETSObjectType()) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedType) |
                                                 checker->GetBoxingFlag(unboxedType));
    }

    return expr->SetTsType(operandType);
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

checker::Type *ETSAnalyzer::Check(ir::StringLiteral *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() == nullptr) {
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
        return ReturnTypeForStatement(st);
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

// compile methods for STATEMENTS in alphabetical order
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::AssertStatement *st) const
{
    ES2PANDA_UNREACHABLE();
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

    auto const *const scope = st->Scope();
    if (scope == nullptr) {
        return ReturnTypeForStatement(st);
    }

    //  Remove possible smart casts for variables declared in inner scope:
    if (scope->IsFunctionScope() && st->Parent()->Parent()->Parent()->IsMethodDefinition()) {
        // When exiting method definition, just clear all smart casts
        checker->Context().ClearSmartCasts();
    } else if (!scope->IsGlobalScope()) {
        // otherwise only check inner declarations
        for (auto const *const decl : scope->Decls()) {
            if (decl->IsLetOrConstDecl() && decl->Node() != nullptr && decl->Node()->IsIdentifier()) {
                checker->Context().RemoveSmartCast(decl->Node()->AsIdentifier()->Variable());
            }
        }
    }

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::BreakStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (!st->HasTarget()) {
        compiler::SetJumpTargetPhase setJumpTarget;
        setJumpTarget.FindJumpTarget(checker->VarBinder()->GetContext(), st);
    }

    if (st->Target() == nullptr) {
        return checker->GlobalTypeError();
    }

    checker->Context().OnBreakStatement(st);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::ClassDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->Definition()->Check(checker);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::AnnotationDeclaration *st) const
{
    if (st->Expr()->TsType() != nullptr) {
        return ReturnTypeForStatement(st);
    }
    ETSChecker *checker = GetETSChecker();
    st->Expr()->Check(checker);

    for (auto *anno : st->Annotations()) {
        checker->CheckStandardAnnotation(anno);
        anno->Check(checker);
    }

    ScopeContext scopeCtx(checker, st->Scope());
    for (auto *it : st->Properties()) {
        auto *property = it->AsClassProperty();
        if (checker::Type *propertyType = property->Check(checker); !propertyType->IsTypeError()) {
            checker->CheckAnnotationPropertyType(property);
        }
    }

    auto baseName = st->GetBaseName();
    if (!baseName->IsErrorPlaceHolder()) {
        auto *annoDecl = baseName->Variable()->Declaration()->Node()->AsAnnotationDeclaration();
        if (annoDecl != st && annoDecl->IsDeclare()) {
            checker->CheckAmbientAnnotation(st, annoDecl);
        }
    }

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::AnnotationUsage *st) const
{
    if (st->Expr()->TsType() != nullptr) {
        return ReturnTypeForStatement(st);
    }
    ETSChecker *checker = GetETSChecker();
    st->Expr()->Check(checker);

    if (st->GetBaseName()->Variable() == nullptr ||
        !st->GetBaseName()->Variable()->Declaration()->Node()->IsAnnotationDeclaration()) {
        checker->LogError(diagnostic::NOT_AN_ANNOTATION, {st->GetBaseName()->Name()}, st->GetBaseName()->Start());
        return ReturnTypeForStatement(st);
    }

    auto *annoDecl = st->GetBaseName()->Variable()->Declaration()->Node()->AsAnnotationDeclaration();
    annoDecl->Check(checker);

    ArenaUnorderedMap<util::StringView, ir::ClassProperty *> fieldMap {checker->Allocator()->Adapter()};
    for (auto *it : annoDecl->Properties()) {
        auto *field = it->AsClassProperty();
        fieldMap.insert(std::make_pair(field->Id()->Name(), field));
    }

    if (annoDecl->Properties().size() < st->Properties().size()) {
        checker->LogError(diagnostic::ANNOTATION_ARG_COUNT_MISMATCH, {}, st->Start());
        return ReturnTypeForStatement(st);
    }

    if (st->Properties().size() == 1 &&
        st->Properties().at(0)->AsClassProperty()->Id()->Name() == compiler::Signatures::ANNOTATION_KEY_VALUE) {
        checker->CheckSinglePropertyAnnotation(st, annoDecl);
        fieldMap.clear();
    } else {
        checker->CheckMultiplePropertiesAnnotation(st, st->GetBaseName()->Name(), fieldMap);
    }

    checker->ProcessRequiredFields(fieldMap, st, checker);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::ContinueStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (!st->HasTarget()) {
        compiler::SetJumpTargetPhase setJumpTarget;
        setJumpTarget.FindJumpTarget(checker->VarBinder()->GetContext(), st);
    }

    if (st->Target() == nullptr) {
        return checker->GlobalTypeError();
    }

    checker->AddStatus(CheckerStatus::MEET_CONTINUE);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::DoWhileStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st, std::nullopt);

    checker->CheckTruthinessOfType(st->Test());
    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::EmptyStatement *st) const
{
    return ReturnTypeForStatement(st);
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

    const auto ident = st->Left()->IsVariableDeclaration()
                           ? st->Left()->AsVariableDeclaration()->Declarators().front()->Id()->AsIdentifier()
                           : st->Left()->AsIdentifier();
    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(ident);

    if (!relation->IsAssignableTo(elemType, iterType)) {
        checker->LogError(diagnostic::ITERATOR_ELEMENT_TYPE_MISMATCH, {elemType, iterType}, st->Start());
        return false;
    }

    relation->SetNode(nullptr);
    relation->SetFlags(checker::TypeRelationFlag::NONE);

    const auto variable = ident->Variable();
    if (variable != nullptr) {
        // Set smart type for variable of 'for-of' statement
        const auto smartType = checker->ResolveSmartType(elemType, variable->TsType());
        checker->Context().SetSmartCast(variable, smartType);
    }

    return true;
}

checker::Type *ETSAnalyzer::Check(ir::ForOfStatement *const st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st, std::nullopt);

    checker::Type *const exprType = st->Right()->Check(checker);
    if (exprType == nullptr) {
        checker->LogError(diagnostic::FOROF_CANT_INFER_SOURCE, {}, st->Right()->Start());
        return checker->GlobalTypeError();
    }

    checker::Type *elemType = nullptr;

    if (exprType->IsETSStringType()) {
        elemType = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else if (exprType->IsETSArrayType()) {
        elemType = exprType->AsETSArrayType()->ElementType();
    } else if (exprType->IsETSObjectType() || exprType->IsETSUnionType() || exprType->IsETSTypeParameter()) {
        elemType = st->CheckIteratorMethod(checker);
    }

    if (elemType == nullptr) {
        checker->LogError(diagnostic::FOROF_SOURCE_NONITERABLE, {}, st->Right()->Start());
        return checker->GlobalTypeError();
    }

    st->Left()->Check(checker);

    if (!ValidateAndProcessIteratorType(checker, elemType, st)) {
        return checker->GlobalTypeError();
    };

    st->Body()->Check(checker);

    checker->Context().ExitLoop(smartCasts, clearFlag, st);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    //  NOTE: Smart casts are not processed correctly within the loops now, thus clear them at this point.
    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st, std::nullopt);

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
    return ReturnTypeForStatement(st);
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

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::LabelledStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->body_->Check(checker);
    return ReturnTypeForStatement(st);
}

static bool CheckIsValidReturnTypeAnnotation(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc,
                                             ir::TypeNode *returnTypeAnnotation, ETSChecker *checker)
{
    // check valid `this` type as return type
    if (containingFunc->GetPreferredReturnType() != nullptr || !returnTypeAnnotation->IsTSThisType()) {
        return true;
    }

    // only extension function and class method could return `this`;
    bool inValidNormalFuncReturnThisType = st->Argument() == nullptr || !st->Argument()->IsThisExpression();
    bool inValidExtensionFuncReturnThisType =
        !containingFunc->HasReceiver() ||
        (containingFunc->HasReceiver() && (st->Argument() == nullptr || !st->Argument()->IsIdentifier() ||
                                           !st->Argument()->AsIdentifier()->IsReceiver()));
    if (inValidNormalFuncReturnThisType && inValidExtensionFuncReturnThisType) {
        checker->LogError(diagnostic::RETURN_THIS_OUTSIDE_METHOD, {}, st->Start());
        return false;
    }

    return true;
}

bool ETSAnalyzer::CheckInferredFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc,
                                                  checker::Type *&funcReturnType, ir::TypeNode *returnTypeAnnotation,
                                                  ETSChecker *checker) const
{
    if (!CheckIsValidReturnTypeAnnotation(st, containingFunc, returnTypeAnnotation, checker)) {
        return false;
    }

    if (containingFunc->ReturnTypeAnnotation() != nullptr) {
        if (containingFunc->IsAsyncFunc()) {
            auto *promiseType = containingFunc->ReturnTypeAnnotation()->GetType(checker);
            if (!promiseType->IsETSObjectType() || promiseType->AsETSObjectType()->TypeArguments().size() != 1) {
                return false;
            }
            funcReturnType = checker->CreateETSAsyncFuncReturnTypeFromPromiseType(promiseType->AsETSObjectType());
        } else {
            funcReturnType = containingFunc->ReturnTypeAnnotation()->GetType(checker);
        }
    } else {
        funcReturnType = containingFunc->GetPreferredReturnType();
    }

    // Case when function's return type is defined explicitly:
    if (st->argument_ == nullptr) {
        if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalVoidType() &&
            !funcReturnType->IsETSAsyncFuncReturnType()) {
            checker->LogError(diagnostic::RETURN_WITHOUT_VALUE, {}, st->Start());
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
        return CheckReturnType(checker, funcReturnType, argumentType, st->argument_, containingFunc);
    }
    return true;
}

checker::Type *ETSAnalyzer::GetFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc) const
{
    ES2PANDA_ASSERT(containingFunc->ReturnTypeAnnotation() != nullptr ||
                    containingFunc->Signature()->ReturnType() != nullptr ||
                    containingFunc->GetPreferredReturnType() != nullptr);

    ETSChecker *checker = GetETSChecker();
    checker::Type *funcReturnType = nullptr;

    if (auto *const returnTypeAnnotation = containingFunc->ReturnTypeAnnotation();
        returnTypeAnnotation != nullptr || containingFunc->GetPreferredReturnType() != nullptr) {
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
    ES2PANDA_ASSERT(ancestor && ancestor->IsScriptFunction());

    auto *containingFunc = ancestor->AsScriptFunction();
    containingFunc->AddFlag(ir::ScriptFunctionFlags::HAS_RETURN);

    if (containingFunc->Signature() == nullptr) {
        ES2PANDA_ASSERT(checker->IsAnyError());
        return ReturnTypeForStatement(st);
    }

    checker->AddStatus(CheckerStatus::MEET_RETURN);

    if (containingFunc->IsConstructor()) {
        if (st->argument_ != nullptr) {
            checker->LogError(diagnostic::NON_VOID_RETURN_IN_CONSTRUCTOR, {}, st->Start());
            return checker->GlobalTypeError();
        }
        return ReturnTypeForStatement(st);
    }

    st->returnType_ = GetFunctionReturnType(st, containingFunc);

    if (containingFunc->ReturnTypeAnnotation() == nullptr) {
        containingFunc->AddReturnStatement(st);
    }

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::SwitchStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(checker->Relation(),
                                                                    checker::TypeRelationFlag::NONE);

    auto *comparedExprType = checker->CheckSwitchDiscriminant(st->Discriminant());
    auto unboxedDiscType = (st->Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
                               ? checker->MaybeUnboxInRelation(comparedExprType)
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
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::ThrowStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker::Type *argType = st->argument_->Check(checker); !argType->IsTypeError()) {
        checker->CheckExceptionOrErrorType(argType, st->Start());
    }

    checker->AddStatus(CheckerStatus::MEET_THROW);
    return ReturnTypeForStatement(st);
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
            checker->LogError(diagnostic::CATCH_DEFAULT_NOT_LAST, {}, catchClause->Start());
            return checker->GlobalTypeError();
        }

        checker->Context().RestoreSmartCasts(smartCasts);

        if (auto const exceptionType = catchClause->Check(checker); !exceptionType->IsTypeError()) {
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

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    ES2PANDA_ASSERT(st->Id()->IsIdentifier());
    auto *const ident = st->Id()->AsIdentifier();
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (ident->Parent()->Parent()->AsVariableDeclaration()->Kind() ==
        ir::VariableDeclaration::VariableDeclarationKind::CONST) {
        flags |= ir::ModifierFlags::CONST;
    }

    if (ident->IsOptionalDeclaration()) {
        flags |= ir::ModifierFlags::OPTIONAL;
    }

    // Processing possible parser errors
    if (ident->Variable() == nullptr) {
        ident->Check(checker);
    }
    auto *const variableType = checker->CheckVariableDeclaration(ident, ident->TypeAnnotation(), st->Init(), flags);

    //  Now try to define the actual type of Identifier so that smart cast can be used in further checker processing
    //  NOTE: T_S and K_o_t_l_i_n don't act in such way, but we can try - why not? :)
    auto *smartType = variableType;
    if (auto *const initType = st->Init() != nullptr ? st->Init()->TsType() : nullptr; initType != nullptr) {
        smartType = checker->ResolveSmartType(initType, variableType);
        //  Set smart type for identifier if it differs from annotated type
        //  Top-level and captured variables are not processed here!
        if (!checker->Relation()->IsIdenticalTo(variableType, smartType)) {
            ident->SetTsType(smartType);
            checker->Context().SetSmartCast(ident->Variable(), smartType);
        }
    }

    return st->SetTsType(smartType);
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();

    checker->CheckAnnotations(st->Annotations());

    for (auto *it : st->Declarators()) {
        it->Check(checker);
    }

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::WhileStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    // Invalidate smart cast for variables in the test condition, that will be reassigned in the loop body
    const auto reassignedVars = checker->Context().GetReassignedVariablesInNode(st->Body());
    for (const auto &[var, _] : reassignedVars) {
        checker->Context().RemoveSmartCast(var);
    }

    SmartCastArray savedSmartCasts = checker->Context().EnterTestExpression();
    checker->CheckTruthinessOfType(st->Test());
    SmartCastTypes testedTypes = checker->Context().ExitTestExpression();
    if (testedTypes.has_value()) {
        for (auto [variable, consequentType, _] : *testedTypes) {
            checker->ApplySmartCast(variable, consequentType);
        }
    }

    auto [smartCasts, clearFlag] = checker->Context().EnterLoop(*st, testedTypes);
    st->Body()->Check(checker);
    checker->Context().ExitLoop(savedSmartCasts, clearFlag, st);
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::TSArrayType *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckAnnotations(node->Annotations());
    node->elementType_->Check(checker);
    node->SetTsType(node->GetType(checker));

    const auto *arrayType = node->TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    return node->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker->CheckAnnotations(expr->TypeAnnotation()->Annotations());
    auto *const targetType = expr->TypeAnnotation()->AsTypeNode()->GetType(checker);
    if (targetType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }

    ETSChecker::SetPreferredTypeIfPossible(expr->Expr(), targetType);

    auto const sourceType = expr->Expr()->Check(checker);
    if (sourceType->IsTypeError()) {
        return checker->InvalidateType(expr);
    }

    // NOTE(vpukhov): #20510 lowering
    if (targetType->IsETSPrimitiveType() && sourceType->IsETSReferenceType()) {
        auto *const boxedTargetType = checker->MaybeBoxInRelation(targetType);
        if (!checker->Relation()->IsIdenticalTo(sourceType, boxedTargetType)) {
            expr->Expr()->AddAstNodeFlags(ir::AstNodeFlags::CHECKCAST);
        }
    }

    if (sourceType->DefinitelyETSNullish() && !targetType->PossiblyETSNullish()) {
        return checker->TypeError(expr, diagnostic::NULLISH_CAST_TO_NONNULLISH, expr->Start());
    }

    const checker::CastingContext ctx(
        checker->Relation(), diagnostic::INVALID_CAST, {sourceType, targetType},
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
        const auto *const targetArrayType = targetType->AsETSArrayType();
        checker->CreateBuiltinArraySignature(targetArrayType, targetArrayType->Rank());
    }

    if (targetType == checker->GetGlobalTypesHolder()->GlobalETSNeverType()) {
        return checker->TypeError(expr, diagnostic::CAST_TO_NEVER, expr->Start());
    }

    checker->ComputeApparentType(targetType);
    expr->SetTsType(targetType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TSEnumDeclaration *st) const
{
    // Some invalid TSEnumDeclaration will not be transformed to class.
    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    ETSChecker *checker = GetETSChecker();
    auto *stmtType = checker->BuildBasicInterfaceProperties(st);
    ES2PANDA_ASSERT(stmtType != nullptr);

    if (stmtType->IsTypeError()) {
        return st->SetTsType(stmtType);
    }

    auto *interfaceType = stmtType->AsETSObjectType();
    checker->CheckInterfaceAnnotations(st);

    interfaceType->SetSuperType(checker->GlobalETSObjectType());
    checker->CheckInvokeMethodsLegitimacy(interfaceType);

    st->SetTsType(interfaceType);

    checker::ScopeContext scopeCtx(checker, st->Scope());
    auto savedContext = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_INTERFACE, interfaceType);

    for (auto *it : st->Body()->Body()) {
        it->Check(checker);
    }
    return st->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::TSNonNullExpression *expr) const
{
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    ETSChecker *checker = GetETSChecker();
    auto exprType = expr->expr_->Check(checker);
    //  If the actual [smart] type is definitely 'null' or 'undefined' then probably CTE should be thrown.
    //  Anyway we'll definitely obtain NullPointerError at runtime.
    if (exprType->DefinitelyETSNullish()) {
        checker->ReportWarning(
            {"Bad operand type, the operand of the non-nullish expression is 'null' or 'undefined'."},
            expr->Expr()->Start());

        if (expr->expr_->IsIdentifier()) {
            ES2PANDA_ASSERT(expr->expr_->AsIdentifier()->Variable() != nullptr);
            auto originalType = expr->expr_->AsIdentifier()->Variable()->TsType();
            if (originalType != nullptr) {
                expr->SetTsType(checker->GetNonNullishType(originalType));
            }
        }
    }

    if (expr->TsType() == nullptr) {
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
        // clang-format off
        auto searchName = expr->Right()->Name();
        // clang-format on
        // NOTE (oeotvos) This should be done differently in the follow-up patch.
        if (searchName.Empty()) {
            searchName = expr->Right()->Name();
        }
        varbinder::Variable *prop =
            baseType->AsETSObjectType()->GetProperty(searchName, checker::PropertySearchFlags::SEARCH_DECL);
        // NOTE(dslynko): in debugger evaluation mode must lazily generate module's properties here.
        if (prop == nullptr) {
            checker->LogError(diagnostic::NONEXISTENT_TYPE, {expr->Right()->Name()}, expr->Right()->Start());
            return checker->GlobalTypeError();
        }

        checker->ValidateNamespaceProperty(prop, baseType->AsETSObjectType(), expr->Right());
        expr->Right()->SetVariable(prop);
        return checker->GetTypeOfVariable(prop);
    }

    checker->LogError(diagnostic::NONEXISTENT_TYPE, {expr->Right()->Name()}, expr->Right()->Start());
    return checker->GlobalTypeError();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();

    checker->CheckAnnotations(st->Annotations());

    if (st->TypeParams() == nullptr) {
        const checker::SavedTypeRelationFlagsContext savedFlagsCtx(
            checker->Relation(), checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

        if (st->TypeAnnotation()->TsType() == nullptr) {
            st->TypeAnnotation()->Check(checker);
        }

        return ReturnTypeForStatement(st);
    }

    if (st->TypeParameterTypes().empty()) {
        auto [typeParamTypes, ok] = checker->CreateUnconstrainedTypeParameters(st->TypeParams());
        st->SetTypeParameterTypes(std::move(typeParamTypes));
        if (ok) {
            checker->AssignTypeParameterConstraints(st->TypeParams());
        }
    }

    const checker::SavedTypeRelationFlagsContext savedFlagsCtx(checker->Relation(),
                                                               checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

    if (st->TypeAnnotation()->TsType() == nullptr) {
        st->TypeAnnotation()->Check(checker);
    }

    return ReturnTypeForStatement(st);
}

checker::Type *ETSAnalyzer::ReturnTypeForStatement([[maybe_unused]] const ir::Statement *const st) const
{
    ES2PANDA_ASSERT(st->IsStatement());
    return nullptr;
}

}  // namespace ark::es2panda::checker
