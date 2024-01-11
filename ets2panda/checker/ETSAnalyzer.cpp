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

#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "util/helpers.h"

#include <memory>

namespace panda::es2panda::checker {

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
        checker->BuildClassProperties(node);
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

static void CheckExtensionIsShadowedInCurrentClassOrInterface(checker::ETSChecker *checker,
                                                              checker::ETSObjectType *objType,
                                                              ir::ScriptFunction *extensionFunc,
                                                              checker::Signature *signature)
{
    const auto methodName = extensionFunc->Id()->Name();
    // Only check if there are class and interfaces' instance methods which would shadow instance extension method
    auto *const variable = objType->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(methodName);
    if (variable == nullptr) {
        return;
    }

    const auto *const funcType = variable->TsType()->AsETSFunctionType();
    for (auto *funcSignature : funcType->CallSignatures()) {
        signature->SetReturnType(funcSignature->ReturnType());
        if (!checker->Relation()->IsIdenticalTo(signature, funcSignature)) {
            continue;
        }

        checker->ReportWarning({"extension is shadowed by a instance member function '", funcType->Name(),
                                funcSignature, "' in class ", objType->Name()},
                               extensionFunc->Body()->Start());
        return;
    }
}

static void CheckExtensionIsShadowedByMethod(checker::ETSChecker *checker, checker::ETSObjectType *objType,
                                             ir::ScriptFunction *extensionFunc, checker::Signature *signature)
{
    if (objType == nullptr) {
        return;
    }

    CheckExtensionIsShadowedInCurrentClassOrInterface(checker, objType, extensionFunc, signature);

    for (auto *interface : objType->Interfaces()) {
        CheckExtensionIsShadowedByMethod(checker, interface, extensionFunc, signature);
    }

    CheckExtensionIsShadowedByMethod(checker, objType->SuperType(), extensionFunc, signature);
}

static void CheckExtensionMethod(checker::ETSChecker *checker, ir::ScriptFunction *extensionFunc,
                                 ir::MethodDefinition *node)
{
    auto *const classType = ETSChecker::GetApparentType(extensionFunc->Signature()->Params()[0]->TsType());
    if (!classType->IsETSObjectType() ||
        (!classType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::CLASS) &&
         !classType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::INTERFACE))) {
        checker->ThrowTypeError("Extension function can only defined for class and interface type.", node->Start());
    }

    checker->AddStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD);

    checker::SignatureInfo *originalExtensionSigInfo = checker->Allocator()->New<checker::SignatureInfo>(
        extensionFunc->Signature()->GetSignatureInfo(), checker->Allocator());
    originalExtensionSigInfo->minArgCount -= 1;
    originalExtensionSigInfo->params.erase(originalExtensionSigInfo->params.begin());
    checker::Signature *originalExtensionSigature =
        checker->CreateSignature(originalExtensionSigInfo, extensionFunc->Signature()->ReturnType(), extensionFunc);

    CheckExtensionIsShadowedByMethod(checker, classType->AsETSObjectType(), extensionFunc, originalExtensionSigature);
}

void DoBodyTypeChecking(ETSChecker *checker, ir::MethodDefinition *node, ir::ScriptFunction *scriptFunc)
{
    if (scriptFunc->HasBody() && (node->IsNative() || node->IsAbstract() || node->IsDeclare())) {
        checker->ThrowTypeError("Native, Abstract and Declare methods cannot have body.", scriptFunc->Body()->Start());
    }

    if (scriptFunc->IsAsyncFunc()) {
        auto *retType = static_cast<checker::ETSObjectType *>(scriptFunc->Signature()->ReturnType());
        if (retType->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async function must be 'Promise'.", scriptFunc->Start());
        }
    } else if (scriptFunc->HasBody() && !scriptFunc->IsExternal()) {
        checker::ScopeContext scopeCtx(checker, scriptFunc->Scope());
        checker::SavedCheckerContext savedContext(checker, checker->Context().Status(),
                                                  checker->Context().ContainingClass());
        checker->Context().SetContainingSignature(checker->GetSignatureFromMethodDefinition(node));

        if (node->IsStatic() && !node->IsConstructor() &&
            !checker->Context().ContainingClass()->HasObjectFlag(checker::ETSObjectFlags::GLOBAL)) {
            checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
        }

        if (node->IsConstructor()) {
            checker->AddStatus(checker::CheckerStatus::IN_CONSTRUCTOR);
        }

        if (node->IsExtensionMethod()) {
            CheckExtensionMethod(checker, scriptFunc, node);
        }

        scriptFunc->Body()->Check(checker);

        // In case of inferred function's return type set it forcedly to all return statements;
        if (scriptFunc->Signature()->HasSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE) &&
            scriptFunc->ReturnTypeAnnotation() == nullptr && scriptFunc->Body() != nullptr &&
            scriptFunc->Body()->IsStatement()) {
            scriptFunc->Body()->AsStatement()->SetReturnType(checker, scriptFunc->Signature()->ReturnType());
        }

        checker->Context().SetContainingSignature(nullptr);
    }
}

void CheckGetterSetterTypeConstrains(ETSChecker *checker, ir::ScriptFunction *scriptFunc)
{
    if (scriptFunc->IsSetter() && (scriptFunc->Signature()->ReturnType() != checker->GlobalBuiltinVoidType())) {
        checker->ThrowTypeError("Setter must have void return type", scriptFunc->Start());
    }

    if (scriptFunc->IsGetter() && (scriptFunc->Signature()->ReturnType() == checker->GlobalBuiltinVoidType())) {
        checker->ThrowTypeError("Getter must return a value", scriptFunc->Start());
    }

    auto const name = scriptFunc->Id()->Name();
    if (name.Is(compiler::Signatures::GET_INDEX_METHOD)) {
        if (scriptFunc->Signature()->ReturnType() == checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError(std::string {ir::INDEX_ACCESS_ERROR_1} + std::string {name.Utf8()} +
                                        std::string {"' shouldn't have void return type."},
                                    scriptFunc->Start());
        }
    } else if (name.Is(compiler::Signatures::SET_INDEX_METHOD)) {
        if (scriptFunc->Signature()->ReturnType() != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError(std::string {ir::INDEX_ACCESS_ERROR_1} + std::string {name.Utf8()} +
                                        std::string {"' should have void return type."},
                                    scriptFunc->Start());
        }
    }
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto *scriptFunc = node->Function();
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

    if (node->IsNative() && scriptFunc->ReturnTypeAnnotation() == nullptr) {
        checker->ThrowTypeError("'Native' method should have explicit return type", scriptFunc->Start());
    }

    if (node->IsNative() && (scriptFunc->IsGetter() || scriptFunc->IsSetter())) {
        checker->ThrowTypeError("'Native' modifier is invalid for Accessors", scriptFunc->Start());
    }

    DoBodyTypeChecking(checker, node, scriptFunc);
    CheckGetterSetterTypeConstrains(checker, scriptFunc);

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
    checker->CreateFunctionalInterfaceForFunctionType(node);
    auto *interfaceType =
        checker->CreateETSObjectType(node->FunctionalInterface()->Id()->Name(), node->FunctionalInterface(),
                                     checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    interfaceType->SetSuperType(checker->GlobalETSObjectType());

    auto *invokeFunc = node->FunctionalInterface()->Body()->Body()[0]->AsMethodDefinition()->Function();
    auto *signatureInfo = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());

    for (auto *it : invokeFunc->Params()) {
        auto *const param = it->AsETSParameterExpression();
        if (param->IsRestParameter()) {
            auto *restIdent = param->Ident();

            ASSERT(restIdent->Variable());
            signatureInfo->restVar = restIdent->Variable()->AsLocalVariable();

            ASSERT(param->TypeAnnotation());
            signatureInfo->restVar->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));

            auto arrayType = signatureInfo->restVar->TsType()->AsETSArrayType();
            checker->CreateBuiltinArraySignature(arrayType, arrayType->Rank());
        } else {
            auto *paramIdent = param->Ident();

            ASSERT(paramIdent->Variable());
            varbinder::Variable *paramVar = paramIdent->Variable();

            ASSERT(param->TypeAnnotation());
            paramVar->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));
            signatureInfo->params.push_back(paramVar->AsLocalVariable());
            ++signatureInfo->minArgCount;
        }
    }

    invokeFunc->ReturnTypeAnnotation()->Check(checker);
    auto *signature =
        checker->Allocator()->New<checker::Signature>(signatureInfo, node->ReturnType()->GetType(checker), invokeFunc);
    signature->SetOwnerVar(invokeFunc->Id()->Variable()->AsLocalVariable());
    signature->AddSignatureFlag(checker::SignatureFlags::FUNCTIONAL_INTERFACE_SIGNATURE);
    signature->SetOwner(interfaceType);

    auto *funcType = checker->CreateETSFunctionType(signature);
    invokeFunc->SetSignature(signature);
    invokeFunc->Id()->Variable()->SetTsType(funcType);
    interfaceType->AddProperty<checker::PropertyType::INSTANCE_METHOD>(invokeFunc->Id()->Variable()->AsLocalVariable());
    node->FunctionalInterface()->SetTsType(interfaceType);

    auto *thisVar = invokeFunc->Scope()->ParamScope()->Params().front();
    thisVar->SetTsType(interfaceType);
    checker->BuildFunctionalInterfaceName(node);

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

    auto *elementType = expr->typeReference_->GetType(checker);
    checker->ValidateArrayIndex(expr->dimension_, true);

    if (!elementType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) && !elementType->IsNullish() &&
        elementType->ToAssemblerName().str() != "Ball") {
        // Ball is workaround for koala ui lib
        if (elementType->IsETSObjectType()) {
            auto *calleeObj = elementType->AsETSObjectType();
            if (!calleeObj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
                // A workaround check for new Interface[...] in test cases
                expr->defaultConstructorSignature_ =
                    checker->CollectParameterlessConstructor(calleeObj->ConstructSignatures(), expr->Start());
                checker->ValidateSignatureAccessibility(calleeObj, nullptr, expr->defaultConstructorSignature_,
                                                        expr->Start());
            }
        }
    }
    expr->SetTsType(checker->CreateETSArrayType(elementType));
    checker->CreateBuiltinArraySignature(expr->TsType()->AsETSArrayType(), 1);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *calleeType = expr->GetTypeRef()->Check(checker);

    if (!calleeType->IsETSObjectType()) {
        checker->ThrowTypeError("This expression is not constructible.", expr->Start());
    }

    auto *calleeObj = calleeType->AsETSObjectType();
    expr->SetTsType(calleeObj);

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

    if (calleeType->IsETSDynamicType() && !calleeType->AsETSDynamicType()->HasDecl()) {
        auto lang = calleeType->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->GetTypeRef(), expr->GetArguments(), lang, true));
    } else {
        auto *signature = checker->ResolveConstructExpression(calleeObj, expr->GetArguments(), expr->Start());

        checker->CheckObjectLiteralArguments(signature, expr->GetArguments());
        checker->AddUndefinedParamsForDefaultParams(signature, expr->arguments_, checker);

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
    auto *elementType = expr->typeReference_->GetType(checker);

    for (auto *dim : expr->dimensions_) {
        checker->ValidateArrayIndex(dim);
        elementType = checker->CreateETSArrayType(elementType);
    }

    expr->SetTsType(elementType);
    expr->signature_ = checker->CreateBuiltinArraySignature(elementType->AsETSArrayType(), expr->dimensions_.size());
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
                [[maybe_unused]] auto *const initType = expr->Initializer()->Check(checker);
            }
        }

        expr->SetTsType(paramType);
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSPrimitiveType *node) const
{
    return nullptr;
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
        auto *const targetElementType =
            isPreferredTuple && !isArray ? expr->preferredType_->AsETSTupleType()->ElementType() : expr->preferredType_;

        for (std::size_t idx = 0; idx < expr->elements_.size(); ++idx) {
            auto *const currentElement = expr->elements_[idx];

            if (currentElement->IsArrayExpression()) {
                expr->HandleNestedArrayExpression(checker, currentElement->AsArrayExpression(), isArray,
                                                  isPreferredTuple, idx);
            }

            if (currentElement->IsObjectExpression()) {
                currentElement->AsObjectExpression()->SetPreferredType(expr->preferredType_);
            }

            checker::Type *elementType = currentElement->Check(checker);

            if (!elementType->IsETSArrayType() && isPreferredTuple) {
                auto *const compareType = expr->preferredType_->AsETSTupleType()->GetTypeAtIndex(idx);

                if (compareType == nullptr) {
                    checker->ThrowTypeError(
                        {"Too many elements in array initializer for tuple with size of ",
                         static_cast<uint32_t>(expr->preferredType_->AsETSTupleType()->GetTupleSize())},
                        currentElement->Start());
                }

                checker::AssignmentContext(
                    checker->Relation(), currentElement, elementType, compareType, currentElement->Start(),
                    {"Array initializer's type is not assignable to tuple type at index: ", idx});

                elementType = compareType;
            }

            checker::AssignmentContext(checker->Relation(), currentElement, elementType, targetElementType,
                                       currentElement->Start(),
                                       {"Array element type '", elementType, "' is not assignable to explicit type '",
                                        expr->GetPreferredType(), "'"});
        }

        expr->SetPreferredType(targetElementType);
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
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *funcType = checker->BuildFunctionSignature(expr->Function(), false);

    if (expr->Function()->IsAsyncFunc()) {
        auto *retType = static_cast<checker::ETSObjectType *>(expr->Function()->Signature()->ReturnType());
        if (retType->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
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

    expr->Function()->Body()->Check(checker);

    checker->Context().SetContainingSignature(nullptr);
    checker->CheckCapturedVariables();

    for (auto [var, _] : checker->Context().CapturedVars()) {
        (void)_;
        expr->CapturedVars().push_back(var);
    }

    expr->SetTsType(funcType);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::AssignmentExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *leftType = expr->Left()->Check(checker);
    if (expr->Left()->IsMemberExpression() &&
        expr->Left()->AsMemberExpression()->Object()->TsType()->IsETSArrayType() &&
        expr->Left()->AsMemberExpression()->Property()->IsIdentifier() &&
        expr->Left()->AsMemberExpression()->Property()->AsIdentifier()->Name().Is("length")) {
        checker->ThrowTypeError("Setting the length of an array is not permitted", expr->Left()->Start());
    }

    if (expr->Left()->IsIdentifier()) {
        expr->target_ = expr->Left()->AsIdentifier()->Variable();
    } else {
        expr->target_ = expr->Left()->AsMemberExpression()->PropVar();
    }

    if (expr->target_ != nullptr) {
        checker->ValidateUnaryOperatorOperand(expr->target_);
    }

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

    checker::AssignmentContext(checker->Relation(), relationNode, sourceType, leftType, expr->Right()->Start(),
                               {"Initializers type is not assignable to the target type"});

    expr->SetTsType(expr->Left()->TsType());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::AwaitExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker::Type *argType = ETSChecker::GetApparentType(expr->argument_->Check(checker));
    // Check the argument type of await expression
    if (!argType->IsETSObjectType() ||
        (argType->AsETSObjectType()->AssemblerName() != compiler::Signatures::BUILTIN_PROMISE)) {
        checker->ThrowTypeError("'await' expressions require Promise object as argument.", expr->Argument()->Start());
    }

    expr->SetTsType(argType->AsETSObjectType()->TypeArguments().at(0));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    checker::Type *newTsType {nullptr};
    std::tie(newTsType, expr->operationType_) =
        checker->CheckBinaryOperator(expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start());
    expr->SetTsType(newTsType);
    return expr->TsType();
}

static checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, ir::Expression *callee,
                                                checker::Type *calleeType)
{
    auto *const arrowFunc = callee->AsArrowFunctionExpression()->Function();
    auto origParams = arrowFunc->Params();
    auto signature = ir::FunctionSignature(nullptr, std::move(origParams), arrowFunc->ReturnTypeAnnotation());
    auto *funcType =
        checker->Allocator()->New<ir::ETSFunctionType>(std::move(signature), ir::ScriptFunctionFlags::NONE);
    funcType->SetScope(arrowFunc->Scope()->AsFunctionScope()->ParamScope());
    auto *const funcIface = funcType->Check(checker);
    checker->Relation()->SetNode(callee);
    checker->Relation()->IsAssignableTo(calleeType, funcIface);
    return funcIface;
}

static checker::Signature *ResolveCallExtensionFunction(checker::ETSFunctionType *functionType,
                                                        checker::ETSChecker *checker, ir::CallExpression *expr)
{
    auto *memberExpr = expr->Callee()->AsMemberExpression();
    expr->Arguments().insert(expr->Arguments().begin(), memberExpr->Object());
    auto *signature =
        checker->ResolveCallExpressionAndTrailingLambda(functionType->CallSignatures(), expr, expr->Start());
    if (!signature->Function()->IsExtensionMethod()) {
        checker->ThrowTypeError({"Property '", memberExpr->Property()->AsIdentifier()->Name(),
                                 "' does not exist on type '", memberExpr->ObjType()->Name(), "'"},
                                memberExpr->Property()->Start());
    }
    expr->SetSignature(signature);
    expr->SetCallee(memberExpr->Property());
    memberExpr->Property()->AsIdentifier()->SetParent(expr);
    expr->Arguments()[0]->SetParent(expr);
    checker->HandleUpdatedCallExpressionNode(expr);
    // Set TsType for new Callee(original member expression's Object)
    expr->Callee()->Check(checker);
    return signature;
}

static checker::Signature *ResolveCallForETSExtensionFuncHelperType(checker::ETSExtensionFuncHelperType *type,
                                                                    checker::ETSChecker *checker,
                                                                    ir::CallExpression *expr)
{
    checker::Signature *signature = checker->ResolveCallExpressionAndTrailingLambda(
        type->ClassMethodType()->CallSignatures(), expr, expr->Start(), checker::TypeRelationFlag::NO_THROW);

    if (signature != nullptr) {
        return signature;
    }

    return ResolveCallExtensionFunction(type->ExtensionMethodType(), checker, expr);
}

checker::Type *ETSAnalyzer::Check(ir::BlockExpression *st) const
{
    (void)st;
    UNREACHABLE();
}

ArenaVector<checker::Signature *> GetUnionTypeSignatures(ETSChecker *checker, checker::ETSUnionType *etsUnionType)
{
    ArenaVector<checker::Signature *> callSignatures(checker->Allocator()->Adapter());

    for (auto *constituentType : etsUnionType->ConstituentTypes()) {
        if (constituentType->IsETSObjectType()) {
            ArenaVector<checker::Signature *> tmpCallSignatures(checker->Allocator()->Adapter());
            tmpCallSignatures = constituentType->AsETSObjectType()
                                    ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke")
                                    ->TsType()
                                    ->AsETSFunctionType()
                                    ->CallSignatures();
            callSignatures.insert(callSignatures.end(), tmpCallSignatures.begin(), tmpCallSignatures.end());
        }
        if (constituentType->IsETSFunctionType()) {
            ArenaVector<checker::Signature *> tmpCallSignatures(checker->Allocator()->Adapter());
            tmpCallSignatures = constituentType->AsETSFunctionType()->CallSignatures();
            callSignatures.insert(callSignatures.end(), tmpCallSignatures.begin(), tmpCallSignatures.end());
        }
        if (constituentType->IsETSUnionType()) {
            ArenaVector<checker::Signature *> tmpCallSignatures(checker->Allocator()->Adapter());
            tmpCallSignatures = GetUnionTypeSignatures(checker, constituentType->AsETSUnionType());
            callSignatures.insert(callSignatures.end(), tmpCallSignatures.begin(), tmpCallSignatures.end());
        }
    }

    return callSignatures;
}

ArenaVector<checker::Signature *> &ChooseSignatures(ETSChecker *checker, checker::Type *calleeType,
                                                    bool isConstructorCall, bool isFunctionalInterface,
                                                    bool isUnionTypeWithFunctionalInterface)
{
    static ArenaVector<checker::Signature *> unionSignatures(checker->Allocator()->Adapter());
    unionSignatures.clear();
    if (isConstructorCall) {
        return calleeType->AsETSObjectType()->ConstructSignatures();
    }
    if (isFunctionalInterface) {
        return calleeType->AsETSObjectType()
            ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke")
            ->TsType()
            ->AsETSFunctionType()
            ->CallSignatures();
    }
    if (isUnionTypeWithFunctionalInterface) {
        unionSignatures = GetUnionTypeSignatures(checker, calleeType->AsETSUnionType());
        return unionSignatures;
    }
    return calleeType->AsETSFunctionType()->CallSignatures();
}

checker::ETSObjectType *ChooseCalleeObj(ETSChecker *checker, ir::CallExpression *expr, checker::Type *calleeType,
                                        bool isConstructorCall)
{
    if (isConstructorCall) {
        return calleeType->AsETSObjectType();
    }
    if (expr->Callee()->IsIdentifier()) {
        return checker->Context().ContainingClass();
    }
    ASSERT(expr->Callee()->IsMemberExpression());
    return expr->Callee()->AsMemberExpression()->ObjType();
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
    checker->AddUndefinedParamsForDefaultParams(signature, expr->Arguments(), checker);

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
    auto *oldCallee = expr->Callee();
    checker::Type *calleeType = ETSChecker::GetApparentType(expr->Callee()->Check(checker));
    if (expr->Callee() != oldCallee) {
        // If it is a static invoke, the callee will be transformed from an identifier to a member expression
        // Type check the callee again for member expression
        calleeType = expr->Callee()->Check(checker);
    }
    if (!expr->IsOptional()) {
        checker->CheckNonNullishType(calleeType, expr->Callee()->Start());
    }
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
    expr->SetOptionalType(returnType);
    if (expr->IsOptional() && checker->MayHaveNulllikeValue(expr->Callee()->Check(checker))) {
        checker->Relation()->SetNode(expr);
        returnType = checker->CreateOptionalResultType(returnType);
        checker->Relation()->SetNode(nullptr);
    }
    expr->SetTsType(returnType);
    expr->SetUncheckedType(checker->GuaranteedTypeForUncheckedCallReturn(expr->Signature()));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ChainExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker->CheckTruthinessOfType(expr->Test());

    checker::Type *consequentType = expr->consequent_->Check(checker);
    checker::Type *alternateType = expr->alternate_->Check(checker);

    auto *primitiveConsequentType = checker->ETSBuiltinTypeAsPrimitiveType(consequentType);
    auto *primitiveAlterType = checker->ETSBuiltinTypeAsPrimitiveType(alternateType);

    if (primitiveConsequentType != nullptr && primitiveAlterType != nullptr) {
        if (checker->IsTypeIdenticalTo(consequentType, alternateType)) {
            expr->SetTsType(checker->GetNonConstantTypeFromPrimitiveType(consequentType));
        } else if (checker->IsTypeIdenticalTo(primitiveConsequentType, primitiveAlterType)) {
            checker->FlagExpressionWithUnboxing(expr->consequent_->TsType(), primitiveConsequentType,
                                                expr->consequent_);
            checker->FlagExpressionWithUnboxing(expr->alternate_->TsType(), primitiveAlterType, expr->alternate_);

            expr->SetTsType(primitiveConsequentType);
        } else if (primitiveConsequentType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) &&
                   primitiveAlterType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
            checker->FlagExpressionWithUnboxing(expr->consequent_->TsType(), primitiveConsequentType,
                                                expr->consequent_);
            checker->FlagExpressionWithUnboxing(expr->alternate_->TsType(), primitiveAlterType, expr->alternate_);

            expr->SetTsType(
                checker->ApplyConditionalOperatorPromotion(checker, primitiveConsequentType, primitiveAlterType));
        } else {
            checker->ThrowTypeError("Type error", expr->Range().start);
        }
    } else {
        if (!(consequentType->IsETSArrayType() || alternateType->IsETSArrayType()) &&
            !(checker->IsReferenceType(consequentType) && checker->IsReferenceType(alternateType))) {
            checker->ThrowTypeError("Type error", expr->Range().start);
        } else {
            checker->Relation()->SetNode(expr->consequent_);
            auto builtinConseqType = checker->PrimitiveTypeAsETSBuiltinType(consequentType);
            auto builtinAlternateType = checker->PrimitiveTypeAsETSBuiltinType(alternateType);

            if (builtinConseqType == nullptr) {
                builtinConseqType = consequentType;
            }

            if (builtinAlternateType == nullptr) {
                builtinAlternateType = alternateType;
            }

            expr->SetTsType(checker->CreateETSUnionType(builtinConseqType, builtinAlternateType));
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
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    expr->SetTsType(checker->ResolveIdentifier(expr));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::MemberExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *const leftType = checker->GetApparentType(expr->Object()->Check(checker));

    if (expr->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
        if (expr->IsOptional() && !leftType->IsNullish()) {
            checker->ThrowTypeError("The type of the object reference must be a nullish array or Record type",
                                    expr->Object()->Start());
        }

        if (!expr->IsOptional() && leftType->IsNullish()) {
            checker->ThrowTypeError("The type of the object reference must be a non-nullish array or Record type",
                                    expr->Object()->Start());
        }
    }

    auto *const baseType = expr->IsOptional() ? checker->GetNonNullishType(leftType) : leftType;
    if (!expr->IsOptional()) {
        checker->CheckNonNullishType(leftType, expr->Object()->Start());
    }

    if (expr->IsComputed()) {
        return expr->AdjustType(checker, expr->CheckComputed(checker, baseType));
    }

    if (baseType->IsETSArrayType() && expr->Property()->AsIdentifier()->Name().Is("length")) {
        return expr->AdjustType(checker, checker->GlobalIntType());
    }

    if (baseType->IsETSObjectType()) {
        expr->SetObjectType(baseType->AsETSObjectType());
        auto [resType, resVar] = expr->ResolveObjectMember(checker);
        expr->SetPropVar(resVar);
        return expr->AdjustType(checker, resType);
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
        checker->Relation()->SetNode(expr);
        expr->SetObjectType(checker->PrimitiveTypeAsETSBuiltinType(baseType)->AsETSObjectType());
        checker->AddBoxingUnboxingFlagsToNode(expr, expr->ObjType());
        auto [resType, resVar] = expr->ResolveObjectMember(checker);
        expr->SetPropVar(resVar);
        return expr->AdjustType(checker, resType);
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
        checker->ThrowTypeError({"target type for class composite needs to be an object type"}, expr->Start());
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
        varbinder::LocalVariable *lv = objType->GetProperty(pname, checker::PropertySearchFlags::SEARCH_INSTANCE_FIELD |
                                                                       checker::PropertySearchFlags::SEARCH_IN_BASE);
        if (lv == nullptr) {
            checker->ThrowTypeError({"type ", objType->Name(), " has no property named ", pname}, propExpr->Start());
        }
        checker->ValidatePropertyAccess(lv, objType, propExpr->Start());
        if (lv->HasFlag(varbinder::VariableFlags::READONLY)) {
            checker->ThrowTypeError({"cannot assign to readonly property ", pname}, propExpr->Start());
        }

        auto *propType = checker->GetTypeOfVariable(lv);
        key->SetTsType(propType);

        if (value->IsObjectExpression()) {
            value->AsObjectExpression()->SetPreferredType(propType);
        }
        value->SetTsType(value->Check(checker));
        checker::AssignmentContext(checker->Relation(), value, value->TsType(), propType, value->Start(),
                                   {"value type is not assignable to the property type"});
    }

    expr->SetTsType(objType);
    return objType;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::OmittedExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::OpaqueTypeNode *expr) const
{
    UNREACHABLE();
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
    parameter(MANDATORY_PARAM_THIS), and capture the paramter's variable other than containing class's variable
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

void ProcessExclamationMark(ETSChecker *checker, ir::UnaryExpression *expr, checker::Type *operandType)
{
    if (checker->IsNullLikeOrVoidExpression(expr->Argument())) {
        auto tsType = checker->CreateETSBooleanType(true);
        tsType->AddTypeFlag(checker::TypeFlag::CONSTANT);
        expr->SetTsType(tsType);
        return;
    }

    if (operandType == nullptr || !operandType->IsConditionalExprType()) {
        checker->ThrowTypeError("Bad operand type, the type of the operand must be boolean type.",
                                expr->Argument()->Start());
    }

    auto exprRes = operandType->ResolveConditionExpr();
    if (std::get<0>(exprRes)) {
        auto tsType = checker->CreateETSBooleanType(!std::get<1>(exprRes));
        tsType->AddTypeFlag(checker::TypeFlag::CONSTANT);
        expr->SetTsType(tsType);
        return;
    }

    expr->SetTsType(checker->GlobalETSBooleanType());
}

void SetTsTypeForUnaryExpression(ETSChecker *checker, ir::UnaryExpression *expr, checker::Type *operandType,
                                 checker::Type *argType)
{
    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            if (operandType == nullptr || !operandType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                        expr->Argument()->Start());
            }

            if (operandType->HasTypeFlag(checker::TypeFlag::CONSTANT) &&
                expr->OperatorType() == lexer::TokenType::PUNCTUATOR_MINUS) {
                expr->SetTsType(checker->NegateNumericType(operandType, expr));
                break;
            }

            expr->SetTsType(operandType);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            if (operandType == nullptr || !operandType->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                        expr->Argument()->Start());
            }

            if (operandType->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                expr->SetTsType(checker->BitwiseNegateNumericType(operandType, expr));
                break;
            }

            expr->SetTsType(checker->SelectGlobalIntegerTypeForNumeric(operandType));
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            ProcessExclamationMark(checker, expr, operandType);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR: {
            expr->SetTsType(argType);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }
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

    SetTsTypeForUnaryExpression(checker, expr, operandType, argType);

    if ((argType != nullptr) && argType->IsETSObjectType() && (unboxedOperandType != nullptr) &&
        unboxedOperandType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        expr->Argument()->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedOperandType));
    }

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

checker::ETSObjectType *CreateSyntheticType(ETSChecker *checker, util::StringView const &syntheticName,
                                            checker::ETSObjectType *lastObjectType, ir::Identifier *id)
{
    auto *syntheticObjType = checker->Allocator()->New<checker::ETSObjectType>(
        checker->Allocator(), syntheticName, syntheticName, id, checker::ETSObjectFlags::NO_OPTS);

    auto *classDecl = checker->Allocator()->New<varbinder::ClassDecl>(syntheticName);
    varbinder::LocalVariable *var =
        checker->Allocator()->New<varbinder::LocalVariable>(classDecl, varbinder::VariableFlags::CLASS);
    var->SetTsType(syntheticObjType);
    lastObjectType->AddProperty<checker::PropertyType::STATIC_FIELD>(var);
    syntheticObjType->SetEnclosingType(lastObjectType);
    return syntheticObjType;
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
    auto importPath = importDecl->Source()->Str();

    if (importDecl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(importDecl->Language());
        checker->SetrModuleObjectTsType(st->Local(), type);
        return type;
    }

    std::string packageName =
        (importDecl->Module() == nullptr) ? importPath.Mutf8() : importDecl->Module()->Str().Mutf8();

    std::replace(packageName.begin(), packageName.end(), '/', '.');
    util::UString packagePath(packageName, checker->Allocator());
    std::vector<util::StringView> syntheticNames = checker->GetNameForSynteticObjectType(packagePath.View());

    ASSERT(!syntheticNames.empty());

    auto assemblerName = syntheticNames[0];
    if (importDecl->Module() != nullptr) {
        assemblerName = util::UString(assemblerName.Mutf8().append(".").append(compiler::Signatures::ETS_GLOBAL),
                                      checker->Allocator())
                            .View();
    }

    auto *moduleObjectType =
        checker->Allocator()->New<checker::ETSObjectType>(checker->Allocator(), syntheticNames[0], assemblerName,
                                                          st->Local()->AsIdentifier(), checker::ETSObjectFlags::CLASS);

    auto *rootDecl = checker->Allocator()->New<varbinder::ClassDecl>(syntheticNames[0]);
    varbinder::LocalVariable *rootVar =
        checker->Allocator()->New<varbinder::LocalVariable>(rootDecl, varbinder::VariableFlags::NONE);
    rootVar->SetTsType(moduleObjectType);

    syntheticNames.erase(syntheticNames.begin());
    checker::ETSObjectType *lastObjectType(moduleObjectType);

    for (const auto &syntheticName : syntheticNames) {
        lastObjectType = CreateSyntheticType(checker, syntheticName, lastObjectType, st->Local()->AsIdentifier());
    }

    checker->SetPropertiesForModuleObject(
        lastObjectType,
        (importDecl->Module() != nullptr)
            ? util::UString(importPath.Mutf8() + importDecl->Module()->Str().Mutf8(), checker->Allocator()).View()
            : importPath);
    checker->SetrModuleObjectTsType(st->Local(), lastObjectType);

    return moduleObjectType;
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

    for (auto *it : st->Statements()) {
        it->Check(checker);
    }

    for (auto [stmt, trailing_block] : st->trailingBlocks_) {
        auto iterator = std::find(st->Statements().begin(), st->Statements().end(), stmt);
        ASSERT(iterator != st->Statements().end());
        st->Statements().insert(iterator + 1, trailing_block);
        trailing_block->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::BreakStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->target_ = checker->FindJumpTarget(st->Type(), st, st->Ident());
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
    st->target_ = checker->FindJumpTarget(st->Type(), st, st->Ident());
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

    checker->CheckTruthinessOfType(st->Test());
    st->Body()->Check(checker);

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
static constexpr char const INVALID_SOURCE_EXPR_TYPE[] =
    "'For-of' statement source expression should be either a string or an array.";
static constexpr char const INVALID_CONST_ASSIGNMENT[] = "Cannot assign a value to a constant variable ";
static constexpr char const ITERATOR_TYPE_ABSENT[] = "Cannot obtain iterator type in 'for-of' statement.";
// NOLINTEND(modernize-avoid-c-arrays)

checker::Type *GetIteratorType(ETSChecker *checker, checker::Type *elemType, ir::AstNode *left)
{
    // Just to avoid extra nested level(s)
    auto const getIterType = [checker, elemType](ir::VariableDeclarator *const declarator) -> checker::Type * {
        if (declarator->TsType() == nullptr) {
            if (auto *resolved = checker->FindVariableInFunctionScope(declarator->Id()->AsIdentifier()->Name());
                resolved != nullptr) {
                resolved->SetTsType(elemType);
                return elemType;
            }
        } else {
            return declarator->TsType();
        }
        return nullptr;
    };

    checker::Type *iterType = nullptr;
    if (left->IsIdentifier()) {
        if (auto *const variable = left->AsIdentifier()->Variable(); variable != nullptr) {
            if (variable->Declaration()->IsConstDecl()) {
                checker->ThrowTypeError({INVALID_CONST_ASSIGNMENT, variable->Name()},
                                        variable->Declaration()->Node()->Start());
            }
        }
        iterType = left->AsIdentifier()->TsType();
    } else if (left->IsVariableDeclaration()) {
        if (auto const &declarators = left->AsVariableDeclaration()->Declarators(); !declarators.empty()) {
            iterType = getIterType(declarators.front());
        }
    }

    if (iterType == nullptr) {
        checker->ThrowTypeError(ITERATOR_TYPE_ABSENT, left->Start());
    }
    return iterType;
}

checker::Type *ETSAnalyzer::Check(ir::ForOfStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

    checker::Type *const exprType = st->Right()->Check(checker);
    checker::Type *elemType;

    if (exprType == nullptr || (!exprType->IsETSArrayType() && !exprType->IsETSStringType())) {
        checker->ThrowTypeError(INVALID_SOURCE_EXPR_TYPE, st->Right()->Start());
    } else if (exprType->IsETSStringType()) {
        elemType = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else {
        elemType = exprType->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                          checker->GetGlobalTypesHolder());
        elemType->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
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

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->Scope());

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

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::IfStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckTruthinessOfType(st->test_);

    st->consequent_->Check(checker);

    if (st->Alternate() != nullptr) {
        st->alternate_->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::LabelledStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->body_->Check(checker);
    return nullptr;
}

void CheckArgumentVoidType(checker::Type *&funcReturnType, ETSChecker *checker, const std::string &name,
                           ir::ReturnStatement *st)
{
    if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
        if (funcReturnType == checker->GlobalBuiltinVoidType()) {
            funcReturnType = checker->GlobalVoidType();
        } else if (!funcReturnType->IsETSVoidType() && !funcReturnType->IsIntType()) {
            checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
        }
    }
}

void CheckReturnType(ETSChecker *checker, checker::Type *funcReturnType, checker::Type *argumentType,
                     ir::Expression *stArgument)
{
    if (funcReturnType->IsETSVoidType() || funcReturnType == checker->GlobalBuiltinVoidType()) {
        if (argumentType != checker->GlobalVoidType() && argumentType != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.",
                                    stArgument->Start());
        }
    } else {
        checker::AssignmentContext(checker->Relation(), stArgument, argumentType, funcReturnType, stArgument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
    }
}

void InferReturnType(ETSChecker *checker, ir::ScriptFunction *containingFunc, checker::Type *&funcReturnType,
                     ir::Expression *stArgument)
{
    //  First (or single) return statement in the function:
    funcReturnType = stArgument == nullptr
                         ? containingFunc->IsEntryPoint() ? checker->GlobalVoidType() : checker->GlobalBuiltinVoidType()
                         : stArgument->Check(checker);
    if (funcReturnType->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        // remove CONSTANT type modifier if exists
        funcReturnType =
            funcReturnType->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
        funcReturnType->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }
    /*
    when st_argment is ArrowFunctionExpression, need infer type for st_argment
    example code:
    ```
    return () => {}
    ```
    */
    if (stArgument != nullptr && stArgument->IsArrowFunctionExpression()) {
        auto arrowFunc = stArgument->AsArrowFunctionExpression();
        auto typeAnnotation = arrowFunc->CreateTypeAnnotation(checker);
        funcReturnType = typeAnnotation->GetType(checker);
        checker::AssignmentContext(checker->Relation(), arrowFunc, arrowFunc->TsType(), funcReturnType,
                                   stArgument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
    }

    containingFunc->Signature()->SetReturnType(funcReturnType);
    containingFunc->Signature()->RemoveSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE);
    checker->VarBinder()->AsETSBinder()->BuildFunctionName(containingFunc);

    if (stArgument != nullptr && stArgument->IsObjectExpression()) {
        stArgument->AsObjectExpression()->SetPreferredType(funcReturnType);
    }
}

void ProcessReturnStatements(ETSChecker *checker, ir::ScriptFunction *containingFunc, checker::Type *&funcReturnType,
                             ir::ReturnStatement *st, ir::Expression *stArgument)
{
    funcReturnType = containingFunc->Signature()->ReturnType();

    if (stArgument == nullptr) {
        // previous return statement(s) have value
        if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st->Start());
        }
    } else {
        //  previous return statement(s) don't have any value
        if (funcReturnType->IsETSVoidType() || funcReturnType == checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    stArgument->Start());
        }

        const auto name = containingFunc->Scope()->InternalName().Mutf8();
        if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
            if (funcReturnType == checker->GlobalBuiltinVoidType()) {
                funcReturnType = checker->GlobalVoidType();
            } else if (!funcReturnType->IsETSVoidType() && !funcReturnType->IsIntType()) {
                checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
            }
        }

        if (stArgument->IsObjectExpression()) {
            stArgument->AsObjectExpression()->SetPreferredType(funcReturnType);
        }

        if (stArgument->IsMemberExpression()) {
            checker->SetArrayPreferredTypeForNestedMemberExpressions(stArgument->AsMemberExpression(), funcReturnType);
        }

        checker::Type *argumentType = stArgument->Check(checker);
        // remove CONSTANT type modifier if exists
        if (argumentType->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
            argumentType =
                argumentType->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
            argumentType->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        }

        auto *const relation = checker->Relation();
        relation->SetNode(stArgument);

        if (!relation->IsIdenticalTo(funcReturnType, argumentType)) {
            checker->ResolveReturnStatement(funcReturnType, argumentType, containingFunc, st);
        }

        relation->SetNode(nullptr);
        relation->SetFlags(checker::TypeRelationFlag::NONE);
    }
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
        funcReturnType = checker->GetTypeFromTypeAnnotation(returnTypeAnnotation);

        if (st->argument_ == nullptr) {
            if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalBuiltinVoidType()) {
                checker->ThrowTypeError("Missing return value.", st->Start());
            }
            funcReturnType =
                containingFunc->IsEntryPoint() ? checker->GlobalVoidType() : checker->GlobalBuiltinVoidType();
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

            CheckReturnType(checker, funcReturnType, argumentType, st->argument_);
        }
    } else {
        //  Case when function's return type should be inferred from return statement(s):
        if (containingFunc->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
            InferReturnType(checker, containingFunc, funcReturnType, st->argument_);
        } else {
            //  All subsequent return statements:
            ProcessReturnStatements(checker, containingFunc, funcReturnType, st, st->argument_);
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

    if (containingFunc->IsConstructor()) {
        if (st->argument_ != nullptr) {
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", st->Start());
        }
        return nullptr;
    }

    st->returnType_ = GetFunctionReturnType(st, containingFunc);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SwitchStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scopeCtx(checker, st->scope_);
    st->discriminant_->Check(checker);
    checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(checker->Relation(),
                                                                    checker::TypeRelationFlag::NONE);
    // NOTE (user): check exhaustive Switch
    checker->CheckSwitchDiscriminant(st->discriminant_);
    auto *comparedExprType = st->discriminant_->TsType();
    auto unboxedDiscType = (st->Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
                               ? checker->ETSBuiltinTypeAsPrimitiveType(comparedExprType)
                               : comparedExprType;

    bool validCaseType;

    for (auto *it : st->Cases()) {
        if (it->Test() != nullptr) {
            auto *caseType = it->Test()->Check(checker);
            validCaseType = true;
            if (caseType->HasTypeFlag(checker::TypeFlag::CHAR)) {
                validCaseType = comparedExprType->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL);
            } else if (caseType->IsETSEnumType() && st->Discriminant()->TsType()->IsETSEnumType()) {
                validCaseType =
                    st->Discriminant()->TsType()->AsETSEnumType()->IsSameEnumType(caseType->AsETSEnumType());
            } else if (caseType->IsETSStringEnumType() && st->Discriminant()->TsType()->IsETSStringEnumType()) {
                validCaseType = st->Discriminant()->TsType()->AsETSStringEnumType()->IsSameEnumType(
                    caseType->AsETSStringEnumType());
            } else {
                checker::AssignmentContext(
                    checker->Relation(), st->discriminant_, caseType, unboxedDiscType, it->Test()->Start(),
                    {"Switch case type ", caseType, " is not comparable to discriminant type ", comparedExprType},
                    (comparedExprType->IsETSObjectType() ? checker::TypeRelationFlag::NO_WIDENING
                                                         : checker::TypeRelationFlag::NO_UNBOXING) |
                        checker::TypeRelationFlag::NO_BOXING);
            }

            if (!validCaseType) {
                checker->ThrowTypeError(
                    {"Switch case type ", caseType, " is not comparable to discriminant type ", comparedExprType},
                    it->Test()->Start());
            }
        }

        for (auto *caseStmt : it->Consequent()) {
            caseStmt->Check(checker);
        }
    }

    checker->CheckForSameSwitchCases(&st->cases_);

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
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TryStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    std::vector<checker::ETSObjectType *> exceptions;
    st->Block()->Check(checker);

    for (auto *catchClause : st->CatchClauses()) {
        auto exceptionType = catchClause->Check(checker);
        if ((exceptionType != nullptr) && (catchClause->Param() != nullptr)) {
            auto *clauseType = exceptionType->AsETSObjectType();

            for (auto *exception : exceptions) {
                checker->Relation()->IsIdenticalTo(clauseType, exception);
                if (checker->Relation()->IsTrue()) {
                    checker->ThrowTypeError("Redeclaration of exception type", catchClause->Start());
                }
            }

            exceptions.push_back(clauseType);
        }
    }

    bool defaultCatchFound = false;

    for (auto *catchClause : st->CatchClauses()) {
        if (defaultCatchFound) {
            checker->ThrowTypeError("Default catch clause should be the last in the try statement",
                                    catchClause->Start());
        }

        defaultCatchFound = catchClause->IsDefaultCatchClause();
    }

    if (st->HasFinalizer()) {
        st->finalizer_->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    ETSChecker *checker = GetETSChecker();
    ASSERT(st->Id()->IsIdentifier());
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (st->Id()->Parent()->Parent()->AsVariableDeclaration()->Kind() ==
        ir::VariableDeclaration::VariableDeclarationKind::CONST) {
        flags |= ir::ModifierFlags::CONST;
    }

    st->SetTsType(checker->CheckVariableDeclaration(st->Id()->AsIdentifier(),
                                                    st->Id()->AsIdentifier()->TypeAnnotation(), st->Init(), flags));
    return st->TsType();
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

    checker->CheckTruthinessOfType(st->Test());

    st->Body()->Check(checker);
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
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

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

    if (targetType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) &&
        sourceType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT | checker::TypeFlag::TYPE_PARAMETER)) {
        auto *const boxedTargetType = checker->PrimitiveTypeAsETSBuiltinType(targetType);
        if (!checker->Relation()->IsIdenticalTo(sourceType, boxedTargetType)) {
            expr->Expr()->AddAstNodeFlags(ir::AstNodeFlags::CHECKCAST);
        }
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
        interfaceType = checker->BuildInterfaceProperties(st);
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
    ETSChecker *checker = GetETSChecker();
    auto exprType = expr->expr_->Check(checker);

    if (!checker->MayHaveNulllikeValue(exprType)) {
        checker->ThrowTypeError("Bad operand type, the operand of the non-null expression must be a nullable type",
                                expr->Expr()->Start());
    }

    expr->SetTsType(exprType->IsNullish() ? checker->GetNonNullishType(exprType) : exprType);
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
    if (st->TypeParams() != nullptr) {
        st->SetTypeParameterTypes(checker->CreateTypeForTypeParameters(st->TypeParams()));
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
    }

    const checker::SavedTypeRelationFlagsContext savedFlagsCtx(checker->Relation(),
                                                               checker::TypeRelationFlag::NO_THROW_GENERIC_TYPEALIAS);

    st->TypeAnnotation()->Check(checker);

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

}  // namespace panda::es2panda::checker
