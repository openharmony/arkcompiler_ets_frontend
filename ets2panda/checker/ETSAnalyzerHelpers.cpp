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

#include "ETSAnalyzerHelpers.h"

namespace ark::es2panda::checker {

void CheckExtensionIsShadowedInCurrentClassOrInterface(checker::ETSChecker *checker, checker::ETSObjectType *objType,
                                                       ir::ScriptFunction *extensionFunc, checker::Signature *signature)
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
        if (!checker->Relation()->IsCompatibleTo(signature, funcSignature)) {
            continue;
        }

        checker->ReportWarning({"extension is shadowed by a instance member function '", funcType->Name(),
                                funcSignature, "' in class ", objType->Name()},
                               extensionFunc->Body()->Start());
        return;
    }
}

void CheckExtensionIsShadowedByMethod(checker::ETSChecker *checker, checker::ETSObjectType *objType,
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

void CheckExtensionMethod(checker::ETSChecker *checker, ir::ScriptFunction *extensionFunc, ir::MethodDefinition *node)
{
    auto *const classType = checker->GetApparentType(extensionFunc->Signature()->Params()[0]->TsType());
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
        auto *retType = scriptFunc->Signature()->ReturnType();
        if (!retType->IsETSObjectType() ||
            retType->AsETSObjectType()->GetOriginalBaseType() != checker->GlobalBuiltinPromiseType()) {
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

        if (scriptFunc->ReturnTypeAnnotation() == nullptr) {
            for (auto &returnStatement : scriptFunc->ReturnStatements()) {
                returnStatement->SetReturnType(checker, scriptFunc->Signature()->ReturnType());
            }
        }

        checker->Context().SetContainingSignature(nullptr);
    }
}

void CheckPredefinedMethodReturnType(ETSChecker *checker, ir::ScriptFunction *scriptFunc)
{
    auto const &position = scriptFunc->Start();

    auto const hasIteratorInterface = [](ETSObjectType const *const objectType) -> bool {
        for (auto const *const interface : objectType->Interfaces()) {
            if (interface->Name().Is(ir::ITERATOR_INTERFACE_NAME)) {
                return true;
            }
        }
        return false;
    };

    if (scriptFunc->IsSetter() && (scriptFunc->Signature()->ReturnType() != checker->GlobalVoidType())) {
        checker->ThrowTypeError("Setter must have void return type", position);
    }

    if (scriptFunc->IsGetter() && (scriptFunc->Signature()->ReturnType() == checker->GlobalVoidType())) {
        checker->ThrowTypeError("Getter must return a value", position);
    }

    auto const name = scriptFunc->Id()->Name();
    auto const methodName = std::string {ir::PREDEFINED_METHOD} + std::string {name.Utf8()};

    if (name.Is(compiler::Signatures::GET_INDEX_METHOD)) {
        if (scriptFunc->Signature()->ReturnType() == checker->GlobalVoidType()) {
            checker->ThrowTypeError(methodName + "' shouldn't have void return type.", position);
        }
    } else if (name.Is(compiler::Signatures::SET_INDEX_METHOD)) {
        if (scriptFunc->Signature()->ReturnType() != checker->GlobalVoidType()) {
            checker->ThrowTypeError(methodName + "' should have void return type.", position);
        }
    } else if (name.Is(compiler::Signatures::ITERATOR_METHOD)) {
        auto const *returnType = scriptFunc->Signature()->ReturnType();

        if (returnType == nullptr) {
            checker->ThrowTypeError(methodName + "' doesn't have return type.", position);
        }

        if (returnType->IsETSTypeParameter()) {
            returnType = checker->GetApparentType(returnType->AsETSTypeParameter()->GetConstraintType());
        }

        if (returnType->IsETSUnionType() &&
            returnType->AsETSUnionType()->AllOfConstituentTypes(
                [hasIteratorInterface](checker::Type const *const constituentType) -> bool {
                    return constituentType->IsETSObjectType() &&
                           hasIteratorInterface(constituentType->AsETSObjectType());
                })) {
            return;
        }

        if (returnType->IsETSObjectType() && hasIteratorInterface(returnType->AsETSObjectType())) {
            return;
        }

        checker->ThrowTypeError(methodName + "' has invalid return type.", position);
    }
}

checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, ir::Expression *callee,
                                         checker::Type *calleeType)
{
    auto *const arrowFunc = callee->AsArrowFunctionExpression()->Function();

    ArenaVector<ir::Expression *> params {checker->Allocator()->Adapter()};
    checker->CopyParams(arrowFunc->Params(), params);
    checker::Type *funcReturnType = nullptr;

    auto *typeAnnotation = arrowFunc->ReturnTypeAnnotation();
    if (typeAnnotation != nullptr) {
        typeAnnotation = typeAnnotation->Clone(checker->Allocator(), nullptr);
        typeAnnotation->SetTsType(arrowFunc->ReturnTypeAnnotation()->TsType());
    } else {
        if ((arrowFunc->Flags() & ir::ScriptFunctionFlags::HAS_RETURN) != 0) {
            InferReturnType(checker, arrowFunc, funcReturnType, callee);
        } else if (arrowFunc->Signature()->ReturnType() != nullptr) {
            auto newTypeAnnotation = callee->AsArrowFunctionExpression()->CreateTypeAnnotation(checker);
            typeAnnotation = arrowFunc->ReturnTypeAnnotation();
            funcReturnType = newTypeAnnotation->GetType(checker);
        }
    }

    auto signature = ir::FunctionSignature(nullptr, std::move(params), typeAnnotation);
    auto *funcType = checker->AllocNode<ir::ETSFunctionType>(std::move(signature), ir::ScriptFunctionFlags::NONE);

    funcType->SetScope(arrowFunc->Scope()->AsFunctionScope()->ParamScope());
    auto *const funcIface = typeAnnotation != nullptr ? funcType->Check(checker) : funcReturnType;
    checker->Relation()->SetNode(callee);
    checker->Relation()->IsAssignableTo(calleeType, funcIface);
    return funcIface;
}

checker::Signature *ResolveCallExtensionFunction(checker::ETSFunctionType *functionType, checker::ETSChecker *checker,
                                                 ir::CallExpression *expr)
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

checker::Signature *ResolveCallForETSExtensionFuncHelperType(checker::ETSExtensionFuncHelperType *type,
                                                             checker::ETSChecker *checker, ir::CallExpression *expr)
{
    checker::Signature *signature = checker->ResolveCallExpressionAndTrailingLambda(
        type->ClassMethodType()->CallSignatures(), expr, expr->Start(), checker::TypeRelationFlag::NO_THROW);

    if (signature != nullptr) {
        return signature;
    }

    return ResolveCallExtensionFunction(type->ExtensionMethodType(), checker, expr);
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
            ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME)
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

void SetTsTypeForUnaryExpression(ETSChecker *checker, ir::UnaryExpression *expr, checker::Type *operandType)
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
            expr->SetTsType(expr->Argument()->TsType());
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }
}

checker::ETSObjectType *CreateSyntheticType(ETSChecker *checker, util::StringView const &syntheticName,
                                            checker::ETSObjectType *lastObjectType, ir::Identifier *id)
{
    auto *syntheticObjType = checker->Allocator()->New<checker::ETSObjectType>(
        checker->Allocator(), syntheticName, syntheticName, id, checker::ETSObjectFlags::NO_OPTS, checker->Relation());

    auto *classDecl = checker->Allocator()->New<varbinder::ClassDecl>(syntheticName);
    varbinder::LocalVariable *var =
        checker->Allocator()->New<varbinder::LocalVariable>(classDecl, varbinder::VariableFlags::CLASS);
    var->SetTsType(syntheticObjType);
    lastObjectType->AddProperty<checker::PropertyType::STATIC_FIELD>(var);
    syntheticObjType->SetEnclosingType(lastObjectType);
    return syntheticObjType;
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
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

void CheckArgumentVoidType(checker::Type *&funcReturnType, ETSChecker *checker, const std::string &name,
                           ir::ReturnStatement *st)
{
    if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
        if (!funcReturnType->IsETSVoidType() && !funcReturnType->IsIntType()) {
            checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
        }
    }
}

void CheckReturnType(ETSChecker *checker, checker::Type *funcReturnType, checker::Type *argumentType,
                     ir::Expression *stArgument, bool isAsync)
{
    if (funcReturnType->IsETSVoidType() || funcReturnType == checker->GlobalVoidType()) {
        if (argumentType != checker->GlobalVoidType()) {
            checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.",
                                    stArgument->Start());
        }
        checker::AssignmentContext(checker->Relation(), stArgument, argumentType, funcReturnType, stArgument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
        return;
    }

    if (isAsync && funcReturnType->IsETSObjectType() &&
        funcReturnType->AsETSObjectType()->GetOriginalBaseType() == checker->GlobalBuiltinPromiseType()) {
        auto promiseArg = funcReturnType->AsETSObjectType()->TypeArguments()[0];
        checker::AssignmentContext(checker->Relation(), stArgument, argumentType, promiseArg, stArgument->Start(), {},
                                   checker::TypeRelationFlag::DIRECT_RETURN | checker::TypeRelationFlag::NO_THROW);
        if (checker->Relation()->IsTrue()) {
            return;
        }
    }

    const Type *targetType = checker->TryGettingFunctionTypeFromInvokeFunction(funcReturnType);
    const Type *sourceType = checker->TryGettingFunctionTypeFromInvokeFunction(argumentType);
    checker::AssignmentContext(
        checker->Relation(), stArgument, argumentType, funcReturnType, stArgument->Start(),
        {"Type '", sourceType, "' is not compatible with the enclosing method's return type '", targetType, "'"},
        checker::TypeRelationFlag::DIRECT_RETURN);
}

void InferReturnType(ETSChecker *checker, ir::ScriptFunction *containingFunc, checker::Type *&funcReturnType,
                     ir::Expression *stArgument)
{
    //  First (or single) return statement in the function:
    funcReturnType = stArgument == nullptr ? checker->GlobalVoidType() : stArgument->Check(checker);
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

        auto *argumentType = arrowFunc->TsType();
        funcReturnType = typeAnnotation->GetType(checker);

        const Type *sourceType = checker->TryGettingFunctionTypeFromInvokeFunction(argumentType);
        const Type *targetType = checker->TryGettingFunctionTypeFromInvokeFunction(funcReturnType);

        checker::AssignmentContext(
            checker->Relation(), arrowFunc, argumentType, funcReturnType, stArgument->Start(),
            {"Type '", sourceType, "' is not compatible with the enclosing method's return type '", targetType, "'"},
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
        if (!funcReturnType->IsETSVoidType() && funcReturnType != checker->GlobalVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st->Start());
        }
    } else {
        //  previous return statement(s) don't have any value
        if (funcReturnType->IsETSVoidType() || funcReturnType == checker->GlobalVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    stArgument->Start());
        }

        const auto name = containingFunc->Scope()->InternalName().Mutf8();
        CheckArgumentVoidType(funcReturnType, checker, name, st);

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

}  // namespace ark::es2panda::checker
