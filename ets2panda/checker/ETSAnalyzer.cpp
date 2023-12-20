/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
    checker::ETSObjectType *exception_type = checker->GlobalETSObjectType();

    ir::Identifier *param_ident = st->Param()->AsIdentifier();

    if (param_ident->TypeAnnotation() != nullptr) {
        checker::Type *catch_param_annotation_type = param_ident->TypeAnnotation()->GetType(checker);

        exception_type = checker->CheckExceptionOrErrorType(catch_param_annotation_type, st->Param()->Start());
    }

    param_ident->Variable()->SetTsType(exception_type);

    st->Body()->Check(checker);

    st->SetTsType(exception_type);
    return exception_type;
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

    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
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
    checker::ScopeContext scope_ctx(checker, func->Scope());
    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
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
                                                              checker::ETSObjectType *obj_type,
                                                              ir::ScriptFunction *extension_func,
                                                              checker::Signature *signature)
{
    const auto method_name = extension_func->Id()->Name();
    // Only check if there are class and interfaces' instance methods which would shadow instance extension method
    auto *const variable = obj_type->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(method_name);
    if (variable == nullptr) {
        return;
    }

    const auto *const func_type = variable->TsType()->AsETSFunctionType();
    for (auto *func_signature : func_type->CallSignatures()) {
        signature->SetReturnType(func_signature->ReturnType());
        if (!checker->Relation()->IsIdenticalTo(signature, func_signature)) {
            continue;
        }

        checker->ReportWarning({"extension is shadowed by a instance member function '", func_type->Name(),
                                func_signature, "' in class ", obj_type->Name()},
                               extension_func->Body()->Start());
        return;
    }
}

static void CheckExtensionIsShadowedByMethod(checker::ETSChecker *checker, checker::ETSObjectType *obj_type,
                                             ir::ScriptFunction *extension_func, checker::Signature *signature)
{
    if (obj_type == nullptr) {
        return;
    }

    CheckExtensionIsShadowedInCurrentClassOrInterface(checker, obj_type, extension_func, signature);

    for (auto *interface : obj_type->Interfaces()) {
        CheckExtensionIsShadowedByMethod(checker, interface, extension_func, signature);
    }

    CheckExtensionIsShadowedByMethod(checker, obj_type->SuperType(), extension_func, signature);
}

static void CheckExtensionMethod(checker::ETSChecker *checker, ir::ScriptFunction *extension_func,
                                 ir::MethodDefinition *node)
{
    auto *const class_type = extension_func->Signature()->Params()[0]->TsType();
    if (!class_type->IsETSObjectType() ||
        (!class_type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::CLASS) &&
         !class_type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::INTERFACE))) {
        checker->ThrowTypeError("Extension function can only defined for class and interface type.", node->Start());
    }

    checker->AddStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD);

    checker::SignatureInfo *original_extension_sig_info = checker->Allocator()->New<checker::SignatureInfo>(
        extension_func->Signature()->GetSignatureInfo(), checker->Allocator());
    original_extension_sig_info->min_arg_count -= 1;
    original_extension_sig_info->params.erase(original_extension_sig_info->params.begin());
    checker::Signature *original_extension_sigature = checker->CreateSignature(
        original_extension_sig_info, extension_func->Signature()->ReturnType(), extension_func);

    CheckExtensionIsShadowedByMethod(checker, class_type->AsETSObjectType(), extension_func,
                                     original_extension_sigature);
}

void DoBodyTypeChecking(ETSChecker *checker, ir::MethodDefinition *node, ir::ScriptFunction *script_func)
{
    if (script_func->HasBody() && (node->IsNative() || node->IsAbstract() || node->IsDeclare())) {
        checker->ThrowTypeError("Native, Abstract and Declare methods cannot have body.", script_func->Body()->Start());
    }

    if (script_func->IsAsyncFunc()) {
        auto *ret_type = static_cast<checker::ETSObjectType *>(script_func->Signature()->ReturnType());
        if (ret_type->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async function must be 'Promise'.", script_func->Start());
        }
    } else if (script_func->HasBody() && !script_func->IsExternal()) {
        checker::ScopeContext scope_ctx(checker, script_func->Scope());
        checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
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
            CheckExtensionMethod(checker, script_func, node);
        }

        script_func->Body()->Check(checker);

        // In case of inferred function's return type set it forcedly to all return statements;
        if (script_func->Signature()->HasSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE) &&
            script_func->ReturnTypeAnnotation() == nullptr && script_func->Body() != nullptr &&
            script_func->Body()->IsStatement()) {
            script_func->Body()->AsStatement()->SetReturnType(checker, script_func->Signature()->ReturnType());
        }

        checker->Context().SetContainingSignature(nullptr);
    }
}

void CheckGetterSetterTypeConstrains(ETSChecker *checker, ir::ScriptFunction *script_func)
{
    if (script_func->IsSetter() && (script_func->Signature()->ReturnType() != checker->GlobalBuiltinVoidType())) {
        checker->ThrowTypeError("Setter must have void return type", script_func->Start());
    }

    if (script_func->IsGetter() && (script_func->Signature()->ReturnType() == checker->GlobalBuiltinVoidType())) {
        checker->ThrowTypeError("Getter must return a value", script_func->Start());
    }

    auto const name = script_func->Id()->Name();
    if (name.Is(compiler::Signatures::GET_INDEX_METHOD)) {
        if (script_func->Signature()->ReturnType() == checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError(std::string {ir::INDEX_ACCESS_ERROR_1} + std::string {name.Utf8()} +
                                        std::string {"' shouldn't have void return type."},
                                    script_func->Start());
        }
    } else if (name.Is(compiler::Signatures::SET_INDEX_METHOD)) {
        if (script_func->Signature()->ReturnType() != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError(std::string {ir::INDEX_ACCESS_ERROR_1} + std::string {name.Utf8()} +
                                        std::string {"' should have void return type."},
                                    script_func->Start());
        }
    }
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto *script_func = node->Function();
    if (script_func->IsProxy()) {
        return nullptr;
    }

    // NOTE: aszilagyi. make it correctly check for open function not have body
    if (!script_func->HasBody() && !(node->IsAbstract() || node->IsNative() || node->IsDeclare() ||
                                     checker->HasStatus(checker::CheckerStatus::IN_INTERFACE))) {
        checker->ThrowTypeError("Only abstract or native methods can't have body.", script_func->Start());
    }

    if (script_func->ReturnTypeAnnotation() == nullptr &&
        (node->IsNative() || (node->IsDeclare() && !node->IsConstructor()))) {
        checker->ThrowTypeError("Native and Declare methods should have explicit return type.", script_func->Start());
    }

    if (node->TsType() == nullptr) {
        node->SetTsType(checker->BuildMethodSignature(node));
    }

    this->CheckMethodModifiers(node);

    if (node->IsNative() && script_func->ReturnTypeAnnotation() == nullptr) {
        checker->ThrowTypeError("'Native' method should have explicit return type", script_func->Start());
    }

    if (node->IsNative() && (script_func->IsGetter() || script_func->IsSetter())) {
        checker->ThrowTypeError("'Native' modifier is invalid for Accessors", script_func->Start());
    }

    DoBodyTypeChecking(checker, node, script_func);
    CheckGetterSetterTypeConstrains(checker, script_func);

    checker->CheckOverride(node->TsType()->AsETSFunctionType()->FindSignature(node->Function()));

    for (auto *it : node->Overloads()) {
        it->Check(checker);
    }

    if (script_func->IsRethrowing()) {
        checker->CheckRethrowingFunction(script_func);
    }

    return node->TsType();
}

void ETSAnalyzer::CheckMethodModifiers(ir::MethodDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    auto const not_valid_in_abstract = ir::ModifierFlags::NATIVE | ir::ModifierFlags::PRIVATE |
                                       ir::ModifierFlags::OVERRIDE | ir::ModifierFlags::FINAL |
                                       ir::ModifierFlags::STATIC;

    if (node->IsAbstract() && (node->flags_ & not_valid_in_abstract) != 0U) {
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

    auto const not_valid_in_final = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::STATIC | ir::ModifierFlags::NATIVE;

    if (node->IsFinal() && (node->flags_ & not_valid_in_final) != 0U) {
        checker->ThrowTypeError(
            "Invalid method modifier(s): a final method can't have abstract, static or native modifier.",
            node->Start());
    }

    auto const not_valid_in_static =
        ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::FINAL | ir::ModifierFlags::OVERRIDE;

    if (node->IsStatic() && (node->flags_ & not_valid_in_static) != 0U) {
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
    auto *expr_type = expr->expr_->GetType(checker);

    if (expr_type->IsETSVoidType()) {
        checker->ThrowTypeError("Invalid .class reference", expr->expr_->Start());
    }

    ArenaVector<checker::Type *> type_arg_types(checker->Allocator()->Adapter());
    type_arg_types.push_back(expr_type);  // NOTE: Box it if it's a primitive type

    checker::InstantiationContext ctx(checker, checker->GlobalBuiltinTypeType(), type_arg_types, expr->range_.start);
    expr->SetTsType(ctx.Result());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CreateFunctionalInterfaceForFunctionType(node);
    auto *interface_type =
        checker->CreateETSObjectType(node->FunctionalInterface()->Id()->Name(), node->FunctionalInterface(),
                                     checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    interface_type->SetSuperType(checker->GlobalETSObjectType());

    auto *invoke_func = node->FunctionalInterface()->Body()->Body()[0]->AsMethodDefinition()->Function();
    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());

    for (auto *it : invoke_func->Params()) {
        auto *const param = it->AsETSParameterExpression();
        if (param->IsRestParameter()) {
            auto *rest_ident = param->Ident();

            ASSERT(rest_ident->Variable());
            signature_info->rest_var = rest_ident->Variable()->AsLocalVariable();

            ASSERT(param->TypeAnnotation());
            signature_info->rest_var->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));

            auto array_type = signature_info->rest_var->TsType()->AsETSArrayType();
            checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
        } else {
            auto *param_ident = param->Ident();

            ASSERT(param_ident->Variable());
            varbinder::Variable *param_var = param_ident->Variable();

            ASSERT(param->TypeAnnotation());
            param_var->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));
            signature_info->params.push_back(param_var->AsLocalVariable());
            ++signature_info->min_arg_count;
        }
    }

    invoke_func->ReturnTypeAnnotation()->Check(checker);
    auto *signature = checker->Allocator()->New<checker::Signature>(signature_info,
                                                                    node->ReturnType()->GetType(checker), invoke_func);
    signature->SetOwnerVar(invoke_func->Id()->Variable()->AsLocalVariable());
    signature->AddSignatureFlag(checker::SignatureFlags::FUNCTIONAL_INTERFACE_SIGNATURE);
    signature->SetOwner(interface_type);

    auto *func_type = checker->CreateETSFunctionType(signature);
    invoke_func->SetSignature(signature);
    invoke_func->Id()->Variable()->SetTsType(func_type);
    interface_type->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invoke_func->Id()->Variable()->AsLocalVariable());
    node->FunctionalInterface()->SetTsType(interface_type);

    auto *this_var = invoke_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(interface_type);
    checker->BuildFunctionalInterfaceName(node);

    node->SetTsType(interface_type);
    return interface_type;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSLaunchExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    expr->expr_->Check(checker);
    auto *const launch_promise_type =
        checker->GlobalBuiltinPromiseType()
            ->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder())
            ->AsETSObjectType();
    launch_promise_type->AddTypeFlag(checker::TypeFlag::GENERIC);

    // Launch expression returns a Promise<T> type, so we need to insert the expression's type
    // as type parameter for the Promise class.

    auto *expr_type =
        expr->expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) && !expr->expr_->TsType()->IsETSVoidType()
            ? checker->PrimitiveTypeAsETSBuiltinType(expr->expr_->TsType())
            : expr->expr_->TsType();
    checker::Substitution *substitution = checker->NewSubstitution();
    ASSERT(launch_promise_type->TypeArguments().size() == 1);
    substitution->emplace(checker->GetOriginalBaseType(launch_promise_type->TypeArguments()[0]), expr_type);

    expr->SetTsType(launch_promise_type->Substitute(checker->Relation(), substitution));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewArrayInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    auto *element_type = expr->type_reference_->GetType(checker);
    checker->ValidateArrayIndex(expr->dimension_, true);

    expr->SetTsType(checker->CreateETSArrayType(element_type));
    checker->CreateBuiltinArraySignature(expr->TsType()->AsETSArrayType(), 1);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *callee_type = expr->GetTypeRef()->Check(checker);

    if (!callee_type->IsETSObjectType()) {
        checker->ThrowTypeError("This expression is not constructible.", expr->Start());
    }

    auto *callee_obj = callee_type->AsETSObjectType();
    expr->SetTsType(callee_obj);

    if (expr->ClassDefinition() != nullptr) {
        if (!callee_obj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT) && callee_obj->GetDeclNode()->IsFinal()) {
            checker->ThrowTypeError({"Class ", callee_obj->Name(), " cannot be both 'abstract' and 'final'."},
                                    callee_obj->GetDeclNode()->Start());
        }

        bool from_interface = callee_obj->HasObjectFlag(checker::ETSObjectFlags::INTERFACE);
        auto *class_type = checker->BuildAnonymousClassProperties(
            expr->ClassDefinition(), from_interface ? checker->GlobalETSObjectType() : callee_obj);
        if (from_interface) {
            class_type->AddInterface(callee_obj);
            callee_obj = checker->GlobalETSObjectType();
        }
        expr->ClassDefinition()->SetTsType(class_type);
        checker->CheckClassDefinition(expr->ClassDefinition());
        checker->CheckInnerClassMembers(class_type);
        expr->SetTsType(class_type);
    } else if (callee_obj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
        checker->ThrowTypeError({callee_obj->Name(), " is abstract therefore cannot be instantiated."}, expr->Start());
    }

    if (callee_type->IsETSDynamicType() && !callee_type->AsETSDynamicType()->HasDecl()) {
        auto lang = callee_type->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->GetTypeRef(), expr->GetArguments(), lang, true));
    } else {
        auto *signature = checker->ResolveConstructExpression(callee_obj, expr->GetArguments(), expr->Start());

        checker->CheckObjectLiteralArguments(signature, expr->GetArguments());
        checker->AddUndefinedParamsForDefaultParams(signature, expr->arguments_, checker);

        checker->ValidateSignatureAccessibility(callee_obj, signature, expr->Start());

        ASSERT(signature->Function() != nullptr);

        if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
            checker->CheckThrowingStatements(expr);
        }

        if (callee_type->IsETSDynamicType()) {
            ASSERT(signature->Function()->IsDynamic());
            auto lang = callee_type->AsETSDynamicType()->Language();
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
    auto *element_type = expr->type_reference_->GetType(checker);

    for (auto *dim : expr->dimensions_) {
        checker->ValidateArrayIndex(dim);
        element_type = checker->CreateETSArrayType(element_type);
    }

    expr->SetTsType(element_type);
    expr->signature_ = checker->CreateBuiltinArraySignature(element_type->AsETSArrayType(), expr->dimensions_.size());
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
        checker::Type *param_type;

        if (expr->Ident()->TsType() != nullptr) {
            param_type = expr->Ident()->TsType();
        } else {
            param_type = !expr->IsRestParameter() ? expr->Ident()->Check(checker) : expr->spread_->Check(checker);
            if (expr->IsDefault()) {
                [[maybe_unused]] auto *const init_type = expr->Initializer()->Check(checker);
            }
        }

        expr->SetTsType(param_type);
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
    return expr->preferred_type_;
}

checker::Type *ETSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    const bool is_array = (expr->preferred_type_ != nullptr) && expr->preferred_type_->IsETSArrayType() &&
                          !expr->preferred_type_->IsETSTupleType();
    if (is_array) {
        expr->preferred_type_ = expr->preferred_type_->AsETSArrayType()->ElementType();
    }

    if (!expr->Elements().empty()) {
        if (expr->preferred_type_ == nullptr) {
            expr->preferred_type_ = expr->Elements()[0]->Check(checker);
        }

        const bool is_preferred_tuple = expr->preferred_type_->IsETSTupleType();
        auto *const target_element_type = is_preferred_tuple && !is_array
                                              ? expr->preferred_type_->AsETSTupleType()->ElementType()
                                              : expr->preferred_type_;

        for (std::size_t idx = 0; idx < expr->elements_.size(); ++idx) {
            auto *const current_element = expr->elements_[idx];

            if (current_element->IsArrayExpression()) {
                expr->HandleNestedArrayExpression(checker, current_element->AsArrayExpression(), is_array,
                                                  is_preferred_tuple, idx);
            }

            if (current_element->IsObjectExpression()) {
                current_element->AsObjectExpression()->SetPreferredType(expr->preferred_type_);
            }

            checker::Type *element_type = current_element->Check(checker);

            if (!element_type->IsETSArrayType() && is_preferred_tuple) {
                auto *const compare_type = expr->preferred_type_->AsETSTupleType()->GetTypeAtIndex(idx);

                if (compare_type == nullptr) {
                    checker->ThrowTypeError(
                        {"Too many elements in array initializer for tuple with size of ",
                         static_cast<uint32_t>(expr->preferred_type_->AsETSTupleType()->GetTupleSize())},
                        current_element->Start());
                }

                const checker::CastingContext cast(
                    checker->Relation(), current_element, element_type, compare_type, current_element->Start(),
                    {"Array initializer's type is not assignable to tuple type at index: ", idx});

                element_type = compare_type;
            }

            checker::AssignmentContext(checker->Relation(), current_element, element_type, target_element_type,
                                       current_element->Start(),
                                       {"Array element type '", element_type, "' is not assignable to explicit type '",
                                        expr->GetPreferredType(), "'"});
        }

        expr->SetPreferredType(target_element_type);
    }

    if (expr->preferred_type_ == nullptr) {
        checker->ThrowTypeError("Can't resolve array type", expr->Start());
    }

    expr->SetTsType(checker->CreateETSArrayType(expr->preferred_type_));
    auto *const array_type = expr->TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *func_type = checker->BuildFunctionSignature(expr->Function(), false);

    if (expr->Function()->IsAsyncFunc()) {
        auto *ret_type = static_cast<checker::ETSObjectType *>(expr->Function()->Signature()->ReturnType());
        if (ret_type->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async lambda must be 'Promise'", expr->Function()->Start());
        }
    }

    checker::ScopeContext scope_ctx(checker, expr->Function()->Scope());

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

    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_LAMBDA);
    checker->Context().SetContainingSignature(func_type->CallSignatures()[0]);

    auto *body_type = expr->Function()->Body()->Check(checker);
    if (expr->Function()->Body()->IsExpression()) {
        /*
        when function body is ArrowFunctionExpression, need infer type for this function body
        example code:
        ```
        let x = () => () => {}
        ```
        */
        if (expr->Function()->ReturnTypeAnnotation() == nullptr) {
            if (expr->Function()->Body()->IsArrowFunctionExpression()) {
                auto *arrow_func = expr->Function()->Body()->AsArrowFunctionExpression();
                auto *type_annotation = arrow_func->CreateTypeAnnotation(checker);
                func_type->CallSignatures()[0]->SetReturnType(type_annotation->GetType(checker));
            } else {
                func_type->CallSignatures()[0]->SetReturnType(body_type);
            }
        }

        checker::AssignmentContext(
            checker->Relation(), expr->Function()->Body()->AsExpression(), body_type,
            func_type->CallSignatures()[0]->ReturnType(), expr->Function()->Start(),
            {"Return statements return type is not compatible with the containing functions return type"},
            checker::TypeRelationFlag::DIRECT_RETURN);
    }

    checker->Context().SetContainingSignature(nullptr);
    checker->CheckCapturedVariables();

    for (auto [var, _] : checker->Context().CapturedVars()) {
        (void)_;
        expr->CapturedVars().push_back(var);
    }

    expr->SetTsType(func_type);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::AssignmentExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *left_type = expr->Left()->Check(checker);
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

    checker::Type *source_type {};
    ir::Expression *relation_node = expr->Right();
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
            std::tie(std::ignore, expr->operation_type_) = checker->CheckBinaryOperator(
                expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start(), true);

            auto unboxed_left = checker->ETSBuiltinTypeAsPrimitiveType(left_type);
            source_type = unboxed_left == nullptr ? left_type : unboxed_left;

            relation_node = expr;
            break;
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            if (left_type->IsETSArrayType() && expr->Right()->IsArrayExpression()) {
                checker->ModifyPreferredType(expr->Right()->AsArrayExpression(), left_type);
            }

            if (expr->Right()->IsObjectExpression()) {
                expr->Right()->AsObjectExpression()->SetPreferredType(left_type);
            }

            source_type = expr->Right()->Check(checker);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    checker::AssignmentContext(checker->Relation(), relation_node, source_type, left_type, expr->Right()->Start(),
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

    checker::Type *arg_type = expr->argument_->Check(checker);
    // Check the argument type of await expression
    if (!arg_type->IsETSObjectType() ||
        (arg_type->AsETSObjectType()->AssemblerName() != compiler::Signatures::BUILTIN_PROMISE)) {
        checker->ThrowTypeError("'await' expressions require Promise object as argument.", expr->Argument()->Start());
    }

    expr->SetTsType(arg_type->AsETSObjectType()->TypeArguments().at(0));
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    checker::Type *new_ts_type {nullptr};
    std::tie(new_ts_type, expr->operation_type_) =
        checker->CheckBinaryOperator(expr->Left(), expr->Right(), expr, expr->OperatorType(), expr->Start());
    expr->SetTsType(new_ts_type);
    return expr->TsType();
}

static checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, ir::Expression *callee,
                                                checker::Type *callee_type)
{
    auto *const arrow_func = callee->AsArrowFunctionExpression()->Function();
    auto orig_params = arrow_func->Params();
    auto signature = ir::FunctionSignature(nullptr, std::move(orig_params), arrow_func->ReturnTypeAnnotation());
    auto *func_type =
        checker->Allocator()->New<ir::ETSFunctionType>(std::move(signature), ir::ScriptFunctionFlags::NONE);
    func_type->SetScope(arrow_func->Scope()->AsFunctionScope()->ParamScope());
    auto *const func_iface = func_type->Check(checker);
    checker->Relation()->SetNode(callee);
    checker->Relation()->IsAssignableTo(callee_type, func_iface);
    return func_iface;
}

static checker::Signature *ResolveCallExtensionFunction(checker::ETSFunctionType *function_type,
                                                        checker::ETSChecker *checker, ir::CallExpression *expr)
{
    auto *member_expr = expr->Callee()->AsMemberExpression();
    expr->Arguments().insert(expr->Arguments().begin(), member_expr->Object());
    auto *signature =
        checker->ResolveCallExpressionAndTrailingLambda(function_type->CallSignatures(), expr, expr->Start());
    if (!signature->Function()->IsExtensionMethod()) {
        checker->ThrowTypeError({"Property '", member_expr->Property()->AsIdentifier()->Name(),
                                 "' does not exist on type '", member_expr->ObjType()->Name(), "'"},
                                member_expr->Property()->Start());
    }
    expr->SetSignature(signature);
    expr->SetCallee(member_expr->Property());
    member_expr->Property()->AsIdentifier()->SetParent(expr);
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

ArenaVector<Signature *> &ChooseSignatures(checker::Type *callee_type, bool is_constructor_call,
                                           bool is_functional_interface)
{
    if (is_constructor_call) {
        return callee_type->AsETSObjectType()->ConstructSignatures();
    }
    if (is_functional_interface) {
        return callee_type->AsETSObjectType()
            ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke")
            ->TsType()
            ->AsETSFunctionType()
            ->CallSignatures();
    }
    return callee_type->AsETSFunctionType()->CallSignatures();
}

checker::ETSObjectType *ChooseCalleeObj(ETSChecker *checker, ir::CallExpression *expr, checker::Type *callee_type,
                                        bool is_constructor_call)
{
    if (is_constructor_call) {
        return callee_type->AsETSObjectType();
    }
    if (expr->Callee()->IsIdentifier()) {
        return checker->Context().ContainingClass();
    }
    ASSERT(expr->Callee()->IsMemberExpression());
    return expr->Callee()->AsMemberExpression()->ObjType();
}

checker::Signature *ResolveSignature(ETSChecker *checker, ir::CallExpression *expr, checker::Type *callee_type,
                                     bool is_constructor_call, bool is_functional_interface)
{
    bool extension_function_type =
        expr->Callee()->IsMemberExpression() && checker->ExtensionETSFunctionType(callee_type);

    if (callee_type->IsETSExtensionFuncHelperType()) {
        return ResolveCallForETSExtensionFuncHelperType(callee_type->AsETSExtensionFuncHelperType(), checker, expr);
    }
    if (extension_function_type) {
        return ResolveCallExtensionFunction(callee_type->AsETSFunctionType(), checker, expr);
    }
    auto &signatures = ChooseSignatures(callee_type, is_constructor_call, is_functional_interface);
    checker::Signature *signature = checker->ResolveCallExpressionAndTrailingLambda(signatures, expr, expr->Start());
    if (signature->Function()->IsExtensionMethod()) {
        checker->ThrowTypeError({"No matching call signature"}, expr->Start());
    }
    return signature;
}

checker::Type *ETSAnalyzer::GetReturnType(ir::CallExpression *expr, checker::Type *callee_type) const
{
    ETSChecker *checker = GetETSChecker();
    bool is_constructor_call = expr->IsETSConstructorCall();
    bool is_functional_interface = callee_type->IsETSObjectType() && callee_type->AsETSObjectType()->HasObjectFlag(
                                                                         checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    bool ets_extension_func_helper_type = callee_type->IsETSExtensionFuncHelperType();

    if (expr->Callee()->IsArrowFunctionExpression()) {
        callee_type = InitAnonymousLambdaCallee(checker, expr->Callee(), callee_type);
        is_functional_interface = true;
    }

    if (!is_functional_interface && !callee_type->IsETSFunctionType() && !is_constructor_call &&
        !ets_extension_func_helper_type) {
        checker->ThrowTypeError("This expression is not callable.", expr->Start());
    }

    checker::Signature *signature =
        ResolveSignature(checker, expr, callee_type, is_constructor_call, is_functional_interface);

    checker->CheckObjectLiteralArguments(signature, expr->Arguments());
    checker->AddUndefinedParamsForDefaultParams(signature, expr->Arguments(), checker);

    if (!is_functional_interface) {
        checker::ETSObjectType *callee_obj = ChooseCalleeObj(checker, expr, callee_type, is_constructor_call);
        checker->ValidateSignatureAccessibility(callee_obj, signature, expr->Start());
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

    return signature->ReturnType();
}

checker::Type *ETSAnalyzer::Check(ir::CallExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }
    auto *old_callee = expr->Callee();
    checker::Type *callee_type = expr->Callee()->Check(checker);
    if (expr->Callee() != old_callee) {
        // If it is a static invoke, the callee will be transformed from an identifier to a member expression
        // Type check the callee again for member expression
        callee_type = expr->Callee()->Check(checker);
    }
    if (!expr->IsOptional()) {
        checker->CheckNonNullishType(callee_type, expr->Callee()->Start());
    }
    checker::Type *return_type;
    if (callee_type->IsETSDynamicType() && !callee_type->AsETSDynamicType()->HasDecl()) {
        // Trailing lambda for js function call is not supported, check the correctness of `foo() {}`
        checker->EnsureValidCurlyBrace(expr);
        auto lang = callee_type->AsETSDynamicType()->Language();
        expr->SetSignature(checker->ResolveDynamicCallExpression(expr->Callee(), expr->Arguments(), lang, false));
        return_type = expr->Signature()->ReturnType();
    } else {
        return_type = GetReturnType(expr, callee_type);
    }

    if (expr->Signature()->RestVar() != nullptr) {
        auto *const element_type = expr->Signature()->RestVar()->TsType()->AsETSArrayType()->ElementType();
        auto *const array_type = checker->CreateETSArrayType(element_type)->AsETSArrayType();
        checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
    }

    if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
        expr->Signature()->OwnerVar()->Declaration()->Node()->Check(checker);
        return_type = expr->Signature()->ReturnType();
    }
    expr->SetOptionalType(return_type);
    if (expr->IsOptional() && callee_type->IsNullishOrNullLike()) {
        checker->Relation()->SetNode(expr);
        return_type = checker->CreateOptionalResultType(return_type);
        checker->Relation()->SetNode(nullptr);
    }
    expr->SetTsType(return_type);
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

    checker::Type *consequent_type = expr->consequent_->Check(checker);
    checker::Type *alternate_type = expr->alternate_->Check(checker);

    auto *primitive_consequent_type = checker->ETSBuiltinTypeAsPrimitiveType(consequent_type);
    auto *primitive_alter_type = checker->ETSBuiltinTypeAsPrimitiveType(alternate_type);

    if (primitive_consequent_type != nullptr && primitive_alter_type != nullptr) {
        if (checker->IsTypeIdenticalTo(consequent_type, alternate_type)) {
            expr->SetTsType(checker->GetNonConstantTypeFromPrimitiveType(consequent_type));
        } else if (checker->IsTypeIdenticalTo(primitive_consequent_type, primitive_alter_type)) {
            checker->FlagExpressionWithUnboxing(expr->consequent_->TsType(), primitive_consequent_type,
                                                expr->consequent_);
            checker->FlagExpressionWithUnboxing(expr->alternate_->TsType(), primitive_alter_type, expr->alternate_);

            expr->SetTsType(primitive_consequent_type);
        } else if (primitive_consequent_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) &&
                   primitive_alter_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
            checker->FlagExpressionWithUnboxing(expr->consequent_->TsType(), primitive_consequent_type,
                                                expr->consequent_);
            checker->FlagExpressionWithUnboxing(expr->alternate_->TsType(), primitive_alter_type, expr->alternate_);

            expr->SetTsType(
                checker->ApplyConditionalOperatorPromotion(checker, primitive_consequent_type, primitive_alter_type));
        } else {
            checker->ThrowTypeError("Type error", expr->Range().start);
        }
    } else {
        if (!(consequent_type->IsETSArrayType() || alternate_type->IsETSArrayType()) &&
            !(consequent_type->IsETSObjectType() && alternate_type->IsETSObjectType())) {
            checker->ThrowTypeError("Type error", expr->Range().start);
        } else {
            checker->Relation()->SetNode(expr->consequent_);
            auto builtin_conseq_type = checker->PrimitiveTypeAsETSBuiltinType(consequent_type);
            auto builtin_alternate_type = checker->PrimitiveTypeAsETSBuiltinType(alternate_type);

            if (builtin_conseq_type == nullptr) {
                builtin_conseq_type = consequent_type;
            }

            if (builtin_alternate_type == nullptr) {
                builtin_alternate_type = alternate_type;
            }

            expr->SetTsType(checker->FindLeastUpperBound(builtin_conseq_type, builtin_alternate_type));
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

    auto *const left_type = expr->Object()->Check(checker);

    if (expr->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
        if (expr->IsOptional() && !left_type->IsNullish()) {
            checker->ThrowTypeError("The type of the object reference must be a nullish array or Record type",
                                    expr->Object()->Start());
        }

        if (!expr->IsOptional() && left_type->IsNullish()) {
            checker->ThrowTypeError("The type of the object reference must be a non-nullish array or Record type",
                                    expr->Object()->Start());
        }
    }

    auto *const base_type = expr->IsOptional() ? checker->GetNonNullishType(left_type) : left_type;
    if (!expr->IsOptional()) {
        checker->CheckNonNullishType(left_type, expr->Object()->Start());
    }

    if (expr->IsComputed()) {
        return expr->AdjustOptional(checker, expr->CheckComputed(checker, base_type));
    }

    if (base_type->IsETSArrayType() && expr->Property()->AsIdentifier()->Name().Is("length")) {
        return expr->AdjustOptional(checker, checker->GlobalIntType());
    }

    if (base_type->IsETSObjectType()) {
        expr->SetObjectType(base_type->AsETSObjectType());
        auto [res_type, res_var] = expr->ResolveObjectMember(checker);
        expr->SetPropVar(res_var);
        return expr->AdjustOptional(checker, res_type);
    }

    if (base_type->IsETSEnumType() || base_type->IsETSStringEnumType()) {
        auto [member_type, member_var] = expr->ResolveEnumMember(checker, base_type);
        expr->SetPropVar(member_var);
        return expr->AdjustOptional(checker, member_type);
    }

    if (base_type->IsETSUnionType()) {
        return expr->AdjustOptional(checker, expr->CheckUnionMember(checker, base_type));
    }

    if (base_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        checker->Relation()->SetNode(expr);
        expr->SetObjectType(checker->PrimitiveTypeAsETSBuiltinType(base_type)->AsETSObjectType());
        checker->AddBoxingUnboxingFlagToNode(expr, expr->ObjType());
        auto [res_type, res_var] = expr->ResolveObjectMember(checker);
        expr->SetPropVar(res_var);
        return expr->AdjustOptional(checker, res_type);
    }

    checker->ThrowTypeError({"Cannot access property of non-object or non-enum type"}, expr->Object()->Start());
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NewExpression *expr) const
{
    UNREACHABLE();
}
checker::Type *ETSAnalyzer::PreferredType(ir::ObjectExpression *expr) const
{
    return expr->preferred_type_;
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
        for (ir::Expression *prop_expr : expr->Properties()) {
            ASSERT(prop_expr->IsProperty());
            ir::Property *prop = prop_expr->AsProperty();
            ir::Expression *value = prop->Value();
            value->Check(checker);
            ASSERT(value->TsType());
        }

        expr->SetTsType(expr->PreferredType());
        return expr->PreferredType();
    }

    checker::ETSObjectType *obj_type = expr->PreferredType()->AsETSObjectType();
    if (obj_type->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT | checker::ETSObjectFlags::INTERFACE)) {
        checker->ThrowTypeError({"target type for class composite ", obj_type->Name(), " is not instantiable"},
                                expr->Start());
    }

    bool have_empty_constructor = false;
    for (checker::Signature *sig : obj_type->ConstructSignatures()) {
        if (sig->Params().empty()) {
            have_empty_constructor = true;
            checker->ValidateSignatureAccessibility(obj_type, sig, expr->Start());
            break;
        }
    }
    if (!have_empty_constructor) {
        checker->ThrowTypeError({"type ", obj_type->Name(), " has no parameterless constructor"}, expr->Start());
    }

    for (ir::Expression *prop_expr : expr->Properties()) {
        ASSERT(prop_expr->IsProperty());
        ir::Property *prop = prop_expr->AsProperty();
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
        varbinder::LocalVariable *lv = obj_type->GetProperty(
            pname, checker::PropertySearchFlags::SEARCH_INSTANCE_FIELD | checker::PropertySearchFlags::SEARCH_IN_BASE);
        if (lv == nullptr) {
            checker->ThrowTypeError({"type ", obj_type->Name(), " has no property named ", pname}, prop_expr->Start());
        }
        checker->ValidatePropertyAccess(lv, obj_type, prop_expr->Start());
        if (lv->HasFlag(varbinder::VariableFlags::READONLY)) {
            checker->ThrowTypeError({"cannot assign to readonly property ", pname}, prop_expr->Start());
        }

        auto *prop_type = checker->GetTypeOfVariable(lv);
        key->SetTsType(prop_type);

        if (value->IsObjectExpression()) {
            value->AsObjectExpression()->SetPreferredType(prop_type);
        }
        value->SetTsType(value->Check(checker));
        checker::AssignmentContext(checker->Relation(), value, value->TsType(), prop_type, value->Start(),
                                   {"value type is not assignable to the property type"});
    }

    expr->SetTsType(obj_type);
    return obj_type;
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

checker::Type *ETSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto arg_type = expr->argument_->Check(checker);
    const auto is_cond_expr = expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK;
    checker::Type *operand_type = checker->ApplyUnaryOperatorPromotion(arg_type, true, true, is_cond_expr);
    auto unboxed_operand_type = is_cond_expr ? checker->ETSBuiltinTypeAsConditionalType(arg_type)
                                             : checker->ETSBuiltinTypeAsPrimitiveType(arg_type);

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            if (operand_type == nullptr || !operand_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                        expr->Argument()->Start());
            }

            if (operand_type->HasTypeFlag(checker::TypeFlag::CONSTANT) &&
                expr->OperatorType() == lexer::TokenType::PUNCTUATOR_MINUS) {
                expr->SetTsType(checker->NegateNumericType(operand_type, expr));
                break;
            }

            expr->SetTsType(operand_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            if (operand_type == nullptr || !operand_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL)) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be integral type.",
                                        expr->Argument()->Start());
            }

            if (operand_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
                expr->SetTsType(checker->BitwiseNegateIntegralType(operand_type, expr));
                break;
            }

            expr->SetTsType(operand_type);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            if (checker->IsNullLikeOrVoidExpression(expr->Argument())) {
                auto ts_type = checker->CreateETSBooleanType(true);
                ts_type->AddTypeFlag(checker::TypeFlag::CONSTANT);
                expr->SetTsType(ts_type);
                break;
            }

            if (operand_type == nullptr || !operand_type->IsConditionalExprType()) {
                checker->ThrowTypeError("Bad operand type, the type of the operand must be boolean type.",
                                        expr->Argument()->Start());
            }

            auto expr_res = operand_type->ResolveConditionExpr();
            if (std::get<0>(expr_res)) {
                auto ts_type = checker->CreateETSBooleanType(!std::get<1>(expr_res));
                ts_type->AddTypeFlag(checker::TypeFlag::CONSTANT);
                expr->SetTsType(ts_type);
                break;
            }

            expr->SetTsType(checker->GlobalETSBooleanType());
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DOLLAR_DOLLAR: {
            expr->SetTsType(arg_type);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    if (arg_type->IsETSObjectType() && (unboxed_operand_type != nullptr) &&
        unboxed_operand_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        expr->Argument()->AddBoxingUnboxingFlag(checker->GetUnboxingFlag(unboxed_operand_type));
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::UpdateExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    checker::Type *operand_type = expr->argument_->Check(checker);
    if (expr->Argument()->IsIdentifier()) {
        checker->ValidateUnaryOperatorOperand(expr->Argument()->AsIdentifier()->Variable());
    } else if (expr->Argument()->IsTSAsExpression()) {
        if (auto *const as_expr_var = expr->Argument()->AsTSAsExpression()->Variable(); as_expr_var != nullptr) {
            checker->ValidateUnaryOperatorOperand(as_expr_var);
        }
    } else {
        ASSERT(expr->Argument()->IsMemberExpression());
        varbinder::LocalVariable *prop_var = expr->argument_->AsMemberExpression()->PropVar();
        if (prop_var != nullptr) {
            checker->ValidateUnaryOperatorOperand(prop_var);
        }
    }

    auto unboxed_type = checker->ETSBuiltinTypeAsPrimitiveType(operand_type);
    if (unboxed_type == nullptr || !unboxed_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
        checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.",
                                expr->Argument()->Start());
    }

    if (operand_type->IsETSObjectType()) {
        expr->Argument()->AddBoxingUnboxingFlag(checker->GetUnboxingFlag(unboxed_type) |
                                                checker->GetBoxingFlag(unboxed_type));
    }

    expr->SetTsType(operand_type);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::YieldExpression *expr) const
{
    UNREACHABLE();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::BigIntLiteral *expr) const
{
    UNREACHABLE();
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

checker::ETSObjectType *CreateSyntheticType(ETSChecker *checker, util::StringView const &synthetic_name,
                                            checker::ETSObjectType *last_object_type, ir::Identifier *id)
{
    auto *synthetic_obj_type = checker->Allocator()->New<checker::ETSObjectType>(
        checker->Allocator(), synthetic_name, synthetic_name, id, checker::ETSObjectFlags::NO_OPTS);

    auto *class_decl = checker->Allocator()->New<varbinder::ClassDecl>(synthetic_name);
    varbinder::LocalVariable *var =
        checker->Allocator()->New<varbinder::LocalVariable>(class_decl, varbinder::VariableFlags::CLASS);
    var->SetTsType(synthetic_obj_type);
    last_object_type->AddProperty<checker::PropertyType::STATIC_FIELD>(var);
    synthetic_obj_type->SetEnclosingType(last_object_type);
    return synthetic_obj_type;
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

    auto *import_decl = st->Parent()->AsETSImportDeclaration();
    auto import_path = import_decl->Source()->Str();

    if (import_decl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(import_decl->Language());
        checker->SetrModuleObjectTsType(st->Local(), type);
        return type;
    }

    std::string package_name =
        (import_decl->Module() == nullptr) ? import_path.Mutf8() : import_decl->Module()->Str().Mutf8();

    std::replace(package_name.begin(), package_name.end(), '/', '.');
    util::UString package_path(package_name, checker->Allocator());
    std::vector<util::StringView> synthetic_names = checker->GetNameForSynteticObjectType(package_path.View());

    ASSERT(!synthetic_names.empty());

    auto assembler_name = synthetic_names[0];
    if (import_decl->Module() != nullptr) {
        assembler_name = util::UString(assembler_name.Mutf8().append(".").append(compiler::Signatures::ETS_GLOBAL),
                                       checker->Allocator())
                             .View();
    }

    auto *module_object_type =
        checker->Allocator()->New<checker::ETSObjectType>(checker->Allocator(), synthetic_names[0], assembler_name,
                                                          st->Local()->AsIdentifier(), checker::ETSObjectFlags::CLASS);

    auto *root_decl = checker->Allocator()->New<varbinder::ClassDecl>(synthetic_names[0]);
    varbinder::LocalVariable *root_var =
        checker->Allocator()->New<varbinder::LocalVariable>(root_decl, varbinder::VariableFlags::NONE);
    root_var->SetTsType(module_object_type);

    synthetic_names.erase(synthetic_names.begin());
    checker::ETSObjectType *last_object_type(module_object_type);

    for (const auto &synthetic_name : synthetic_names) {
        last_object_type = CreateSyntheticType(checker, synthetic_name, last_object_type, st->Local()->AsIdentifier());
    }

    checker->SetPropertiesForModuleObject(
        last_object_type,
        (import_decl->Module() != nullptr)
            ? util::UString(import_path.Mutf8() + import_decl->Module()->Str().Mutf8(), checker->Allocator()).View()
            : import_path);
    checker->SetrModuleObjectTsType(st->Local(), last_object_type);

    return module_object_type;
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
        auto *msg_type = st->second_->Check(checker);

        if (!msg_type->IsETSStringType()) {
            checker->ThrowTypeError("Assert message must be string", st->Second()->Start());
        }
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::BlockStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    for (auto *it : st->Statements()) {
        it->Check(checker);
    }

    for (auto [stmt, trailing_block] : st->trailing_blocks_) {
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
    checker::ScopeContext scope_ctx(checker, st->Scope());

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

checker::Type *GetIteratorType(ETSChecker *checker, checker::Type *elem_type, ir::AstNode *left)
{
    // Just to avoid extra nested level(s)
    auto const get_iter_type = [checker, elem_type](ir::VariableDeclarator *const declarator) -> checker::Type * {
        if (declarator->TsType() == nullptr) {
            if (auto *resolved = checker->FindVariableInFunctionScope(declarator->Id()->AsIdentifier()->Name());
                resolved != nullptr) {
                resolved->SetTsType(elem_type);
                return elem_type;
            }
        } else {
            return declarator->TsType();
        }
        return nullptr;
    };

    checker::Type *iter_type = nullptr;
    if (left->IsIdentifier()) {
        if (auto *const variable = left->AsIdentifier()->Variable(); variable != nullptr) {
            if (variable->Declaration()->IsConstDecl()) {
                checker->ThrowTypeError({INVALID_CONST_ASSIGNMENT, variable->Name()},
                                        variable->Declaration()->Node()->Start());
            }
        }
        iter_type = left->AsIdentifier()->TsType();
    } else if (left->IsVariableDeclaration()) {
        if (auto const &declarators = left->AsVariableDeclaration()->Declarators(); !declarators.empty()) {
            iter_type = get_iter_type(declarators.front());
        }
    }

    if (iter_type == nullptr) {
        checker->ThrowTypeError(ITERATOR_TYPE_ABSENT, left->Start());
    }
    return iter_type;
}

checker::Type *ETSAnalyzer::Check(ir::ForOfStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker::Type *const expr_type = st->Right()->Check(checker);
    checker::Type *elem_type;

    if (expr_type == nullptr || (!expr_type->IsETSArrayType() && !expr_type->IsETSStringType())) {
        checker->ThrowTypeError(INVALID_SOURCE_EXPR_TYPE, st->Right()->Start());
    } else if (expr_type->IsETSStringType()) {
        elem_type = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else {
        elem_type = expr_type->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                            checker->GetGlobalTypesHolder());
        elem_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }

    st->Left()->Check(checker);
    checker::Type *iter_type = GetIteratorType(checker, elem_type, st->Left());
    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(checker->AllocNode<ir::SuperExpression>());  // Dummy node to avoid assertion!

    if (!relation->IsAssignableTo(elem_type, iter_type)) {
        std::stringstream ss {};
        ss << "Source element type '";
        elem_type->ToString(ss);
        ss << "' is not assignable to the loop iterator type '";
        iter_type->ToString(ss);
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
    checker::ScopeContext scope_ctx(checker, st->Scope());

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

void CheckArgumentVoidType(checker::Type *&func_return_type, ETSChecker *checker, const std::string &name,
                           ir::ReturnStatement *st)
{
    if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
        if (func_return_type == checker->GlobalBuiltinVoidType()) {
            func_return_type = checker->GlobalVoidType();
        } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
            checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
        }
    }
}

void CheckReturnType(ETSChecker *checker, checker::Type *func_return_type, checker::Type *argument_type,
                     ir::Expression *st_argument)
{
    if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
        if (argument_type != checker->GlobalVoidType() && argument_type != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.",
                                    st_argument->Start());
        }
    } else {
        checker::AssignmentContext(checker->Relation(), st_argument, argument_type, func_return_type,
                                   st_argument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
    }
}

void InferReturnType(ETSChecker *checker, ir::ScriptFunction *containing_func, checker::Type *&func_return_type,
                     ir::Expression *st_argument)
{
    //  First (or single) return statement in the function:
    func_return_type = st_argument == nullptr ? checker->GlobalBuiltinVoidType() : st_argument->Check(checker);
    if (func_return_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        // remove CONSTANT type modifier if exists
        func_return_type =
            func_return_type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
        func_return_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }
    /*
    when st_argment is ArrowFunctionExpression, need infer type for st_argment
    example code:
    ```
    return () => {}
    ```
    */
    if (st_argument != nullptr && st_argument->IsArrowFunctionExpression()) {
        auto arrow_func = st_argument->AsArrowFunctionExpression();
        auto type_annotation = arrow_func->CreateTypeAnnotation(checker);
        func_return_type = type_annotation->GetType(checker);
        checker::AssignmentContext(checker->Relation(), arrow_func, arrow_func->TsType(), func_return_type,
                                   st_argument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
    }

    containing_func->Signature()->SetReturnType(func_return_type);
    containing_func->Signature()->RemoveSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE);
    checker->VarBinder()->AsETSBinder()->BuildFunctionName(containing_func);

    if (st_argument != nullptr && st_argument->IsObjectExpression()) {
        st_argument->AsObjectExpression()->SetPreferredType(func_return_type);
    }
}

void ProcessReturnStatements(ETSChecker *checker, ir::ScriptFunction *containing_func, checker::Type *&func_return_type,
                             ir::ReturnStatement *st, ir::Expression *st_argument)
{
    func_return_type = containing_func->Signature()->ReturnType();

    if (st_argument == nullptr) {
        // previous return statement(s) have value
        if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st->Start());
        }
    } else {
        //  previous return statement(s) don't have any value
        if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st_argument->Start());
        }

        const auto name = containing_func->Scope()->InternalName().Mutf8();
        if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
            if (func_return_type == checker->GlobalBuiltinVoidType()) {
                func_return_type = checker->GlobalVoidType();
            } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
                checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
            }
        }

        if (st_argument->IsObjectExpression()) {
            st_argument->AsObjectExpression()->SetPreferredType(func_return_type);
        }

        if (st_argument->IsMemberExpression()) {
            checker->SetArrayPreferredTypeForNestedMemberExpressions(st_argument->AsMemberExpression(),
                                                                     func_return_type);
        }

        checker::Type *argument_type = st_argument->Check(checker);
        // remove CONSTANT type modifier if exists
        if (argument_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
            argument_type =
                argument_type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
            argument_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        }

        auto *const relation = checker->Relation();
        relation->SetNode(st_argument);

        if (!relation->IsIdenticalTo(func_return_type, argument_type)) {
            checker->ResolveReturnStatement(func_return_type, argument_type, containing_func, st);
        }

        relation->SetNode(nullptr);
        relation->SetFlags(checker::TypeRelationFlag::NONE);
    }
}

checker::Type *ETSAnalyzer::Check(ir::ReturnStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(st, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->IsConstructor()) {
        if (st->argument_ != nullptr) {
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", st->Start());
        }
        return nullptr;
    }

    ASSERT(containing_func->ReturnTypeAnnotation() != nullptr || containing_func->Signature()->ReturnType() != nullptr);

    checker::Type *func_return_type = nullptr;

    if (auto *const return_type_annotation = containing_func->ReturnTypeAnnotation();
        return_type_annotation != nullptr) {
        // Case when function's return type is defined explicitly:
        func_return_type = checker->GetTypeFromTypeAnnotation(return_type_annotation);

        if (st->argument_ == nullptr) {
            if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
                checker->ThrowTypeError("Missing return value.", st->Start());
            }
            func_return_type =
                containing_func->IsEntryPoint() ? checker->GlobalVoidType() : checker->GlobalBuiltinVoidType();
        } else {
            const auto name = containing_func->Scope()->InternalName().Mutf8();
            CheckArgumentVoidType(func_return_type, checker, name, st);

            if (st->argument_->IsObjectExpression()) {
                st->argument_->AsObjectExpression()->SetPreferredType(func_return_type);
            }
            if (st->argument_->IsMemberExpression()) {
                checker->SetArrayPreferredTypeForNestedMemberExpressions(st->argument_->AsMemberExpression(),
                                                                         func_return_type);
            }

            checker::Type *argument_type = st->argument_->Check(checker);

            CheckReturnType(checker, func_return_type, argument_type, st->argument_);
        }
    } else {
        //  Case when function's return type should be inferred from return statement(s):
        if (containing_func->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
            InferReturnType(checker, containing_func, func_return_type, st->argument_);
        } else {
            //  All subsequent return statements:
            ProcessReturnStatements(checker, containing_func, func_return_type, st, st->argument_);
        }
    }

    if ((st->argument_ != nullptr) && st->argument_->IsArrayExpression()) {
        checker->ModifyPreferredType(st->argument_->AsArrayExpression(), func_return_type);
        st->argument_->Check(checker);
    }

    st->return_type_ = func_return_type;
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SwitchStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->scope_);
    st->discriminant_->Check(checker);
    checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(checker->Relation(),
                                                                        checker::TypeRelationFlag::NONE);
    // NOTE (user): check exhaustive Switch
    checker->CheckSwitchDiscriminant(st->discriminant_);
    auto *compared_expr_type = st->discriminant_->TsType();
    auto unboxed_disc_type =
        (st->Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
            ? checker->ETSBuiltinTypeAsPrimitiveType(compared_expr_type)
            : compared_expr_type;

    bool valid_case_type;

    for (auto *it : st->Cases()) {
        if (it->Test() != nullptr) {
            auto *case_type = it->Test()->Check(checker);
            valid_case_type = true;
            if (case_type->HasTypeFlag(checker::TypeFlag::CHAR)) {
                valid_case_type = compared_expr_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL);
            } else if (case_type->IsETSEnumType() && st->Discriminant()->TsType()->IsETSEnumType()) {
                valid_case_type =
                    st->Discriminant()->TsType()->AsETSEnumType()->IsSameEnumType(case_type->AsETSEnumType());
            } else if (case_type->IsETSStringEnumType() && st->Discriminant()->TsType()->IsETSStringEnumType()) {
                valid_case_type = st->Discriminant()->TsType()->AsETSStringEnumType()->IsSameEnumType(
                    case_type->AsETSStringEnumType());
            } else {
                checker::AssignmentContext(
                    checker->Relation(), st->discriminant_, case_type, unboxed_disc_type, it->Test()->Start(),
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    (compared_expr_type->IsETSObjectType() ? checker::TypeRelationFlag::NO_WIDENING
                                                           : checker::TypeRelationFlag::NO_UNBOXING) |
                        checker::TypeRelationFlag::NO_BOXING);
            }

            if (!valid_case_type) {
                checker->ThrowTypeError(
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    it->Test()->Start());
            }
        }

        for (auto *case_stmt : it->Consequent()) {
            case_stmt->Check(checker);
        }
    }

    checker->CheckForSameSwitchCases(&st->cases_);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ThrowStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    auto *arg_type = st->argument_->Check(checker);
    checker->CheckExceptionOrErrorType(arg_type, st->Start());

    if (checker->Relation()->IsAssignableTo(arg_type, checker->GlobalBuiltinExceptionType())) {
        checker->CheckThrowingStatements(st);
    }
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TryStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    std::vector<checker::ETSObjectType *> exceptions;
    st->Block()->Check(checker);

    for (auto *catch_clause : st->CatchClauses()) {
        auto exception_type = catch_clause->Check(checker);
        if ((exception_type != nullptr) && (catch_clause->Param() != nullptr)) {
            auto *clause_type = exception_type->AsETSObjectType();

            for (auto *exception : exceptions) {
                checker->Relation()->IsIdenticalTo(clause_type, exception);
                if (checker->Relation()->IsTrue()) {
                    checker->ThrowTypeError("Redeclaration of exception type", catch_clause->Start());
                }
            }

            exceptions.push_back(clause_type);
        }
    }

    bool default_catch_found = false;

    for (auto *catch_clause : st->CatchClauses()) {
        if (default_catch_found) {
            checker->ThrowTypeError("Default catch clause should be the last in the try statement",
                                    catch_clause->Start());
        }

        default_catch_found = catch_clause->IsDefaultCatchClause();
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
    checker::ScopeContext scope_ctx(checker, st->Scope());

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
    node->element_type_->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();

    auto *const target_type = expr->TypeAnnotation()->AsTypeNode()->GetType(checker);
    // Object expression requires that its type be set by the context before checking. in this case, the target type
    // provides that context.
    if (expr->Expr()->IsObjectExpression()) {
        expr->Expr()->AsObjectExpression()->SetPreferredType(target_type);
    }
    auto *const source_type = expr->Expr()->Check(checker);

    const checker::CastingContext ctx(checker->Relation(), expr->Expr(), source_type, target_type,
                                      expr->Expr()->Start(),
                                      {"Cannot cast type '", source_type, "' to '", target_type, "'"});

    if (source_type->IsETSDynamicType() && target_type->IsLambdaObject()) {
        // NOTE: itrubachev. change target_type to created lambdaobject type.
        // Now target_type is not changed, only construct signature is added to it
        checker->BuildLambdaObjectClass(target_type->AsETSObjectType(),
                                        expr->TypeAnnotation()->AsETSFunctionType()->ReturnType());
    }
    expr->is_unchecked_cast_ = ctx.UncheckedCast();

    // Make sure the array type symbol gets created for the assembler to be able to emit checkcast.
    // Because it might not exist, if this particular array type was never created explicitly.
    if (!expr->is_unchecked_cast_ && target_type->IsETSArrayType()) {
        auto *const target_array_type = target_type->AsETSArrayType();
        checker->CreateBuiltinArraySignature(target_array_type, target_array_type->Rank());
    }

    expr->SetTsType(target_type);
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
    varbinder::Variable *enum_var = st->Key()->Variable();
    ASSERT(enum_var != nullptr);

    if (enum_var->TsType() == nullptr) {
        checker::Type *ets_enum_type;
        if (auto *const item_init = st->Members().front()->AsTSEnumMember()->Init(); item_init->IsNumberLiteral()) {
            ets_enum_type = checker->CreateETSEnumType(st);
        } else if (item_init->IsStringLiteral()) {
            ets_enum_type = checker->CreateETSStringEnumType(st);
        } else {
            checker->ThrowTypeError("Invalid enumeration value type.", st->Start());
        }
        st->SetTsType(ets_enum_type);
        ets_enum_type->SetVariable(enum_var);
        enum_var->SetTsType(ets_enum_type);
    } else if (st->TsType() == nullptr) {
        st->SetTsType(enum_var->TsType());
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

    checker::ETSObjectType *interface_type {};

    if (st->TsType() == nullptr) {
        interface_type = checker->BuildInterfaceProperties(st);
        ASSERT(interface_type != nullptr);
        interface_type->SetSuperType(checker->GlobalETSObjectType());
        checker->CheckInvokeMethodsLegitimacy(interface_type);
        st->SetTsType(interface_type);
    }

    checker::ScopeContext scope_ctx(checker, st->Scope());
    auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_INTERFACE, interface_type);

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
    auto expr_type = expr->expr_->Check(checker);

    if (!expr_type->IsNullish()) {
        checker->ThrowTypeError("Bad operand type, the operand of the non-null expression must be a nullable type",
                                expr->Expr()->Start());
    }

    expr->SetTsType(expr_type->IsNullish() ? checker->GetNonNullishType(expr_type) : expr_type);
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
    checker::Type *base_type = expr->Left()->Check(checker);
    if (base_type->IsETSObjectType()) {
        varbinder::Variable *prop =
            base_type->AsETSObjectType()->GetProperty(expr->Right()->Name(), checker::PropertySearchFlags::SEARCH_DECL);

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
