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

#include "binder/variableFlags.h"
#include "checker/types/ets/etsObjectType.h"
#include "ir/astNode.h"
#include "ir/typeNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classElement.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/scriptFunction.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/expressionStatement.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/superExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/returnStatement.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "binder/variable.h"
#include "binder/scope.h"
#include "binder/declaration.h"
#include "binder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/types/typeFlag.h"
#include "checker/types/ets/etsDynamicType.h"
#include "checker/types/ets/types.h"
#include "checker/ets/typeRelationContext.h"

namespace panda::es2panda::checker {
ETSObjectType *ETSChecker::GetSuperType(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_SUPER)) {
        return type->SuperType();
    }

    ASSERT(type->Variable() && type->GetDeclNode()->IsClassDefinition());
    auto *class_def = type->GetDeclNode()->AsClassDefinition();

    if (class_def->Super() == nullptr) {
        type->AddObjectFlag(ETSObjectFlags::RESOLVED_SUPER);
        if (type != GlobalETSObjectType()) {
            type->SetSuperType(GlobalETSObjectType());
        }
        return GlobalETSObjectType();
    }

    TypeStackElement tse(this, type, {"Cyclic inheritance involving ", type->Name(), "."}, class_def->Ident()->Start());

    Type *super_type = class_def->Super()->AsTypeNode()->GetType(this);

    if (!super_type->IsETSObjectType() || !super_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::CLASS)) {
        ThrowTypeError({"The super type of '", class_def->Ident()->Name(), "' class is not extensible."},
                       class_def->Super()->Start());
    }

    ETSObjectType *super_obj = super_type->AsETSObjectType();

    // struct node has class defination, too
    if (super_obj->GetDeclNode()->Parent()->IsETSStructDeclaration()) {
        ThrowTypeError({"struct ", class_def->Ident()->Name(), " is not extensible."}, class_def->Super()->Start());
    }

    if (super_obj->GetDeclNode()->IsFinal()) {
        ThrowTypeError("Cannot inherit with 'final' modifier.", class_def->Super()->Start());
    }

    type->SetSuperType(super_obj);
    GetSuperType(super_obj);

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_SUPER);
    return type->SuperType();
}

void ETSChecker::ValidateImplementedInterface(ETSObjectType *type, Type *interface,
                                              std::unordered_set<Type *> *extends_set, const lexer::SourcePosition &pos)
{
    if (!interface->IsETSObjectType() || !interface->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        ThrowTypeError("Interface expected here.", pos);
    }

    if (!extends_set->insert(interface).second) {
        ThrowTypeError("Repeated interface.", pos);
    }

    type->AddInterface(interface->AsETSObjectType());
    GetInterfacesOfInterface(interface->AsETSObjectType());
}

ArenaVector<ETSObjectType *> ETSChecker::GetInterfacesOfClass(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES)) {
        return type->Interfaces();
    }

    const auto *decl_node = type->GetDeclNode()->AsClassDefinition();

    std::unordered_set<Type *> extends_set;
    for (auto *it : decl_node->Implements()) {
        ValidateImplementedInterface(type, it->Expr()->AsTypeNode()->GetType(this), &extends_set, it->Start());
    }

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES);
    return type->Interfaces();
}

ArenaVector<ETSObjectType *> ETSChecker::GetInterfacesOfInterface(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES)) {
        return type->Interfaces();
    }

    const auto *decl_node = type->GetDeclNode()->AsTSInterfaceDeclaration();

    TypeStackElement tse(this, type, {"Cyclic inheritance involving ", type->Name(), "."}, decl_node->Id()->Start());

    std::unordered_set<Type *> extends_set;
    for (auto *it : decl_node->Extends()) {
        ValidateImplementedInterface(type, it->Expr()->AsTypeNode()->GetType(this), &extends_set, it->Start());
    }

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES);
    return type->Interfaces();
}

ArenaVector<ETSObjectType *> ETSChecker::GetInterfaces(ETSObjectType *type)
{
    ASSERT(type->GetDeclNode()->IsClassDefinition() || type->GetDeclNode()->IsTSInterfaceDeclaration());

    if (type->GetDeclNode()->IsClassDefinition()) {
        GetInterfacesOfClass(type);
    } else {
        GetInterfacesOfInterface(type);
    }

    return type->Interfaces();
}

void ETSChecker::SetTypeParameterType(ir::TSTypeParameter *type_param, Type *type_param_type)
{
    auto *var = type_param->Name()->Variable();
    var->SetTsType(type_param_type);
}

ArenaVector<Type *> ETSChecker::CreateTypeForTypeParameters(ir::TSTypeParameterDeclaration *type_params)
{
    ArenaVector<Type *> result {Allocator()->Adapter()};
    checker::ScopeContext scope_ctx(this, type_params->Scope());

    for (auto *const param : type_params->Params()) {
        result.push_back(CreateTypeParameterType(param));
    }

    return result;
}

Type *ETSChecker::CreateTypeParameterType(ir::TSTypeParameter *const param)
{
    ETSObjectType *param_type =
        CreateNewETSObjectType(param->Name()->Name(), param, GlobalETSObjectType()->ObjectFlags());
    param_type->SetAssemblerName(GlobalETSObjectType()->AssemblerName());
    param_type->AddTypeFlag(TypeFlag::GENERIC);
    param_type->AddObjectFlag(ETSObjectFlags::TYPE_PARAMETER);
    // We'll decide whether to make the supertype nullable after looking at constraint
    ETSObjectType *maybe_nullable_object =
        GlobalETSObjectType()->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsETSObjectType();
    param_type->SetSuperType(maybe_nullable_object);
    param_type->SetVariable(param->Variable());

    if (param->Constraint() != nullptr) {
        if (param->Constraint()->IsETSTypeReference() &&
            param->Constraint()->AsETSTypeReference()->Part()->Name()->IsIdentifier() &&
            param->Name()->Name() ==
                param->Constraint()->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name()) {
            ThrowTypeError({"Type variable '", param->Name()->Name(), "' cannot depend on itself"},
                           param->Constraint()->Start());
        }

        if (param->Constraint()->IsETSTypeReference()) {
            const auto constraint_name =
                param->Constraint()->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name();
            const auto *const type_param_scope = param->Parent()->AsTSTypeParameterDeclaration()->Scope();

            if (auto *const found_param = type_param_scope->FindLocal(constraint_name); found_param != nullptr) {
                CreateTypeParameterType(found_param->Declaration()->Node()->AsTSTypeParameter());
            }
        }

        auto *constraint_type = param->Constraint()->GetType(this);
        if (!constraint_type->IsETSObjectType()) {
            ThrowTypeError("Extends constraint must be an object", param->Constraint()->Start());
        }
        auto *constraint_obj_type = constraint_type->AsETSObjectType();
        param_type->SetAssemblerName(constraint_obj_type->AssemblerName());
        if (constraint_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
            param_type->AddInterface(constraint_obj_type);
        } else {
            param_type->SetSuperType(constraint_obj_type);
        }
        if (constraint_obj_type->IsNullableType()) {
            param_type->SuperType()->AddTypeFlag(TypeFlag::NULLABLE);
            param_type->AddTypeFlag(TypeFlag::NULLABLE);
        }
    } else {
        // No constraint, so it's Object|null
        param_type->SuperType()->AddTypeFlag(TypeFlag::NULLABLE);
        param_type->AddTypeFlag(TypeFlag::NULLABLE);
    }

    SetTypeParameterType(param, param_type);
    return param_type;
}

void ETSChecker::CreateTypeForClassOrInterfaceTypeParameters(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_TYPE_PARAMS)) {
        return;
    }

    ir::TSTypeParameterDeclaration *type_params = type->GetDeclNode()->IsClassDefinition()
                                                      ? type->GetDeclNode()->AsClassDefinition()->TypeParams()
                                                      : type->GetDeclNode()->AsTSInterfaceDeclaration()->TypeParams();
    type->SetTypeArguments(CreateTypeForTypeParameters(type_params));
    type->AddObjectFlag(ETSObjectFlags::RESOLVED_TYPE_PARAMS);
}

ETSObjectType *ETSChecker::BuildInterfaceProperties(ir::TSInterfaceDeclaration *interface_decl)
{
    auto *var = interface_decl->Id()->Variable();
    ASSERT(var);

    checker::ETSObjectType *interface_type {};
    if (var->TsType() == nullptr) {
        interface_type = CreateETSObjectType(var->Name(), interface_decl,
                                             checker::ETSObjectFlags::INTERFACE | checker::ETSObjectFlags::ABSTRACT);
        interface_type->SetVariable(var);
        var->SetTsType(interface_type);
    } else {
        interface_type = var->TsType()->AsETSObjectType();
    }

    if (interface_decl->TypeParams() != nullptr) {
        interface_type->AddTypeFlag(TypeFlag::GENERIC);
        CreateTypeForClassOrInterfaceTypeParameters(interface_type);
    }

    GetInterfacesOfInterface(interface_type);

    checker::ScopeContext scope_ctx(this, interface_decl->Scope());
    auto saved_context = checker::SavedCheckerContext(this, checker::CheckerStatus::IN_INTERFACE, interface_type);

    ResolveDeclaredMembersOfObject(interface_type);

    return interface_type;
}

ETSObjectType *ETSChecker::BuildClassProperties(ir::ClassDefinition *class_def)
{
    if (class_def->IsFinal() && class_def->IsAbstract()) {
        ThrowTypeError("Cannot use both 'final' and 'abstract' modifiers.", class_def->Start());
    }

    auto *var = class_def->Ident()->Variable();
    ASSERT(var);

    const util::StringView &class_name = class_def->Ident()->Name();
    auto *class_scope = class_def->Scope();

    checker::ETSObjectType *class_type {};
    if (var->TsType() == nullptr) {
        class_type = CreateETSObjectType(class_name, class_def, checker::ETSObjectFlags::CLASS);
        class_type->SetVariable(var);
        var->SetTsType(class_type);
        if (class_def->IsAbstract()) {
            class_type->AddObjectFlag(checker::ETSObjectFlags::ABSTRACT);
        }
    } else {
        class_type = var->TsType()->AsETSObjectType();
    }

    class_def->SetTsType(class_type);

    if (class_def->TypeParams() != nullptr) {
        class_type->AddTypeFlag(TypeFlag::GENERIC);
        CreateTypeForClassOrInterfaceTypeParameters(class_type);
    }

    auto *enclosing_class = Context().ContainingClass();
    class_type->SetEnclosingType(enclosing_class);
    CheckerStatus new_status = CheckerStatus::IN_CLASS;

    if (class_def->IsInner()) {
        new_status |= CheckerStatus::INNER_CLASS;
        class_type->AddObjectFlag(checker::ETSObjectFlags::INNER);
    }

    auto saved_context = checker::SavedCheckerContext(this, new_status, class_type);

    if (!class_type->HasObjectFlag(ETSObjectFlags::RESOLVED_SUPER)) {
        GetSuperType(class_type);
        GetInterfacesOfClass(class_type);
    }

    if (class_type->HasObjectFlag(ETSObjectFlags::RESOLVED_MEMBERS)) {
        return class_type;
    }

    checker::ScopeContext scope_ctx(this, class_scope);

    ResolveDeclaredMembersOfObject(class_type);

    return class_type;
}

ETSObjectType *ETSChecker::BuildAnonymousClassProperties(ir::ClassDefinition *class_def, ETSObjectType *super_type)
{
    auto class_type = CreateETSObjectType(class_def->Ident()->Name(), class_def, checker::ETSObjectFlags::CLASS);
    class_def->SetTsType(class_type);
    class_type->SetSuperType(super_type);
    class_type->AddObjectFlag(checker::ETSObjectFlags::RESOLVED_SUPER);

    checker::ScopeContext scope_ctx(this, class_def->Scope());
    auto saved_context = checker::SavedCheckerContext(this, checker::CheckerStatus::IN_CLASS, class_type);

    ResolveDeclaredMembersOfObject(class_type);

    return class_type;
}

void ETSChecker::ResolveDeclaredMembersOfObject(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_MEMBERS)) {
        return;
    }

    auto *decl_node = type->GetDeclNode();
    binder::ClassScope *scope = decl_node->IsTSInterfaceDeclaration()
                                    ? decl_node->AsTSInterfaceDeclaration()->Scope()->AsClassScope()
                                    : decl_node->AsClassDefinition()->Scope()->AsClassScope();

    for (auto &[_, it] : scope->InstanceFieldScope()->Bindings()) {
        (void)_;
        ASSERT(it->Declaration()->Node()->IsClassProperty());
        auto *class_prop = it->Declaration()->Node()->AsClassProperty();
        it->AddFlag(GetAccessFlagFromNode(class_prop));
        type->AddProperty<PropertyType::INSTANCE_FIELD>(it->AsLocalVariable());

        if (class_prop->TypeAnnotation() != nullptr && class_prop->TypeAnnotation()->IsETSFunctionType()) {
            type->AddProperty<PropertyType::INSTANCE_METHOD>(it->AsLocalVariable());
            it->AddFlag(binder::VariableFlags::METHOD_REFERENCE);
        }
    }

    for (auto &[_, it] : scope->StaticFieldScope()->Bindings()) {
        (void)_;
        ASSERT(it->Declaration()->Node()->IsClassProperty());
        auto *class_prop = it->Declaration()->Node()->AsClassProperty();
        it->AddFlag(GetAccessFlagFromNode(class_prop));
        type->AddProperty<PropertyType::STATIC_FIELD>(it->AsLocalVariable());

        if (class_prop->TypeAnnotation() != nullptr && class_prop->TypeAnnotation()->IsETSFunctionType()) {
            type->AddProperty<PropertyType::STATIC_METHOD>(it->AsLocalVariable());
            it->AddFlag(binder::VariableFlags::METHOD_REFERENCE);
        }
    }

    for (auto &[_, it] : scope->InstanceMethodScope()->Bindings()) {
        (void)_;
        auto *node = it->Declaration()->Node()->AsMethodDefinition();

        if (node->Function()->IsProxy()) {
            continue;
        }

        it->AddFlag(GetAccessFlagFromNode(node));
        auto *func_type = BuildMethodSignature(node);
        it->SetTsType(func_type);
        func_type->SetVariable(it);
        node->SetTsType(func_type);
        type->AddProperty<PropertyType::INSTANCE_METHOD>(it->AsLocalVariable());
    }

    for (auto &[_, it] : scope->StaticMethodScope()->Bindings()) {
        (void)_;
        if (!it->Declaration()->Node()->IsMethodDefinition() ||
            it->Declaration()->Node()->AsMethodDefinition()->Function()->IsProxy()) {
            continue;
        }
        auto *node = it->Declaration()->Node()->AsMethodDefinition();
        it->AddFlag(GetAccessFlagFromNode(node));
        auto *func_type = BuildMethodSignature(node);
        it->SetTsType(func_type);
        func_type->SetVariable(it);
        node->SetTsType(func_type);

        if (node->IsConstructor()) {
            type->AddConstructSignature(func_type->CallSignatures());
            continue;
        }

        type->AddProperty<PropertyType::STATIC_METHOD>(it->AsLocalVariable());
    }

    for (auto &[_, it] : scope->InstanceDeclScope()->Bindings()) {
        (void)_;
        it->AddFlag(GetAccessFlagFromNode(it->Declaration()->Node()));
        type->AddProperty<PropertyType::INSTANCE_DECL>(it->AsLocalVariable());
    }

    for (auto &[_, it] : scope->StaticDeclScope()->Bindings()) {
        (void)_;
        it->AddFlag(GetAccessFlagFromNode(it->Declaration()->Node()));
        type->AddProperty<PropertyType::STATIC_DECL>(it->AsLocalVariable());
    }

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_MEMBERS);
}

std::vector<Signature *> ETSChecker::CollectAbstractSignaturesFromObject(const ETSObjectType *obj_type)
{
    std::vector<Signature *> abstracts;
    for (const auto &prop : obj_type->Methods()) {
        GetTypeOfVariable(prop);

        if (!prop->TsType()->IsETSFunctionType()) {
            continue;
        }

        for (auto *sig : prop->TsType()->AsETSFunctionType()->CallSignatures()) {
            if (sig->HasSignatureFlag(SignatureFlags::ABSTRACT) && !sig->HasSignatureFlag(SignatureFlags::PRIVATE)) {
                abstracts.push_back(sig);
            }
        }
    }

    return abstracts;
}

void ETSChecker::CreateFunctionTypesFromAbstracts(const std::vector<Signature *> &abstracts,
                                                  ArenaVector<ETSFunctionType *> *target)
{
    for (auto *it : abstracts) {
        auto name = it->Function()->Id()->Name();
        auto *found = FindFunctionInVectorGivenByName(name, *target);
        if (found != nullptr) {
            found->AddCallSignature(it);
            continue;
        }

        auto *created = CreateETSFunctionType(it);
        created->AddTypeFlag(TypeFlag::SYNTHETIC);
        target->push_back(created);
    }
}

void ETSChecker::ComputeAbstractsFromInterface(ETSObjectType *interface_type)
{
    auto cached = cached_computed_abstracts_.find(interface_type);
    if (cached != cached_computed_abstracts_.end()) {
        return;
    }

    for (auto *it : interface_type->Interfaces()) {
        ComputeAbstractsFromInterface(it);
    }

    ArenaVector<ETSFunctionType *> merged(Allocator()->Adapter());
    CreateFunctionTypesFromAbstracts(CollectAbstractSignaturesFromObject(interface_type), &merged);
    std::unordered_set<ETSObjectType *> abstract_inheritance_target;

    for (auto *interface : interface_type->Interfaces()) {
        auto found = cached_computed_abstracts_.find(interface);
        ASSERT(found != cached_computed_abstracts_.end());

        if (!abstract_inheritance_target.insert(found->first).second) {
            continue;
        }

        MergeComputedAbstracts(merged, found->second.first);

        for (auto *base : found->second.second) {
            abstract_inheritance_target.insert(base);
        }
    }

    cached_computed_abstracts_.insert({interface_type, {merged, abstract_inheritance_target}});
}

ArenaVector<ETSFunctionType *> &ETSChecker::GetAbstractsForClass(ETSObjectType *class_type)
{
    ArenaVector<ETSFunctionType *> merged(Allocator()->Adapter());
    CreateFunctionTypesFromAbstracts(CollectAbstractSignaturesFromObject(class_type), &merged);

    std::unordered_set<ETSObjectType *> abstract_inheritance_target;
    if (class_type->SuperType() != nullptr) {
        auto base = cached_computed_abstracts_.find(class_type->SuperType());
        ASSERT(base != cached_computed_abstracts_.end());
        MergeComputedAbstracts(merged, base->second.first);

        abstract_inheritance_target.insert(base->first);
        for (auto *it : base->second.second) {
            abstract_inheritance_target.insert(it);
        }
    }

    for (auto *it : class_type->Interfaces()) {
        ComputeAbstractsFromInterface(it);
        auto found = cached_computed_abstracts_.find(it);
        ASSERT(found != cached_computed_abstracts_.end());

        if (!abstract_inheritance_target.insert(found->first).second) {
            continue;
        }

        MergeComputedAbstracts(merged, found->second.first);

        for (auto *interface : found->second.second) {
            abstract_inheritance_target.insert(interface);
        }
    }

    return cached_computed_abstracts_.insert({class_type, {merged, abstract_inheritance_target}}).first->second.first;
}

void ETSChecker::ValidateOverriding(ETSObjectType *class_type, const lexer::SourcePosition &pos)
{
    if (class_type->HasObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS)) {
        return;
    }

    bool throw_error = true;
    if (class_type->HasObjectFlag(ETSObjectFlags::ABSTRACT)) {
        throw_error = false;
    }

    if (class_type->SuperType() != nullptr) {
        ValidateOverriding(class_type->SuperType(), class_type->SuperType()->GetDeclNode()->Start());
    }

    auto &abstracts_to_be_implemented = GetAbstractsForClass(class_type);
    std::vector<Signature *> implemented_signatures;

    auto *super_iter = class_type;
    do {
        for (auto &it : abstracts_to_be_implemented) {
            for (const auto &prop : super_iter->Methods()) {
                GetTypeOfVariable(prop);
                AddImplementedSignature(&implemented_signatures, prop, it);
            }
        }
        super_iter = super_iter->SuperType();
    } while (super_iter != nullptr);

    SavedTypeRelationFlagsContext saved_flags_ctx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);
    for (auto it = abstracts_to_be_implemented.begin(); it != abstracts_to_be_implemented.end();) {
        bool function_overridden = false;
        for (auto abstract_signature = (*it)->CallSignatures().begin();
             abstract_signature != (*it)->CallSignatures().end();) {
            bool found_signature = false;
            for (auto *const implemented : implemented_signatures) {
                Signature *subst_implemented = AdjustForTypeParameters(*abstract_signature, implemented);
                if (subst_implemented == nullptr) {
                    continue;
                }
                if (AreOverrideEquivalent(*abstract_signature, subst_implemented) &&
                    IsReturnTypeSubstitutable(subst_implemented, *abstract_signature)) {
                    if (!implemented->Function()->IsOverride() && (implemented->Owner() == class_type)) {
                        ThrowTypeError("Method overriding is only allowed with 'override' modifier",
                                       implemented->Function()->Start());
                    }

                    if ((*it)->CallSignatures().size() > 1) {
                        abstract_signature = (*it)->CallSignatures().erase(abstract_signature);
                        found_signature = true;
                    } else {
                        it = abstracts_to_be_implemented.erase(it);
                        function_overridden = true;
                    }

                    break;
                }
            }

            if (function_overridden) {
                break;
            }

            if (!found_signature) {
                abstract_signature++;
            }
        }

        if (!function_overridden) {
            it++;
        }
    }

    if (!abstracts_to_be_implemented.empty() && throw_error) {
        auto unimplemented_signature = abstracts_to_be_implemented.front()->CallSignatures().front();
        ThrowTypeError({class_type->Name(), " is not abstract and does not override abstract method ",
                        unimplemented_signature->Function()->Id()->Name(), unimplemented_signature, " in ",
                        GetContainingObjectNameFromSignature(unimplemented_signature)},
                       pos);
    }

    class_type->AddObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS);
}

void ETSChecker::AddImplementedSignature(std::vector<Signature *> *implemented_signatures,
                                         binder::LocalVariable *function, ETSFunctionType *it)
{
    if (!function->TsType()->IsETSFunctionType()) {
        return;
    }

    for (auto signature : function->TsType()->AsETSFunctionType()->CallSignatures()) {
        if (signature->Function()->IsAbstract() || signature->Function()->IsStatic()) {
            continue;
        }

        if (signature->Function()->Id()->Name() == it->Name()) {
            implemented_signatures->emplace_back(signature);
        }
    }
}

void ETSChecker::CheckClassDefinition(ir::ClassDefinition *class_def)
{
    auto *class_type = class_def->TsType()->AsETSObjectType();
    auto *enclosing_class = Context().ContainingClass();
    auto new_status = checker::CheckerStatus::IN_CLASS;
    class_type->SetEnclosingType(enclosing_class);

    if (class_def->IsInner()) {
        new_status |= CheckerStatus::INNER_CLASS;
        class_type->AddObjectFlag(checker::ETSObjectFlags::INNER);
    }

    if (class_def->IsGlobal()) {
        class_type->AddObjectFlag(checker::ETSObjectFlags::GLOBAL);
    }

    checker::ScopeContext scope_ctx(this, class_def->Scope());
    auto saved_context = SavedCheckerContext(this, new_status, class_type);

    if (class_def->IsAbstract()) {
        AddStatus(checker::CheckerStatus::IN_ABSTRACT);
        class_type->AddObjectFlag(checker::ETSObjectFlags::ABSTRACT);
    }

    if (class_def->IsStatic() && !Context().ContainingClass()->HasObjectFlag(ETSObjectFlags::GLOBAL)) {
        AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    for (auto *it : class_def->Body()) {
        if (it->IsClassProperty()) {
            it->Check(this);
        }
    }

    for (auto *it : class_def->Body()) {
        if (!it->IsClassProperty()) {
            it->Check(this);
        }
    }
    CreateAsyncProxyMethods(class_def);

    if (class_def->IsGlobal()) {
        return;
    }

    for (auto *it : class_type->ConstructSignatures()) {
        CheckCyclicConstructorCall(it);
        CheckImplicitSuper(class_type, it);
    }

    ValidateOverriding(class_type, class_def->Start());
    CheckValidInheritance(class_type, class_def);
    CheckConstFields(class_type);
    CheckGetterSetterModifiers(class_def);
}

static bool IsAsyncMethod(ir::AstNode *node)
{
    if (!node->IsMethodDefinition()) {
        return false;
    }
    auto *method = node->AsMethodDefinition();
    return method->Function()->IsAsyncFunc() && !method->Function()->IsProxy();
}

void ETSChecker::CreateAsyncProxyMethods(ir::ClassDefinition *class_def)
{
    ArenaVector<ir::MethodDefinition *> async_impls(Allocator()->Adapter());
    for (auto *it : class_def->Body()) {
        if (IsAsyncMethod(it)) {
            auto *method = it->AsMethodDefinition();
            async_impls.push_back(CreateAsyncProxy(method, class_def));
            auto *proxy = async_impls.back();
            for (auto *overload : method->Overloads()) {
                auto *impl = CreateAsyncProxy(overload, class_def, false);
                impl->Function()->Id()->SetVariable(proxy->Function()->Id()->Variable());
                proxy->AddOverload(impl);
            }
        }
    }
    for (auto *it : async_impls) {
        it->Check(this);
        class_def->Body().push_back(it);
    }
}

void ETSChecker::CheckImplicitSuper(ETSObjectType *class_type, Signature *ctor_sig)
{
    if (class_type == GlobalETSObjectType()) {
        return;
    }

    auto &stmts = ctor_sig->Function()->Body()->AsBlockStatement()->Statements();
    const auto this_call = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        return stmt->IsExpressionStatement() && stmt->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
               stmt->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee()->IsThisExpression();
    });

    // There is an alternate constructor invocation, no need for super constructor invocation
    if (this_call != stmts.end()) {
        return;
    }

    const auto super_expr = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        return stmt->IsExpressionStatement() && stmt->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
               stmt->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee()->IsSuperExpression();
    });

    // There is no super expression
    if (super_expr == stmts.end()) {
        const auto super_type_ctor_sigs = class_type->SuperType()->ConstructSignatures();
        const auto super_type_ctor_sig = std::find_if(super_type_ctor_sigs.begin(), super_type_ctor_sigs.end(),
                                                      [](const Signature *sig) { return sig->Params().empty(); });

        // Super type has no parameterless ctor
        if (super_type_ctor_sig == super_type_ctor_sigs.end()) {
            ThrowTypeError("Must call super constructor", ctor_sig->Function()->Start());
        }

        ctor_sig->Function()->AddFlag(ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED);
    }
}

void ETSChecker::CheckConstFields(const ETSObjectType *class_type)
{
    for (const auto &prop : class_type->Fields()) {
        if (!prop->Declaration()->IsConstDecl() || !prop->HasFlag(binder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            continue;
        }
        CheckConstFieldInitialized(class_type, prop);
    }
}

void ETSChecker::CheckConstFieldInitialized(const ETSObjectType *class_type, binder::LocalVariable *class_var)
{
    const bool class_var_static = class_var->Declaration()->Node()->AsClassProperty()->IsStatic();
    for (const auto &prop : class_type->Methods()) {
        const auto &call_sigs = prop->TsType()->AsETSFunctionType()->CallSignatures();
        for (const auto *signature : call_sigs) {
            if ((signature->Function()->IsConstructor() && !class_var_static) ||
                (signature->Function()->IsStaticBlock() && class_var_static)) {
                CheckConstFieldInitialized(signature, class_var);
            }
        }
    }
}

void ETSChecker::FindAssignment(const ir::AstNode *node, const binder::LocalVariable *class_var, bool &initialized)
{
    if (node->IsAssignmentExpression() && node->AsAssignmentExpression()->Target() == class_var) {
        if (initialized) {
            ThrowTypeError({"Variable '", class_var->Declaration()->Name(), "' might already have been initialized"},
                           node->Start());
        }

        initialized = true;
        return;
    }

    FindAssignments(node, class_var, initialized);
}

void ETSChecker::FindAssignments(const ir::AstNode *node, const binder::LocalVariable *class_var, bool &initialized)
{
    node->Iterate([this, class_var, &initialized](ir::AstNode *child_node) {
        FindAssignment(child_node, class_var, initialized);
    });
}

void ETSChecker::CheckConstFieldInitialized(const Signature *signature, binder::LocalVariable *class_var)
{
    bool initialized = false;
    const auto &stmts = signature->Function()->Body()->AsBlockStatement()->Statements();
    const auto it = stmts.begin();

    if (it != stmts.end()) {
        if (const auto *first = *it;
            first->IsExpressionStatement() && first->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
            first->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee()->IsThisExpression()) {
            initialized = true;
        }
    }

    // TODO(szd) control flow
    FindAssignments(signature->Function()->Body(), class_var, initialized);
    if (!initialized) {
        ThrowTypeError({"Variable '", class_var->Declaration()->Name(), "' might not have been initialized"},
                       signature->Function()->End());
    }

    class_var->RemoveFlag(binder::VariableFlags::EXPLICIT_INIT_REQUIRED);
}

void ETSChecker::CheckInnerClassMembers(const ETSObjectType *class_type)
{
    for (const auto &[_, it] : class_type->StaticMethods()) {
        (void)_;
        ThrowTypeError("Inner class cannot have static methods", it->Declaration()->Node()->Start());
    }

    for (const auto &[_, it] : class_type->StaticFields()) {
        (void)_;
        if (!it->Declaration()->IsConstDecl()) {
            ThrowTypeError("Inner class cannot have non-const static properties", it->Declaration()->Node()->Start());
        }
    }
}

Type *ETSChecker::ValidateArrayIndex(ir::Expression *expr)
{
    auto expression_type = expr->Check(this);
    auto unboxed_expression_type = ETSBuiltinTypeAsPrimitiveType(expression_type);

    Type *index_type = ApplyUnaryOperatorPromotion(expression_type);

    if (expression_type->IsETSObjectType() && (unboxed_expression_type != nullptr)) {
        expr->AddBoxingUnboxingFlag(GetUnboxingFlag(unboxed_expression_type));
    }

    if (index_type == nullptr || !index_type->HasTypeFlag(TypeFlag::ETS_ARRAY_INDEX)) {
        std::stringstream message("");
        if (expression_type->IsNonPrimitiveType()) {
            message << expression_type->Variable()->Name();
        } else {
            expression_type->ToString(message);
        }

        ThrowTypeError(
            "Type '" + message.str() +
                "' cannot be used as an index type. Only primitive or unboxable integral types can be used as index.",
            expr->Start());
    }

    return index_type;
}

Type *ETSChecker::CheckArrayElementAccess(ir::MemberExpression *expr)
{
    Type *array_type = expr->Object()->Check(this);

    if (!array_type->IsETSArrayType() && !array_type->IsETSDynamicType()) {
        ThrowTypeError("Indexed access expression can only be used in array type.", expr->Object()->Start());
    }

    ValidateArrayIndex(expr->Property());

    if (expr->Property()->IsIdentifier()) {
        expr->SetPropVar(expr->Property()->AsIdentifier()->Variable()->AsLocalVariable());
    } else if (auto var = expr->Property()->Variable(); (var != nullptr) && var->IsLocalVariable()) {
        expr->SetPropVar(var->AsLocalVariable());
    }

    // TODO(user): apply capture conversion on this type
    if (array_type->IsETSArrayType()) {
        return array_type->AsETSArrayType()->ElementType();
    }

    // Dynamic
    return GlobalBuiltinDynamicType(array_type->AsETSDynamicType()->Language());
}

ETSObjectType *ETSChecker::CheckThisOrSuperAccess(ir::Expression *node, ETSObjectType *class_type, std::string_view msg)
{
    if (node->Parent()->IsCallExpression() && (node->Parent()->AsCallExpression()->Callee() == node)) {
        if (Context().ContainingSignature() == nullptr) {
            ThrowTypeError({"Call to '", msg, "' must be first statement in constructor"}, node->Start());
        }

        auto *sig = Context().ContainingSignature();
        ASSERT(sig->Function()->Body() && sig->Function()->Body()->IsBlockStatement());

        if (!sig->HasSignatureFlag(checker::SignatureFlags::CONSTRUCT)) {
            ThrowTypeError({"Call to '", msg, "' must be first statement in constructor"}, node->Start());
        }

        if (sig->Function()->Body()->AsBlockStatement()->Statements().front() != node->Parent()->Parent()) {
            ThrowTypeError({"Call to '", msg, "' must be first statement in constructor"}, node->Start());
        }
    }

    if (HasStatus(checker::CheckerStatus::IN_STATIC_CONTEXT)) {
        ThrowTypeError({"'", msg, "' cannot be referenced from a static context"}, node->Start());
    }

    if (class_type->GetDeclNode()->AsClassDefinition()->IsGlobal()) {
        ThrowTypeError({"Cannot reference '", msg, "' in this context."}, node->Start());
    }

    return class_type;
}

void ETSChecker::CheckCyclicConstructorCall(Signature *signature)
{
    ASSERT(signature->Function());

    if (signature->Function()->Body() == nullptr || signature->Function()->IsExternal()) {
        return;
    }

    auto *func_body = signature->Function()->Body()->AsBlockStatement();

    TypeStackElement tse(this, signature, "Recursive constructor invocation", signature->Function()->Start());

    if (!func_body->Statements().empty() && func_body->Statements()[0]->IsExpressionStatement() &&
        func_body->Statements()[0]->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
        func_body->Statements()[0]
            ->AsExpressionStatement()
            ->GetExpression()
            ->AsCallExpression()
            ->Callee()
            ->IsThisExpression()) {
        auto *constructor_call =
            func_body->Statements()[0]->AsExpressionStatement()->GetExpression()->AsCallExpression();
        ASSERT(constructor_call->Signature());
        CheckCyclicConstructorCall(constructor_call->Signature());
    }
}

ETSObjectType *ETSChecker::CheckExceptionOrErrorType(checker::Type *type, const lexer::SourcePosition pos)
{
    if (!type->IsETSObjectType() || (!Relation()->IsAssignableTo(type, GlobalBuiltinExceptionType()) &&
                                     !Relation()->IsAssignableTo(type, GlobalBuiltinErrorType()))) {
        ThrowTypeError({"Argument must be an instance of '", compiler::Signatures::BUILTIN_EXCEPTION_CLASS, "' or '",
                        compiler::Signatures::BUILTIN_ERROR_CLASS, "'"},
                       pos);
    }

    return type->AsETSObjectType();
}

Type *ETSChecker::TryToInstantiate(Type *const type, ArenaAllocator *const allocator, TypeRelation *const relation,
                                   GlobalTypesHolder *const global_types)
{
    // TODO(user): Handle generic functions
    auto *return_type = type;
    const bool is_incomplete =
        type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INCOMPLETE_INSTANTIATION);
    if (const bool is_function_type = type->IsETSFunctionType(); is_function_type || is_incomplete) {
        return_type = type->Instantiate(allocator, relation, global_types);
    }

    return return_type;
}

void ETSChecker::ValidateResolvedProperty(const binder::LocalVariable *const property,
                                          const ETSObjectType *const target, const ir::Identifier *const ident,
                                          const PropertySearchFlags flags)
{
    if (property != nullptr) {
        return;
    }

    using Utype = std::underlying_type_t<PropertySearchFlags>;
    static constexpr uint32_t CORRECT_PROPERTY_SEARCH_ORDER_INSTANCE = 7U;
    static_assert(static_cast<Utype>(PropertySearchFlags::SEARCH_INSTANCE) == CORRECT_PROPERTY_SEARCH_ORDER_INSTANCE,
                  "PropertySearchFlags order changed");
    static constexpr uint32_t CORRECT_PROPERTY_SEARCH_ORDER_STATIC = 56U;
    static_assert(static_cast<Utype>(PropertySearchFlags::SEARCH_STATIC) == CORRECT_PROPERTY_SEARCH_ORDER_STATIC,
                  "PropertySearchFlags order changed");
    const auto flags_num = static_cast<Utype>(flags);
    // This algorithm swaps the first 3 bits of a number with it's consecutive 3 bits, example: 0b110001 -> 0b001110
    // Effectively it changes PropertySearchFlags to search for the appropriate declarations
    const Utype x = (flags_num ^ (flags_num >> 3U)) & 7U;
    const auto new_flags = PropertySearchFlags {flags_num ^ (x | (x << 3U))};

    const auto *const new_prop = target->GetProperty(ident->Name(), new_flags);
    if (new_prop == nullptr) {
        ThrowTypeError({"Property '", ident->Name(), "' does not exist on type '", target->Name(), "'"},
                       ident->Start());
    }
    if (IsVariableStatic(new_prop)) {
        ThrowTypeError({"'", ident->Name(), "' is a static property of '", target->Name(), "'"}, ident->Start());
    } else {
        ThrowTypeError({"'", ident->Name(), "' is an instance property of '", target->Name(), "'"}, ident->Start());
    }
}

void ETSChecker::CreateBinaryExpressionForSetter(ir::Expression *member)
{
    ASSERT(member->Parent()->IsAssignmentExpression());

    auto *assignment_expr = member->Parent()->AsAssignmentExpression();
    if (GetOperatorForSetterGetter(assignment_expr)) {
        assignment_expr->CreateBinaryExpressionForRight(this);

        if (member->IsMemberExpression() &&
            member->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::GETTER)) {
            member->AsMemberExpression()->RemoveMemberKind(ir::MemberExpressionKind::GETTER);
        }
    }
}

// NOLINTNEXTLINE(readability-function-size)
binder::LocalVariable *ETSChecker::ResolveMemberReference(const ir::MemberExpression *const member_expr,
                                                          const ETSObjectType *const target)
{
    if (target->IsETSDynamicType()) {
        auto prop_name = member_expr->Property()->AsIdentifier()->Name();
        binder::LocalVariable *prop_var = target->AsETSDynamicType()->GetPropertyDynamic(prop_name, this);
        return prop_var;
    }

    auto search_flag = [member_expr]() {
        const auto base_flags = PropertySearchFlags::SEARCH_IN_BASE | PropertySearchFlags::SEARCH_IN_INTERFACES;

        switch (member_expr->Parent()->Type()) {
            case ir::AstNodeType::CALL_EXPRESSION: {
                if (member_expr->Parent()->AsCallExpression()->Callee() == member_expr) {
                    return PropertySearchFlags::SEARCH_METHOD | base_flags;
                }

                if (member_expr->HasMemberKind(ir::MemberExpressionKind::GETTER)) {
                    return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                           PropertySearchFlags::IS_GETTER;
                }

                break;
            }
            case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
                if (member_expr->Parent()->AsETSNewClassInstanceExpression()->GetTypeRef() == member_expr) {
                    return PropertySearchFlags::SEARCH_DECL | base_flags;
                }

                break;
            }
            case ir::AstNodeType::MEMBER_EXPRESSION: {
                return PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL | base_flags;
            }
            case ir::AstNodeType::VARIABLE_DECLARATOR: {
                const auto *var_init = member_expr->Parent()->AsVariableDeclarator()->Init();
                if (var_init->IsMemberExpression() &&
                    var_init->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::GETTER)) {
                    return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                           PropertySearchFlags::IS_GETTER;
                }

                break;
            }
            case ir::AstNodeType::UPDATE_EXPRESSION:
            case ir::AstNodeType::UNARY_EXPRESSION:
            case ir::AstNodeType::BINARY_EXPRESSION: {
                auto prop_search_flags = PropertySearchFlags::SEARCH_FIELD;
                if (member_expr->Parent()->IsBinaryExpression()) {
                    const auto *binary = member_expr->Parent()->AsBinaryExpression();
                    auto properflags = [](const ir::MemberExpression *expr) {
                        if (expr->HasMemberKind(ir::MemberExpressionKind::GETTER)) {
                            return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                   PropertySearchFlags::IS_GETTER;
                        }

                        return PropertySearchFlags::NO_OPTS;
                    };

                    if (binary->Left()->IsMemberExpression()) {
                        prop_search_flags |= properflags(binary->Left()->AsMemberExpression());
                    }

                    if (binary->Right()->IsMemberExpression()) {
                        prop_search_flags |= properflags(binary->Right()->AsMemberExpression());
                    }
                }

                return prop_search_flags | base_flags;
            }
            case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
                const auto *const assignment_expr = member_expr->Parent()->AsAssignmentExpression();

                if (assignment_expr->Left()->IsMemberExpression() &&
                    assignment_expr->Left()->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::SETTER)) {
                    if (assignment_expr->Right()->IsMemberExpression() &&
                        assignment_expr->Right()->AsMemberExpression()->HasMemberKind(
                            ir::MemberExpressionKind::GETTER)) {
                        return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                               PropertySearchFlags::IS_GETTER;
                    }

                    if (assignment_expr->Right()->IsBinaryExpression()) {
                        const auto *binary_expr = assignment_expr->Right()->AsBinaryExpression();
                        if ((binary_expr->Left()->IsMemberExpression() &&
                             binary_expr->Left()->AsMemberExpression()->HasMemberKind(
                                 ir::MemberExpressionKind::GETTER)) ||
                            (binary_expr->Right()->IsMemberExpression() &&
                             binary_expr->Right()->AsMemberExpression()->HasMemberKind(
                                 ir::MemberExpressionKind::GETTER))) {
                            return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                   PropertySearchFlags::IS_GETTER;
                        }
                    }

                    return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                           PropertySearchFlags::IS_SETTER;
                }

                if (assignment_expr->Left() == member_expr) {
                    return PropertySearchFlags::SEARCH_FIELD | base_flags;
                }

                if (assignment_expr->Right() == member_expr) {
                    auto *target_type = assignment_expr->Left()->TsType();
                    ASSERT(target_type != nullptr);

                    if (target_type->IsETSObjectType() &&
                        target_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
                        return PropertySearchFlags::SEARCH_METHOD | base_flags;
                    }

                    ASSERT(assignment_expr->Right()->IsMemberExpression());
                    if (assignment_expr->Right()->AsMemberExpression()->HasMemberKind(
                            ir::MemberExpressionKind::GETTER)) {
                        return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                               PropertySearchFlags::IS_GETTER;
                    }

                    return PropertySearchFlags::SEARCH_FIELD | base_flags;
                }

                break;
            }
            case ir::AstNodeType::RETURN_STATEMENT: {
                const auto *return_statement = member_expr->Parent()->AsReturnStatement();
                if (return_statement->Argument()->IsMemberExpression() &&
                    return_statement->Argument()->AsMemberExpression()->HasMemberKind(
                        ir::MemberExpressionKind::GETTER)) {
                    return PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                           PropertySearchFlags::IS_GETTER;
                }

                break;
            }
            default: {
                break;
            }
        }

        return PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_METHOD | base_flags;
    }();

    const auto *const target_ref = [member_expr]() -> const binder::Variable * {
        if (member_expr->Object()->IsIdentifier()) {
            return member_expr->Object()->AsIdentifier()->Variable();
        }
        if (member_expr->Object()->IsMemberExpression()) {
            return member_expr->Object()->AsMemberExpression()->PropVar();
        }
        return nullptr;
    }();

    if (target_ref != nullptr && target_ref->HasFlag(binder::VariableFlags::CLASS_OR_INTERFACE)) {
        search_flag &= ~(PropertySearchFlags::SEARCH_INSTANCE);
    } else if (member_expr->Object()->IsThisExpression() ||
               (member_expr->Object()->IsIdentifier() && member_expr->ObjType()->GetDeclNode() != nullptr &&
                member_expr->ObjType()->GetDeclNode()->IsTSInterfaceDeclaration())) {
        search_flag &= ~(PropertySearchFlags::SEARCH_STATIC);
    }

    if (target->HasTypeFlag(TypeFlag::GENERIC)) {
        search_flag |= PropertySearchFlags::SEARCH_ALL;
    }

    auto *const prop = target->GetProperty(member_expr->Property()->AsIdentifier()->Name(), search_flag);
    ValidateResolvedProperty(prop, target, member_expr->Property()->AsIdentifier(), search_flag);

    if (prop->TsType() != nullptr) {
        if ((search_flag & PropertySearchFlags::IS_GETTER) != 0) {
            const auto get_return_type = [](ir::MethodDefinition *method) {
                if (method->Kind() == ir::MethodDefinitionKind::GET) {
                    return method->Function()->Signature()->ReturnType();
                }

                return method->Overloads()[0]->Function()->Signature()->ReturnType();
            };

            const auto &methods = member_expr->AsMemberExpression()->ObjType()->InstanceMethods();
            const auto res = methods.find(member_expr->Property()->AsIdentifier()->Name());
            if (res != methods.end()) {
                prop->SetTsType(get_return_type(res->second->Declaration()->Node()->AsMethodDefinition()));
            } else {
                const auto &static_methods = member_expr->AsMemberExpression()->ObjType()->StaticMethods();
                const auto static_res = static_methods.find(member_expr->Property()->AsIdentifier()->Name());
                if (static_res != static_methods.end()) {
                    prop->SetTsType(get_return_type(static_res->second->Declaration()->Node()->AsMethodDefinition()));
                }
            }

            return prop;
        }

        if ((search_flag & PropertySearchFlags::IS_SETTER) != 0) {
            const auto &func_type = prop->TsType()->AsETSFunctionType();
            for (const auto *sig : func_type->CallSignatures()) {
                if (sig->Function()->IsSetter()) {
                    if (sig->Function()->ReturnTypeAnnotation() != nullptr &&
                        sig->Function()->ReturnTypeAnnotation()->TsType() != GlobalBuiltinVoidType()) {
                        ThrowTypeError("Setter must have void return type", sig->Function()->Start());
                    }

                    func_type->AddTypeFlag(TypeFlag::SETTER);
                }
            }

            return prop;
        }
    }

    // Before returning the computed property variable, we have to validate the special case where we are in a variable
    // declaration, and the properties type is a function type but the currently declared variable doesn't have a type
    // annotation
    if (member_expr->Parent()->IsVariableDeclarator() || member_expr->Parent()->IsClassProperty()) {
        const auto [target_ident,
                    type_annotation] = [member_expr]() -> std::pair<const ir::Identifier *, const ir::TypeNode *> {
            if (member_expr->Parent()->IsVariableDeclarator()) {
                const auto *const ident = member_expr->Parent()->AsVariableDeclarator()->Id()->AsIdentifier();
                return {ident, ident->TypeAnnotation()};
            }
            return {member_expr->Parent()->AsClassProperty()->Key()->AsIdentifier(),
                    member_expr->Parent()->AsClassProperty()->TypeAnnotation()};
        }();

        GetTypeOfVariable(prop);

        if (prop->TsType()->IsETSFunctionType()) {
            if (type_annotation == nullptr) {
                ThrowTypeError({"Cannot infer type for ", target_ident->Name(),
                                " because method reference needs an explicit target type"},
                               target_ident->Start());
            }

            auto *target_type = GetTypeOfVariable(target_ident->Variable());
            ASSERT(target_type != nullptr);

            if (!target_type->IsETSObjectType() ||
                !target_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
                ThrowTypeError(
                    {"Method ", member_expr->Property()->AsIdentifier()->Name(), " does not exist on this type."},
                    member_expr->Property()->Start());
            }
        }
    }

    return prop;
}

void ETSChecker::CheckValidInheritance(ETSObjectType *class_type, ir::ClassDefinition *class_def)
{
    if (class_type->SuperType() == nullptr) {
        return;
    }

    if (class_def->TypeParams() != nullptr &&
        (Relation()->IsAssignableTo(class_type->SuperType(), GlobalBuiltinExceptionType()) ||
         Relation()->IsAssignableTo(class_type->SuperType(), GlobalBuiltinErrorType()))) {
        ThrowTypeError({"Generics are not allowed as '", compiler::Signatures::BUILTIN_EXCEPTION_CLASS, "' or '",
                        compiler::Signatures::BUILTIN_ERROR_CLASS, "' subclasses."},
                       class_def->TypeParams()->Start());
    }

    const auto &all_props = class_type->GetAllProperties();

    for (auto *it : all_props) {
        auto *found = class_type->SuperType()->GetProperty(
            it->Name(), PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE |
                            PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);

        if (found == nullptr) {
            continue;
        }

        if (!IsSameDeclarationType(it, found)) {
            const char *target_type {};

            if (it->HasFlag(binder::VariableFlags::PROPERTY)) {
                target_type = "field";
            } else if (it->HasFlag(binder::VariableFlags::METHOD)) {
                target_type = "method";
            } else if (it->HasFlag(binder::VariableFlags::CLASS)) {
                target_type = "class";
            } else if (it->HasFlag(binder::VariableFlags::INTERFACE)) {
                target_type = "interface";
            } else {
                target_type = "enum";
            }

            ThrowTypeError({"Cannot inherit from class ", class_type->SuperType()->Name(), ", because ", target_type,
                            " ", it->Name(), " is inherited with a different declaration type"},
                           class_def->Super()->Start());
        }
    }
}

void ETSChecker::CheckGetterSetterModifiers(const ir::ClassDefinition *class_def)
{
    const auto accessor_modifiers = ir::ModifierFlags::ACCESSOR_MODIFIERS;

    const auto check_modifiers = [this](const ir::ModifierFlags base_modifiers, const ir::ModifierFlags other_modifiers,
                                        const lexer::SourcePosition &pos) {
        if (static_cast<uint32_t>(accessor_modifiers & base_modifiers) !=
            static_cast<uint32_t>(accessor_modifiers & other_modifiers)) {
            ThrowTypeError("Getter and setter methods must have the same accessor modifiers", pos);
        }
    };

    for (auto *it : class_def->Body()) {
        if (it->IsMethodDefinition() &&
            (it->AsMethodDefinition()->Function()->IsGetter() || it->AsMethodDefinition()->Function()->IsSetter())) {
            // Base case
            if (!it->AsMethodDefinition()->Overloads().empty()) {
                check_modifiers(it->AsMethodDefinition()->Modifiers(),
                                it->AsMethodDefinition()->Overloads()[0]->Modifiers(),
                                it->AsMethodDefinition()->Start());
                return;
            }
            // Static case
            if (it->AsMethodDefinition()->IsStatic()) {
                for (auto class_body : class_def->Body()) {
                    if (class_body->IsMethodDefinition() &&
                        (class_body->AsMethodDefinition()->Function()->IsGetter() ||
                         class_body->AsMethodDefinition()->Function()->IsSetter())) {
                        const auto *base = class_body->AsMethodDefinition();
                        const auto *other = it->AsMethodDefinition();
                        if (base != other &&
                            base->Function()->Id()->Name().Is(other->Function()->Id()->Name().Mutf8())) {
                            check_modifiers(base->Modifiers(), other->Modifiers(), base->Start());
                        }
                    }
                }
            }
        }
    }
}

void ETSChecker::AddElementsToModuleObject(ETSObjectType *module_obj, const util::StringView &str)
{
    for (const auto &[name, var] : Binder()->GetScope()->Bindings()) {
        if (name.Is(str.Mutf8()) || name.Is(compiler::Signatures::ETS_GLOBAL)) {
            continue;
        }

        if (var->HasFlag(binder::VariableFlags::METHOD)) {
            module_obj->AddProperty<checker::PropertyType::STATIC_METHOD>(var->AsLocalVariable());
        } else if (var->HasFlag(binder::VariableFlags::PROPERTY)) {
            module_obj->AddProperty<checker::PropertyType::STATIC_FIELD>(var->AsLocalVariable());
        } else {
            module_obj->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }
}

Type *ETSChecker::FindLeastUpperBound(Type *source, Type *target)
{
    ASSERT(source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) && target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT));

    // GetCommonClass(GenA<A>, GenB<B>) => LUB(GenA, GenB)<T>
    auto common_class = GetCommonClass(source, target);

    if (!common_class->IsETSObjectType() || !common_class->HasTypeFlag(TypeFlag::GENERIC)) {
        return common_class->HasTypeFlag(TypeFlag::CONSTANT) ? common_class->Variable()->TsType() : common_class;
    }

    // GetRelevantArgumentedTypeFromChild(GenA<A>, LUB(GenA, GenB)<T>) => LUB(GenA, GenB)<A>
    ETSObjectType *relevant_source_type =
        GetRelevantArgumentedTypeFromChild(source->AsETSObjectType(), common_class->AsETSObjectType());
    ETSObjectType *relevant_target_type =
        GetRelevantArgumentedTypeFromChild(target->AsETSObjectType(), common_class->AsETSObjectType());

    // GetTypeargumentedLUB(LUB(GenA, GenB)<A>, LUB(GenA, GenB)<B>) => LUB(GenA, GenB)<LUB(A, B)>
    return GetTypeargumentedLUB(relevant_source_type, relevant_target_type);
}

Type *ETSChecker::GetCommonClass(Type *source, Type *target)
{
    SavedTypeRelationFlagsContext checker_ctx(this->Relation(), TypeRelationFlag::IGNORE_TYPE_PARAMETERS);

    if (IsTypeIdenticalTo(source, target)) {
        return source;
    }

    target->IsSupertypeOf(Relation(), source);
    if (Relation()->IsTrue()) {
        return target;
    }

    source->IsSupertypeOf(Relation(), target);
    if (Relation()->IsTrue()) {
        return source;
    }

    if (source->IsETSObjectType() && target->IsETSObjectType()) {
        if (source->IsETSNullType()) {
            return target;
        }

        if (target->IsETSNullType()) {
            return source;
        }

        if (source->AsETSObjectType()->GetDeclNode() == target->AsETSObjectType()->GetDeclNode()) {
            return source;
        }

        return GetClosestCommonAncestor(source->AsETSObjectType(), target->AsETSObjectType());
    }

    return GlobalETSObjectType();
}

ETSObjectType *ETSChecker::GetClosestCommonAncestor(ETSObjectType *source, ETSObjectType *target)
{
    ASSERT(target->SuperType() != nullptr);

    auto *target_base = GetOriginalBaseType(target->SuperType());
    auto *target_type = target_base == nullptr ? target->SuperType() : target_base;

    auto *source_base = GetOriginalBaseType(source);
    auto *source_type = source_base == nullptr ? source : source_base;

    target_type->IsSupertypeOf(Relation(), source_type);
    if (Relation()->IsTrue()) {
        // TODO(TorokG): Extending the search to find intersection types
        return target_type;
    }

    return GetClosestCommonAncestor(source_type, target_type);
}

ETSObjectType *ETSChecker::GetTypeargumentedLUB(ETSObjectType *const source, ETSObjectType *const target)
{
    ASSERT(source->TypeArguments().size() == target->TypeArguments().size());

    ArenaVector<Type *> params(Allocator()->Adapter());

    for (uint32_t i = 0; i < source->TypeArguments().size(); i++) {
        params.push_back(FindLeastUpperBound(source->TypeArguments()[i], target->TypeArguments()[i]));
    }

    const util::StringView hash = GetHashFromTypeArguments(params);

    ETSObjectType *template_type = source->GetDeclNode()->AsClassDefinition()->TsType()->AsETSObjectType();

    auto *lub_type = template_type->GetInstantiatedType(hash);

    if (lub_type == nullptr) {
        lub_type = template_type->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsETSObjectType();
        lub_type->SetTypeArguments(std::move(params));

        template_type->GetInstantiationMap().try_emplace(hash, lub_type);
    }

    return lub_type;
}

}  // namespace panda::es2panda::checker
