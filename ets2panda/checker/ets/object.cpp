/**
 * Copyright (c) 2021-2023 - Huawei Device Co., Ltd.
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

#include "varbinder/variableFlags.h"
#include "checker/ets/castingContext.h"
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
#include "varbinder/variable.h"
#include "varbinder/scope.h"
#include "varbinder/declaration.h"
#include "varbinder/ETSBinder.h"
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
    auto *classDef = type->GetDeclNode()->AsClassDefinition();

    if (classDef->Super() == nullptr) {
        type->AddObjectFlag(ETSObjectFlags::RESOLVED_SUPER);
        if (type != GlobalETSObjectType()) {
            type->SetSuperType(GlobalETSObjectType());
        }
        return GlobalETSObjectType();
    }

    TypeStackElement tse(this, type, {"Cyclic inheritance involving ", type->Name(), "."}, classDef->Ident()->Start());

    Type *superType = classDef->Super()->AsTypeNode()->GetType(this);

    if (!superType->IsETSObjectType() || !superType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::CLASS)) {
        ThrowTypeError({"The super type of '", classDef->Ident()->Name(), "' class is not extensible."},
                       classDef->Super()->Start());
    }

    ETSObjectType *superObj = superType->AsETSObjectType();

    // struct node has class defination, too
    if (superObj->GetDeclNode()->Parent()->IsETSStructDeclaration()) {
        ThrowTypeError({"struct ", classDef->Ident()->Name(), " is not extensible."}, classDef->Super()->Start());
    }

    if (superObj->GetDeclNode()->IsFinal()) {
        ThrowTypeError("Cannot inherit with 'final' modifier.", classDef->Super()->Start());
    }

    type->SetSuperType(superObj);
    GetSuperType(superObj);

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_SUPER);
    return type->SuperType();
}

void ETSChecker::ValidateImplementedInterface(ETSObjectType *type, Type *interface,
                                              std::unordered_set<Type *> *extendsSet, const lexer::SourcePosition &pos)
{
    if (!interface->IsETSObjectType() || !interface->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        ThrowTypeError("Interface expected here.", pos);
    }

    if (!extendsSet->insert(interface).second) {
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

    const auto *declNode = type->GetDeclNode()->AsClassDefinition();

    std::unordered_set<Type *> extendsSet;
    for (auto *it : declNode->Implements()) {
        ValidateImplementedInterface(type, it->Expr()->AsTypeNode()->GetType(this), &extendsSet, it->Start());
    }

    type->AddObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES);
    return type->Interfaces();
}

ArenaVector<ETSObjectType *> ETSChecker::GetInterfacesOfInterface(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_INTERFACES)) {
        return type->Interfaces();
    }

    const auto *declNode = type->GetDeclNode()->AsTSInterfaceDeclaration();

    TypeStackElement tse(this, type, {"Cyclic inheritance involving ", type->Name(), "."}, declNode->Id()->Start());

    std::unordered_set<Type *> extendsSet;
    for (auto *it : declNode->Extends()) {
        ValidateImplementedInterface(type, it->Expr()->AsTypeNode()->GetType(this), &extendsSet, it->Start());
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

ArenaVector<Type *> ETSChecker::CreateTypeForTypeParameters(ir::TSTypeParameterDeclaration *typeParams)
{
    ArenaVector<Type *> result {Allocator()->Adapter()};
    checker::ScopeContext scopeCtx(this, typeParams->Scope());

    // Note: we have to run pure check loop first to avoid endless loop because of possible circular dependencies
    Type2TypeMap extends {};
    for (auto *const typeParam : typeParams->Params()) {
        if (auto *const constraint = typeParam->Constraint();
            constraint != nullptr && constraint->IsETSTypeReference() &&
            constraint->AsETSTypeReference()->Part()->Name()->IsIdentifier()) {
            CheckTypeParameterConstraint(typeParam, extends);
        }
    }

    for (auto *const typeParam : typeParams->Params()) {
        result.emplace_back(SetUpParameterType(typeParam));
    }

    // The type parameter might be used in the constraint, like 'K extend Comparable<K>',
    // so we need to create their type first, then set up the constraint
    for (auto *const param : typeParams->Params()) {
        SetUpTypeParameterConstraint(param);
    }

    return result;
}

void ETSChecker::CheckTypeParameterConstraint(ir::TSTypeParameter *param, Type2TypeMap &extends)
{
    const auto typeParamName = param->Name()->Name().Utf8();
    const auto constraintName =
        param->Constraint()->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name().Utf8();
    if (typeParamName == constraintName) {
        ThrowTypeError({"Type parameter '", typeParamName, "' cannot extend/implement itself."},
                       param->Constraint()->Start());
    }

    auto it = extends.find(typeParamName);
    if (it != extends.cend()) {
        ThrowTypeError({"Type parameter '", typeParamName, "' is duplicated in the list."},
                       param->Constraint()->Start());
    }

    it = extends.find(constraintName);
    while (it != extends.cend()) {
        if (it->second == typeParamName) {
            ThrowTypeError({"Type parameter '", typeParamName, "' has circular constraint dependency."},
                           param->Constraint()->Start());
        }
        it = extends.find(it->second);
    }

    extends.emplace(typeParamName, constraintName);
}

void ETSChecker::SetUpTypeParameterConstraint(ir::TSTypeParameter *const param)
{
    ETSTypeParameter *const paramType = [this, param]() {
        auto *const type = param->Name()->Variable()->TsType();
        return type != nullptr ? type->AsETSTypeParameter() : SetUpParameterType(param);
    }();

    auto const traverseReferenced =
        [this, scope = param->Parent()->AsTSTypeParameterDeclaration()->Scope()](ir::TypeNode *typeNode) {
            if (!typeNode->IsETSTypeReference()) {
                return;
            }
            const auto typeName = typeNode->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name();
            auto *const found = scope->FindLocal(typeName, varbinder::ResolveBindingOptions::BINDINGS);
            if (found != nullptr) {
                SetUpTypeParameterConstraint(found->Declaration()->Node()->AsTSTypeParameter());
            }
        };

    if (param->Constraint() != nullptr) {
        traverseReferenced(param->Constraint());
        auto *const constraint = param->Constraint()->GetType(this);
        if (!constraint->IsETSObjectType() && !constraint->IsETSTypeParameter() && !constraint->IsETSUnionType()) {
            ThrowTypeError("Extends constraint must be an object", param->Constraint()->Start());
        }
        paramType->SetConstraintType(constraint);
    }
    if (param->DefaultType() != nullptr) {
        traverseReferenced(param->DefaultType());
        auto *const dflt = param->DefaultType()->GetType(this);
        // NOTE: #14993 ensure default matches constraint
        paramType->SetDefaultType(dflt);
    }
}

ETSTypeParameter *ETSChecker::SetUpParameterType(ir::TSTypeParameter *const param)
{
    auto *const paramType = CreateTypeParameter();

    paramType->AddTypeFlag(TypeFlag::GENERIC);
    paramType->SetDeclNode(param);
    paramType->SetVariable(param->Variable());

    param->Name()->Variable()->SetTsType(paramType);
    return paramType;
}

void ETSChecker::CreateTypeForClassOrInterfaceTypeParameters(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_TYPE_PARAMS)) {
        return;
    }

    ir::TSTypeParameterDeclaration *typeParams = type->GetDeclNode()->IsClassDefinition()
                                                     ? type->GetDeclNode()->AsClassDefinition()->TypeParams()
                                                     : type->GetDeclNode()->AsTSInterfaceDeclaration()->TypeParams();
    type->SetTypeArguments(CreateTypeForTypeParameters(typeParams));
    type->AddObjectFlag(ETSObjectFlags::RESOLVED_TYPE_PARAMS);
}

ETSObjectType *ETSChecker::BuildInterfaceProperties(ir::TSInterfaceDeclaration *interfaceDecl)
{
    auto *var = interfaceDecl->Id()->Variable();
    ASSERT(var);

    checker::ETSObjectType *interfaceType {};
    if (var->TsType() == nullptr) {
        interfaceType = CreateETSObjectType(var->Name(), interfaceDecl,
                                            checker::ETSObjectFlags::INTERFACE | checker::ETSObjectFlags::ABSTRACT);
        interfaceType->SetVariable(var);
        var->SetTsType(interfaceType);
    } else {
        interfaceType = var->TsType()->AsETSObjectType();
    }

    if (interfaceDecl->TypeParams() != nullptr) {
        interfaceType->AddTypeFlag(TypeFlag::GENERIC);
        CreateTypeForClassOrInterfaceTypeParameters(interfaceType);
    }

    GetInterfacesOfInterface(interfaceType);

    checker::ScopeContext scopeCtx(this, interfaceDecl->Scope());
    auto savedContext = checker::SavedCheckerContext(this, checker::CheckerStatus::IN_INTERFACE, interfaceType);

    ResolveDeclaredMembersOfObject(interfaceType);

    return interfaceType;
}

ETSObjectType *ETSChecker::BuildClassProperties(ir::ClassDefinition *classDef)
{
    if (classDef->IsFinal() && classDef->IsAbstract()) {
        ThrowTypeError("Cannot use both 'final' and 'abstract' modifiers.", classDef->Start());
    }

    auto *var = classDef->Ident()->Variable();
    ASSERT(var);

    const util::StringView &className = classDef->Ident()->Name();
    auto *classScope = classDef->Scope();

    checker::ETSObjectType *classType {};
    if (var->TsType() == nullptr) {
        classType = CreateETSObjectType(className, classDef, checker::ETSObjectFlags::CLASS);
        classType->SetVariable(var);
        var->SetTsType(classType);
        if (classDef->IsAbstract()) {
            classType->AddObjectFlag(checker::ETSObjectFlags::ABSTRACT);
        }
    } else {
        classType = var->TsType()->AsETSObjectType();
    }

    classDef->SetTsType(classType);

    if (classDef->TypeParams() != nullptr) {
        classType->AddTypeFlag(TypeFlag::GENERIC);
        CreateTypeForClassOrInterfaceTypeParameters(classType);
    }

    auto *enclosingClass = Context().ContainingClass();
    classType->SetEnclosingType(enclosingClass);
    CheckerStatus newStatus = CheckerStatus::IN_CLASS;

    if (classDef->IsInner()) {
        newStatus |= CheckerStatus::INNER_CLASS;
        classType->AddObjectFlag(checker::ETSObjectFlags::INNER);
    }

    auto savedContext = checker::SavedCheckerContext(this, newStatus, classType);

    if (!classType->HasObjectFlag(ETSObjectFlags::RESOLVED_SUPER)) {
        GetSuperType(classType);
        GetInterfacesOfClass(classType);
    }

    if (classType->HasObjectFlag(ETSObjectFlags::RESOLVED_MEMBERS)) {
        return classType;
    }

    checker::ScopeContext scopeCtx(this, classScope);

    ResolveDeclaredMembersOfObject(classType);

    return classType;
}

ETSObjectType *ETSChecker::BuildAnonymousClassProperties(ir::ClassDefinition *classDef, ETSObjectType *superType)
{
    auto classType = CreateETSObjectType(classDef->Ident()->Name(), classDef, checker::ETSObjectFlags::CLASS);
    classDef->SetTsType(classType);
    classType->SetSuperType(superType);
    classType->AddObjectFlag(checker::ETSObjectFlags::RESOLVED_SUPER);

    checker::ScopeContext scopeCtx(this, classDef->Scope());
    auto savedContext = checker::SavedCheckerContext(this, checker::CheckerStatus::IN_CLASS, classType);

    ResolveDeclaredMembersOfObject(classType);

    return classType;
}

void ETSChecker::ResolveDeclaredMembersOfObject(ETSObjectType *type)
{
    if (type->HasObjectFlag(ETSObjectFlags::RESOLVED_MEMBERS)) {
        return;
    }

    auto *declNode = type->GetDeclNode();
    varbinder::ClassScope *scope = declNode->IsTSInterfaceDeclaration()
                                       ? declNode->AsTSInterfaceDeclaration()->Scope()->AsClassScope()
                                       : declNode->AsClassDefinition()->Scope()->AsClassScope();

    for (auto &[_, it] : scope->InstanceFieldScope()->Bindings()) {
        (void)_;
        ASSERT(it->Declaration()->Node()->IsClassProperty());
        auto *classProp = it->Declaration()->Node()->AsClassProperty();
        it->AddFlag(GetAccessFlagFromNode(classProp));
        type->AddProperty<PropertyType::INSTANCE_FIELD>(it->AsLocalVariable());

        if (classProp->TypeAnnotation() != nullptr && classProp->TypeAnnotation()->IsETSFunctionType()) {
            type->AddProperty<PropertyType::INSTANCE_METHOD>(it->AsLocalVariable());
            it->AddFlag(varbinder::VariableFlags::METHOD_REFERENCE);
        }
    }

    for (auto &[_, it] : scope->StaticFieldScope()->Bindings()) {
        (void)_;
        ASSERT(it->Declaration()->Node()->IsClassProperty());
        auto *classProp = it->Declaration()->Node()->AsClassProperty();
        it->AddFlag(GetAccessFlagFromNode(classProp));
        type->AddProperty<PropertyType::STATIC_FIELD>(it->AsLocalVariable());

        if (classProp->TypeAnnotation() != nullptr && classProp->TypeAnnotation()->IsETSFunctionType()) {
            type->AddProperty<PropertyType::STATIC_METHOD>(it->AsLocalVariable());
            it->AddFlag(varbinder::VariableFlags::METHOD_REFERENCE);
        }
    }

    for (auto &[_, it] : scope->InstanceMethodScope()->Bindings()) {
        (void)_;
        auto *node = it->Declaration()->Node()->AsMethodDefinition();

        if (node->Function()->IsProxy()) {
            continue;
        }

        it->AddFlag(GetAccessFlagFromNode(node));
        auto *funcType = BuildMethodSignature(node);
        it->SetTsType(funcType);
        funcType->SetVariable(it);
        node->SetTsType(funcType);
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
        auto *funcType = BuildMethodSignature(node);
        it->SetTsType(funcType);
        funcType->SetVariable(it);
        node->SetTsType(funcType);

        if (node->IsConstructor()) {
            type->AddConstructSignature(funcType->CallSignatures());
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

std::vector<Signature *> ETSChecker::CollectAbstractSignaturesFromObject(const ETSObjectType *objType)
{
    std::vector<Signature *> abstracts;
    for (const auto &prop : objType->Methods()) {
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

void ETSChecker::ComputeAbstractsFromInterface(ETSObjectType *interfaceType)
{
    auto cached = cachedComputedAbstracts_.find(interfaceType);
    if (cached != cachedComputedAbstracts_.end()) {
        return;
    }

    for (auto *it : interfaceType->Interfaces()) {
        ComputeAbstractsFromInterface(it);
    }

    ArenaVector<ETSFunctionType *> merged(Allocator()->Adapter());
    CreateFunctionTypesFromAbstracts(CollectAbstractSignaturesFromObject(interfaceType), &merged);
    std::unordered_set<ETSObjectType *> abstractInheritanceTarget;

    for (auto *interface : interfaceType->Interfaces()) {
        auto found = cachedComputedAbstracts_.find(interface);
        ASSERT(found != cachedComputedAbstracts_.end());

        if (!abstractInheritanceTarget.insert(found->first).second) {
            continue;
        }

        MergeComputedAbstracts(merged, found->second.first);

        for (auto *base : found->second.second) {
            abstractInheritanceTarget.insert(base);
        }
    }

    cachedComputedAbstracts_.insert({interfaceType, {merged, abstractInheritanceTarget}});
}

ArenaVector<ETSFunctionType *> &ETSChecker::GetAbstractsForClass(ETSObjectType *classType)
{
    ArenaVector<ETSFunctionType *> merged(Allocator()->Adapter());
    CreateFunctionTypesFromAbstracts(CollectAbstractSignaturesFromObject(classType), &merged);

    std::unordered_set<ETSObjectType *> abstractInheritanceTarget;
    if (classType->SuperType() != nullptr) {
        auto base = cachedComputedAbstracts_.find(classType->SuperType());
        ASSERT(base != cachedComputedAbstracts_.end());
        MergeComputedAbstracts(merged, base->second.first);

        abstractInheritanceTarget.insert(base->first);
        for (auto *it : base->second.second) {
            abstractInheritanceTarget.insert(it);
        }
    }

    for (auto *it : classType->Interfaces()) {
        ComputeAbstractsFromInterface(it);
        auto found = cachedComputedAbstracts_.find(it);
        ASSERT(found != cachedComputedAbstracts_.end());

        if (!abstractInheritanceTarget.insert(found->first).second) {
            continue;
        }

        MergeComputedAbstracts(merged, found->second.first);

        for (auto *interface : found->second.second) {
            abstractInheritanceTarget.insert(interface);
        }
    }

    return cachedComputedAbstracts_.insert({classType, {merged, abstractInheritanceTarget}}).first->second.first;
}

void ETSChecker::ValidateOverriding(ETSObjectType *classType, const lexer::SourcePosition &pos)
{
    if (classType->HasObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS)) {
        return;
    }

    bool throwError = true;
    if (classType->HasObjectFlag(ETSObjectFlags::ABSTRACT)) {
        throwError = false;
    }

    if (classType->SuperType() != nullptr) {
        ValidateOverriding(classType->SuperType(), classType->SuperType()->GetDeclNode()->Start());
    }

    auto &abstractsToBeImplemented = GetAbstractsForClass(classType);
    std::vector<Signature *> implementedSignatures;

    auto *superIter = classType;
    do {
        for (auto &it : abstractsToBeImplemented) {
            for (const auto &prop : superIter->Methods()) {
                GetTypeOfVariable(prop);
                AddImplementedSignature(&implementedSignatures, prop, it);
            }
        }
        superIter = superIter->SuperType();
    } while (superIter != nullptr);

    SavedTypeRelationFlagsContext savedFlagsCtx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);
    for (auto it = abstractsToBeImplemented.begin(); it != abstractsToBeImplemented.end();) {
        bool functionOverridden = false;
        bool isGetterSetter = false;
        for (auto abstractSignature = (*it)->CallSignatures().begin();
             abstractSignature != (*it)->CallSignatures().end();) {
            bool foundSignature = false;
            isGetterSetter = (*abstractSignature)->HasSignatureFlag(SignatureFlags::GETTER_OR_SETTER);
            for (auto *const implemented : implementedSignatures) {
                Signature *substImplemented = AdjustForTypeParameters(*abstractSignature, implemented);

                if (substImplemented == nullptr) {
                    continue;
                }

                if (!AreOverrideEquivalent(*abstractSignature, substImplemented) ||
                    !IsReturnTypeSubstitutable(substImplemented, *abstractSignature)) {
                    continue;
                }

                if ((*it)->CallSignatures().size() > 1) {
                    abstractSignature = (*it)->CallSignatures().erase(abstractSignature);
                    foundSignature = true;
                } else {
                    it = abstractsToBeImplemented.erase(it);
                    functionOverridden = true;
                }

                break;
            }

            if (functionOverridden) {
                break;
            }

            if (!foundSignature) {
                abstractSignature++;
            }
        }

        if (isGetterSetter && !functionOverridden) {
            for (auto *field : classType->Fields()) {
                if (field->Name() == (*it)->Name()) {
                    it = abstractsToBeImplemented.erase(it);
                    functionOverridden = true;
                    break;
                }
            }
        }

        if (!functionOverridden) {
            it++;
        }
    }

    if (!abstractsToBeImplemented.empty() && throwError) {
        auto unimplementedSignature = abstractsToBeImplemented.front()->CallSignatures().front();
        ThrowTypeError({classType->Name(), " is not abstract and does not override abstract method ",
                        unimplementedSignature->Function()->Id()->Name(), unimplementedSignature, " in ",
                        GetContainingObjectNameFromSignature(unimplementedSignature)},
                       pos);
    }

    classType->AddObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS);
}

void ETSChecker::AddImplementedSignature(std::vector<Signature *> *implementedSignatures,
                                         varbinder::LocalVariable *function, ETSFunctionType *it)
{
    if (!function->TsType()->IsETSFunctionType()) {
        return;
    }

    for (auto signature : function->TsType()->AsETSFunctionType()->CallSignatures()) {
        if (signature->Function()->IsAbstract() || signature->Function()->IsStatic()) {
            continue;
        }

        if (signature->Function()->Id()->Name() == it->Name()) {
            implementedSignatures->emplace_back(signature);
        }
    }
}

void ETSChecker::CheckClassDefinition(ir::ClassDefinition *classDef)
{
    auto *classType = classDef->TsType()->AsETSObjectType();
    auto *enclosingClass = Context().ContainingClass();
    auto newStatus = checker::CheckerStatus::IN_CLASS;
    classType->SetEnclosingType(enclosingClass);

    if (classDef->IsInner()) {
        newStatus |= CheckerStatus::INNER_CLASS;
        classType->AddObjectFlag(checker::ETSObjectFlags::INNER);
    }

    if (classDef->IsGlobal()) {
        classType->AddObjectFlag(checker::ETSObjectFlags::GLOBAL);
    }

    checker::ScopeContext scopeCtx(this, classDef->Scope());
    auto savedContext = SavedCheckerContext(this, newStatus, classType);

    if (classDef->IsAbstract()) {
        AddStatus(checker::CheckerStatus::IN_ABSTRACT);
        classType->AddObjectFlag(checker::ETSObjectFlags::ABSTRACT);
    }

    if (classDef->IsStatic() && !Context().ContainingClass()->HasObjectFlag(ETSObjectFlags::GLOBAL)) {
        AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    for (auto *it : classDef->Body()) {
        if (it->IsClassProperty()) {
            it->Check(this);
        }
    }

    for (auto *it : classDef->Body()) {
        if (!it->IsClassProperty()) {
            it->Check(this);
        }
    }
    CreateAsyncProxyMethods(classDef);

    if (classDef->IsGlobal()) {
        return;
    }

    if (!classDef->IsDeclare()) {
        for (auto *it : classType->ConstructSignatures()) {
            CheckCyclicConstructorCall(it);
            CheckImplicitSuper(classType, it);
        }
    }

    ValidateOverriding(classType, classDef->Start());
    CheckValidInheritance(classType, classDef);
    CheckConstFields(classType);
    CheckGetterSetterProperties(classType);
    CheckInvokeMethodsLegitimacy(classType);
}

static bool IsAsyncMethod(ir::AstNode *node)
{
    if (!node->IsMethodDefinition()) {
        return false;
    }
    auto *method = node->AsMethodDefinition();
    return method->Function()->IsAsyncFunc() && !method->Function()->IsProxy();
}

void ETSChecker::CreateAsyncProxyMethods(ir::ClassDefinition *classDef)
{
    ArenaVector<ir::MethodDefinition *> asyncImpls(Allocator()->Adapter());
    for (auto *it : classDef->Body()) {
        if (IsAsyncMethod(it)) {
            auto *method = it->AsMethodDefinition();
            asyncImpls.push_back(CreateAsyncProxy(method, classDef));
            auto *proxy = asyncImpls.back();
            for (auto *overload : method->Overloads()) {
                auto *impl = CreateAsyncProxy(overload, classDef, false);
                impl->Function()->Id()->SetVariable(proxy->Function()->Id()->Variable());
                proxy->AddOverload(impl);
            }
        }
    }
    for (auto *it : asyncImpls) {
        it->Check(this);
        classDef->Body().push_back(it);
    }
}

void ETSChecker::CheckImplicitSuper(ETSObjectType *classType, Signature *ctorSig)
{
    if (classType == GlobalETSObjectType()) {
        return;
    }

    auto &stmts = ctorSig->Function()->Body()->AsBlockStatement()->Statements();
    const auto thisCall = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        return stmt->IsExpressionStatement() && stmt->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
               stmt->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee()->IsThisExpression();
    });

    // There is an alternate constructor invocation, no need for super constructor invocation
    if (thisCall != stmts.end()) {
        return;
    }

    const auto superExpr = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        return stmt->IsExpressionStatement() && stmt->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
               stmt->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee()->IsSuperExpression();
    });

    // There is no super expression
    if (superExpr == stmts.end()) {
        const auto superTypeCtorSigs = classType->SuperType()->ConstructSignatures();
        const auto superTypeCtorSig = std::find_if(superTypeCtorSigs.begin(), superTypeCtorSigs.end(),
                                                   [](const Signature *sig) { return sig->Params().empty(); });

        // Super type has no parameterless ctor
        if (superTypeCtorSig == superTypeCtorSigs.end()) {
            ThrowTypeError("Must call super constructor", ctorSig->Function()->Start());
        }

        ctorSig->Function()->AddFlag(ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED);
    }
}

void ETSChecker::CheckConstFields(const ETSObjectType *classType)
{
    for (const auto &prop : classType->Fields()) {
        if (!prop->Declaration()->IsConstDecl() || !prop->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            continue;
        }
        CheckConstFieldInitialized(classType, prop);
    }
}

void ETSChecker::CheckConstFieldInitialized(const ETSObjectType *classType, varbinder::LocalVariable *classVar)
{
    const bool classVarStatic = classVar->Declaration()->Node()->AsClassProperty()->IsStatic();
    for (const auto &prop : classType->Methods()) {
        if (!prop->TsType()->IsETSFunctionType()) {
            continue;
        }

        const auto &callSigs = prop->TsType()->AsETSFunctionType()->CallSignatures();
        for (const auto *signature : callSigs) {
            if ((signature->Function()->IsConstructor() && !classVarStatic) ||
                (signature->Function()->IsStaticBlock() && classVarStatic)) {
                CheckConstFieldInitialized(signature, classVar);
            }
        }
    }
}

void ETSChecker::FindAssignment(const ir::AstNode *node, const varbinder::LocalVariable *classVar, bool &initialized)
{
    if (node->IsAssignmentExpression() && node->AsAssignmentExpression()->Target() == classVar) {
        if (initialized) {
            ThrowTypeError({"Variable '", classVar->Declaration()->Name(), "' might already have been initialized"},
                           node->Start());
        }

        initialized = true;
        return;
    }

    FindAssignments(node, classVar, initialized);
}

void ETSChecker::FindAssignments(const ir::AstNode *node, const varbinder::LocalVariable *classVar, bool &initialized)
{
    node->Iterate(
        [this, classVar, &initialized](ir::AstNode *childNode) { FindAssignment(childNode, classVar, initialized); });
}

void ETSChecker::CheckConstFieldInitialized(const Signature *signature, varbinder::LocalVariable *classVar)
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

    // NOTE: szd. control flow
    FindAssignments(signature->Function()->Body(), classVar, initialized);
    if (!initialized) {
        ThrowTypeError({"Variable '", classVar->Declaration()->Name(), "' might not have been initialized"},
                       signature->Function()->End());
    }

    classVar->RemoveFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED);
}

void ETSChecker::CheckInnerClassMembers(const ETSObjectType *classType)
{
    for (const auto &[_, it] : classType->StaticMethods()) {
        (void)_;
        ThrowTypeError("Inner class cannot have static methods", it->Declaration()->Node()->Start());
    }

    for (const auto &[_, it] : classType->StaticFields()) {
        (void)_;
        if (!it->Declaration()->IsConstDecl()) {
            ThrowTypeError("Inner class cannot have non-const static properties", it->Declaration()->Node()->Start());
        }
    }
}

void ETSChecker::ValidateArrayIndex(ir::Expression *const expr, bool relaxed)
{
    auto *const expressionType = expr->Check(this);
    auto const *const unboxedExpressionType = ETSBuiltinTypeAsPrimitiveType(expressionType);

    Type const *const indexType = ApplyUnaryOperatorPromotion(expressionType);

    if (expressionType->IsETSObjectType() && (unboxedExpressionType != nullptr)) {
        expr->AddBoxingUnboxingFlags(GetUnboxingFlag(unboxedExpressionType));
    }

    if (relaxed && indexType != nullptr && indexType->HasTypeFlag(TypeFlag::ETS_FLOATING_POINT)) {
        if (!expr->IsNumberLiteral()) {
            return;
        }

        auto num = expr->AsNumberLiteral()->Number();
        ASSERT(num.IsReal());
        double value = num.GetDouble();
        double intpart;
        if (std::modf(value, &intpart) != 0.0) {
            ThrowTypeError("Index fracional part should not be different from 0.0", expr->Start());
        }
        return;
    }

    if (indexType == nullptr || !indexType->HasTypeFlag(TypeFlag::ETS_ARRAY_INDEX)) {
        std::stringstream message("");
        if (expressionType->IsNonPrimitiveType()) {
            message << expressionType->Variable()->Name();
        } else {
            expressionType->ToString(message);
        }

        ThrowTypeError(
            "Type '" + message.str() +
                "' cannot be used as an index type. Only primitive or unboxable integral types can be used as index.",
            expr->Start());
    }
}

int32_t ETSChecker::GetTupleElementAccessValue(const Type *const type) const
{
    ASSERT(type->HasTypeFlag(TypeFlag::CONSTANT | TypeFlag::ETS_NUMERIC));

    switch (ETSType(type)) {
        case TypeFlag::BYTE: {
            return type->AsByteType()->GetValue();
        }
        case TypeFlag::SHORT: {
            return type->AsShortType()->GetValue();
        }
        case TypeFlag::INT: {
            return type->AsIntType()->GetValue();
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSChecker::ValidateTupleIndex(const ETSTupleType *const tuple, const ir::MemberExpression *const expr)
{
    const auto *const exprType = expr->Property()->TsType();
    ASSERT(exprType != nullptr);

    if (!exprType->HasTypeFlag(TypeFlag::CONSTANT) && !tuple->HasSpreadType()) {
        ThrowTypeError("Only constant expression allowed for element access on tuples.", expr->Property()->Start());
    }

    if (!exprType->HasTypeFlag(TypeFlag::ETS_ARRAY_INDEX)) {
        ThrowTypeError("Only integer type allowed for element access on tuples.", expr->Property()->Start());
    }

    const int32_t exprValue = GetTupleElementAccessValue(exprType);
    if (((exprValue >= tuple->GetTupleSize()) && !tuple->HasSpreadType()) || (exprValue < 0)) {
        ThrowTypeError("Element accessor value is out of tuple size bounds.", expr->Property()->Start());
    }
}

ETSObjectType *ETSChecker::CheckThisOrSuperAccess(ir::Expression *node, ETSObjectType *classType, std::string_view msg)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U) {
        return classType;
    }

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

    if (classType->GetDeclNode()->IsClassDefinition() && classType->GetDeclNode()->AsClassDefinition()->IsGlobal()) {
        ThrowTypeError({"Cannot reference '", msg, "' in this context."}, node->Start());
    }

    return classType;
}

void ETSChecker::CheckCyclicConstructorCall(Signature *signature)
{
    ASSERT(signature->Function());

    if (signature->Function()->Body() == nullptr || signature->Function()->IsExternal()) {
        return;
    }

    auto *funcBody = signature->Function()->Body()->AsBlockStatement();

    TypeStackElement tse(this, signature, "Recursive constructor invocation", signature->Function()->Start());

    if (!funcBody->Statements().empty() && funcBody->Statements()[0]->IsExpressionStatement() &&
        funcBody->Statements()[0]->AsExpressionStatement()->GetExpression()->IsCallExpression() &&
        funcBody->Statements()[0]
            ->AsExpressionStatement()
            ->GetExpression()
            ->AsCallExpression()
            ->Callee()
            ->IsThisExpression()) {
        auto *constructorCall = funcBody->Statements()[0]->AsExpressionStatement()->GetExpression()->AsCallExpression();
        ASSERT(constructorCall->Signature());
        CheckCyclicConstructorCall(constructorCall->Signature());
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
                                   GlobalTypesHolder *const globalTypes)
{
    // NOTE: Handle generic functions
    auto *returnType = type;
    const bool isIncomplete =
        type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INCOMPLETE_INSTANTIATION);
    if (const bool isFunctionType = type->IsETSFunctionType(); isFunctionType || isIncomplete) {
        returnType = type->Instantiate(allocator, relation, globalTypes);
    }

    return returnType;
}

void ETSChecker::ValidateResolvedProperty(const varbinder::LocalVariable *const property,
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
    const auto flagsNum = static_cast<Utype>(flags);
    // This algorithm swaps the first 3 bits of a number with it's consecutive 3 bits, example: 0b110001 -> 0b001110
    // Effectively it changes PropertySearchFlags to search for the appropriate declarations
    const Utype x = (flagsNum ^ (flagsNum >> 3U)) & 7U;
    const auto newFlags = PropertySearchFlags {flagsNum ^ (x | (x << 3U))};

    const auto *const newProp = target->GetProperty(ident->Name(), newFlags);
    if (newProp == nullptr) {
        ThrowTypeError({"Property '", ident->Name(), "' does not exist on type '", target->Name(), "'"},
                       ident->Start());
    }
    if (IsVariableStatic(newProp)) {
        ThrowTypeError({"'", ident->Name(), "' is a static property of '", target->Name(), "'"}, ident->Start());
    } else {
        ThrowTypeError({"'", ident->Name(), "' is an instance property of '", target->Name(), "'"}, ident->Start());
    }
}

varbinder::Variable *ETSChecker::ResolveInstanceExtension(const ir::MemberExpression *const memberExpr)
{
    auto *globalFunctionVar = Scope()
                                  ->FindInGlobal(memberExpr->Property()->AsIdentifier()->Name(),
                                                 varbinder::ResolveBindingOptions::STATIC_METHODS)
                                  .variable;

    if (globalFunctionVar == nullptr || !ExtensionETSFunctionType(this->GetTypeOfVariable(globalFunctionVar))) {
        return nullptr;
    }

    return globalFunctionVar;
}

PropertySearchFlags ETSChecker::GetInitialSearchFlags(const ir::MemberExpression *const memberExpr)
{
    constexpr auto FUNCTIONAL_FLAGS = PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::IS_FUNCTIONAL;
    constexpr auto GETTER_FLAGS = PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::IS_GETTER;
    constexpr auto SETTER_FLAGS = PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::IS_SETTER;

    switch (memberExpr->Parent()->Type()) {
        case ir::AstNodeType::CALL_EXPRESSION: {
            if (memberExpr->Parent()->AsCallExpression()->Callee() == memberExpr) {
                return FUNCTIONAL_FLAGS;
            }

            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            if (memberExpr->Parent()->AsETSNewClassInstanceExpression()->GetTypeRef() == memberExpr) {
                return PropertySearchFlags::SEARCH_DECL;
            }
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            return PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL | GETTER_FLAGS;
        }
        case ir::AstNodeType::UPDATE_EXPRESSION:
        case ir::AstNodeType::UNARY_EXPRESSION:
        case ir::AstNodeType::BINARY_EXPRESSION: {
            return PropertySearchFlags::SEARCH_FIELD | GETTER_FLAGS;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            const auto *const assignmentExpr = memberExpr->Parent()->AsAssignmentExpression();

            if (assignmentExpr->Left() == memberExpr) {
                if (assignmentExpr->OperatorType() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
                    return PropertySearchFlags::SEARCH_FIELD | SETTER_FLAGS;
                }
                return PropertySearchFlags::SEARCH_FIELD | GETTER_FLAGS | SETTER_FLAGS;
            }

            auto const *targetType = assignmentExpr->Left()->TsType();
            if (targetType->IsETSObjectType() &&
                targetType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
                return FUNCTIONAL_FLAGS;
            }

            return PropertySearchFlags::SEARCH_FIELD | GETTER_FLAGS;
        }
        default: {
            break;
        }
    }

    return PropertySearchFlags::SEARCH_FIELD | FUNCTIONAL_FLAGS | GETTER_FLAGS;
}

PropertySearchFlags ETSChecker::GetSearchFlags(const ir::MemberExpression *const memberExpr,
                                               const varbinder::Variable *targetRef)
{
    auto searchFlag = GetInitialSearchFlags(memberExpr);
    searchFlag |= PropertySearchFlags::SEARCH_IN_BASE | PropertySearchFlags::SEARCH_IN_INTERFACES;

    if (targetRef != nullptr && targetRef->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE)) {
        searchFlag &= ~(PropertySearchFlags::SEARCH_INSTANCE);
    } else if (memberExpr->Object()->IsThisExpression() ||
               (memberExpr->Object()->IsIdentifier() && memberExpr->ObjType()->GetDeclNode() != nullptr &&
                memberExpr->ObjType()->GetDeclNode()->IsTSInterfaceDeclaration())) {
        searchFlag &= ~(PropertySearchFlags::SEARCH_STATIC);
    }
    return searchFlag;
}

const varbinder::Variable *ETSChecker::GetTargetRef(const ir::MemberExpression *const memberExpr)
{
    if (memberExpr->Object()->IsIdentifier()) {
        return memberExpr->Object()->AsIdentifier()->Variable();
    }
    if (memberExpr->Object()->IsMemberExpression()) {
        return memberExpr->Object()->AsMemberExpression()->PropVar();
    }
    return nullptr;
}

void ETSChecker::ValidateGetterSetter(const ir::MemberExpression *const memberExpr,
                                      const varbinder::LocalVariable *const prop, PropertySearchFlags searchFlag)
{
    auto *propType = prop->TsType()->AsETSFunctionType();
    ASSERT((propType->FindGetter() != nullptr) == propType->HasTypeFlag(TypeFlag::GETTER));
    ASSERT((propType->FindSetter() != nullptr) == propType->HasTypeFlag(TypeFlag::SETTER));

    auto const &sourcePos = memberExpr->Property()->Start();
    auto callExpr = memberExpr->Parent()->IsCallExpression() ? memberExpr->Parent()->AsCallExpression() : nullptr;

    if ((searchFlag & PropertySearchFlags::IS_GETTER) != 0) {
        if (!propType->HasTypeFlag(TypeFlag::GETTER)) {
            ThrowTypeError("Cannot read from this property because it is writeonly.", sourcePos);
        }
        ValidateSignatureAccessibility(memberExpr->ObjType(), callExpr, propType->FindGetter(), sourcePos);
    }

    if ((searchFlag & PropertySearchFlags::IS_SETTER) != 0) {
        if (!propType->HasTypeFlag(TypeFlag::SETTER)) {
            ThrowTypeError("Cannot assign to this property because it is readonly.", sourcePos);
        }
        ValidateSignatureAccessibility(memberExpr->ObjType(), callExpr, propType->FindSetter(), sourcePos);
    }
}

void ETSChecker::ValidateVarDeclaratorOrClassProperty(const ir::MemberExpression *const memberExpr,
                                                      varbinder::LocalVariable *const prop)
{
    const auto [target_ident,
                type_annotation] = [memberExpr]() -> std::pair<const ir::Identifier *, const ir::TypeNode *> {
        if (memberExpr->Parent()->IsVariableDeclarator()) {
            const auto *const ident = memberExpr->Parent()->AsVariableDeclarator()->Id()->AsIdentifier();
            return {ident, ident->TypeAnnotation()};
        }
        return {memberExpr->Parent()->AsClassProperty()->Key()->AsIdentifier(),
                memberExpr->Parent()->AsClassProperty()->TypeAnnotation()};
    }();

    GetTypeOfVariable(prop);

    if (prop->TsType()->IsETSFunctionType() && !IsVariableGetterSetter(prop)) {
        if (type_annotation == nullptr) {
            ThrowTypeError({"Cannot infer type for ", target_ident->Name(),
                            " because method reference needs an explicit target type"},
                           target_ident->Start());
        }

        auto *targetType = GetTypeOfVariable(target_ident->Variable());
        ASSERT(targetType != nullptr);

        if (!targetType->IsETSObjectType() ||
            !targetType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
            ThrowTypeError({"Method ", memberExpr->Property()->AsIdentifier()->Name(), " does not exist on this type."},
                           memberExpr->Property()->Start());
        }
    }
}

// NOLINTNEXTLINE(readability-function-size)
std::vector<ResolveResult *> ETSChecker::ResolveMemberReference(const ir::MemberExpression *const memberExpr,
                                                                const ETSObjectType *const target)
{
    std::vector<ResolveResult *> resolveRes {};

    if (target->IsETSDynamicType() && !target->AsETSDynamicType()->HasDecl()) {
        auto propName = memberExpr->Property()->AsIdentifier()->Name();
        varbinder::LocalVariable *propVar = target->AsETSDynamicType()->GetPropertyDynamic(propName, this);
        resolveRes.emplace_back(Allocator()->New<ResolveResult>(propVar, ResolvedKind::PROPERTY));
        return resolveRes;
    }

    const auto *const targetRef = GetTargetRef(memberExpr);
    auto searchFlag = GetSearchFlags(memberExpr, targetRef);

    if (target->HasTypeFlag(TypeFlag::GENERIC)) {
        searchFlag |= PropertySearchFlags::SEARCH_ALL;
    }

    auto *const prop = target->GetProperty(memberExpr->Property()->AsIdentifier()->Name(), searchFlag);
    varbinder::Variable *globalFunctionVar = nullptr;

    if (memberExpr->Parent()->IsCallExpression() && memberExpr->Parent()->AsCallExpression()->Callee() == memberExpr) {
        globalFunctionVar = ResolveInstanceExtension(memberExpr);
    }

    if (globalFunctionVar == nullptr ||
        (targetRef != nullptr && targetRef->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE))) {
        /*
            Instance extension function can only be called by class instance, if a property is accessed by
            CLASS or INTERFACE type, it couldn't be an instance extension function call

            Example code:
                class A {}
                static function A.xxx() {}
                function main() {
                    A.xxx()
                }

            !NB: When supporting static extension function, the above code case would be supported
        */
        ValidateResolvedProperty(prop, target, memberExpr->Property()->AsIdentifier(), searchFlag);
    } else {
        resolveRes.emplace_back(
            Allocator()->New<ResolveResult>(globalFunctionVar, ResolvedKind::INSTANCE_EXTENSION_FUNCTION));

        if (prop == nullptr) {
            // No matched property, but have possible matched global extension function
            return resolveRes;
        }
    }

    resolveRes.emplace_back(Allocator()->New<ResolveResult>(prop, ResolvedKind::PROPERTY));

    if (prop->HasFlag(varbinder::VariableFlags::METHOD) && !IsVariableGetterSetter(prop) &&
        (searchFlag & PropertySearchFlags::IS_FUNCTIONAL) == 0) {
        ThrowTypeError("Method used in wrong context", memberExpr->Property()->Start());
    }

    if (IsVariableGetterSetter(prop)) {
        ValidateGetterSetter(memberExpr, prop, searchFlag);
    }

    // Before returning the computed property variable, we have to validate the special case where we are in a variable
    // declaration, and the properties type is a function type but the currently declared variable doesn't have a type
    // annotation
    if (memberExpr->Parent()->IsVariableDeclarator() || memberExpr->Parent()->IsClassProperty()) {
        ValidateVarDeclaratorOrClassProperty(memberExpr, prop);
    }

    return resolveRes;
}

void ETSChecker::CheckValidInheritance(ETSObjectType *classType, ir::ClassDefinition *classDef)
{
    if (classType->SuperType() == nullptr) {
        return;
    }

    if (classDef->TypeParams() != nullptr &&
        (Relation()->IsAssignableTo(classType->SuperType(), GlobalBuiltinExceptionType()) ||
         Relation()->IsAssignableTo(classType->SuperType(), GlobalBuiltinErrorType()))) {
        ThrowTypeError({"Generics are not allowed as '", compiler::Signatures::BUILTIN_EXCEPTION_CLASS, "' or '",
                        compiler::Signatures::BUILTIN_ERROR_CLASS, "' subclasses."},
                       classDef->TypeParams()->Start());
    }

    const auto &allProps = classType->GetAllProperties();

    for (auto *it : allProps) {
        const auto searchFlag = PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE |
                                PropertySearchFlags::SEARCH_IN_INTERFACES |
                                PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION;
        auto *found = classType->SuperType()->GetProperty(it->Name(), searchFlag);

        ETSObjectType *interfaceFound = nullptr;
        if (found == nullptr) {
            auto interfaceList = GetInterfacesOfClass(classType);
            for (auto *interface : interfaceList) {
                auto *propertyFound = interface->GetProperty(it->Name(), searchFlag);
                if (propertyFound == nullptr) {
                    continue;
                }
                found = propertyFound;
                interfaceFound = interface;
                break;
            }
        }
        if (found == nullptr) {
            continue;
        }

        if (!IsSameDeclarationType(it, found)) {
            const char *targetType {};

            if (it->HasFlag(varbinder::VariableFlags::PROPERTY)) {
                targetType = "field";
            } else if (it->HasFlag(varbinder::VariableFlags::METHOD)) {
                targetType = "method";
            } else if (it->HasFlag(varbinder::VariableFlags::CLASS)) {
                targetType = "class";
            } else if (it->HasFlag(varbinder::VariableFlags::INTERFACE)) {
                targetType = "interface";
            } else {
                targetType = "enum";
            }

            if (interfaceFound != nullptr) {
                ThrowTypeError({"Cannot inherit from interface ", interfaceFound->Name(), " because ", targetType, " ",
                                it->Name(), " is inherited with a different declaration type"},
                               interfaceFound->GetDeclNode()->Start());
            }
            ThrowTypeError({"Cannot inherit from class ", classType->SuperType()->Name(), ", because ", targetType, " ",
                            it->Name(), " is inherited with a different declaration type"},
                           classDef->Super()->Start());
        }
    }
}

void ETSChecker::CheckGetterSetterProperties(ETSObjectType *classType)
{
    auto const checkGetterSetter = [this](varbinder::LocalVariable *var, util::StringView name) {
        auto const *type = var->TsType()->AsETSFunctionType();
        auto const *sigGetter = type->FindGetter();
        auto const *sigSetter = type->FindSetter();

        for (auto const *sig : type->CallSignatures()) {
            if (!sig->Function()->IsGetter() && !sig->Function()->IsSetter()) {
                ThrowTypeError({"Method cannot use the same name as ", name, " accessor property"},
                               sig->Function()->Start());
            }
            if (sig != sigGetter && sig != sigSetter) {
                ThrowTypeError("Duplicate accessor definition", sig->Function()->Start());
            }
        }

        if (((sigGetter->Function()->Modifiers() ^ sigSetter->Function()->Modifiers()) &
             ir::ModifierFlags::ACCESSOR_MODIFIERS) != 0) {
            ThrowTypeError("Getter and setter methods must have the same accessor modifiers",
                           sigGetter->Function()->Start());
        }
    };

    for (const auto &[name, var] : classType->InstanceMethods()) {
        if (IsVariableGetterSetter(var)) {
            checkGetterSetter(var, name);
        }
    }

    for (const auto &[name, var] : classType->StaticMethods()) {
        if (IsVariableGetterSetter(var)) {
            checkGetterSetter(var, name);
        }
    }
}

void ETSChecker::AddElementsToModuleObject(ETSObjectType *moduleObj, const util::StringView &str)
{
    for (const auto &[name, var] : VarBinder()->GetScope()->Bindings()) {
        if (name.Is(str.Mutf8()) || name.Is(compiler::Signatures::ETS_GLOBAL)) {
            continue;
        }

        if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
            moduleObj->AddProperty<checker::PropertyType::STATIC_METHOD>(var->AsLocalVariable());
        } else if (var->HasFlag(varbinder::VariableFlags::PROPERTY)) {
            moduleObj->AddProperty<checker::PropertyType::STATIC_FIELD>(var->AsLocalVariable());
        } else {
            moduleObj->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }
}

Type *ETSChecker::FindLeastUpperBound(Type *source, Type *target)
{
    ASSERT(source->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) && target->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT));

    // GetCommonClass(GenA<A>, GenB<B>) => LUB(GenA, GenB)<T>
    auto commonClass = GetCommonClass(source, target);

    if (!commonClass->IsETSObjectType() || !commonClass->HasTypeFlag(TypeFlag::GENERIC)) {
        return commonClass->HasTypeFlag(TypeFlag::CONSTANT) ? commonClass->Variable()->TsType() : commonClass;
    }

    // GetRelevantArgumentedTypeFromChild(GenA<A>, LUB(GenA, GenB)<T>) => LUB(GenA, GenB)<A>
    ETSObjectType *relevantSourceType =
        GetRelevantArgumentedTypeFromChild(source->AsETSObjectType(), commonClass->AsETSObjectType());
    ETSObjectType *relevantTargetType =
        GetRelevantArgumentedTypeFromChild(target->AsETSObjectType(), commonClass->AsETSObjectType());

    // GetTypeargumentedLUB(LUB(GenA, GenB)<A>, LUB(GenA, GenB)<B>) => LUB(GenA, GenB)<LUB(A, B)>
    return GetTypeargumentedLUB(relevantSourceType, relevantTargetType);
}

Type *ETSChecker::GetApparentType(Type *type)
{
    if (type->IsETSTypeParameter()) {
        auto *const param = type->AsETSTypeParameter();
        return param->HasConstraint() ? param->GetConstraintType() : param;
    }
    return type;
}

Type const *ETSChecker::GetApparentType(Type const *type)
{
    if (type->IsETSTypeParameter()) {
        auto *const param = type->AsETSTypeParameter();
        return param->HasConstraint() ? param->GetConstraintType() : param;
    }
    return type;
}

Type *ETSChecker::GetCommonClass(Type *source, Type *target)
{
    SavedTypeRelationFlagsContext checkerCtx(this->Relation(), TypeRelationFlag::IGNORE_TYPE_PARAMETERS);

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
        if (source->IsETSNullLike()) {
            return target;
        }

        if (target->IsETSNullLike()) {
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

    auto *targetBase = GetOriginalBaseType(target->SuperType());
    auto *targetType = targetBase == nullptr ? target->SuperType() : targetBase;

    auto *sourceBase = GetOriginalBaseType(source);
    auto *sourceType = sourceBase == nullptr ? source : sourceBase;

    targetType->IsSupertypeOf(Relation(), sourceType);
    if (Relation()->IsTrue()) {
        // NOTE: TorokG. Extending the search to find intersection types
        return targetType;
    }

    return GetClosestCommonAncestor(sourceType, targetType);
}

ETSObjectType *ETSChecker::GetTypeargumentedLUB(ETSObjectType *const source, ETSObjectType *const target)
{
    ASSERT(source->TypeArguments().size() == target->TypeArguments().size());

    ArenaVector<Type *> params(Allocator()->Adapter());

    for (uint32_t i = 0; i < source->TypeArguments().size(); i++) {
        params.push_back(FindLeastUpperBound(source->TypeArguments()[i], target->TypeArguments()[i]));
    }

    const util::StringView hash = GetHashFromTypeArguments(params);

    if (!source->GetDeclNode()->IsClassDefinition()) {
        return source;
    }

    ETSObjectType *templateType = source->GetDeclNode()->AsClassDefinition()->TsType()->AsETSObjectType();

    auto *lubType = templateType->GetInstantiatedType(hash);

    if (lubType == nullptr) {
        lubType = templateType->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsETSObjectType();
        lubType->SetTypeArguments(std::move(params));

        templateType->GetInstantiationMap().try_emplace(hash, lubType);
    }

    return lubType;
}

void ETSChecker::CheckInvokeMethodsLegitimacy(ETSObjectType *const classType)
{
    if (classType->HasObjectFlag(ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY)) {
        return;
    }

    auto searchFlag = PropertySearchFlags::SEARCH_IN_INTERFACES | PropertySearchFlags::SEARCH_IN_BASE |
                      PropertySearchFlags::SEARCH_STATIC_METHOD;

    auto *const invokeMethod = classType->GetProperty(compiler::Signatures::STATIC_INVOKE_METHOD, searchFlag);
    if (invokeMethod == nullptr) {
        classType->AddObjectFlag(ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
        return;
    }

    auto *const instantiateMethod = classType->GetProperty(compiler::Signatures::STATIC_INSTANTIATE_METHOD, searchFlag);
    if (instantiateMethod != nullptr) {
        ThrowTypeError({"Static ", compiler::Signatures::STATIC_INVOKE_METHOD, " method and static ",
                        compiler::Signatures::STATIC_INSTANTIATE_METHOD, " method both exist in class/interface ",
                        classType->Name(), " is not allowed."},
                       classType->GetDeclNode()->Start());
    }
    classType->AddObjectFlag(ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
}
}  // namespace panda::es2panda::checker
