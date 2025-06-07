/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ir/expressions/identifier.h"
#include "ir/ets/etsNullishTypes.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/ets/etsUnionType.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "varbinder/ETSBinder.h"
#include "checker/types/ets/etsPartialTypeParameter.h"

namespace ark::es2panda::checker {

std::optional<ir::TypeNode *> ETSChecker::GetUtilityTypeTypeParamNode(
    const ir::TSTypeParameterInstantiation *const typeParams, const std::string_view &utilityTypeName)
{
    if (typeParams->Params().size() != 1) {
        LogError(diagnostic::UTIL_TYPE_INVALID_TYPE_PARAM_COUNT, {utilityTypeName}, typeParams->Start());
        return std::nullopt;
    }
    return typeParams->Params().front();
}

Type *ETSChecker::HandleUtilityTypeParameterNode(const ir::TSTypeParameterInstantiation *const typeParams,
                                                 const ir::Identifier *const ident)
{
    if (typeParams == nullptr) {
        LogError(diagnostic::USING_RESERVED_NAME_AS_VARIABLE_OR_TYPE_NAME, {ident->Name().Utf8()}, ident->Start());
        return GlobalTypeError();
    }
    const std::string_view &utilityType = ident->Name().Utf8();
    std::optional<ir::TypeNode *> possiblyTypeParam = GetUtilityTypeTypeParamNode(typeParams, utilityType);
    if (!possiblyTypeParam.has_value()) {
        return GlobalTypeError();
    }

    Type *baseType = possiblyTypeParam.value()->Check(this);

    if (baseType->IsTypeError()) {
        return baseType;
    }

    if (!baseType->IsETSReferenceType()) {
        LogError(diagnostic::UTIL_TYPE_OF_NONREFERENCE, {}, typeParams->Start());
        return GlobalTypeError();
    }

    if (utilityType == compiler::Signatures::PARTIAL_TYPE_NAME) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return CreatePartialType(baseType);
    }

    if (utilityType == compiler::Signatures::READONLY_TYPE_NAME) {
        return GetReadonlyType(baseType);
    }

    if (utilityType == compiler::Signatures::REQUIRED_TYPE_NAME) {
        return HandleRequiredType(baseType);
    }

    LogError(diagnostic::UTILITY_TYPE_UNIMPLEMENTED, {}, typeParams->Start());
    return baseType;
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Partial utility type
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

static std::pair<util::StringView, util::StringView> GetPartialClassName(ETSChecker *checker, ir::AstNode *typeNode)
{
    // Partial class name for class 'T' will be 'T$partial'
    auto const addSuffix = [checker](util::StringView name) {
        return util::UString(name.Mutf8() + PARTIAL_CLASS_SUFFIX, checker->Allocator()).View();
    };

    auto declIdent = typeNode->IsClassDefinition() ? typeNode->AsClassDefinition()->Ident()
                                                   : typeNode->AsTSInterfaceDeclaration()->Id();
    auto internalName = typeNode->IsClassDefinition() ? typeNode->AsClassDefinition()->InternalName()
                                                      : typeNode->AsTSInterfaceDeclaration()->InternalName();
    return {addSuffix(declIdent->Name()), addSuffix(internalName)};
}

static std::pair<parser::Program *, varbinder::RecordTable *> GetPartialClassProgram(ETSChecker *checker,
                                                                                     ir::AstNode *typeNode)
{
    auto classDefProgram = typeNode->GetTopStatement()->AsETSModule()->Program();
    if (classDefProgram == checker->VarBinder()->Program()) {
        return {classDefProgram, checker->VarBinder()->AsETSBinder()->GetGlobalRecordTable()};
    }
    return {classDefProgram, checker->VarBinder()->AsETSBinder()->GetExternalRecordTable().at(classDefProgram)};
}

template <typename T>
static T *CloneNodeIfNotNullptr(T *node, ArenaAllocator *allocator)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return node != nullptr ? node->Clone(allocator, nullptr) : nullptr;
}

Type *ETSChecker::CreatePartialType(Type *const typeToBePartial)
{
    ES2PANDA_ASSERT(typeToBePartial->IsETSReferenceType());

    if (typeToBePartial->IsETSTypeParameter()) {
        return CreatePartialTypeParameter(typeToBePartial->AsETSTypeParameter());
    }

    if (typeToBePartial->IsETSUnionType()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return HandleUnionForPartialType(typeToBePartial->AsETSUnionType());
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreatePartialTypeClass(typeToBePartial->AsETSObjectType(),
                                  typeToBePartial->Variable()->Declaration()->Node());
}

Type *ETSChecker::CreatePartialTypeParameter(ETSTypeParameter *typeToBePartial)
{
    return Allocator()->New<ETSPartialTypeParameter>(typeToBePartial, this);
}

Type *ETSChecker::CreatePartialTypeClass(ETSObjectType *typeToBePartial, ir::AstNode *typeDeclNode)
{
    auto const [partialName, partialQualifiedName] = GetPartialClassName(this, typeDeclNode);
    auto const [partialProgram, recordTable] = GetPartialClassProgram(this, typeDeclNode);

    // Check if we've already generated the partial class, then don't do it again
    const auto classNameToFind =
        partialProgram == VarBinder()->Program() || VarBinder()->IsGenStdLib() ? partialName : partialQualifiedName;
    if (auto *var =
            SearchNamesInMultiplePrograms({partialProgram, VarBinder()->Program()}, {classNameToFind, partialName});
        var != nullptr) {
        return var->TsType();
    }

    if (typeDeclNode->IsTSInterfaceDeclaration()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return HandlePartialInterface(typeDeclNode->AsTSInterfaceDeclaration(), typeToBePartial);
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ir::ClassDefinition *partialClassDef = CreateClassPrototype(partialName, partialProgram);
    partialClassDef->SetInternalName(partialQualifiedName);

    // Create only class 'header' (no properties and methods, but base type created)
    BuildBasicClassProperties(partialClassDef);

    // If class prototype was created before, then we cached it's type. In that case return it.
    // This handles cases where a Partial<T> presents in class T, because during generating T$partial we'd need the
    // complete class T$partial which is not present at the time. Binding it's own type for it however will make it
    // possible to resolve member references later, when the full T$partial class was created.
    if (const auto found = NamedTypeStack().find(partialClassDef->TsType()); found != NamedTypeStack().end()) {
        return *found;
    }

    const varbinder::BoundContext boundCtx(recordTable, partialClassDef);

    NamedTypeStackElement ntse(this, partialClassDef->TsType());

    // If class is external, put partial of it in global scope for the varbinder
    if (partialProgram != VarBinder()->Program()) {
        VarBinder()->Program()->GlobalScope()->InsertBinding(partialClassDef->Ident()->Name(),
                                                             partialClassDef->Variable());
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreatePartialTypeClassDef(partialClassDef, typeDeclNode->AsClassDefinition(), typeToBePartial, recordTable);
}

Type *ETSChecker::HandlePartialInterface(ir::TSInterfaceDeclaration *interfaceDecl, ETSObjectType *typeToBePartial)
{
    auto const [partialName, partialQualifiedName] = GetPartialClassName(this, interfaceDecl);
    auto const [partialProgram, recordTable] = GetPartialClassProgram(this, interfaceDecl);

    auto *const partialInterDecl =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        CreateInterfaceProto(partialName, partialProgram, interfaceDecl->IsStatic(), interfaceDecl->Modifiers());
    partialInterDecl->SetInternalName(partialQualifiedName);

    if (const auto found = NamedTypeStack().find(partialInterDecl->TsType()); found != NamedTypeStack().end()) {
        return *found;
    }

    const varbinder::BoundContext boundCtx(recordTable, partialInterDecl);

    // If class is external, put partial of it in global scope for the varbinder
    if (partialProgram != VarBinder()->Program()) {
        VarBinder()->Program()->GlobalScope()->InsertBinding(partialInterDecl->Id()->Name(),
                                                             partialInterDecl->Variable());
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *partialType = CreatePartialTypeInterfaceDecl(interfaceDecl, typeToBePartial, partialInterDecl);
    ES2PANDA_ASSERT(partialType != nullptr);
    NamedTypeStackElement ntse(this, partialType);

    return partialType;
}

ir::ClassProperty *ETSChecker::CreateNullishPropertyFromAccessor(ir::MethodDefinition *const accessor,
                                                                 ir::ClassDefinition *const newClassDefinition)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *ident = accessor->Id()->Clone(Allocator(), nullptr);
    auto modifierFlag = accessor->Function()->IsGetter() && accessor->Overloads().empty() ? ir::ModifierFlags::READONLY
                                                                                          : ir::ModifierFlags::NONE;

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *prop = Allocator()->New<ir::ClassProperty>(ident, nullptr, nullptr, modifierFlag, Allocator(), false);

    prop->SetParent(newClassDefinition);
    ident->SetParent(prop);

    prop->SetTypeAnnotation(accessor->Function()->IsGetter()
                                ? accessor->Function()->ReturnTypeAnnotation()
                                : accessor->Function()->Params()[0]->AsETSParameterExpression()->TypeAnnotation());

    if (prop->TypeAnnotation() != nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return CreateNullishProperty(prop, newClassDefinition);
    }

    if (accessor->TsType() == nullptr) {
        accessor->Parent()->Check(this);
    }

    auto callSign = accessor->TsType()->AsETSFunctionType()->CallSignatures()[0];

    auto tsType = accessor->Function()->IsGetter() ? callSign->ReturnType() : callSign->Params()[0]->TsType();

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    prop->SetTypeAnnotation(Allocator()->New<ir::OpaqueTypeNode>(tsType, Allocator()));

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return CreateNullishProperty(prop, newClassDefinition);
}

ir::ClassProperty *ETSChecker::CreateNullishProperty(ir::ClassProperty *const prop,
                                                     ir::TSInterfaceDeclaration *const newTSInterfaceDefinition)
{
    auto *const propSavedValue = prop->Value();

    // Set value to nullptr to prevent cloning it (as for arrow functions that is not possible yet), we set it
    // to 'undefined' anyway
    prop->SetValue(nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const propClone = prop->Clone(Allocator(), newTSInterfaceDefinition->Body())->AsClassProperty();

    // Revert original property value
    prop->SetValue(propSavedValue);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    propClone->SetValue(Allocator()->New<ir::UndefinedLiteral>());

    auto *propTypeAnn = propClone->TypeAnnotation();
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());

    // Handle implicit type annotation
    if (propTypeAnn == nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        propTypeAnn = Allocator()->New<ir::OpaqueTypeNode>(prop->TsType(), Allocator());
    }

    // Create new nullish type
    types.push_back(propTypeAnn);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    types.push_back(AllocNode<ir::ETSUndefinedType>(Allocator()));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const unionType = AllocNode<ir::ETSUnionType>(std::move(types), Allocator());
    propClone->SetTypeAnnotation(unionType);

    // Set new parents
    unionType->SetParent(propClone);
    propClone->SetParent(newTSInterfaceDefinition->Body());

    return propClone;
}

ir::ClassProperty *ETSChecker::CreateNullishProperty(ir::ClassProperty *const prop,
                                                     ir::ClassDefinition *const newClassDefinition)
{
    auto *const propSavedValue = prop->Value();

    // Set value to nullptr to prevent cloning it (as for arrow functions that is not possible yet), we set it
    // to 'undefined' anyway
    prop->SetValue(nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const propClone = prop->Clone(Allocator(), newClassDefinition)->AsClassProperty();

    // Revert original property value
    prop->SetValue(propSavedValue);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    propClone->SetValue(Allocator()->New<ir::UndefinedLiteral>());
    propClone->AsClassProperty()->Value()->Check(this);

    ir::TypeNode *propertyTypeAnnotation = propClone->TypeAnnotation();
    if (propertyTypeAnnotation == nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        propertyTypeAnnotation = Allocator()->New<ir::OpaqueTypeNode>(prop->Check(this), Allocator());
    }

    // Create new nullish type annotation
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());
    types.push_back(propertyTypeAnnotation);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    types.push_back(AllocNode<ir::ETSUndefinedType>(Allocator()));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    propertyTypeAnnotation = AllocNode<ir::ETSUnionType>(std::move(types), Allocator());
    propClone->SetTypeAnnotation(propertyTypeAnnotation);
    propClone->SetTsType(nullptr);

    // Set new parents
    propertyTypeAnnotation->SetParent(propClone);
    propClone->SetParent(newClassDefinition);

    return propClone;
}

ir::TSTypeParameterDeclaration *ETSChecker::ProcessTypeParamAndGenSubstitution(
    ir::TSTypeParameterDeclaration const *const thisTypeParams,
    ArenaMap<ir::TSTypeParameter *, ir::TSTypeParameter *> *likeSubstitution,
    ir::TSTypeParameterDeclaration *newTypeParams = nullptr)
{
    ArenaVector<ir::TSTypeParameter *> typeParams(Allocator()->Adapter());
    if (newTypeParams == nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        newTypeParams = AllocNode<ir::TSTypeParameterDeclaration>(std::move(typeParams), typeParams.size());
    }
    for (auto *const classOrInterfaceDefTypeParam : thisTypeParams->Params()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *newTypeParam = AllocNode<ir::TSTypeParameter>(
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            CloneNodeIfNotNullptr(classOrInterfaceDefTypeParam->Name(), Allocator()),
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            CloneNodeIfNotNullptr(classOrInterfaceDefTypeParam->Constraint(), Allocator()),
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            CloneNodeIfNotNullptr(classOrInterfaceDefTypeParam->DefaultType(), Allocator()), Allocator());
        newTypeParams->AddParam(newTypeParam);
        newTypeParam->SetParent(newTypeParams);
        (*likeSubstitution)[classOrInterfaceDefTypeParam] = newTypeParam;
    }
    return newTypeParams;
}

ir::TSTypeParameterInstantiation *ETSChecker::CreateNewSuperPartialRefTypeParamsDecl(
    ArenaMap<ir::TSTypeParameter *, ir::TSTypeParameter *> *likeSubstitution, const Type *const superPartialType,
    ir::Expression *superRef)
{
    ir::TSTypeParameterInstantiation *superPartialRefTypeParams = nullptr;
    if (superPartialType == nullptr || superRef == nullptr ||
        superRef->AsETSTypeReference()->Part()->TypeParams() == nullptr) {
        return superPartialRefTypeParams;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    superPartialRefTypeParams = superRef->AsETSTypeReference()->Part()->TypeParams()->Clone(Allocator(), nullptr);
    superPartialRefTypeParams->SetTsType(nullptr);
    auto superRefParams = superPartialRefTypeParams->Params();
    auto originRefParams = superRef->AsETSTypeReference()->Part()->TypeParams()->Params();
    for (size_t ix = 0; ix < superRefParams.size(); ++ix) {
        if (!originRefParams[ix]->IsETSTypeReference() ||
            !originRefParams[ix]->AsETSTypeReference()->Part()->TsType()->IsETSTypeParameter()) {
            continue;
        }
        auto it = likeSubstitution->find(
            originRefParams[ix]->AsETSTypeReference()->Part()->TsType()->AsETSTypeParameter()->GetDeclNode());
        if (it != likeSubstitution->end()) {
            auto *typeParamRefPart =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                AllocNode<ir::ETSTypeReferencePart>(it->second->Name()->Clone(Allocator(), nullptr), Allocator());
            typeParamRefPart->Name()->SetParent(typeParamRefPart);
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *typeParamRef = AllocNode<ir::ETSTypeReference>(typeParamRefPart, Allocator());
            typeParamRefPart->SetParent(typeParamRef);

            typeParamRef->SetParent(superPartialRefTypeParams);
            superRefParams[ix] = typeParamRef;
        }
    }
    return superPartialRefTypeParams;
}

ir::ETSTypeReference *ETSChecker::BuildSuperPartialTypeReference(
    Type *superPartialType, ir::TSTypeParameterInstantiation *superPartialRefTypeParams)
{
    ir::ETSTypeReference *superPartialRef = nullptr;
    if (superPartialType != nullptr) {
        auto *superPartialDeclNode = superPartialType->AsETSObjectType()->GetDeclNode();
        auto *clonedId = superPartialDeclNode->IsClassDefinition()
                             // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                             ? superPartialDeclNode->AsClassDefinition()->Ident()->Clone(Allocator(), nullptr)
                             // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                             : superPartialDeclNode->AsTSInterfaceDeclaration()->Id()->Clone(Allocator(), nullptr);
        auto *superPartialRefPart =
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            AllocNode<ir::ETSTypeReferencePart>(clonedId, superPartialRefTypeParams, nullptr, Allocator());
        superPartialRefPart->Name()->SetParent(superPartialRefPart);
        if (superPartialRefTypeParams != nullptr) {
            superPartialRefTypeParams->SetParent(superPartialRefPart);
        }

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        superPartialRef = AllocNode<ir::ETSTypeReference>(superPartialRefPart, Allocator());
        superPartialRefPart->SetParent(superPartialRef);
    }
    return superPartialRef;
}

void ETSChecker::CreatePartialClassDeclaration(ir::ClassDefinition *const newClassDefinition,
                                               ir::ClassDefinition *classDef)
{
    if (classDef->TypeParams() != nullptr) {
        ArenaVector<ir::TSTypeParameter *> typeParams(Allocator()->Adapter());
        for (auto *const classDefTypeParam : classDef->TypeParams()->Params()) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *const newTypeParam = AllocNode<ir::TSTypeParameter>(
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                CloneNodeIfNotNullptr(classDefTypeParam->Name(), Allocator()),
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                CloneNodeIfNotNullptr(classDefTypeParam->Constraint(), Allocator()),
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                CloneNodeIfNotNullptr(classDefTypeParam->DefaultType(), Allocator()), Allocator());
            typeParams.emplace_back(newTypeParam);
        }

        auto *const newTypeParams =
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            AllocNode<ir::TSTypeParameterDeclaration>(std::move(typeParams), classDef->TypeParams()->RequiredParams());

        newClassDefinition->SetTypeParams(newTypeParams);
        newTypeParams->SetParent(newClassDefinition);
    }

    newClassDefinition->SetVariable(newClassDefinition->Ident()->Variable());
    newClassDefinition->AddModifier(static_cast<const ir::AstNode *>(classDef)->Modifiers());

    for (auto *const prop : classDef->Body()) {
        // Only handle class properties (members)
        // Method calls on partial classes will make the class not type safe, so we don't copy any methods
        if (prop->IsClassProperty()) {
            if (prop->AsClassProperty()->Id()->Name().Mutf8().find(compiler::Signatures::PROPERTY, 0) == 0) {
                continue;
            }

            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            auto *const newProp = CreateNullishProperty(prop->AsClassProperty(), newClassDefinition);

            // Put the new property into the class declaration
            newClassDefinition->Body().emplace_back(newProp);
        }

        if (prop->IsMethodDefinition() && (prop->AsMethodDefinition()->Function()->IsGetter() ||
                                           prop->AsMethodDefinition()->Function()->IsSetter())) {
            auto *method = prop->AsMethodDefinition();
            if (newClassDefinition->Scope()->FindLocal(method->Id()->Name(),
                                                       varbinder::ResolveBindingOptions::VARIABLES) != nullptr) {
                continue;
            }
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            newClassDefinition->Body().emplace_back(CreateNullishPropertyFromAccessor(method, newClassDefinition));
        }
    }
    if (classDef->IsDeclare()) {
        newClassDefinition->AddModifier(ir::ModifierFlags::DECLARE);
    }

    // Run varbinder for new partial class to set scopes
    compiler::InitScopesPhaseETS::RunExternalNode(newClassDefinition, VarBinder());

    newClassDefinition->SetTsType(nullptr);
    newClassDefinition->Variable()->SetTsType(nullptr);
}

ir::MethodDefinition *ETSChecker::CreateNullishAccessor(ir::MethodDefinition *const accessor,
                                                        ir::TSInterfaceDeclaration *interface)
{
    const auto interfaceCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(VarBinder(), interface->Scope());
    auto *paramScope = Allocator()->New<varbinder::FunctionParamScope>(Allocator(), interface->Scope());
    auto *functionScope = Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);

    {
        auto paramScopeCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), paramScope);
        VarBinder()->AddMandatoryParam(varbinder::TypedBinder::MANDATORY_PARAM_THIS);
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ir::MethodDefinition *nullishAccessor = accessor->Clone(Allocator(), interface->Body());

    auto *decl = Allocator()->New<varbinder::FunctionDecl>(Allocator(), nullishAccessor->Id()->Name(), nullishAccessor);
    auto *var = Allocator()->New<varbinder::LocalVariable>(decl, varbinder::VariableFlags::VAR);
    var->AddFlag(varbinder::VariableFlags::METHOD);
    nullishAccessor->Id()->SetVariable(var);
    nullishAccessor->SetVariable(var);

    functionScope->BindName(interface->InternalName());

    auto *function = nullishAccessor->Function();
    function->SetVariable(var);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    function->SetIdent(nullishAccessor->Id()->Clone(Allocator(), function));
    function->SetScope(functionScope);
    paramScope->BindNode(function);
    functionScope->BindNode(function);

    if (function->IsGetter()) {
        auto *propTypeAnn = function->ReturnTypeAnnotation();

        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        function->SetReturnTypeAnnotation(AllocNode<ir::ETSUnionType>(
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ArenaVector<ir::TypeNode *>({propTypeAnn, AllocNode<ir::ETSUndefinedType>(Allocator())},
                                        Allocator()->Adapter()),
            Allocator()));
    } else {
        for (auto *params : function->Params()) {
            auto *paramExpr = params->AsETSParameterExpression();

            auto *unionType =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                AllocNode<ir::ETSUnionType>(
                    ArenaVector<ir::TypeNode *>({paramExpr->Ident()->TypeAnnotation(),
                                                 // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                                 AllocNode<ir::ETSUndefinedType>(Allocator())},
                                                Allocator()->Adapter()),
                    Allocator());
            paramExpr->Ident()->SetTsTypeAnnotation(unionType);
            unionType->SetParent(paramExpr->Ident());

            auto [paramVar, node] = paramScope->AddParamDecl(Allocator(), VarBinder(), paramExpr);
            if (node != nullptr) {
                VarBinder()->ThrowRedeclaration(node->Start(), paramVar->Name());
            }

            paramExpr->SetVariable(paramVar);
        }
    }

    nullishAccessor->SetOverloads(ArenaVector<ir::MethodDefinition *>(Allocator()->Adapter()));

    return nullishAccessor;
}

ir::TSInterfaceDeclaration *ETSChecker::CreateInterfaceProto(util::StringView name,
                                                             parser::Program *const interfaceDeclProgram,
                                                             const bool isStatic, const ir::ModifierFlags flags)
{
    const auto globalCtx =
        varbinder::LexicalScope<varbinder::GlobalScope>::Enter(VarBinder(), interfaceDeclProgram->GlobalScope());

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const interfaceId = AllocNode<ir::Identifier>(name, Allocator());
    const auto [decl, var] =
        VarBinder()->NewVarDecl<varbinder::InterfaceDecl>(interfaceId->Start(), Allocator(), interfaceId->Name());
    interfaceId->SetVariable(var);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = AllocNode<ir::TSInterfaceBody>(ArenaVector<ir::AstNode *>(Allocator()->Adapter()));
    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());

    ArenaVector<ir::TSTypeParameter *> typeParams(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *newTypeParams = AllocNode<ir::TSTypeParameterDeclaration>(std::move(typeParams), typeParams.size());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto partialInterface = AllocNode<ir::TSInterfaceDeclaration>(
        Allocator(), std::move(extends),
        ir::TSInterfaceDeclaration::ConstructorData {interfaceId, newTypeParams, body, isStatic,
                                                     interfaceDeclProgram != VarBinder()->Program(),
                                                     Language(Language::Id::ETS)});

    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    partialInterface->TypeParams()->SetParent(partialInterface);
    partialInterface->SetScope(classCtx.GetScope());
    partialInterface->SetVariable(var);
    decl->BindNode(partialInterface);

    // Put class declaration in global scope, and in program AST
    partialInterface->SetParent(interfaceDeclProgram->Ast());
    interfaceDeclProgram->Ast()->Statements().push_back(partialInterface);
    interfaceDeclProgram->GlobalScope()->InsertBinding(name, var);

    partialInterface->AddModifier(flags);

    return partialInterface;
}

void ETSChecker::CreatePartialTypeInterfaceMethods(ir::TSInterfaceDeclaration *const interfaceDecl,
                                                   ir::TSInterfaceDeclaration *partialInterface)
{
    auto &partialInterfaceMethods = partialInterface->Body()->Body();

    auto const addNullishAccessor = [&partialInterfaceMethods](ir::MethodDefinition *accessor) -> void {
        auto const it = std::find_if(partialInterfaceMethods.begin(), partialInterfaceMethods.end(),
                                     [accessor](ir::AstNode const *node) -> bool {
                                         return node->AsMethodDefinition()->Id()->Name() == accessor->Id()->Name();
                                     });
        if (it == partialInterfaceMethods.end()) {
            accessor->Function()->ClearFlag(ir::ScriptFunctionFlags::OVERLOAD);
            partialInterfaceMethods.emplace_back(accessor);
        } else if (accessor->Function()->IsSetter()) {
            ES2PANDA_ASSERT_POS((*it)->AsMethodDefinition()->Function()->IsGetter(), (*it)->Start());
            (*it)->AsMethodDefinition()->AddOverload(accessor);
            accessor->SetParent(*it);
            accessor->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
        } else {
            ES2PANDA_ASSERT_POS((*it)->AsMethodDefinition()->Function()->IsSetter(), (*it)->Start());
            auto setter = (*it)->AsMethodDefinition();
            accessor->AddOverload(setter);
            setter->SetParent(accessor);
            setter->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
            partialInterfaceMethods.erase(it);
            partialInterfaceMethods.emplace_back(accessor);
        }
    };

    for (auto *const prop : interfaceDecl->Body()->Body()) {
        if (!prop->IsMethodDefinition()) {
            continue;
        }

        auto *const method = prop->AsMethodDefinition();
        ES2PANDA_ASSERT((method->Function()->Flags() & ir::ScriptFunctionFlags::OVERLOAD) == 0U);

        if (method->Function()->IsGetter() || method->Function()->IsSetter()) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            addNullishAccessor(CreateNullishAccessor(method, partialInterface));
        }

        for (auto *overload : method->Overloads()) {
            if (overload->Function()->IsGetter() || overload->Function()->IsSetter()) {
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                addNullishAccessor(CreateNullishAccessor(overload, partialInterface));
            }
        }
    }
}

Type *ETSChecker::CreatePartialTypeInterfaceDecl(ir::TSInterfaceDeclaration *const interfaceDecl,
                                                 ETSObjectType *const typeToBePartial,
                                                 ir::TSInterfaceDeclaration *partialInterface)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    CreatePartialTypeInterfaceMethods(interfaceDecl, partialInterface);
    // Create nullish properties of the partial class
    // Build the new Partial class based on the 'T' type parameter of 'Partial<T>'
    auto *likeSubstitution =
        Allocator()->New<ArenaMap<ir::TSTypeParameter *, ir::TSTypeParameter *>>(Allocator()->Adapter());

    if (interfaceDecl->TypeParams() != nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ProcessTypeParamAndGenSubstitution(interfaceDecl->TypeParams(), likeSubstitution,
                                           partialInterface->TypeParams());
    }

    compiler::InitScopesPhaseETS::RunExternalNode(partialInterface, VarBinder());

    auto methodscope = partialInterface->Scope()->AsClassScope()->InstanceMethodScope();
    // Add getter methods to instancemethodscope.
    for (auto *const prop : partialInterface->Body()->Body()) {
        if (prop->IsMethodDefinition() && prop->AsMethodDefinition()->Function()->IsGetter()) {
            auto *decl = Allocator()->New<varbinder::FunctionDecl>(
                Allocator(), prop->AsMethodDefinition()->Key()->AsIdentifier()->Name(), prop);
            methodscope->AddDecl(Allocator(), decl, ScriptExtension::ETS);
        }
    }

    // Create partial type for super type
    for (auto *extend : interfaceDecl->Extends()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *t = extend->Expr()->AsETSTypeReference()->Part()->GetType(this);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        if (auto *superPartialType = CreatePartialType(t); superPartialType != nullptr) {
            ir::TSTypeParameterInstantiation *superPartialRefTypeParams =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                CreateNewSuperPartialRefTypeParamsDecl(likeSubstitution, superPartialType, extend->Expr());

            ir::ETSTypeReference *superPartialRef =
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                BuildSuperPartialTypeReference(superPartialType, superPartialRefTypeParams);
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            partialInterface->Extends().push_back(AllocNode<ir::TSInterfaceHeritage>(superPartialRef));
            partialInterface->Extends().back()->SetParent(partialInterface);
        }
    }

    auto *const partialType = partialInterface->Check(this)->AsETSObjectType();
    partialType->SetBaseType(typeToBePartial);

    return partialType;
}

void ETSChecker::CreateConstructorForPartialType(ir::ClassDefinition *const partialClassDef,
                                                 checker::ETSObjectType *const partialType,
                                                 varbinder::RecordTable *const recordTable)
{
    // Create scopes
    auto *const scope = partialClassDef->Scope()->AsClassScope();
    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), scope);

    // Create ctor
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const ctor = CreateNonStaticClassInitializer(classCtx.GetScope(), recordTable);
    auto *const ctorFunc = ctor->Function();
    if (partialClassDef->IsDeclare()) {
        ctorFunc->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
    }
    auto *const ctorId = ctor->Function()->Id();

    // Handle bindings, create method decl for ctor
    ctorFunc->Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS).variable->SetTsType(partialType);
    partialType->AddConstructSignature(ctorFunc->Signature());
    ctorFunc->Signature()->SetOwner(partialType);
    ctor->SetParent(partialClassDef);
    ctorId->SetVariable(Allocator()->New<varbinder::LocalVariable>(
        Allocator()->New<varbinder::MethodDecl>(ctorId->Name()), varbinder::VariableFlags::METHOD));
    ctor->Id()->SetVariable(ctorId->Variable());

    // Put ctor in partial class body
    partialClassDef->Body().emplace_back(ctor);
}

ir::ClassDefinition *ETSChecker::CreateClassPrototype(util::StringView name, parser::Program *const classDeclProgram)
{
    const auto globalCtx =
        varbinder::LexicalScope<varbinder::GlobalScope>::Enter(VarBinder(), classDeclProgram->GlobalScope());

    // Create class name, and declaration variable
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const classId = AllocNode<ir::Identifier>(name, Allocator());
    const auto [decl, var] = VarBinder()->NewVarDecl<varbinder::ClassDecl>(classId->Start(), classId->Name());
    classId->SetVariable(var);

    // Create class definition node
    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *const classDef =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::ClassDefinition>(Allocator(), classId, ir::ClassDefinitionModifiers::DECLARATION,
                                       ir::ModifierFlags::NONE, Language(Language::Id::ETS));
    classDef->SetScope(classCtx.GetScope());
    classDef->SetVariable(var);

    // Create class declaration node
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const classDecl = AllocNode<ir::ClassDeclaration>(classDef, Allocator());
    classDecl->SetParent(classDeclProgram->Ast());

    // Class definition is scope bearer, not class declaration
    classDef->Scope()->BindNode(classDecl->Definition());
    decl->BindNode(classDef);

    // Put class declaration in global scope, and in program AST
    classDeclProgram->Ast()->Statements().push_back(classDecl);
    classDeclProgram->GlobalScope()->InsertBinding(name, var);

    return classDef;
}

varbinder::Variable *ETSChecker::SearchNamesInMultiplePrograms(const std::set<const parser::Program *> &programs,
                                                               const std::set<util::StringView> &classNamesToFind)
{
    for (const auto *const program : programs) {
        for (const auto &className : classNamesToFind) {
            auto *const var = program->GlobalScope()->Find(className, varbinder::ResolveBindingOptions::ALL).variable;
            if (var == nullptr) {
                continue;
            }

            if (var->TsType() == nullptr) {
                var->Declaration()->Node()->Check(this);
            }

            return var;
        }
    }

    return nullptr;
}

Type *ETSChecker::HandleUnionForPartialType(ETSUnionType *const typeToBePartial)
{
    // Convert a union type to partial, by converting all types in it to partial, and making a new union
    // type out of them
    const auto *const unionTypeNode = typeToBePartial->AsETSUnionType();
    ArenaVector<checker::Type *> newTypesForUnion(Allocator()->Adapter());

    for (auto *const typeFromUnion : unionTypeNode->ConstituentTypes()) {
        if ((typeFromUnion->Variable() != nullptr) && (typeFromUnion->Variable()->Declaration() != nullptr)) {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            newTypesForUnion.emplace_back(CreatePartialType(typeFromUnion));
        } else {
            newTypesForUnion.emplace_back(typeFromUnion);
        }
    }

    return CreateETSUnionType(std::move(newTypesForUnion));
}

Type *ETSChecker::CreatePartialTypeClassDef(ir::ClassDefinition *const partialClassDef,
                                            ir::ClassDefinition *const classDef, ETSObjectType *const typeToBePartial,
                                            varbinder::RecordTable *const recordTableToUse)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    CreatePartialClassDeclaration(partialClassDef, classDef);

    // Run checker
    auto *const partialType = partialClassDef->Check(this)->AsETSObjectType();

    for (auto *interface : typeToBePartial->Interfaces()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        partialType->AddInterface(CreatePartialType(interface)->AsETSObjectType());
    }

    partialType->SetBaseType(typeToBePartial);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    CreateConstructorForPartialType(partialClassDef, partialType, recordTableToUse);

    // Create partial type for super type
    if (typeToBePartial != GlobalETSObjectType()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const partialSuper = CreatePartialType((classDef->Super() == nullptr || !classDef->Super()->IsTypeNode())
                                                         ? GlobalETSObjectType()
                                                         : classDef->Super()->TsType());

        partialType->SetSuperType(partialSuper->AsETSObjectType());
    }

    return partialType;
}

std::pair<ir::ScriptFunction *, ir::Identifier *> ETSChecker::CreateScriptFunctionForConstructor(
    varbinder::FunctionScope *const scope)
{
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    ir::ScriptFunction *func {};
    ir::Identifier *id {};

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    id = AllocNode<ir::Identifier>(util::UString(std::string("constructor"), Allocator()).View(), Allocator());
    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    func = AllocNode<ir::ScriptFunction>(Allocator(),
                                         ir::ScriptFunction::ScriptFunctionData {
                                             body, std::move(funcSignature),
                                             ir::ScriptFunctionFlags::CONSTRUCTOR | ir::ScriptFunctionFlags::EXPRESSION,
                                             ir::ModifierFlags::PUBLIC});

    func->SetScope(scope);
    scope->BindNode(func);
    func->SetIdent(id);
    VarBinder()->AsETSBinder()->AddFunctionThisParam(func);

    return std::make_pair(func, id);
}

ir::MethodDefinition *ETSChecker::CreateNonStaticClassInitializer(varbinder::ClassScope *classScope,
                                                                  varbinder::RecordTable *const recordTable)
{
    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), classScope);

    auto *paramScope = Allocator()->New<varbinder::FunctionParamScope>(Allocator(), classScope);
    auto *const functionScope = Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);
    functionScope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(functionScope);

    const auto funcParamCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), paramScope);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto [func, id] = CreateScriptFunctionForConstructor(functionScope);

    paramScope->BindNode(func);
    functionScope->BindNode(func);

    auto *const signatureInfo = CreateSignatureInfo();
    auto *const signature = CreateSignature(signatureInfo, GlobalVoidType(), func);
    func->SetSignature(signature);

    VarBinder()->AsETSBinder()->BuildInternalNameWithCustomRecordTable(func, recordTable);
    VarBinder()->AsETSBinder()->BuildFunctionName(func);
    VarBinder()->Functions().push_back(functionScope);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR,
                                                       // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                                                       id->Clone(Allocator(), classScope->Node()), funcExpr,
                                                       ir::ModifierFlags::NONE, Allocator(), false);

    auto *const funcType = CreateETSMethodType(id->Name(), {{signature}, Allocator()->Adapter()});
    ctor->SetTsType(funcType);

    return ctor;
}

Type *ETSChecker::GetReadonlyType(Type *type)
{
    if (const auto found = NamedTypeStack().find(type); found != NamedTypeStack().end()) {
        return *found;
    }

    NamedTypeStackElement ntse(this, type);

    if (type->IsETSArrayType()) {
        ETSArrayType *const clonedArrayType = Allocator()->New<ETSArrayType>(type->AsETSArrayType()->ElementType());
        clonedArrayType->AddTypeFlag(TypeFlag::READONLY);
        return clonedArrayType;
    }
    if (type->IsETSTupleType()) {
        Type *const clonedType = type->Clone(this);
        clonedType->AddTypeFlag(TypeFlag::READONLY);
        return clonedType;
    }

    if (type->IsETSObjectType()) {
        type->AsETSObjectType()->InstanceFields();
        auto *clonedType = type->Clone(this)->AsETSObjectType();
        MakePropertiesReadonly(clonedType);
        return clonedType;
    }
    if (type->IsETSTypeParameter()) {
        return Allocator()->New<ETSReadonlyType>(type->AsETSTypeParameter());
    }
    if (type->IsETSUnionType()) {
        ArenaVector<Type *> unionTypes(Allocator()->Adapter());
        for (auto *t : type->AsETSUnionType()->ConstituentTypes()) {
            unionTypes.emplace_back(t->IsETSObjectType() ? GetReadonlyType(t) : t->Clone(this));
        }
        return CreateETSUnionType(std::move(unionTypes));
    }
    return type;
}

void ETSChecker::MakePropertiesReadonly(ETSObjectType *const classType)
{
    classType->UpdateTypeProperties(this, [this](auto *property, auto *propType) {
        auto *newDecl = Allocator()->New<varbinder::ReadonlyDecl>(property->Name(), property->Declaration()->Node());
        auto *const propCopy = property->Copy(Allocator(), newDecl);
        propCopy->AddFlag(varbinder::VariableFlags::READONLY);
        propCopy->SetTsType(propType);
        return propCopy;
    });
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Required utility type
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Type *ETSChecker::HandleRequiredType(Type *typeToBeRequired)
{
    if (const auto found = NamedTypeStack().find(typeToBeRequired); found != NamedTypeStack().end()) {
        return *found;
    }

    NamedTypeStackElement ntse(this, typeToBeRequired);

    if (typeToBeRequired->IsETSTypeParameter()) {
        auto *const requiredClone = typeToBeRequired->Clone(this);
        requiredClone->AddTypeFlag(TypeFlag::ETS_REQUIRED_TYPE_PARAMETER);
        return requiredClone;
    }

    if (typeToBeRequired->IsETSUnionType()) {
        ArenaVector<Type *> unionTypes(Allocator()->Adapter());
        for (auto *type : typeToBeRequired->AsETSUnionType()->ConstituentTypes()) {
            if (type->IsETSObjectType()) {
                type = type->Clone(this);
                MakePropertiesNonNullish(type->AsETSObjectType());
            }

            if (type->IsETSNullType() || type->IsETSUndefinedType()) {
                continue;
            }

            unionTypes.emplace_back(type);
        }

        return CreateETSUnionType(std::move(unionTypes));
    }

    if (typeToBeRequired->IsETSObjectType()) {
        typeToBeRequired->AsETSObjectType()->InstanceFields();  // call to instantiate properties
    }

    typeToBeRequired = typeToBeRequired->Clone(this);

    MakePropertiesNonNullish(typeToBeRequired->AsETSObjectType());

    return typeToBeRequired;
}

void ETSChecker::MakePropertiesNonNullish(ETSObjectType *const classType)
{
    classType->AddObjectFlag(ETSObjectFlags::REQUIRED);
    classType->InstanceFields();

    for (const auto &[_, propVar] : classType->InstanceFields()) {
        MakePropertyNonNullish<PropertyType::INSTANCE_FIELD>(classType, propVar);
    }

    for (const auto &[_, propVar] : classType->StaticFields()) {
        MakePropertyNonNullish<PropertyType::STATIC_FIELD>(classType, propVar);
    }

    if (classType->SuperType() != nullptr) {
        auto *const superRequired = classType->SuperType()->Clone(this)->AsETSObjectType();
        MakePropertiesNonNullish(superRequired);
        classType->SetSuperType(superRequired);
    }
}

template <PropertyType PROP_TYPE>
void ETSChecker::MakePropertyNonNullish(ETSObjectType *const classType, varbinder::LocalVariable *const prop)
{
    auto *const propType = prop->TsType();
    auto *const nonNullishPropType = GetNonNullishType(propType);

    auto *const propCopy = prop->Copy(Allocator(), prop->Declaration());

    propCopy->SetTsType(nonNullishPropType);
    classType->RemoveProperty<PROP_TYPE>(prop);
    classType->AddProperty<PROP_TYPE>(propCopy);
}

static bool StringEqualsPropertyName(const util::StringView pname1, const ir::Expression *const prop2Key)
{
    util::StringView pname2;
    if (prop2Key->IsStringLiteral()) {
        pname2 = prop2Key->AsStringLiteral()->Str();
    } else if (prop2Key->IsIdentifier()) {
        pname2 = prop2Key->AsIdentifier()->Name();
    }

    return pname1 == pname2;
}

void ETSChecker::ValidateObjectLiteralForRequiredType(const ETSObjectType *const requiredType,
                                                      const ir::ObjectExpression *const initObjExpr)
{
    auto initObjExprContainsField = [&initObjExpr](const util::StringView pname1) {
        return std::find_if(initObjExpr->Properties().begin(), initObjExpr->Properties().end(),
                            [&pname1](const ir::Expression *const initProp) {
                                return StringEqualsPropertyName(pname1, initProp->AsProperty()->Key());
                            }) != initObjExpr->Properties().end();
    };

    if (requiredType->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        for (const auto *method : requiredType->GetDeclNode()->AsTSInterfaceDeclaration()->Body()->Body()) {
            if (!method->IsMethodDefinition() || !method->AsMethodDefinition()->Function()->IsGetter()) {
                continue;
            }

            auto fieldname = method->AsMethodDefinition()->Key()->AsIdentifier()->Name();
            if (!initObjExprContainsField(fieldname)) {
                LogError(diagnostic::REQUIRED_PROP_MISSING_INIT, {fieldname, requiredType->Name()},
                         initObjExpr->Start());
            }
        }

        return;
    }

    for (const auto &[propName, _] : requiredType->InstanceFields()) {
        if (!initObjExprContainsField(propName)) {
            LogError(diagnostic::REQUIRED_PROP_MISSING_INIT, {propName, requiredType->Name()}, initObjExpr->Start());
        }
    }
}
}  // namespace ark::es2panda::checker
