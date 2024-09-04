/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "varbinder/ETSBinder.h"

namespace ark::es2panda::checker {

ir::TypeNode *ETSChecker::GetUtilityTypeTypeParamNode(const ir::TSTypeParameterInstantiation *const typeParams,
                                                      const std::string_view &utilityTypeName)
{
    if (typeParams->Params().size() != 1) {
        ThrowTypeError({"Invalid number of type parameters for ", utilityTypeName, " type"}, typeParams->Start());
    }

    return typeParams->Params().front();
}

Type *ETSChecker::HandleUtilityTypeParameterNode(const ir::TSTypeParameterInstantiation *const typeParams,
                                                 const std::string_view &utilityType)
{
    auto *const bareType = GetUtilityTypeTypeParamNode(typeParams, utilityType)->Check(this);

    if (utilityType == compiler::Signatures::PARTIAL_TYPE_NAME) {
        return HandlePartialType(bareType);
    }

    if (utilityType == compiler::Signatures::READONLY_TYPE_NAME) {
        return GetReadonlyType(bareType);
    }

    if (utilityType == compiler::Signatures::REQUIRED_TYPE_NAME) {
        return HandleRequiredType(bareType);
    }

    ThrowTypeError("This utility type is not yet implemented.", typeParams->Start());
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Partial utility type
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Type *ETSChecker::HandlePartialType(Type *const typeToBePartial)
{
    if (typeToBePartial->IsETSTypeParameter()) {
        // NOTE (mmartin): this is not type safe!
        return HandlePartialType(GetApparentType(typeToBePartial));
    }

    if (typeToBePartial->IsETSUnionType()) {
        return HandleUnionForPartialType(typeToBePartial->AsETSUnionType());
    }

    if (!typeToBePartial->Variable()->Declaration()->Node()->IsClassDefinition()) {
        // NOTE (mmartin): there is a bug, that modifies the declaration of the variable of a type. That could make the
        // declaration node of an ETSObjectType eg. a ClassProperty, instead of the actual class declaration. When it's
        // fixed, remove this.
        return typeToBePartial;
    }

    auto *const classDef = typeToBePartial->Variable()->Declaration()->Node()->AsClassDefinition();

    constexpr auto *PARTIAL_CLASS_SUFFIX = "$partial";

    // Partial class name for class 'T' will be 'T$partial'
    const auto partialClassName =
        util::UString(classDef->Ident()->Name().Mutf8() + PARTIAL_CLASS_SUFFIX, Allocator()).View();

    auto *const classDefProgram = classDef->GetTopStatement()->AsETSScript()->Program();
    const bool isClassDeclaredInCurrentFile = classDefProgram == VarBinder()->Program();
    auto *const programToUse = isClassDeclaredInCurrentFile ? VarBinder()->Program() : classDefProgram;
    const auto qualifiedClassName = GetQualifiedClassName(programToUse, partialClassName);

    // Check if we've already generated the partial class, then don't do it again
    const auto classNameToFind =
        isClassDeclaredInCurrentFile || VarBinder()->IsGenStdLib() ? partialClassName : qualifiedClassName;
    if (const auto *const var =
            SearchNamesInMultiplePrograms({programToUse, VarBinder()->Program()}, {classNameToFind, partialClassName});
        var != nullptr) {
        return var->TsType();
    }

    // Create only the 'header' of the class
    auto *const partialClassDef = CreateClassPrototype(partialClassName, programToUse);

    auto *const recordTableToUse = isClassDeclaredInCurrentFile
                                       ? VarBinder()->AsETSBinder()->GetGlobalRecordTable()
                                       : VarBinder()->AsETSBinder()->GetExternalRecordTable().at(programToUse);

    const varbinder::BoundContext boundCtx(recordTableToUse, partialClassDef);
    partialClassDef->SetInternalName(
        util::UString(classDef->InternalName().Mutf8() + PARTIAL_CLASS_SUFFIX, Allocator()).View());

    // If class prototype was created before, then we cached it's type. In that case return it.
    // This handles cases where a Partial<T> presents in class T, because during generating T$partial we'd need the
    // complete class T$partial which is not present at the time. Binding it's own type for it however will make it
    // possible to resolve member references later, when the full T$partial class was created.
    if (const auto found = NamedTypeStack().find(partialClassDef->TsType()); found != NamedTypeStack().end()) {
        return *found;
    }

    NamedTypeStackElement ntse(this, partialClassDef->TsType());

    // If class is external, put partial of it in global scope for the varbinder
    if (!isClassDeclaredInCurrentFile) {
        VarBinder()->Program()->GlobalScope()->InsertBinding(partialClassDef->Ident()->Name(),
                                                             partialClassDef->Variable());
    }

    return CreatePartialTypeClassDef(partialClassDef, classDef, typeToBePartial, recordTableToUse);
}

ir::ClassProperty *ETSChecker::CreateNullishProperty(ir::ClassProperty *const prop,
                                                     ir::ClassDefinition *const newClassDefinition)
{
    auto *const classProp = prop->AsClassProperty();
    auto *const propSavedValue = classProp->Value();

    // Set value to nullptr to prevent cloning it (as for arrow functions that is not possible yet), we set it
    // to 'undefined' anyway
    classProp->SetValue(nullptr);
    auto *const propClone = prop->Clone(Allocator(), newClassDefinition)->AsClassProperty();

    // Revert original property value
    classProp->SetValue(propSavedValue);
    propClone->AsClassProperty()->SetValue(Allocator()->New<ir::UndefinedLiteral>());

    auto *propTypeAnn = propClone->TypeAnnotation();
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());

    // Handle implicit type annotation
    if (propTypeAnn == nullptr) {
        propTypeAnn = Allocator()->New<ir::OpaqueTypeNode>(classProp->TsType());
    }

    // NOTE (mmartin): Union type check fails if it contains ETSEnum type, workaround until fix
    if ((classProp->TsType() != nullptr) && classProp->TsType()->IsETSIntEnumType()) {
        propTypeAnn = Allocator()->New<ir::OpaqueTypeNode>(GlobalETSObjectType());
    }

    // Create new nullish type
    types.push_back(propTypeAnn);
    types.push_back(AllocNode<ir::ETSUndefinedType>());
    auto *const unionType = AllocNode<ir::ETSUnionType>(std::move(types));
    propClone->SetTypeAnnotation(unionType);

    // Set new parents
    unionType->SetParent(propClone);
    propClone->SetParent(newClassDefinition);

    // Handle bindings, variables
    varbinder::Decl *const newDecl =
        classProp->IsConst()
            ? static_cast<varbinder::Decl *>(Allocator()->New<varbinder::ConstDecl>(propClone->Id()->Name()))
            : Allocator()->New<varbinder::LetDecl>(propClone->Id()->Name());

    propClone->SetVariable(Allocator()->New<varbinder::LocalVariable>(newDecl, varbinder::VariableFlags::PROPERTY));

    propClone->Variable()->SetScope(classProp->IsStatic()
                                        ? newClassDefinition->Scope()->AsClassScope()->StaticFieldScope()
                                        : newClassDefinition->Scope()->AsClassScope()->InstanceFieldScope());

    propClone->Variable()->Declaration()->BindNode(propClone);

    return propClone;
}

template <typename T>
static T *CloneNodeIfNotNullptr(T *node, ArenaAllocator *allocator)
{
    return node != nullptr ? node->Clone(allocator, nullptr) : nullptr;
}

ir::ClassDefinition *ETSChecker::CreatePartialClassDeclaration(ir::ClassDefinition *const newClassDefinition,
                                                               const ir::ClassDefinition *const classDef)
{
    // Build the new Partial class based on the 'T' type parameter of 'Partial<T>'

    for (auto *const prop : classDef->Body()) {
        // Only handle class properties (members)
        // Method calls on partial classes will make the class not type safe, so we don't copy any methods
        if (prop->IsClassProperty()) {
            auto *const newProp = CreateNullishProperty(prop->AsClassProperty(), newClassDefinition);

            newClassDefinition->Scope()->AddBinding(Allocator(), nullptr, newProp->Variable()->Declaration(),
                                                    ScriptExtension::ETS);

            // Put the new property into the class declaration
            newClassDefinition->Body().emplace_back(newProp);
        }
    }

    newClassDefinition->SetVariable(newClassDefinition->Ident()->Variable());
    newClassDefinition->AddModifier(static_cast<const ir::AstNode *>(classDef)->Modifiers());

    if (classDef->TypeParams() != nullptr) {
        ArenaVector<ir::TSTypeParameter *> typeParams(Allocator()->Adapter());
        for (auto *const classDefTypeParam : classDef->TypeParams()->Params()) {
            auto *const newTypeParam =
                AllocNode<ir::TSTypeParameter>(CloneNodeIfNotNullptr(classDefTypeParam->Name(), Allocator()),
                                               CloneNodeIfNotNullptr(classDefTypeParam->Constraint(), Allocator()),
                                               CloneNodeIfNotNullptr(classDefTypeParam->DefaultType(), Allocator()));
            typeParams.emplace_back(newTypeParam);
        }

        auto *const newTypeParams =
            AllocNode<ir::TSTypeParameterDeclaration>(std::move(typeParams), classDef->TypeParams()->RequiredParams());

        newClassDefinition->SetTypeParams(newTypeParams);
        newTypeParams->SetParent(newClassDefinition);
        newTypeParams->SetScope(newClassDefinition->Scope());
    }

    newClassDefinition->SetTsType(nullptr);

    return newClassDefinition;
}

void ETSChecker::CreateConstructorForPartialType(ir::ClassDefinition *const partialClassDef,
                                                 checker::ETSObjectType *const partialType,
                                                 varbinder::RecordTable *const recordTable)
{
    // Create scopes
    auto *const scope = partialClassDef->Scope()->AsClassScope();
    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), scope);

    // Create ctor
    auto *const ctor = CreateNonStaticClassInitializer(classCtx.GetScope(), recordTable);
    auto *const ctorFunc = ctor->Function();
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
    auto *const classId = AllocNode<ir::Identifier>(name, Allocator());
    const auto [decl, var] = VarBinder()->NewVarDecl<varbinder::ClassDecl>(classId->Start(), classId->Name());
    classId->SetVariable(var);

    // Create class definition node
    const auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *const classDef =
        AllocNode<ir::ClassDefinition>(Allocator(), classId, ir::ClassDefinitionModifiers::DECLARATION,
                                       ir::ModifierFlags::NONE, Language(Language::Id::ETS));
    classDef->SetScope(classCtx.GetScope());
    classDef->SetVariable(var);

    // Create class declaration node
    auto *const classDecl = AllocNode<ir::ClassDeclaration>(classDef, Allocator());
    classDecl->SetParent(classDeclProgram->Ast());
    classDef->Scope()->BindNode(classDecl);
    decl->BindNode(classDef);

    // Put class declaration in global scope, and in program AST
    classDeclProgram->Ast()->Statements().push_back(classDecl);
    classDeclProgram->GlobalScope()->InsertBinding(name, var);

    // Create only class 'header' (no properties and methods, but base type created)
    BuildBasicClassProperties(classDef);

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

util::StringView ETSChecker::GetQualifiedClassName(const parser::Program *const classDefProgram,
                                                   const util::StringView className)
{
    auto packageName = classDefProgram->ModuleName().Mutf8();
    if (!packageName.empty()) {
        packageName.append(".");
    }

    return util::UString(packageName + className.Mutf8(), Allocator()).View();
}

Type *ETSChecker::HandleUnionForPartialType(ETSUnionType *const typeToBePartial)
{
    // Convert a union type to partial, by converting all types in it to partial, and making a new union
    // type out of them
    const auto *const unionTypeNode = typeToBePartial->AsETSUnionType();
    ArenaVector<checker::Type *> newTypesForUnion(Allocator()->Adapter());

    for (auto *const typeFromUnion : unionTypeNode->ConstituentTypes()) {
        if (typeFromUnion->IsETSIntEnumType()) {
            // NOTE (mmartin): Union type check fails if it contains ETSEnum type, workaround until fix
            return typeFromUnion;
        }

        if ((typeFromUnion->Variable() != nullptr) && (typeFromUnion->Variable()->Declaration() != nullptr)) {
            newTypesForUnion.emplace_back(HandlePartialType(typeFromUnion));
        } else {
            newTypesForUnion.emplace_back(typeFromUnion);
        }
    }

    return CreateETSUnionType(std::move(newTypesForUnion));
}

Type *ETSChecker::CreatePartialTypeClassDef(ir::ClassDefinition *const partialClassDef,
                                            ir::ClassDefinition *const classDef, const Type *const typeToBePartial,
                                            varbinder::RecordTable *const recordTableToUse)
{
    // Create nullish properties of the partial class
    CreatePartialClassDeclaration(partialClassDef, classDef);
    partialClassDef->Check(this);

    auto *const partialType = partialClassDef->TsType()->AsETSObjectType();
    partialType->SetAssemblerName(partialClassDef->InternalName());

    CreateConstructorForPartialType(partialClassDef, partialType, recordTableToUse);

    // Create partial type for super type
    if (typeToBePartial != GlobalETSObjectType()) {
        auto *const partialSuper =
            HandlePartialType(classDef->Super() == nullptr ? GlobalETSObjectType() : classDef->Super()->TsType());

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

    auto *const body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    id = AllocNode<ir::Identifier>(util::UString(std::string("constructor"), Allocator()).View(), Allocator());
    auto funcSignature = ir::FunctionSignature(nullptr, std::move(params), nullptr);
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

    auto [func, id] = CreateScriptFunctionForConstructor(functionScope);

    paramScope->BindNode(func);
    functionScope->BindNode(func);

    auto *const signatureInfo = CreateSignatureInfo();
    auto *const signature = CreateSignature(signatureInfo, GlobalVoidType(), func);
    func->SetSignature(signature);

    VarBinder()->AsETSBinder()->BuildInternalNameWithCustomRecordTable(func, recordTable);
    VarBinder()->AsETSBinder()->BuildFunctionName(func);
    VarBinder()->Functions().push_back(functionScope);

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    auto *const ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR,
                                                       id->Clone(Allocator(), classScope->Node()), funcExpr,
                                                       ir::ModifierFlags::NONE, Allocator(), false);

    auto *const funcType = CreateETSFunctionType(signature, id->Name());
    ctor->SetTsType(funcType);

    return ctor;
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Readonly utility type
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Type *ETSChecker::HandleReadonlyType(const ir::TSTypeParameterInstantiation *const typeParams)
{
    auto *const typeParamNode = GetUtilityTypeTypeParamNode(typeParams, compiler::Signatures::READONLY_TYPE_NAME);
    auto *typeToBeReadonly = typeParamNode->Check(this);

    if (auto found = NamedTypeStack().find(typeToBeReadonly); found != NamedTypeStack().end()) {
        return *found;
    }

    NamedTypeStackElement ntse(this, typeToBeReadonly);
    return GetReadonlyType(typeToBeReadonly);
}

Type *ETSChecker::GetReadonlyType(Type *type)
{
    if (const auto found = NamedTypeStack().find(type); found != NamedTypeStack().end()) {
        return *found;
    }

    NamedTypeStackElement ntse(this, type);

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
    const std::size_t classPropertyCount = requiredType->InstanceFields().size() + requiredType->StaticFields().size();

    auto initObjExprContainsField = [&initObjExpr](const util::StringView pname1) {
        return std::find_if(initObjExpr->Properties().begin(), initObjExpr->Properties().end(),
                            [&pname1](const ir::Expression *const initProp) {
                                return StringEqualsPropertyName(pname1, initProp->AsProperty()->Key());
                            }) != initObjExpr->Properties().end();
    };

    if (classPropertyCount > initObjExpr->Properties().size()) {
        std::string_view missingProp;

        for (const auto &[propName, _] : requiredType->InstanceFields()) {
            if (!initObjExprContainsField(propName)) {
                missingProp = propName.Utf8();
            }
        }

        for (const auto &[propName, _] : requiredType->StaticFields()) {
            if (!initObjExprContainsField(propName)) {
                missingProp = propName.Utf8();
            }
        }

        if (!missingProp.empty()) {
            ThrowTypeError({"Class property '", missingProp, "' needs to be initialized for required type."},
                           initObjExpr->Start());
        }
    }
}
}  // namespace ark::es2panda::checker
