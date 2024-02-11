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

#include "ETSemitter.h"

#include "compiler/core/ETSGen.h"
#include "varbinder/varbinder.h"
#include "varbinder/variableFlags.h"
#include "varbinder/ETSBinder.h"
#include "ir/astNode.h"
#include "ir/expressions/identifier.h"
#include "ir/base/decorator.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/typeNode.h"
#include "parser/program/program.h"
#include "compiler/core/compilerContext.h"
#include "checker/checker.h"
#include "checker/types/signature.h"
#include "checker/ETSchecker.h"
#include "checker/types/type.h"
#include "checker/types/ets/types.h"

#include "assembly-program.h"

namespace ark::es2panda::compiler {

#ifdef PANDA_WITH_ETS
static constexpr auto EXTENSION = panda_file::SourceLang::ETS;
#else
// NOTE: temporary dummy gn buildfix until ETS plugin has gn build support
static constexpr auto EXTENSION = panda_file::SourceLang::PANDA_ASSEMBLY;
#endif

static uint32_t TranslateModifierFlags(ir::ModifierFlags modifierFlags)
{
    uint32_t accessFlags = 0;

    if ((modifierFlags & ir::ModifierFlags::PRIVATE) != 0) {
        accessFlags = ACC_PRIVATE;
    } else if ((modifierFlags & ir::ModifierFlags::INTERNAL) != 0) {
        if ((modifierFlags & ir::ModifierFlags::PROTECTED) != 0) {
            accessFlags = ACC_PROTECTED;
        }
        // NOTE: torokg. Add ACC_INTERNAL access flag to libpandabase
    } else if ((modifierFlags & ir::ModifierFlags::PROTECTED) != 0) {
        accessFlags = ACC_PROTECTED;
    } else {
        accessFlags = ACC_PUBLIC;
    }

    if ((modifierFlags & ir::ModifierFlags::STATIC) != 0) {
        accessFlags |= ACC_STATIC;
    }

    if ((modifierFlags & ir::ModifierFlags::CONST) != 0) {
        accessFlags |= ACC_FINAL;
    }

    if ((modifierFlags & ir::ModifierFlags::ABSTRACT) != 0) {
        accessFlags |= ACC_ABSTRACT;
    }

    if ((modifierFlags & ir::ModifierFlags::NATIVE) != 0) {
        accessFlags |= ACC_NATIVE;
    }

    return accessFlags;
}

static pandasm::Function GenScriptFunction(CompilerContext const *context, const ir::ScriptFunction *scriptFunc)
{
    auto *funcScope = scriptFunc->Scope();
    auto *paramScope = funcScope->ParamScope();

    auto func = pandasm::Function(funcScope->InternalName().Mutf8(), EXTENSION);

    func.params.reserve(paramScope->Params().size());

    for (const auto *var : paramScope->Params()) {
        std::stringstream ss;
        context->Checker()->AsETSChecker()->MaybeBoxedType(var)->ToAssemblerType(ss);
        func.params.emplace_back(pandasm::Type(ss.str(), var->TsType()->Rank()), EXTENSION);
    }

    std::stringstream ss;

    if (scriptFunc->IsConstructor() || scriptFunc->IsStaticBlock()) {
        func.returnType = pandasm::Type(Signatures::PRIMITIVE_VOID, 0);
    } else {
        const auto *returnType = scriptFunc->Signature()->ReturnType();

        returnType->ToAssemblerType(ss);
        ASSERT(!ss.str().empty());
        func.returnType = pandasm::Type(ss.str(), returnType->Rank());
    }

    if (!scriptFunc->IsStaticBlock()) {
        const auto *methodDef = util::Helpers::GetContainingClassMethodDefinition(scriptFunc);
        func.metadata->SetAccessFlags(TranslateModifierFlags(methodDef->Modifiers()));
    }

    return func;
}

pandasm::Function *ETSFunctionEmitter::GenFunctionSignature()
{
    auto func = GenScriptFunction(Cg()->Context(), Cg()->RootNode()->AsScriptFunction());
    auto *funcElement = new pandasm::Function(func.name, func.language);
    *funcElement = std::move(func);
    GetProgramElement()->SetFunction(funcElement);
    funcElement->regsNum = VReg::REG_START - Cg()->TotalRegsNum();

    return funcElement;
}

void ETSFunctionEmitter::GenVariableSignature(pandasm::debuginfo::LocalVariable &variableDebug,
                                              [[maybe_unused]] varbinder::LocalVariable *variable) const
{
    variableDebug.signature = Signatures::ANY;
    variableDebug.signatureType = Signatures::ANY;
}

void ETSFunctionEmitter::GenFunctionAnnotations([[maybe_unused]] pandasm::Function *func) {}

template <typename T>
static pandasm::Function GenExternalFunction(T signature, bool isCtor)
{
    auto iter = signature.begin();
    std::string name(*iter++);

    auto func = pandasm::Function(name, EXTENSION);

    while (iter != signature.end()) {
        auto paramName = *iter++;
        func.params.emplace_back(pandasm::Type(paramName, 0), EXTENSION);
    }

    func.returnType = pandasm::Type(Signatures::PRIMITIVE_VOID, 0);
    if (isCtor) {
        func.metadata->SetAttribute(Signatures::CONSTRUCTOR);
    }
    func.metadata->SetAttribute(Signatures::EXTERNAL);

    return func;
}

static pandasm::Function GenExternalFunction(checker::Signature *signature, bool isCtor)
{
    auto func = pandasm::Function(signature->InternalName().Mutf8(), EXTENSION);

    for (auto param : signature->Params()) {
        auto *paramType = param->TsType();

        std::stringstream ss;
        paramType->ToAssemblerType(ss);
        func.params.emplace_back(pandasm::Type(ss.str(), paramType->Rank()), EXTENSION);
    }

    std::stringstream ss;
    signature->ReturnType()->ToAssemblerType(ss);
    func.returnType = pandasm::Type(ss.str(), signature->ReturnType()->Rank());

    if (isCtor) {
        func.metadata->SetAttribute(Signatures::CONSTRUCTOR);
    }
    func.metadata->SetAttribute(Signatures::EXTERNAL);

    return func;
}

void ETSEmitter::GenAnnotation()
{
    Program()->lang = EXTENSION;
    const auto *varbinder = static_cast<varbinder::ETSBinder *>(Context()->VarBinder());

    auto *globalRecordTable = varbinder->GetGlobalRecordTable();

    for (auto *classDecl : globalRecordTable->ClassDefinitions()) {
        GenClassRecord(classDecl, false);
    }

    for (auto *interfaceDecl : globalRecordTable->InterfaceDeclarations()) {
        GenInterfaceRecord(interfaceDecl, false);
    }

    for (auto *signature : globalRecordTable->Signatures()) {
        auto *scriptFunc = signature->Node()->AsScriptFunction();
        auto func = GenScriptFunction(Context(), scriptFunc);
        if (scriptFunc->IsAsyncFunc()) {
            std::vector<pandasm::AnnotationData> annotations;
            annotations.push_back(GenAnnotationAsync(scriptFunc));
            func.metadata->SetAnnotations(std::move(annotations));
        }
        Program()->functionTable.emplace(func.name, std::move(func));
    }

    for (auto [extProg, recordTable] : varbinder->GetExternalRecordTable()) {
        (void)extProg;
        GenExternalRecord(recordTable);
    }

    const auto *checker = static_cast<checker::ETSChecker *>(Context()->Checker());

    for (auto [arrType, signature] : checker->GlobalArrayTypes()) {
        GenGlobalArrayRecord(arrType, signature);
    }
}

void ETSEmitter::GenExternalRecord(varbinder::RecordTable *recordTable)
{
    bool isGenStdLib = recordTable->Program()->VarBinder()->IsGenStdLib();
    for (auto *classDecl : recordTable->ClassDefinitions()) {
        GenClassRecord(classDecl, !isGenStdLib);
    }

    for (auto *interfaceDecl : recordTable->InterfaceDeclarations()) {
        GenInterfaceRecord(interfaceDecl, !isGenStdLib);
    }

    for (auto *signature : recordTable->Signatures()) {
        auto func = GenScriptFunction(Context(), signature->Node()->AsScriptFunction());

        if (!isGenStdLib) {
            func.metadata->SetAttribute(Signatures::EXTERNAL);
        }

        Program()->functionTable.emplace(func.name, std::move(func));
    }
}

void ETSEmitter::EmitDefaultFieldValue(pandasm::Field &classField, const ir::Expression *init)
{
    if (init == nullptr) {
        return;
    }

    const auto *type = init->TsType();

    if (!type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return;
    }

    auto typeKind = checker::ETSChecker::TypeKind(type);

    classField.metadata->SetFieldType(classField.type);
    switch (typeKind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            classField.metadata->SetValue(pandasm::ScalarValue::Create<pandasm::Value::Type::U1>(
                static_cast<uint8_t>(type->AsETSBooleanType()->GetValue())));
            break;
        }
        case checker::TypeFlag::BYTE: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I8>(type->AsByteType()->GetValue()));
            break;
        }
        case checker::TypeFlag::SHORT: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I16>(type->AsShortType()->GetValue()));
            break;
        }
        case checker::TypeFlag::INT: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I32>(type->AsIntType()->GetValue()));
            break;
        }
        case checker::TypeFlag::LONG: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I64>(type->AsLongType()->GetValue()));
            break;
        }
        case checker::TypeFlag::FLOAT: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::F32>(type->AsFloatType()->GetValue()));
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::F64>(type->AsDoubleType()->GetValue()));
            break;
        }
        case checker::TypeFlag::CHAR: {
            classField.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::U16>(type->AsCharType()->GetValue()));
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            classField.metadata->SetValue(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(
                type->AsETSObjectType()->AsETSStringType()->GetValue().Mutf8()));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSEmitter::GenInterfaceMethodDefinition(const ir::MethodDefinition *methodDef, bool external)
{
    auto *scriptFunc = methodDef->Function();
    auto func = GenScriptFunction(Context(), scriptFunc);

    if (external) {
        func.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    if (scriptFunc->Body() != nullptr) {
        return;
    }

    func.metadata->SetAccessFlags(func.metadata->GetAccessFlags() | ACC_ABSTRACT);
    Program()->functionTable.emplace(func.name, std::move(func));
}

void ETSEmitter::GenClassField(const ir::ClassProperty *field, pandasm::Record &classRecord, bool external)
{
    GenField(field->TsType(), field->Id()->Name(), field->Value(), TranslateModifierFlags(field->Modifiers()),
             classRecord, external);
}

void ETSEmitter::GenField(const checker::Type *tsType, const util::StringView &name, const ir::Expression *value,
                          uint32_t accesFlags, pandasm::Record &record, bool external)
{
    auto field = pandasm::Field(Program()->lang);
    std::stringstream ss;
    tsType->ToAssemblerType(ss);

    field.name = name.Mutf8();
    field.type = pandasm::Type(ss.str(), tsType->Rank());

    field.metadata->SetAccessFlags(accesFlags);

    if (external) {
        field.metadata->SetAttribute(Signatures::EXTERNAL);
    } else if (tsType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) || tsType->IsETSStringType()) {
        EmitDefaultFieldValue(field, value);
    }

    record.fieldList.emplace_back(std::move(field));
}

void ETSEmitter::GenClassInheritedFields(const checker::ETSObjectType *baseType, pandasm::Record &classRecord)
{
    std::vector<const varbinder::LocalVariable *> foreignProps = baseType->ForeignProperties();

    for (const auto *foreignProp : foreignProps) {
        auto *declNode = foreignProp->Declaration()->Node();
        if (!declNode->IsClassProperty()) {
            continue;
        }

        GenClassField(declNode->AsClassProperty(), classRecord, true);
    }
}

void ETSEmitter::GenGlobalArrayRecord(checker::ETSArrayType *arrayType, checker::Signature *signature)
{
    std::stringstream ss;
    arrayType->ToAssemblerTypeWithRank(ss);

    auto arrayRecord = pandasm::Record(ss.str(), Program()->lang);

    auto func = GenExternalFunction(signature, true);
    func.params.emplace(func.params.begin(), pandasm::Type(ss.str(), 0), EXTENSION);

    Program()->functionTable.emplace(func.name, std::move(func));

    arrayRecord.metadata->SetAttribute(Signatures::EXTERNAL);
    Program()->recordTable.emplace(arrayRecord.name, std::move(arrayRecord));

    std::stringstream ss2;
    arrayType->ElementType()->ToAssemblerType(ss2);
    ark::pandasm::Type atypePa(ss2.str(), arrayType->Rank());
    Program()->arrayTypes.emplace(std::move(atypePa));
}

void ETSEmitter::GenInterfaceRecord(const ir::TSInterfaceDeclaration *interfaceDecl, bool external)
{
    auto *baseType = interfaceDecl->TsType()->AsETSObjectType();

    auto interfaceRecord = pandasm::Record(interfaceDecl->InternalName().Mutf8(), Program()->lang);

    if (external) {
        interfaceRecord.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    uint32_t accessFlags = ACC_PUBLIC | ACC_ABSTRACT | ACC_INTERFACE;

    if (interfaceDecl->IsStatic()) {
        accessFlags |= ACC_STATIC;
    }

    interfaceRecord.metadata->SetAccessFlags(accessFlags);
    interfaceRecord.sourceFile = Context()->VarBinder()->Program()->SourceFile().GetAbsolutePath().Mutf8();
    interfaceRecord.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE, Signatures::BUILTIN_OBJECT);

    for (auto *it : baseType->Interfaces()) {
        auto *declNode = it->GetDeclNode();
        ASSERT(declNode->IsTSInterfaceDeclaration());
        std::string name = declNode->AsTSInterfaceDeclaration()->InternalName().Mutf8();
        interfaceRecord.metadata->SetAttributeValue(Signatures::IMPLEMENTS_ATTRIBUTE, name);
    }

    GenClassInheritedFields(baseType, interfaceRecord);

    for (const auto *prop : interfaceDecl->Body()->Body()) {
        if (prop->IsClassProperty()) {
            GenClassField(prop->AsClassProperty(), interfaceRecord, external);
        } else if (prop->IsMethodDefinition()) {
            GenInterfaceMethodDefinition(prop->AsMethodDefinition(), external);
        }
    }

    Program()->recordTable.emplace(interfaceRecord.name, std::move(interfaceRecord));
}

void ETSEmitter::GenClassRecord(const ir::ClassDefinition *classDef, bool external)
{
    auto classRecord = pandasm::Record(classDef->InternalName().Mutf8(), Program()->lang);

    if (external) {
        classRecord.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    uint32_t accessFlags = ACC_PUBLIC;

    if (classDef->IsAbstract()) {
        accessFlags |= ACC_ABSTRACT;
    } else if (classDef->IsFinal()) {
        accessFlags |= ACC_FINAL;
    }

    if (classDef->IsStatic()) {
        accessFlags |= ACC_STATIC;
    }

    classRecord.metadata->SetAccessFlags(accessFlags);
    classRecord.sourceFile = Context()->VarBinder()->Program()->SourceFile().GetAbsolutePath().Mutf8();

    auto *baseType = classDef->TsType()->AsETSObjectType();
    if (baseType->SuperType() != nullptr) {
        classRecord.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE,
                                                baseType->SuperType()->AssemblerName().Mutf8());
    } else {
        // NOTE: rtakacs. Replace the whole if block (below) with assert when lambda objects have super class.
        if (baseType->AssemblerName().Mutf8() != Signatures::BUILTIN_OBJECT) {
            classRecord.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE, Signatures::BUILTIN_OBJECT);
        }
    }

    for (auto *it : baseType->Interfaces()) {
        // We do not need to add dynamic interfaces
        if (it->IsETSDynamicType()) {
            continue;
        }

        auto *declNode = it->GetDeclNode();
        // NOTE: itrubachev. replace it with ASSERT(decl_node->IsTSInterfaceDeclaration())
        // after adding proper creation of lambda object in ETSFunctionType::AssignmentSource
        if (!declNode->IsTSInterfaceDeclaration()) {
            continue;
        }
        std::string name = declNode->AsTSInterfaceDeclaration()->InternalName().Mutf8();
        classRecord.metadata->SetAttributeValue(Signatures::IMPLEMENTS_ATTRIBUTE, name);
    }

    GenClassInheritedFields(baseType, classRecord);

    for (const auto *prop : classDef->Body()) {
        if (!prop->IsClassProperty()) {
            continue;
        }

        GenClassField(prop->AsClassProperty(), classRecord, external);
    }

    std::vector<pandasm::AnnotationData> annotations;

    const ir::AstNode *parent = classDef->Parent();
    while (parent != nullptr) {
        if (parent->IsMethodDefinition()) {
            annotations.emplace_back(GenAnnotationEnclosingMethod(parent->AsMethodDefinition()));
            annotations.emplace_back(GenAnnotationInnerClass(classDef, parent));
            break;
        }
        if (parent->IsClassDefinition()) {
            annotations.emplace_back(GenAnnotationEnclosingClass(
                parent->AsClassDefinition()->TsType()->AsETSObjectType()->AssemblerName().Utf8()));
            annotations.emplace_back(GenAnnotationInnerClass(classDef, parent));
            break;
        }
        parent = parent->Parent();
    }

    if (!annotations.empty()) {
        classRecord.metadata->SetAnnotations(std::move(annotations));
    }

    Program()->recordTable.emplace(classRecord.name, std::move(classRecord));
}

pandasm::AnnotationData ETSEmitter::GenAnnotationSignature(const ir::ClassDefinition *classDef)
{
    static constexpr std::string_view OBJECT = "Lstd/core/Object";
    std::vector<pandasm::ScalarValue> parts {};
    std::stringstream ss {};
    const auto &params = classDef->TypeParams()->Params();

    bool firstIteration = true;
    for (const auto *param : params) {
        if (firstIteration) {
            ss << Signatures::GENERIC_BEGIN;
            firstIteration = false;
        }
        ss << param->Name()->Name() << Signatures::MANGLE_BEGIN;
        parts.emplace_back(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(ss.str()));

        std::stringstream {}.swap(ss);
        if (param->Constraint() == nullptr) {
            ss << OBJECT;
        } else {
            param->Constraint()->TsType()->ToAssemblerTypeWithRank(ss);
            auto str = ss.str();
            std::replace(str.begin(), str.end(), *Signatures::METHOD_SEPARATOR.begin(),
                         *Signatures::NAMESPACE_SEPARATOR.begin());
            std::stringstream {}.swap(ss);
            ss << Signatures::CLASS_REF_BEGIN << str << Signatures::MANGLE_SEPARATOR;
        }

        parts.emplace_back(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(ss.str()));
        std::stringstream {}.swap(ss);  // cleanup
    }

    ss << Signatures::GENERIC_END;
    parts.emplace_back(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(ss.str()));

    std::stringstream {}.swap(ss);
    if (classDef->TsType()->AsETSObjectType()->SuperType() == nullptr) {
        ss << OBJECT;
    } else {
        ss << Signatures::CLASS_REF_BEGIN;
        auto superType = classDef->TsType()->AsETSObjectType()->SuperType()->AssemblerName().Mutf8();
        std::replace(superType.begin(), superType.end(), *Signatures::METHOD_SEPARATOR.begin(),
                     *Signatures::NAMESPACE_SEPARATOR.begin());
        ss << superType << Signatures::MANGLE_SEPARATOR;
    }
    parts.emplace_back(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(ss.str()));

    GenAnnotationRecord(Signatures::ETS_ANNOTATION_SIGNATURE);
    pandasm::AnnotationData signature(Signatures::ETS_ANNOTATION_SIGNATURE);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ArrayValue>(pandasm::Value::Type::STRING, std::move(parts)));
    signature.AddElement(std::move(value));
    return signature;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationEnclosingMethod(const ir::MethodDefinition *methodDef)
{
    GenAnnotationRecord(Signatures::ETS_ANNOTATION_ENCLOSING_METHOD);
    pandasm::AnnotationData enclosingMethod(Signatures::ETS_ANNOTATION_ENCLOSING_METHOD);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(pandasm::ScalarValue::Create<pandasm::Value::Type::METHOD>(
            methodDef->Function()->Scope()->InternalName().Mutf8())));
    enclosingMethod.AddElement(std::move(value));
    return enclosingMethod;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationEnclosingClass(std::string_view className)
{
    GenAnnotationRecord(Signatures::ETS_ANNOTATION_ENCLOSING_CLASS);
    pandasm::AnnotationData enclosingClass(Signatures::ETS_ANNOTATION_ENCLOSING_CLASS);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(
            pandasm::ScalarValue::Create<pandasm::Value::Type::RECORD>(pandasm::Type::FromName(className, true))));
    enclosingClass.AddElement(std::move(value));
    return enclosingClass;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationInnerClass(const ir::ClassDefinition *classDef,
                                                            const ir::AstNode *parent)
{
    GenAnnotationRecord(Signatures::ETS_ANNOTATION_INNER_CLASS);
    pandasm::AnnotationData innerClass(Signatures::ETS_ANNOTATION_INNER_CLASS);
    const bool isAnonymous = (classDef->Modifiers() & ir::ClassDefinitionModifiers::ANONYMOUS) != 0;
    pandasm::AnnotationElement name(Signatures::ANNOTATION_KEY_NAME,
                                    std::make_unique<pandasm::ScalarValue>(
                                        isAnonymous
                                            ? pandasm::ScalarValue::Create<pandasm::Value::Type::STRING_NULLPTR>(0)
                                            : pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(
                                                  classDef->TsType()->AsETSObjectType()->AssemblerName().Mutf8())));
    innerClass.AddElement(std::move(name));

    pandasm::AnnotationElement accessFlags(
        Signatures::ANNOTATION_KEY_ACCESS_FLAGS,
        std::make_unique<pandasm::ScalarValue>(
            pandasm::ScalarValue::Create<pandasm::Value::Type::I32>(TranslateModifierFlags(parent->Modifiers()))));
    innerClass.AddElement(std::move(accessFlags));
    return innerClass;
}

ir::MethodDefinition *ETSEmitter::FindAsyncImpl(ir::ScriptFunction *asyncFunc)
{
    std::string implName = checker::ETSChecker::GetAsyncImplName(asyncFunc->Id()->Name());
    ir::AstNode *ownerNode = asyncFunc->Signature()->Owner()->GetDeclNode();
    ASSERT(ownerNode != nullptr && ownerNode->IsClassDefinition());
    const ir::ClassDefinition *classDef = ownerNode->AsClassDefinition();
    ASSERT(classDef != nullptr);

    auto it = std::find_if(classDef->Body().rbegin(), classDef->Body().rend(), [&implName](ir::AstNode *node) {
        return node->IsMethodDefinition() && node->AsMethodDefinition()->Id()->Name().Utf8() == implName;
    });
    if (it == classDef->Body().rend()) {
        return nullptr;
    }

    ir::MethodDefinition *method = (*it)->AsMethodDefinition();
    auto *checker = static_cast<checker::ETSChecker *>(Context()->Checker());
    checker::TypeRelation *typeRel = checker->Relation();
    checker::SavedTypeRelationFlagsContext savedFlagsCtx(typeRel, checker::TypeRelationFlag::NO_RETURN_TYPE_CHECK);
    method->Function()->Signature()->Identical(typeRel, asyncFunc->Signature());
    auto overloadIt = method->Overloads().begin();
    while (overloadIt != method->Overloads().end() && !typeRel->IsTrue()) {
        method = *overloadIt;
        method->Function()->Signature()->Identical(typeRel, asyncFunc->Signature());
        ++overloadIt;
    }
    return typeRel->IsTrue() ? method : nullptr;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationAsync(ir::ScriptFunction *scriptFunc)
{
    GenAnnotationRecord(Signatures::ETS_COROUTINE_ASYNC);
    const ir::MethodDefinition *impl = FindAsyncImpl(scriptFunc);
    ASSERT(impl != nullptr);
    pandasm::AnnotationData ann(Signatures::ETS_COROUTINE_ASYNC);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(pandasm::ScalarValue::Create<pandasm::Value::Type::METHOD>(
            impl->Function()->Scope()->InternalName().Mutf8())));
    ann.AddElement(std::move(value));
    return ann;
}

void ETSEmitter::GenAnnotationRecord(std::string_view recordNameView, bool isRuntime, bool isType)
{
    const std::string recordName(recordNameView);
    const auto recordIt = Program()->recordTable.find(recordName);
    if (recordIt == Program()->recordTable.end()) {
        pandasm::Record record(recordName, EXTENSION);
        record.metadata->SetAttribute(Signatures::EXTERNAL);
        record.metadata->SetAttribute(Signatures::ANNOTATION_ATTRIBUTE);
        if (isRuntime && isType) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE,
                                               Signatures::RUNTIME_TYPE_ANNOTATION);
        } else if (isRuntime && !isType) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE, Signatures::RUNTIME_ANNOTATION);
        } else if (!isRuntime && isType) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE, Signatures::TYPE_ANNOTATION);
        }
        Program()->recordTable.emplace(record.name, std::move(record));
    }
}
}  // namespace ark::es2panda::compiler