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

#include "ETSemitter.h"

#include "compiler/core/ETSGen.h"
#include "binder/binder.h"
#include "binder/variableFlags.h"
#include "binder/ETSBinder.h"
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

namespace panda::es2panda::compiler {

#ifdef PANDA_WITH_ETS
static constexpr auto EXTENSION = panda_file::SourceLang::ETS;
#else
// TODO: temporary dummy gn buildfix until ETS plugin has gn build support
static constexpr auto EXTENSION = panda_file::SourceLang::PANDA_ASSEMBLY;
#endif

static uint32_t TranslateModifierFlags(ir::ModifierFlags modifier_flags)
{
    uint32_t access_flags = 0;

    if ((modifier_flags & ir::ModifierFlags::PRIVATE) != 0) {
        access_flags = ACC_PRIVATE;
    } else if ((modifier_flags & ir::ModifierFlags::INTERNAL) != 0) {
        if ((modifier_flags & ir::ModifierFlags::PROTECTED) != 0) {
            access_flags = ACC_PROTECTED;
        }
        // TODO(torokg): Add ACC_INTERNAL access flag to libpandabase
    } else if ((modifier_flags & ir::ModifierFlags::PROTECTED) != 0) {
        access_flags = ACC_PROTECTED;
    } else {
        access_flags = ACC_PUBLIC;
    }

    if ((modifier_flags & ir::ModifierFlags::STATIC) != 0) {
        access_flags |= ACC_STATIC;
    }

    if ((modifier_flags & ir::ModifierFlags::CONST) != 0) {
        access_flags |= ACC_FINAL;
    }

    if ((modifier_flags & ir::ModifierFlags::ABSTRACT) != 0) {
        access_flags |= ACC_ABSTRACT;
    }

    if ((modifier_flags & ir::ModifierFlags::NATIVE) != 0) {
        access_flags |= ACC_NATIVE;
    }

    return access_flags;
}

static pandasm::Function GenScriptFunction(CompilerContext const *context, const ir::ScriptFunction *script_func)
{
    auto *func_scope = script_func->Scope();
    auto *param_scope = func_scope->ParamScope();

    auto func = pandasm::Function(func_scope->InternalName().Mutf8(), EXTENSION);

    func.params.reserve(param_scope->Params().size());

    for (const auto *var : param_scope->Params()) {
        std::stringstream ss;
        context->Checker()->AsETSChecker()->MaybeBoxedType(var)->ToAssemblerType(ss);
        func.params.emplace_back(pandasm::Type(ss.str(), var->TsType()->Rank()), EXTENSION);
    }

    std::stringstream ss;

    if (script_func->IsConstructor() || script_func->IsStaticBlock()) {
        func.return_type = pandasm::Type(Signatures::PRIMITIVE_VOID, 0);
    } else {
        const auto *return_type = script_func->Signature()->ReturnType();

        return_type->ToAssemblerType(ss);
        ASSERT(!ss.str().empty());
        func.return_type = pandasm::Type(ss.str(), return_type->Rank());
    }

    if (!script_func->IsStaticBlock()) {
        const auto *method_def = util::Helpers::GetContainingClassMethodDefinition(script_func);
        func.metadata->SetAccessFlags(TranslateModifierFlags(method_def->Modifiers()));
    }

    return func;
}

pandasm::Function *ETSFunctionEmitter::GenFunctionSignature()
{
    auto func = GenScriptFunction(Cg()->Context(), Cg()->RootNode()->AsScriptFunction());
    auto *func_element = new pandasm::Function(func.name, func.language);
    *func_element = std::move(func);
    GetProgramElement()->SetFunction(func_element);
    func_element->regs_num = VReg::REG_START - Cg()->TotalRegsNum();

    return func_element;
}

void ETSFunctionEmitter::GenVariableSignature(pandasm::debuginfo::LocalVariable &variable_debug,
                                              [[maybe_unused]] binder::LocalVariable *variable) const
{
    variable_debug.signature = Signatures::ANY;
    variable_debug.signature_type = Signatures::ANY;
}

void ETSFunctionEmitter::GenFunctionAnnotations([[maybe_unused]] pandasm::Function *func) {}

template <typename T>
static pandasm::Function GenExternalFunction(T signature, bool is_ctor)
{
    auto iter = signature.begin();
    std::string name(*iter++);

    auto func = pandasm::Function(name, EXTENSION);

    while (iter != signature.end()) {
        auto param_name = *iter++;
        func.params.emplace_back(pandasm::Type(param_name, 0), EXTENSION);
    }

    func.return_type = pandasm::Type(Signatures::PRIMITIVE_VOID, 0);
    if (is_ctor) {
        func.metadata->SetAttribute(Signatures::CONSTRUCTOR);
    }
    func.metadata->SetAttribute(Signatures::EXTERNAL);

    return func;
}

static pandasm::Function GenExternalFunction(checker::Signature *signature, bool is_ctor)
{
    auto func = pandasm::Function(signature->InternalName().Mutf8(), EXTENSION);

    for (auto param : signature->Params()) {
        auto *param_type = param->TsType();

        std::stringstream ss;
        param_type->ToAssemblerType(ss);
        func.params.emplace_back(pandasm::Type(ss.str(), param_type->Rank()), EXTENSION);
    }

    std::stringstream ss;
    signature->ReturnType()->ToAssemblerType(ss);
    func.return_type = pandasm::Type(ss.str(), signature->ReturnType()->Rank());

    if (is_ctor) {
        func.metadata->SetAttribute(Signatures::CONSTRUCTOR);
    }
    func.metadata->SetAttribute(Signatures::EXTERNAL);

    return func;
}

void ETSEmitter::GenAnnotation()
{
    Program()->lang = EXTENSION;
    const auto *binder = static_cast<binder::ETSBinder *>(Context()->Binder());

    auto *global_record_table = binder->GetGlobalRecordTable();

    for (auto *class_decl : global_record_table->ClassDefinitions()) {
        GenClassRecord(class_decl, false);
    }

    for (auto *interface_decl : global_record_table->InterfaceDeclarations()) {
        GenInterfaceRecord(interface_decl, false);
    }

    for (auto *signature : global_record_table->Signatures()) {
        auto *script_func = signature->Node()->AsScriptFunction();
        auto func = GenScriptFunction(Context(), script_func);
        if (script_func->IsAsyncFunc()) {
            std::vector<pandasm::AnnotationData> annotations;
            annotations.push_back(GenAnnotationAsync(script_func));
            func.metadata->SetAnnotations(std::move(annotations));
        }
        Program()->function_table.emplace(func.name, std::move(func));
    }

    for (auto [extProg, recordTable] : binder->GetExternalRecordTable()) {
        (void)extProg;
        GenExternalRecord(recordTable);
    }

    const auto *checker = static_cast<checker::ETSChecker *>(Context()->Checker());

    for (auto [arrType, signature] : checker->GlobalArrayTypes()) {
        GenGlobalArrayRecord(arrType, signature);
    }
}

void ETSEmitter::GenExternalRecord(binder::RecordTable *record_table)
{
    bool is_gen_std_lib = record_table->Program()->Binder()->IsGenStdLib();
    for (auto *class_decl : record_table->ClassDefinitions()) {
        GenClassRecord(class_decl, !is_gen_std_lib);
    }

    for (auto *interface_decl : record_table->InterfaceDeclarations()) {
        GenInterfaceRecord(interface_decl, !is_gen_std_lib);
    }

    for (auto *signature : record_table->Signatures()) {
        auto func = GenScriptFunction(Context(), signature->Node()->AsScriptFunction());

        if (!is_gen_std_lib) {
            func.metadata->SetAttribute(Signatures::EXTERNAL);
        }

        Program()->function_table.emplace(func.name, std::move(func));
    }
}

void ETSEmitter::EmitDefaultFieldValue(pandasm::Field &class_field, const ir::Expression *init)
{
    if (init == nullptr) {
        return;
    }

    const auto *type = init->TsType();

    if (!type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return;
    }

    auto type_kind = checker::ETSChecker::TypeKind(type);

    class_field.metadata->SetFieldType(class_field.type);
    switch (type_kind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            class_field.metadata->SetValue(pandasm::ScalarValue::Create<pandasm::Value::Type::U1>(
                static_cast<uint8_t>(type->AsETSBooleanType()->GetValue())));
            break;
        }
        case checker::TypeFlag::BYTE: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I8>(type->AsByteType()->GetValue()));
            break;
        }
        case checker::TypeFlag::SHORT: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I16>(type->AsShortType()->GetValue()));
            break;
        }
        case checker::TypeFlag::INT: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I32>(type->AsIntType()->GetValue()));
            break;
        }
        case checker::TypeFlag::LONG: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::I64>(type->AsLongType()->GetValue()));
            break;
        }
        case checker::TypeFlag::FLOAT: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::F32>(type->AsFloatType()->GetValue()));
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::F64>(type->AsDoubleType()->GetValue()));
            break;
        }
        case checker::TypeFlag::CHAR: {
            class_field.metadata->SetValue(
                pandasm::ScalarValue::Create<pandasm::Value::Type::U16>(type->AsCharType()->GetValue()));
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            class_field.metadata->SetValue(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(
                type->AsETSObjectType()->AsETSStringType()->GetValue().Mutf8()));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSEmitter::GenInterfaceMethodDefinition(const ir::MethodDefinition *method_def, bool external)
{
    auto *script_func = method_def->Function();
    auto func = GenScriptFunction(Context(), script_func);

    if (external) {
        func.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    if (script_func->Body() != nullptr) {
        return;
    }

    func.metadata->SetAccessFlags(func.metadata->GetAccessFlags() | ACC_ABSTRACT);
    Program()->function_table.emplace(func.name, std::move(func));
}

void ETSEmitter::GenClassField(const ir::ClassProperty *field, pandasm::Record &class_record, bool external)
{
    GenField(field->TsType(), field->Id()->Name(), field->Value(), TranslateModifierFlags(field->Modifiers()),
             class_record, external);
}

void ETSEmitter::GenField(const checker::Type *ts_type, const util::StringView &name, const ir::Expression *value,
                          uint32_t acces_flags, pandasm::Record &record, bool external)
{
    auto field = pandasm::Field(Program()->lang);
    std::stringstream ss;
    ts_type->ToAssemblerType(ss);

    field.name = name.Mutf8();
    field.type = pandasm::Type(ss.str(), ts_type->Rank());

    field.metadata->SetAccessFlags(acces_flags);

    if (external) {
        field.metadata->SetAttribute(Signatures::EXTERNAL);
    } else if (ts_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) || ts_type->IsETSStringType()) {
        EmitDefaultFieldValue(field, value);
    }

    record.field_list.emplace_back(std::move(field));
}

void ETSEmitter::GenClassInheritedFields(const checker::ETSObjectType *base_type, pandasm::Record &class_record)
{
    std::vector<const binder::LocalVariable *> foreign_props = base_type->ForeignProperties();

    for (const auto *foreign_prop : foreign_props) {
        auto *decl_node = foreign_prop->Declaration()->Node();
        if (!decl_node->IsClassProperty()) {
            continue;
        }

        GenClassField(decl_node->AsClassProperty(), class_record, true);
    }
}

void ETSEmitter::GenGlobalArrayRecord(checker::ETSArrayType *array_type, checker::Signature *signature)
{
    std::stringstream ss;
    array_type->ToAssemblerTypeWithRank(ss);

    auto array_record = pandasm::Record(ss.str(), Program()->lang);

    auto func = GenExternalFunction(signature, true);
    func.params.emplace(func.params.begin(), pandasm::Type(ss.str(), 0), EXTENSION);

    Program()->function_table.emplace(func.name, std::move(func));

    array_record.metadata->SetAttribute(Signatures::EXTERNAL);
    Program()->record_table.emplace(array_record.name, std::move(array_record));

    std::stringstream ss2;
    array_type->ElementType()->ToAssemblerType(ss2);
    panda::pandasm::Type atype_pa(ss2.str(), array_type->Rank());
    Program()->array_types.emplace(std::move(atype_pa));
}

void ETSEmitter::GenInterfaceRecord(const ir::TSInterfaceDeclaration *interface_decl, bool external)
{
    auto *base_type = interface_decl->TsType()->AsETSObjectType();

    auto interface_record = pandasm::Record(interface_decl->InternalName().Mutf8(), Program()->lang);

    if (external) {
        interface_record.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    uint32_t access_flags = ACC_PUBLIC | ACC_ABSTRACT | ACC_INTERFACE;

    if (interface_decl->IsStatic()) {
        access_flags |= ACC_STATIC;
    }

    interface_record.metadata->SetAccessFlags(access_flags);
    interface_record.source_file = Context()->Binder()->Program()->AbsoluteName().Mutf8();
    interface_record.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE, Signatures::BUILTIN_OBJECT);

    for (auto *it : base_type->Interfaces()) {
        auto *decl_node = it->GetDeclNode();
        ASSERT(decl_node->IsTSInterfaceDeclaration());
        std::string name = decl_node->AsTSInterfaceDeclaration()->InternalName().Mutf8();
        interface_record.metadata->SetAttributeValue(Signatures::IMPLEMENTS_ATTRIBUTE, name);
    }

    GenClassInheritedFields(base_type, interface_record);

    for (const auto *prop : interface_decl->Body()->Body()) {
        if (prop->IsClassProperty()) {
            GenClassField(prop->AsClassProperty(), interface_record, false);
        } else if (prop->IsMethodDefinition()) {
            GenInterfaceMethodDefinition(prop->AsMethodDefinition(), external);
        }
    }

    Program()->record_table.emplace(interface_record.name, std::move(interface_record));
}

void ETSEmitter::GenClassRecord(const ir::ClassDefinition *class_def, bool external)
{
    auto class_record = pandasm::Record(class_def->InternalName().Mutf8(), Program()->lang);

    if (external) {
        class_record.metadata->SetAttribute(Signatures::EXTERNAL);
    }

    uint32_t access_flags = ACC_PUBLIC;

    if (class_def->IsAbstract()) {
        access_flags |= ACC_ABSTRACT;
    } else if (class_def->IsFinal()) {
        access_flags |= ACC_FINAL;
    }

    if (class_def->IsStatic()) {
        access_flags |= ACC_STATIC;
    }

    class_record.metadata->SetAccessFlags(access_flags);
    class_record.source_file = Context()->Binder()->Program()->AbsoluteName().Mutf8();

    auto *base_type = class_def->TsType()->AsETSObjectType();

    if (base_type->SuperType() != nullptr) {
        class_record.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE,
                                                 base_type->SuperType()->AssemblerName().Mutf8());
    } else {
        // TODO(rtakacs): replace the whole if block (below) with assert when lambda objects have super class.
        // ASSERT(base_type->AssemblerName().Mutf8() == Signatures::BUILTIN_OBJECT);
        if (base_type->AssemblerName().Mutf8() != Signatures::BUILTIN_OBJECT) {
            class_record.metadata->SetAttributeValue(Signatures::EXTENDS_ATTRIBUTE, Signatures::BUILTIN_OBJECT);
        }
    }

    for (auto *it : base_type->Interfaces()) {
        auto *decl_node = it->GetDeclNode();
        // TODO(itrubachev): replace it with ASSERT(decl_node->IsTSInterfaceDeclaration())
        // after adding proper creation of lambda object in ETSFunctionType::AssignmentSource
        if (!decl_node->IsTSInterfaceDeclaration()) {
            continue;
        }
        std::string name = decl_node->AsTSInterfaceDeclaration()->InternalName().Mutf8();
        class_record.metadata->SetAttributeValue(Signatures::IMPLEMENTS_ATTRIBUTE, name);
    }

    if (!class_def->IsAbstract()) {
        GenClassInheritedFields(base_type, class_record);
    }

    for (const auto *prop : class_def->Body()) {
        if (!prop->IsClassProperty()) {
            continue;
        }

        GenClassField(prop->AsClassProperty(), class_record, external);
    }

    std::vector<pandasm::AnnotationData> annotations;

    const ir::AstNode *parent = class_def->Parent();
    while (parent != nullptr) {
        if (parent->IsMethodDefinition()) {
            annotations.emplace_back(GenAnnotationEnclosingMethod(parent->AsMethodDefinition()));
            annotations.emplace_back(GenAnnotationInnerClass(class_def, parent));
            break;
        }
        if (parent->IsClassDefinition()) {
            annotations.emplace_back(GenAnnotationEnclosingClass(
                parent->AsClassDefinition()->TsType()->AsETSObjectType()->AssemblerName().Utf8()));
            annotations.emplace_back(GenAnnotationInnerClass(class_def, parent));
            break;
        }
        parent = parent->Parent();
    }

    if (!annotations.empty()) {
        class_record.metadata->SetAnnotations(std::move(annotations));
    }

    Program()->record_table.emplace(class_record.name, std::move(class_record));
}

pandasm::AnnotationData ETSEmitter::GenAnnotationSignature(const ir::ClassDefinition *class_def)
{
    static constexpr std::string_view OBJECT = "Lstd/core/Object";
    std::vector<pandasm::ScalarValue> parts {};
    std::stringstream ss {};
    const auto &params = class_def->TypeParams()->Params();

    bool first_iteration = true;
    for (const auto *param : params) {
        if (first_iteration) {
            ss << Signatures::GENERIC_BEGIN;
            first_iteration = false;
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
    if (class_def->TsType()->AsETSObjectType()->SuperType() == nullptr) {
        ss << OBJECT;
    } else {
        ss << Signatures::CLASS_REF_BEGIN;
        auto super_type = class_def->TsType()->AsETSObjectType()->SuperType()->AssemblerName().Mutf8();
        std::replace(super_type.begin(), super_type.end(), *Signatures::METHOD_SEPARATOR.begin(),
                     *Signatures::NAMESPACE_SEPARATOR.begin());
        ss << super_type << Signatures::MANGLE_SEPARATOR;
    }
    parts.emplace_back(pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(ss.str()));

    GenAnnotationRecord(Signatures::DALVIK_ANNOTATION_SIGNATURE);
    pandasm::AnnotationData signature(Signatures::DALVIK_ANNOTATION_SIGNATURE);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ArrayValue>(pandasm::Value::Type::STRING, std::move(parts)));
    signature.AddElement(std::move(value));
    return signature;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationEnclosingMethod(const ir::MethodDefinition *method_def)
{
    GenAnnotationRecord(Signatures::DALVIK_ANNOTATION_ENCLOSING_METHOD);
    pandasm::AnnotationData enclosing_method(Signatures::DALVIK_ANNOTATION_ENCLOSING_METHOD);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(pandasm::ScalarValue::Create<pandasm::Value::Type::METHOD>(
            method_def->Function()->Scope()->InternalName().Mutf8())));
    enclosing_method.AddElement(std::move(value));
    return enclosing_method;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationEnclosingClass(std::string_view class_name)
{
    GenAnnotationRecord(Signatures::DALVIK_ANNOTATION_ENCLOSING_CLASS);
    pandasm::AnnotationData enclosing_class(Signatures::DALVIK_ANNOTATION_ENCLOSING_CLASS);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(
            pandasm::ScalarValue::Create<pandasm::Value::Type::RECORD>(pandasm::Type::FromName(class_name, true))));
    enclosing_class.AddElement(std::move(value));
    return enclosing_class;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationInnerClass(const ir::ClassDefinition *class_def,
                                                            const ir::AstNode *parent)
{
    GenAnnotationRecord(Signatures::DALVIK_ANNOTATION_INNER_CLASS);
    pandasm::AnnotationData inner_class(Signatures::DALVIK_ANNOTATION_INNER_CLASS);
    const bool is_anonymous = (class_def->Modifiers() & ir::ClassDefinitionModifiers::ANONYMOUS) != 0;
    pandasm::AnnotationElement name(Signatures::ANNOTATION_KEY_NAME,
                                    std::make_unique<pandasm::ScalarValue>(
                                        is_anonymous
                                            ? pandasm::ScalarValue::Create<pandasm::Value::Type::STRING_NULLPTR>(0)
                                            : pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(
                                                  class_def->TsType()->AsETSObjectType()->AssemblerName().Mutf8())));
    inner_class.AddElement(std::move(name));

    pandasm::AnnotationElement access_flags(
        Signatures::ANNOTATION_KEY_ACCESS_FLAGS,
        std::make_unique<pandasm::ScalarValue>(
            pandasm::ScalarValue::Create<pandasm::Value::Type::I32>(TranslateModifierFlags(parent->Modifiers()))));
    inner_class.AddElement(std::move(access_flags));
    return inner_class;
}

ir::MethodDefinition *ETSEmitter::FindAsyncImpl(ir::ScriptFunction *async_func)
{
    std::string impl_name = checker::ETSChecker::GetAsyncImplName(async_func->Id()->Name());
    ir::AstNode *owner_node = async_func->Signature()->Owner()->GetDeclNode();
    ASSERT(owner_node != nullptr && owner_node->IsClassDefinition());
    const ir::ClassDefinition *class_def = owner_node->AsClassDefinition();
    ASSERT(class_def != nullptr);

    auto it = std::find_if(class_def->Body().rbegin(), class_def->Body().rend(), [&impl_name](ir::AstNode *node) {
        return node->IsMethodDefinition() && node->AsMethodDefinition()->Id()->Name().Utf8() == impl_name;
    });
    if (it == class_def->Body().rend()) {
        return nullptr;
    }

    ir::MethodDefinition *method = (*it)->AsMethodDefinition();
    auto *checker = static_cast<checker::ETSChecker *>(Context()->Checker());
    checker::TypeRelation *type_rel = checker->Relation();
    checker::SavedTypeRelationFlagsContext saved_flags_ctx(type_rel, checker::TypeRelationFlag::NO_RETURN_TYPE_CHECK);
    method->Function()->Signature()->Identical(type_rel, async_func->Signature());
    auto overload_it = method->Overloads().begin();
    while (overload_it != method->Overloads().end() && !type_rel->IsTrue()) {
        method = *overload_it;
        method->Function()->Signature()->Identical(type_rel, async_func->Signature());
        ++overload_it;
    }
    return type_rel->IsTrue() ? method : nullptr;
}

pandasm::AnnotationData ETSEmitter::GenAnnotationAsync(ir::ScriptFunction *script_func)
{
    GenAnnotationRecord(Signatures::ETS_COROUTINE_ASYNC);
    const ir::MethodDefinition *impl = FindAsyncImpl(script_func);
    ASSERT(impl != nullptr);
    pandasm::AnnotationData ann(Signatures::ETS_COROUTINE_ASYNC);
    pandasm::AnnotationElement value(
        Signatures::ANNOTATION_KEY_VALUE,
        std::make_unique<pandasm::ScalarValue>(pandasm::ScalarValue::Create<pandasm::Value::Type::METHOD>(
            impl->Function()->Scope()->InternalName().Mutf8())));
    ann.AddElement(std::move(value));
    return ann;
}

void ETSEmitter::GenAnnotationRecord(std::string_view record_name_view, bool is_runtime, bool is_type)
{
    const std::string record_name(record_name_view);
    const auto record_it = Program()->record_table.find(record_name);
    if (record_it == Program()->record_table.end()) {
        pandasm::Record record(record_name, EXTENSION);
        record.metadata->SetAttribute(Signatures::EXTERNAL);
        record.metadata->SetAttribute(Signatures::ANNOTATION_ATTRIBUTE);
        if (is_runtime && is_type) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE,
                                               Signatures::RUNTIME_TYPE_ANNOTATION);
        } else if (is_runtime && !is_type) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE, Signatures::RUNTIME_ANNOTATION);
        } else if (!is_runtime && is_type) {
            record.metadata->SetAttributeValue(Signatures::ANNOTATION_ATTRIBUTE_TYPE, Signatures::TYPE_ANNOTATION);
        }
        Program()->record_table.emplace(record.name, std::move(record));
    }
}
}  // namespace panda::es2panda::compiler
