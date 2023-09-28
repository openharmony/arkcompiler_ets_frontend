/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "declgenEts2Ts.h"

#include "plugins/ecmascript/es2panda/ir/base/classProperty.h"
#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsImportDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsPrimitiveType.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/module/importSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"
#include "plugins/ecmascript/es2panda/ir/statements/classDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsClassImplements.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumMember.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsInterfaceBody.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeAliasDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"

#define DEBUG_PRINT 0

namespace panda::es2panda::util {

static void DebugPrint([[maybe_unused]] const std::string &msg)
{
#if DEBUG_PRINT
    std::cerr << msg << std::endl;
#endif
}

static void Warning(const std::string &msg)
{
    std::cerr << "Warning declgen ets2ts: " << msg << std::endl;
}

void TSDeclGen::Generate()
{
    Out("declare const exports: any;");
    OutEndl(2);

    for (auto *global_statement : program_->Ast()->Statements()) {
        ResetState();
        if (global_statement->IsETSImportDeclaration()) {
            GenImportDeclaration(global_statement->AsETSImportDeclaration());
        } else if (global_statement->IsTSEnumDeclaration()) {
            GenEnumDeclaration(global_statement->AsTSEnumDeclaration());
        } else if (global_statement->IsClassDeclaration()) {
            GenClassDeclaration(global_statement->AsClassDeclaration());
        } else if (global_statement->IsTSInterfaceDeclaration()) {
            GenInterfaceDeclaration(global_statement->AsTSInterfaceDeclaration());
        } else if (global_statement->IsTSTypeAliasDeclaration()) {
            GenTypeAliasDeclaration(global_statement->AsTSTypeAliasDeclaration());
        }
    }
}

template <class T, class CB>
void TSDeclGen::GenCommaSeparated(const T &container, const CB &cb)
{
    if (container.empty()) {
        return;
    }

    cb(container[0]);
    for (std::size_t i = 1; i < container.size(); ++i) {
        Out(", ");
        cb(container[i]);
    }
}

void TSDeclGen::ThrowError(const std::string_view message, const lexer::SourcePosition &pos = lexer::SourcePosition())
{
    lexer::LineIndex index(program_->SourceCode());
    const lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::GENERIC, program_->SourceFile().Utf8(), "declgen ts2ets: " + std::string(message), loc.line,
                 loc.col};
}

std::string TSDeclGen::GetKeyName(const ir::Expression *key)
{
    if (!key->IsIdentifier()) {
        ThrowError("Not identifier keys are not supported", key->Start());
    }

    return key->AsIdentifier()->Name().Mutf8();
}

void TSDeclGen::GenType(const checker::Type *checker_type)
{
    ASSERT(checker_type != nullptr);
    DebugPrint("  GenType: ");
#if DEBUG_PRINT
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_CHECKS(type_flag, type_name)                                                                          \
    if (checker_type->Is##type_name()) {                                                                           \
        const auto var_name = checker_type->Variable() == nullptr ? "" : checker_type->Variable()->Name().Mutf8(); \
        DebugPrint("  Converting type: " #type_name " (" + var_name + ")");                                        \
    }
    TYPE_MAPPING(TYPE_CHECKS)
#undef TYPE_CHECKS
#endif

    if (checker_type->IsCharType() || checker_type->IsByteType() || checker_type->IsIntType() ||
        checker_type->IsShortType() || checker_type->IsNumberType() || checker_type->IsLongType() ||
        checker_type->IsFloatType() || checker_type->IsDoubleType()) {
        Out("number");
        return;
    }
    if (checker_type->IsETSBooleanType()) {
        Out("boolean");
        return;
    }
    if (checker_type->IsETSVoidType()) {
        Out("void");
        return;
    }
    if (checker_type->IsETSStringType()) {
        Out("string");
        return;
    }
    if (checker_type->IsETSArrayType()) {
        GenType(checker_type->AsETSArrayType()->ElementType());
        Out("[]");
        return;
    }
    if (checker_type->IsETSEnumType()) {
        GenEnumType(checker_type->AsETSEnumType());
        return;
    }
    if (checker_type->IsETSFunctionType()) {
        GenFunctionType(checker_type->AsETSFunctionType());
        return;
    }
    if (checker_type->IsETSObjectType()) {
        GenObjectType(checker_type->AsETSObjectType());
        return;
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_CHECKS(typeFlag, typeName)              \
    if (checker_type->Is##typeName()) {              \
        ThrowError("Unsupported type: '" #typeName); \
    }
    TYPE_MAPPING(TYPE_CHECKS)
#undef TYPE_CHECKS
    UNREACHABLE();
}

void TSDeclGen::GenLiteral(const ir::Literal *literal)
{
    if (!literal->IsNumberLiteral()) {
        ThrowError("Unsupported literal type", literal->Start());
    }

    const auto number = literal->AsNumberLiteral()->Number();
    if (number.IsInt()) {
        Out(std::to_string(number.GetInt()));
        return;
    }
    if (number.IsLong()) {
        Out(std::to_string(number.GetLong()));
        return;
    }
    if (number.IsFloat()) {
        Out(std::to_string(number.GetFloat()));
        return;
    }
    if (number.IsDouble()) {
        Out(std::to_string(number.GetDouble()));
        return;
    }

    ThrowError("Unexpected number literal type", literal->Start());
}

void TSDeclGen::GenFunctionType(const checker::ETSFunctionType *ets_function_type,
                                const ir::MethodDefinition *method_def)
{
    const bool is_constructor = method_def != nullptr ? method_def->IsConstructor() : false;

    if (ets_function_type->CallSignatures().size() != 1) {
        const auto loc = method_def != nullptr ? method_def->Start() : lexer::SourcePosition();
        ThrowError("Method overloads are not supported", loc);
    }

    for (const auto *sig : ets_function_type->CallSignatures()) {
        const auto *func = sig->Function();

        GenTypeParameters(func->TypeParams());

        Out("(");

        GenCommaSeparated(sig->Params(), [this](binder::LocalVariable *param) {
            Out(param->Name());
            const auto *param_type = param->TsType();

            if (param->HasFlag(binder::VariableFlags::OPTIONAL) ||
                param_type->HasTypeFlag(checker::TypeFlag::NULLABLE)) {
                Out("?");
            }

            Out(": ");
            GenType(param_type);
        });

        const auto *sig_info = sig->GetSignatureInfo();
        if (sig_info->rest_var != nullptr) {
            Out("...", sig_info->rest_var->Name().Mutf8(), ": ");
            GenType(sig_info->rest_var->TsType());
            Out("[]");
        }

        Out(")");

        if (!is_constructor) {
            Out(method_def != nullptr ? ": " : " => ");
            GenType(sig->ReturnType());
        }
    }
}

void TSDeclGen::GenEnumType(const checker::ETSEnumType *enum_type)
{
    for (auto *member : enum_type->GetMembers()) {
        Out(INDENT);
        if (!member->IsTSEnumMember()) {
            ThrowError("Member of enum not of type TSEnumMember", member->Start());
        }

        const auto *enum_member = member->AsTSEnumMember();
        Out(GetKeyName(enum_member->Key()));
        const auto *init = enum_member->Init();
        if (init != nullptr) {
            Out(" = ");

            if (!init->IsLiteral()) {
                ThrowError("Only literal enum initializers are supported", member->Start());
            }

            GenLiteral(init->AsLiteral());
        }

        Out(",");
        OutEndl();
    }
}

void TSDeclGen::GenObjectType(const checker::ETSObjectType *object_type)
{
    if (object_type->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL)) {
        const auto *invoke = object_type->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke");
        ASSERT(invoke && invoke->TsType() && invoke->TsType()->IsETSFunctionType());
        GenType(invoke->TsType());
        return;
    }

    if (object_type->HasObjectFlag(checker::ETSObjectFlags::DYNAMIC)) {
        Out("any");
        return;
    }

    Out(object_type->Name());

    const auto &type_args = object_type->TypeArguments();
    if (!type_args.empty()) {
        Warning("Type arguments are not properly supported");
        Out("<");
        GenCommaSeparated(type_args, [this](checker::Type *arg) { GenType(arg); });
        Out(">");
    }
}

void TSDeclGen::GenTypeParameters(const ir::TSTypeParameterDeclaration *type_params)
{
    if (type_params != nullptr) {
        Out("<");
        GenCommaSeparated(type_params->Params(), [this](ir::TSTypeParameter *param) {
            Out(param->Name()->Name());
            auto *constraint = param->Constraint();
            if (constraint != nullptr) {
                Out(" extends ");
                GenType(constraint->GetType(checker_));
            }
        });
        Out(">");
    }
}

template <class T>
void TSDeclGen::GenModifier(const T *node)
{
    if (state_.in_interface) {
        return;
    }

    if (node->IsPrivate()) {
        Out("private ");
    }
    if (node->IsProtected()) {
        Out("protected ");
    }
    if (node->IsPublic()) {
        Out("public ");
    }
    if (node->IsReadonly()) {
        Out("readonly ");
    }
    if (node->IsStatic()) {
        Out("static ");
    }
}

void TSDeclGen::GenImportDeclaration(const ir::ETSImportDeclaration *import_declaration)
{
    DebugPrint("GenImportDeclaration");
    if (import_declaration->IsPureDynamic()) {
        return;
    }

    const auto &specifiers = import_declaration->Specifiers();
    Out("import { ");
    GenCommaSeparated(specifiers, [&](ir::AstNode *specifier) {
        if (!specifier->IsImportSpecifier()) {
            ThrowError("Only import specifiers are supported", import_declaration->Start());
        }

        const auto local = specifier->AsImportSpecifier()->Local()->Name();
        const auto imported = specifier->AsImportSpecifier()->Imported()->Name();
        if (local != imported) {
            ThrowError("Imports with local bindings are not supported", import_declaration->Start());
        }

        Out(local);
    });

    auto source = import_declaration->Source()->Str().Mutf8();
    if (import_declaration->Module() != nullptr) {
        source += "/" + import_declaration->Module()->Str().Mutf8();
    }

    Out(" } from \"", source, "\";");
    OutEndl(2);
}

void TSDeclGen::GenTypeAliasDeclaration(const ir::TSTypeAliasDeclaration *type_alias)
{
    const auto name = type_alias->Id()->Name().Mutf8();
    DebugPrint("GenTypeAliasDeclaration: " + name);
    const auto *aliased_type = type_alias->TypeAnnotation()->GetType(checker_);
    Out("export type ", name, " = ");
    GenType(aliased_type);
    Out(";");
    OutEndl(2);
}

void TSDeclGen::GenEnumDeclaration(const ir::TSEnumDeclaration *enum_decl)
{
    const auto enum_name = GetKeyName(enum_decl->Key());
    DebugPrint("GenEnumDeclaration: " + enum_name);
    Out("export enum ", enum_name, " {");
    OutEndl();

    ASSERT(enum_decl->TsType()->IsETSEnumType());
    GenEnumType(enum_decl->TsType()->AsETSEnumType());

    Out("}");
    OutEndl(2);
}

void TSDeclGen::GenInterfaceDeclaration(const ir::TSInterfaceDeclaration *interface_decl)
{
    state_.in_interface = true;
    const auto interface_name = interface_decl->Id()->Name().Mutf8();
    DebugPrint("GenInterfaceDeclaration: " + interface_name);
    Out("export interface ", interface_name);

    GenTypeParameters(interface_decl->TypeParams());

    Out(" {");
    OutEndl();

    for (auto *prop : interface_decl->Body()->Body()) {
        if (prop->IsMethodDefinition()) {
            GenMethodDeclaration(prop->AsMethodDefinition());
        }
        if (prop->IsClassProperty()) {
            GenPropDeclaration(prop->AsClassProperty());
        }
    }

    Out("}");
    OutEndl(2);
}

void TSDeclGen::GenClassDeclaration(const ir::ClassDeclaration *class_decl)
{
    const auto *class_def = class_decl->Definition();
    std::string class_descriptor = "L" + class_def->InternalName().Mutf8() + ";";
    std::replace(class_descriptor.begin(), class_descriptor.end(), '.', '/');
    state_.current_class_descriptor = class_descriptor;
    const auto class_name = class_def->Ident()->Name().Mutf8();
    state_.in_global_class = class_def->IsGlobal();

    DebugPrint("GenClassDeclaration: " + class_name);

    if (class_name == compiler::Signatures::DYNAMIC_MODULE_CLASS || class_name == compiler::Signatures::JSNEW_CLASS ||
        class_name == compiler::Signatures::JSCALL_CLASS) {
        return;
    }

    if (!state_.in_global_class) {
        Out("export declare class ", class_name);

        GenTypeParameters(class_def->TypeParams());

        const auto *super = class_def->Super();
        if (super != nullptr) {
            Out(" extends ");
            GenType(super->TsType());
        }

        const auto &interfaces = class_def->TsType()->AsETSObjectType()->Interfaces();
        if (!interfaces.empty()) {
            Out(" implements ");
            ASSERT(class_def->TsType()->IsETSObjectType());
            GenCommaSeparated(interfaces, [this](checker::ETSObjectType *interface) { GenType(interface); });
        }

        Out(" {");
        OutEndl();
    }

    for (const auto *prop : class_def->Body()) {
        if (prop->IsMethodDefinition()) {
            GenMethodDeclaration(prop->AsMethodDefinition());
        } else if (prop->IsClassProperty()) {
            GenPropDeclaration(prop->AsClassProperty());
        }
    }

    if (!state_.in_global_class) {
        Out("};");
        OutEndl();
        Out("exports.", class_name, " = (globalThis as any).Panda.getClass('", state_.current_class_descriptor, "');");
        OutEndl(2);
    }
}

void TSDeclGen::GenMethodDeclaration(const ir::MethodDefinition *method_def)
{
    switch (method_def->Kind()) {
        case ir::MethodDefinitionKind::GET:
        case ir::MethodDefinitionKind::SET: {
            ThrowError("Unsupported method kind", method_def->Start());
        }
        default:
            break;
    }

    if (state_.in_global_class) {
        Out("export declare function ");
    } else {
        Out(INDENT);
        GenModifier(method_def);
    }

    const auto method_name = GetKeyName(method_def->Key());
    DebugPrint("  GenMethodDeclaration: " + method_name);
    Out(method_name);

    if (method_def->TsType() == nullptr) {
        Warning("Untyped method encountered: " + method_name);
        Out(": any");
    } else {
        GenFunctionType(method_def->TsType()->AsETSFunctionType(), method_def);
    }

    Out(";");
    OutEndl();

    if (state_.in_global_class) {
        Out("exports.", method_name, " = (globalThis as any).Panda.getFunction('", state_.current_class_descriptor,
            "', '", method_name, "');");
        OutEndl(2);
    }
}

void TSDeclGen::GenPropDeclaration(const ir::ClassProperty *class_prop)
{
    if (state_.in_global_class) {
        return;
    }

    const auto prop_name = GetKeyName(class_prop->Key());
    DebugPrint("  GenPropDeclaration: " + prop_name);

    Out(INDENT);
    GenModifier(class_prop);
    Out(prop_name);

    const auto *prop_type = class_prop->TsType();
    if (prop_type->HasTypeFlag(checker::TypeFlag::NULLABLE)) {
        Out("?");
    }

    Out(": ");
    GenType(prop_type);
    Out(";");
    OutEndl();
}

bool GenerateTsDeclarations(checker::ETSChecker *checker, const panda::es2panda::parser::Program *program,
                            const std::string &out_path)
{
    TSDeclGen decl_builder(checker, program);
    decl_builder.Generate();

    std::ofstream out_stream(out_path);
    if (out_stream.fail()) {
        std::cerr << "Failed to open file: " << out_path << std::endl;
        return false;
    }

    out_stream << decl_builder.Output().str();
    out_stream.close();

    return true;
}
}  // namespace panda::es2panda::util
