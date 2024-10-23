/**
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

#include "declgenEts2Ts.h"

#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/module/importSpecifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameter.h"

#define DEBUG_PRINT 0

namespace ark::es2panda::declgen_ets2ts {

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
    std::stringstream license;
    license << "/*\n";
    license << " * Copyright (c) 2023-2024 Huawei Device Co., Ltd.\n";
    license << " * Licensed under the Apache License, Version 2.0 (the \"License\");\n";
    license << " * you may not use this file except in compliance with the License.\n";
    license << " * You may obtain a copy of the License at\n";
    license << " *\n";
    license << " *     http://www.apache.org/licenses/LICENSE-2.0\n";
    license << " *\n";
    license << " * Unless required by applicable law or agreed to in writing, software\n";
    license << " * distributed under the License is distributed on an \"AS IS\" BASIS,\n";
    license << " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n";
    license << " * See the License for the specific language governing permissions and\n";
    license << " * limitations under the License.\n";
    license << " */\n\n";
    Out(license.str());
    Out("declare const exports: any;");
    OutEndl();
    Out("let ETSGLOBAL: any = (globalThis as any).Panda.getClass('LETSGLOBAL;');");
    OutEndl(2U);

    for (auto *globalStatement : program_->Ast()->Statements()) {
        ResetState();
        if (globalStatement->IsETSImportDeclaration()) {
            GenImportDeclaration(globalStatement->AsETSImportDeclaration());
        } else if (globalStatement->IsTSEnumDeclaration()) {
            GenEnumDeclaration(globalStatement->AsTSEnumDeclaration());
        } else if (globalStatement->IsClassDeclaration()) {
            // The classes generated for enums starts with '#' but those are invalid names and
            // not requred for the ts code
            if (globalStatement->AsClassDeclaration()->Definition()->Ident()->Name().Mutf8().find('#') ==
                std::string::npos) {
                GenClassDeclaration(globalStatement->AsClassDeclaration());
            }
        } else if (globalStatement->IsTSInterfaceDeclaration()) {
            GenInterfaceDeclaration(globalStatement->AsTSInterfaceDeclaration());
        } else if (globalStatement->IsTSTypeAliasDeclaration()) {
            GenTypeAliasDeclaration(globalStatement->AsTSTypeAliasDeclaration());
        }
    }
}

template <class T, class CB>
void TSDeclGen::GenSeparated(const T &container, const CB &cb, const char *separator)
{
    if (container.empty()) {
        return;
    }

    cb(container[0]);
    for (std::size_t i = 1; i < container.size(); ++i) {
        Out(separator);
        cb(container[i]);
    }
}

void TSDeclGen::ThrowError(const std::string_view message, const lexer::SourcePosition &pos = lexer::SourcePosition())
{
    lexer::LineIndex index(program_->SourceCode());
    const lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::GENERIC, program_->SourceFilePath().Utf8(), "declgen ets2ts: " + std::string(message),
                 loc.line, loc.col};
}

const ir::Identifier *TSDeclGen::GetKeyIdent(const ir::Expression *key)
{
    if (!key->IsIdentifier()) {
        ThrowError("Not identifier keys are not supported", key->Start());
    }

    return key->AsIdentifier();
}

static char const *GetDebugTypeName(const checker::Type *checkerType)
{
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_CHECKS(type_flag, typeName) \
    if (checkerType->Is##typeName()) {   \
        return #typeName;                \
    }
    TYPE_MAPPING(TYPE_CHECKS)
#undef TYPE_CHECKS
    return "unknown type";
}

void TSDeclGen::GenType(const checker::Type *checkerType)
{
    DebugPrint("  GenType: ");
#if DEBUG_PRINT
    const auto var_name = checkerType->Variable() == nullptr ? "" : checkerType->Variable()->Name().Mutf8();
    DebugPrint(std::string("  Converting type: ") + GetDebugTypeName(checkerType) + " (" + var_name + ")");
#endif

    if (checkerType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        Out("number");
        return;
    }
    if (checkerType->HasTypeFlag(checker::TypeFlag::FUNCTION)) {
        GenFunctionType(checkerType->AsETSFunctionType());
        return;
    }

    switch (checker::ETSChecker::ETSType(checkerType)) {
        case checker::TypeFlag::ETS_VOID:
        case checker::TypeFlag::ETS_NULL:
        case checker::TypeFlag::ETS_UNDEFINED:
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::ETS_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_NONNULLISH:
        case checker::TypeFlag::ETS_READONLY:
        case checker::TypeFlag::ETS_INT_ENUM:
            Out(checkerType->ToString());
            return;
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_DYNAMIC_TYPE:
            GenObjectType(checkerType->AsETSObjectType());
            return;
        case checker::TypeFlag::ETS_ARRAY:
            GenType(checkerType->AsETSArrayType()->ElementType());
            Out("[]");
            return;
        case checker::TypeFlag::ETS_UNION:
            GenUnionType(checkerType->AsETSUnionType());
            return;
        default:
            ThrowError(std::string("Unsupported type: '") + GetDebugTypeName(checkerType));
    }
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

void TSDeclGen::GenFunctionBody(const ir::MethodDefinition *methodDef, const checker::Signature *sig,
                                const bool isConstructor, const bool isSetter)
{
    if (isConstructor) {
        if (state_.super != nullptr) {
            Out("{ super(...{} as (ConstructorParameters<typeof ");
            GenType(state_.super->TsType());
            Out(">)); }");
        } else {
            Out(" {}");
        }
    } else if (isSetter) {
        Out(" {}");
    } else {
        Out(methodDef != nullptr ? ": " : " => ");
        GenType(sig->ReturnType());
        if (methodDef != nullptr && !state_.inInterface) {
            Out(" { return {} as any; }");
        }
    }
}

void TSDeclGen::GenFunctionType(const checker::ETSFunctionType *etsFunctionType, const ir::MethodDefinition *methodDef)
{
    const bool isConstructor = methodDef != nullptr ? methodDef->IsConstructor() : false;
    const bool isSetter = methodDef != nullptr ? methodDef->Kind() == ir::MethodDefinitionKind::SET : false;

    const auto *sig = [this, methodDef, etsFunctionType]() -> const checker::Signature * {
        if (methodDef != nullptr) {
            return methodDef->Function()->Signature();
        }
        if (etsFunctionType->CallSignatures().size() != 1) {
            const auto loc = methodDef != nullptr ? methodDef->Start() : lexer::SourcePosition();
            ThrowError("Method overloads are not supported", loc);
        }
        return etsFunctionType->CallSignatures()[0];
    }();

    const auto *func = sig->Function();
    GenTypeParameters(func->TypeParams());
    Out("(");

    GenSeparated(sig->Params(), [this](varbinder::LocalVariable *param) {
        Out(param->Name());
        const auto *paramType = param->TsType();

        if (param->HasFlag(varbinder::VariableFlags::OPTIONAL)) {
            Out("?");
        }
        Out(": ");
        GenType(paramType);
    });

    const auto *sigInfo = sig->GetSignatureInfo();
    if (sigInfo->restVar != nullptr) {
        if (!sig->Params().empty()) {
            Out(", ");
        }
        Out("...", sigInfo->restVar->Name().Mutf8(), ": ");
        GenType(sigInfo->restVar->TsType());
    }

    Out(")");

    GenFunctionBody(methodDef, sig, isConstructor, isSetter);
}

void TSDeclGen::GenEnumType(const checker::ETSIntEnumType *enumType)
{
    for (auto *member : enumType->GetMembers()) {
        Out(INDENT);
        if (!member->IsTSEnumMember()) {
            ThrowError("Member of enum not of type TSEnumMember", member->Start());
        }

        const auto *enumMember = member->AsTSEnumMember();
        Out(GetKeyIdent(enumMember->Key())->Name().Mutf8());
        const auto *init = enumMember->Init();
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

void TSDeclGen::GenUnionType(const checker::ETSUnionType *unionType)
{
    GenSeparated(
        unionType->ConstituentTypes(), [this](checker::Type *arg) { GenType(arg); }, " | ");
}

void TSDeclGen::GenObjectType(const checker::ETSObjectType *objectType)
{
    if (objectType->IsETSStringType()) {
        Out("string");
        return;
    }
    if (objectType->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE)) {
        Out("number");  // NOTE(ivagin): create precise builtin type
        return;
    }
    if (objectType->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL)) {
        const auto *invoke = objectType->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(
            checker::FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME);
        ASSERT(invoke && invoke->TsType() && invoke->TsType()->IsETSFunctionType());
        GenType(invoke->TsType());
        return;
    }
    if (objectType->HasObjectFlag(checker::ETSObjectFlags::DYNAMIC)) {
        Out("any");
        return;
    }

    auto typeName = objectType->Name();
    if (typeName.Empty()) {
        Warning("Object type name is empty");
        Out("any");
    } else {
        Out(typeName);
    }

    const auto &typeArgs = objectType->TypeArguments();
    if (!typeArgs.empty()) {
        Out("<");
        GenSeparated(typeArgs, [this](checker::Type *arg) { GenType(arg); });
        Out(">");
    }
}

void TSDeclGen::GenTypeParameters(const ir::TSTypeParameterDeclaration *typeParams)
{
    if (typeParams != nullptr) {
        Out("<");
        GenSeparated(typeParams->Params(), [this](ir::TSTypeParameter *param) {
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

void TSDeclGen::GenExport(const ir::Identifier *symbol)
{
    const auto symbolName = symbol->Name().Mutf8();
    Out("export {", symbolName, "};");
    OutEndl();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        Out("exports.", symbolName, " = ", symbolName, ";");
    }
    OutEndl();
}

void TSDeclGen::GenExport(const ir::Identifier *symbol, const std::string &alias)
{
    const auto symbolName = symbol->Name().Mutf8();
    Out("export {", symbolName, " as ", alias, "};");
    OutEndl();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        Out("exports.", alias, " = ", symbolName, ";");
    }
    OutEndl();
}

void TSDeclGen::GenDefaultExport(const ir::Identifier *symbol)
{
    const auto symbolName = symbol->Name().Mutf8();
    Out("export default ", symbolName, ";");
    OutEndl();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        Out("exports.default = ", symbolName, ";");
    }
    OutEndl();
}

void TSDeclGen::ExportIfNeeded(const ir::Identifier *symbol)
{
    if (symbol->Parent()->IsExported()) {
        GenExport(symbol);
    }
    if (symbol->Parent()->IsExportedType()) {
        GenExport(symbol);
    }
    if (symbol->Parent()->IsDefaultExported()) {
        GenDefaultExport(symbol);
    }
}

template <class T>
void TSDeclGen::GenModifier(const T *node)
{
    if (state_.inInterface) {
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

void TSDeclGen::GenImportDeclaration(const ir::ETSImportDeclaration *importDeclaration)
{
    DebugPrint("GenImportDeclaration");
    if (importDeclaration->IsPureDynamic()) {
        return;
    }

    const auto &specifiers = importDeclaration->Specifiers();
    Out("import { ");
    GenSeparated(specifiers, [this, &importDeclaration](ir::AstNode *specifier) {
        if (!specifier->IsImportSpecifier()) {
            ThrowError("Only import specifiers are supported", importDeclaration->Start());
        }

        const auto local = specifier->AsImportSpecifier()->Local()->Name();
        const auto imported = specifier->AsImportSpecifier()->Imported()->Name();
        Out(local);
        if (local != imported) {
            ThrowError("Imports with local bindings are not supported", importDeclaration->Start());
        }
    });

    auto source = importDeclaration->Source()->Str().Mutf8();
    Out(" } from \"", source, "\";");
    OutEndl(2U);
}

void TSDeclGen::GenTypeAliasDeclaration(const ir::TSTypeAliasDeclaration *typeAlias)
{
    const auto name = typeAlias->Id()->Name().Mutf8();
    DebugPrint("GenTypeAliasDeclaration: " + name);
    const auto *aliasedType = typeAlias->TypeAnnotation()->GetType(checker_);
    Out("type ", name, " = ");
    GenType(aliasedType);
    Out(";");
    OutEndl();

    ExportIfNeeded(typeAlias->Id());
    OutEndl();
}

void TSDeclGen::GenEnumDeclaration(const ir::TSEnumDeclaration *enumDecl)
{
    const auto enumIdent = GetKeyIdent(enumDecl->Key());
    const auto enumName = enumIdent->Name().Mutf8();
    DebugPrint("GenEnumDeclaration: " + enumName);
    Out("enum ", enumName, " {");
    OutEndl();

    ASSERT(enumDecl->TsType()->IsETSIntEnumType());
    GenEnumType(enumDecl->TsType()->AsETSIntEnumType());

    Out("}");
    OutEndl();

    ExportIfNeeded(enumIdent);
    OutEndl();
}

void TSDeclGen::GenInterfaceDeclaration(const ir::TSInterfaceDeclaration *interfaceDecl)
{
    state_.inInterface = true;
    const auto interfaceName = interfaceDecl->Id()->Name().Mutf8();
    DebugPrint("GenInterfaceDeclaration: " + interfaceName);
    Out("interface ", interfaceName);

    GenTypeParameters(interfaceDecl->TypeParams());

    Out(" {");
    OutEndl();

    for (auto *prop : interfaceDecl->Body()->Body()) {
        if (prop->IsMethodDefinition()) {
            GenMethodDeclaration(prop->AsMethodDefinition());
            for (const auto *methodDef : prop->AsMethodDefinition()->Overloads()) {
                GenMethodDeclaration(methodDef);
            }
        }
        if (prop->IsClassProperty()) {
            GenPropDeclaration(prop->AsClassProperty());
        }
    }

    Out("}");
    OutEndl();

    ExportIfNeeded(interfaceDecl->Id());
    OutEndl();
}

void TSDeclGen::GenClassDeclaration(const ir::ClassDeclaration *classDecl)
{
    const auto *classDef = classDecl->Definition();
    std::string classDescriptor = "L" + classDef->InternalName().Mutf8() + ";";
    std::replace(classDescriptor.begin(), classDescriptor.end(), '.', '/');
    state_.currentClassDescriptor = classDescriptor;
    const auto className = classDef->Ident()->Name().Mutf8();
    state_.inGlobalClass = classDef->IsGlobal();

    DebugPrint("GenClassDeclaration: " + className);

    if (className == compiler::Signatures::DYNAMIC_MODULE_CLASS || className == compiler::Signatures::JSNEW_CLASS ||
        className == compiler::Signatures::JSCALL_CLASS || (className.find("$partial") != std::string::npos)) {
        return;
    }

    if (!state_.inGlobalClass) {
        Out("class ", className);
        GenTypeParameters(classDef->TypeParams());

        const auto *super = classDef->Super();
        state_.super = super;
        if (super != nullptr) {
            Out(" extends ");
            GenType(super->TsType());
        }

        const auto &interfaces = classDef->TsType()->AsETSObjectType()->Interfaces();
        if (!interfaces.empty()) {
            Out(" implements ");
            ASSERT(classDef->TsType()->IsETSObjectType());
            GenSeparated(interfaces, [this](checker::ETSObjectType *interface) { GenType(interface); });
        }

        Out(" {");
        OutEndl();
    }

    for (const auto *prop : classDef->Body()) {
        if (prop->IsMethodDefinition()) {
            GenMethodDeclaration(prop->AsMethodDefinition());
            for (const auto *methodDef : prop->AsMethodDefinition()->Overloads()) {
                GenMethodDeclaration(methodDef);
            }
        } else if (prop->IsClassProperty()) {
            GenPropDeclaration(prop->AsClassProperty());
        }
    }

    if (!state_.inGlobalClass) {
        Out("};");
        OutEndl();
        Out("(", className, " as any) = (globalThis as any).Panda.getClass('", state_.currentClassDescriptor, "');");
        OutEndl();
        ExportIfNeeded(classDef->Ident());
        OutEndl();
    }
}

void TSDeclGen::GenMethodDeclaration(const ir::MethodDefinition *methodDef)
{
    const auto methodIdent = GetKeyIdent(methodDef->Key());
    const auto methodName = methodIdent->Name().Mutf8();
    if (methodName.find('#') != std::string::npos) {
        return;
    }

    if (state_.inGlobalClass) {
        Out("function ");
    } else {
        Out(INDENT);
        GenModifier(methodDef);
    }

    if (methodDef->Kind() == ir::MethodDefinitionKind::GET) {
        Out("get ");
    }
    if (methodDef->Kind() == ir::MethodDefinitionKind::SET) {
        Out("set ");
    }

    DebugPrint("  GenMethodDeclaration: " + methodName);
    Out(methodName);

    if (methodDef->TsType() == nullptr) {
        Warning("Untyped method encountered: " + methodName);
        Out(": any");
    } else {
        GenFunctionType(methodDef->TsType()->AsETSFunctionType(), methodDef);
    }

    Out(";");
    OutEndl();

    if (state_.inGlobalClass) {
        Out("(", methodName, " as any) = ETSGLOBAL.", methodName, ";");
        OutEndl();
        ExportIfNeeded(methodIdent);
        if (methodName == compiler::Signatures::INIT_METHOD) {
            Out(methodName, "();");
        }
        OutEndl(2U);
    }
}

void TSDeclGen::GenPropDeclaration(const ir::ClassProperty *classProp)
{
    if (state_.inGlobalClass) {
        GenGlobalVarDeclaration(classProp);
        return;
    }

    const auto propName = GetKeyIdent(classProp->Key())->Name().Mutf8();
    DebugPrint("  GenPropDeclaration: " + propName);

    Out(INDENT);
    GenModifier(classProp);
    Out(propName);

    Out(": ");
    GenType(classProp->TsType());
    if (!state_.inInterface) {
        Out(" = {} as any");
    }
    Out(";");
    OutEndl();
}

void TSDeclGen::GenGlobalVarDeclaration(const ir::ClassProperty *globalVar)
{
    if (!globalVar->IsExported() && !globalVar->IsDefaultExported()) {
        return;
    }

    const auto symbol = GetKeyIdent(globalVar->Key());
    const auto varName = symbol->Name().Mutf8();
    DebugPrint("GenGlobalVarDeclaration: " + varName);
    if (!globalVar->IsConst()) {
        Warning("Not constant global variables are not supported, variable \"" + varName + "\" was skipped");
        return;
    }

    Out("const ", varName, ": ");
    GenType(globalVar->TsType());
    Out(" = ETSGLOBAL.", varName, ';');
    OutEndl();

    GenExport(symbol);
    OutEndl();
}

bool GenerateTsDeclarations(checker::ETSChecker *checker, const ark::es2panda::parser::Program *program,
                            const std::string &outPath)
{
    TSDeclGen declBuilder(checker, program);
    declBuilder.Generate();

    std::ofstream outStream(outPath);
    if (outStream.fail()) {
        std::cerr << "Failed to open file: " << outPath << std::endl;
        return false;
    }

    outStream << declBuilder.Output().str();
    outStream.close();

    return true;
}
}  // namespace ark::es2panda::declgen_ets2ts
