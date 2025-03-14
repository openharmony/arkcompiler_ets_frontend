/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "checker/types/ets/etsTupleType.h"
#include "generated/diagnostic.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
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

void TSDeclGen::Generate()
{
    GenGlobalDescriptor();
    CollectIndirectExportDependencies();
    GenDeclarations();
}

void TSDeclGen::GenGlobalDescriptor()
{
    globalDesc_ =
        checker::ETSObjectType::NameToDescriptor(program_->GlobalClass()->TsType()->AsETSObjectType()->AssemblerName());
    OutTs("let ETSGLOBAL = (globalThis as any).Panda.getClass('", globalDesc_, "');");
    OutEndlTs();
}

void TSDeclGen::CollectIndirectExportDependencies()
{
    for (auto *stmt : program_->Ast()->Statements()) {
        if (stmt->IsTSTypeAliasDeclaration()) {
            ProcessTypeAliasDependencies(stmt->AsTSTypeAliasDeclaration());
        } else if (stmt->IsClassDeclaration()) {
            ProcessClassDependencies(stmt->AsClassDeclaration());
        }
    }
}

void TSDeclGen::ProcessTypeAliasDependencies(const ir::TSTypeAliasDeclaration *typeAliasDecl)
{
    const auto name = typeAliasDecl->Id()->Name().Mutf8();
    if (typeAliasDecl->Id()->Parent()->IsExportedType()) {
        return;
    }
    const auto *aliasedType = typeAliasDecl->TypeAnnotation()->GetType(checker_);
    const auto typeFlag = checker::ETSChecker::ETSType(aliasedType);
    if (typeFlag == checker::TypeFlag::ETS_OBJECT || typeFlag == checker::TypeFlag::ETS_DYNAMIC_TYPE) {
        auto objectType = aliasedType->AsETSObjectType();
        auto typeName = objectType->Name();
        AddObjectDependencies(typeName, name);
    }
}

void TSDeclGen::ProcessClassDependencies(const ir::ClassDeclaration *classDecl)
{
    auto *classDef = classDecl->Definition();
    if (classDef->Ident()->Name().Mutf8().find('#') != std::string::npos) {
        return;
    }
    state_.super = classDef->Super();

    if (state_.super != nullptr) {
        AddSuperType(state_.super);
    }
    ProcessInterfacesDependencies(classDef->TsType()->AsETSObjectType()->Interfaces());
}

void TSDeclGen::AddSuperType(const ir::Expression *super)
{
    const auto superType = checker::ETSChecker::ETSType(super->TsType());
    if (superType == checker::TypeFlag::ETS_OBJECT || superType == checker::TypeFlag::ETS_DYNAMIC_TYPE) {
        auto objectType = super->TsType()->AsETSObjectType();
        AddObjectDependencies(objectType->Name());
    }
}

void TSDeclGen::ProcessInterfacesDependencies(const ArenaVector<checker::ETSObjectType *> &interfaces)
{
    GenSeparated(
        interfaces,
        [this](checker::ETSObjectType *interface) {
            if (checker::ETSChecker::ETSType(interface) == checker::TypeFlag::ETS_OBJECT ||
                checker::ETSChecker::ETSType(interface) == checker::TypeFlag::ETS_DYNAMIC_TYPE) {
                AddObjectDependencies(interface->Name());
            }
        },
        "");
}

void TSDeclGen::AddObjectDependencies(const util::StringView &typeName, const std::string &alias)
{
    if (typeName.Empty()) {
        return;
    }
    indirectDependencyObjects_.insert(typeName.Mutf8());
    if (!alias.empty()) {
        typeAliasMap_[alias] = typeName.Mutf8();
    }
}

void TSDeclGen::GenDeclarations()
{
    for (auto *globalStatement : program_->Ast()->Statements()) {
        ResetState();
        if (globalStatement->IsETSImportDeclaration()) {
            GenImportDeclaration(globalStatement->AsETSImportDeclaration());
        } else if (globalStatement->IsTSEnumDeclaration()) {
            GenEnumDeclaration(globalStatement->AsTSEnumDeclaration());
        } else if (globalStatement->IsClassDeclaration()) {
            GenClassDeclaration(globalStatement->AsClassDeclaration());
        } else if (globalStatement->IsTSInterfaceDeclaration()) {
            GenInterfaceDeclaration(globalStatement->AsTSInterfaceDeclaration());
        } else if (globalStatement->IsTSTypeAliasDeclaration()) {
            GenTypeAliasDeclaration(globalStatement->AsTSTypeAliasDeclaration());
        } else if (globalStatement->IsETSReExportDeclaration()) {
            GenReExportDeclaration(globalStatement->AsETSReExportDeclaration());
        }
    }
}

template <class T, class CB>
void TSDeclGen::GenSeparated(const T &container, const CB &cb, const char *separator, bool isReExport)
{
    if (container.empty()) {
        return;
    }

    cb(container[0]);
    for (std::size_t i = 1; i < container.size(); ++i) {
        if (isReExport) {
            OutTs(separator);
        }
        OutDts(separator);
        cb(container[i]);
    }
}

void TSDeclGen::LogError(const diagnostic::DiagnosticKind &kind, const util::DiagnosticMessageParams &params = {},
                         const lexer::SourcePosition &pos = lexer::SourcePosition())
{
    diagnosticEngine_.LogDiagnostic(kind, params, pos);
}

void TSDeclGen::LogWarning(const diagnostic::DiagnosticKind &kind, const util::DiagnosticMessageParams &params = {},
                           const lexer::SourcePosition &pos = lexer::SourcePosition())
{
    ES2PANDA_ASSERT(kind.Type() == util::DiagnosticType::DECLGEN_ETS2TS_WARNING);
    LogError(kind, params, pos);
}

const ir::Identifier *TSDeclGen::GetKeyIdent(const ir::Expression *key)
{
    if (!key->IsIdentifier()) {
        LogError(diagnostic::IDENT_KEY_SUPPORT, {}, key->Start());
    }

    return key->AsIdentifier();
}

static char const *GetDebugTypeName(const checker::Type *checkerType)
{
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TYPE_CHECKS(type_flag, typeName)                                                    \
    if (checkerType->Is##typeName()) {                                                      \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed*/ \
        return #typeName;                                                                   \
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

    if (HandleBasicTypes(checkerType)) {
        return;
    }
    if (checkerType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        OutDts("number");
        return;
    }
    if (checkerType->IsETSStringEnumType()) {
        OutDts("string");
        return;
    }

    if (checkerType->IsETSFunctionType()) {
        HandleFunctionType(checkerType);
        return;
    }

    if (HandleETSSpecificTypes(checkerType)) {
        return;
    }

    LogError(diagnostic::UNSUPPORTED_TYPE, {GetDebugTypeName(checkerType)});
}

bool TSDeclGen::HandleBasicTypes(const checker::Type *checkerType)
{
    if (checkerType->IsETSEnumType()) {
        OutDts(checkerType->ToString());
        return true;
    }
    if (checkerType->HasTypeFlag(checker::TypeFlag::CHAR)) {
        OutDts("string");
        return true;
    }
    if (checkerType->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC)) {
        OutDts("number");
        return true;
    }
    return false;
}

void TSDeclGen::HandleFunctionType(const checker::Type *checkerType)
{
    if (!state_.inUnionBodyStack.empty() && state_.inUnionBodyStack.top()) {
        OutDts("(");
        GenFunctionType(checkerType->AsETSFunctionType());
        OutDts(")");
    } else {
        GenFunctionType(checkerType->AsETSFunctionType());
    }
}

bool TSDeclGen::HandleETSSpecificTypes(const checker::Type *checkerType)
{
    switch (checker::ETSChecker::ETSType(checkerType)) {
        case checker::TypeFlag::ETS_VOID:
        case checker::TypeFlag::ETS_NULL:
        case checker::TypeFlag::ETS_UNDEFINED:
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::ETS_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_NONNULLISH:
        case checker::TypeFlag::ETS_PARTIAL_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_NEVER:
        case checker::TypeFlag::ETS_READONLY:
            OutDts(checkerType->ToString());
            return true;

        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_DYNAMIC_TYPE:
            return HandleObjectType(checkerType);

        case checker::TypeFlag::ETS_ARRAY:
            HandleArrayType(checkerType);
            return true;

        case checker::TypeFlag::ETS_UNION:
            GenUnionType(checkerType->AsETSUnionType());
            return true;
        case checker::TypeFlag::ETS_TUPLE:
            GenTupleType(checkerType->AsETSTupleType());
            return true;
        default:
            LogError(diagnostic::UNSUPPORTED_TYPE, {GetDebugTypeName(checkerType)});
    }
    return false;
}

bool TSDeclGen::HandleObjectType(const checker::Type *checkerType)
{
    std::string typeStr = checkerType->ToString();
    if (typeStr == "Boolean") {
        OutDts("boolean");
    } else if (stringTypes_.count(typeStr)) {
        OutDts("string");
    } else if (numberTypes_.count(typeStr)) {
        OutDts("number");
    } else if (typeStr == "ESObject") {
        OutDts("any");
    } else if (typeStr == "BigInt") {
        OutDts("bigint");
    } else {
        GenObjectType(checkerType->AsETSObjectType());
    }
    return true;
}

void TSDeclGen::HandleArrayType(const checker::Type *checkerType)
{
    const auto *elementType = checkerType->AsETSArrayType()->ElementType();
    std::string elementTypeStr = elementType->ToString();
    bool isUnionType = elementTypeStr.find('|') != std::string::npos;
    if (isUnionType) {
        OutDts("(");
        GenType(elementType);
        OutDts(")");
    } else {
        GenType(elementType);
    }
    OutDts("[]");
}

void TSDeclGen::GenLiteral(const ir::Literal *literal)
{
    if (literal->IsNumberLiteral()) {
        const auto number = literal->AsNumberLiteral()->Number();
        if (number.IsInt()) {
            OutDts(std::to_string(number.GetInt()));
            OutTs(std::to_string(number.GetInt()));
            return;
        }
        if (number.IsLong()) {
            OutDts(std::to_string(number.GetLong()));
            OutTs(std::to_string(number.GetLong()));
            return;
        }
        if (number.IsFloat()) {
            OutDts(std::to_string(number.GetFloat()));
            OutTs(std::to_string(number.GetFloat()));
            return;
        }
        if (number.IsDouble()) {
            OutDts(std::to_string(number.GetDouble()));
            OutTs(std::to_string(number.GetDouble()));
            return;
        }
        LogError(diagnostic::UNEXPECTED_NUMBER_LITERAL_TYPE, {}, literal->Start());
    } else if (literal->IsStringLiteral()) {
        const auto string = literal->AsStringLiteral()->ToString();
        OutDts("\"" + string + "\"");
        OutTs("\"" + string + "\"");
    } else {
        LogError(diagnostic::UNSUPPORTED_LITERAL_TYPE, {}, literal->Start());
    }
}

void TSDeclGen::ProcessParamDefaultToMap(const ir::Statement *stmt)
{
    if (!stmt->IsVariableDeclaration()) {
        return;
    }
    GenSeparated(
        stmt->AsVariableDeclaration()->Declarators(),
        [this](ir::VariableDeclarator *declarator) {
            const auto *init = declarator->Init();
            if (init != nullptr && init->IsConditionalExpression() &&
                init->AsConditionalExpression()->Test()->IsBinaryExpression()) {
                const auto *left = init->AsConditionalExpression()->Test()->AsBinaryExpression()->Left();
                if (left->IsIdentifier()) {
                    const auto varName = GetKeyIdent(declarator->Id())->Name();
                    paramDefaultMap_.insert({left->AsIdentifier()->Name(), varName});
                }
            }
        },
        "");
}

const checker::Signature *TSDeclGen::GetFuncSignature(const checker::ETSFunctionType *etsFunctionType,
                                                      const ir::MethodDefinition *methodDef)
{
    if (etsFunctionType->IsETSArrowType()) {
        return etsFunctionType->ArrowSignature();
    }
    if (methodDef != nullptr) {
        return methodDef->Function()->Signature();
    }
    if (etsFunctionType->CallSignatures().size() != 1) {
        const auto loc = methodDef != nullptr ? methodDef->Start() : lexer::SourcePosition();
        LogError(diagnostic::NOT_OVERLOAD_SUPPORT, {}, loc);
    }
    return etsFunctionType->CallSignatures()[0];
}

void TSDeclGen::ProcessFuncParameter(varbinder::LocalVariable *param)
{
    if (std::string(param->Name()).find("<property>") != std::string::npos) {
        return;
    }
    if (!paramDefaultMap_.empty() && paramDefaultMap_.find(param->Name()) != paramDefaultMap_.end()) {
        OutDts(paramDefaultMap_[param->Name()]);
        paramDefaultMap_.erase(param->Name());
    } else {
        OutDts(param->Name().Is("=t") ? "this" : param->Name());
    }
    const auto *paramType = param->TsType();
    const auto *paramDeclNode = param->Declaration()->Node();
    if (paramDeclNode->IsETSParameterExpression()) {
        const auto *expr = paramDeclNode->AsETSParameterExpression();
        OutDts(expr->IsOptional() ? "?" : "");
        OutDts(": ");

        const auto *typeAnnotation = expr->TypeAnnotation();
        if (typeAnnotation != nullptr && typeAnnotation->IsETSTypeReference() && paramType->IsETSFunctionType()) {
            auto name = typeAnnotation->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name();
            OutDts(name);
        } else if (typeAnnotation != nullptr && expr->IsOptional()) {
            GenType(typeAnnotation->TsType());
        } else {
            GenType(paramType);
        }
    } else {
        if (param->HasFlag(varbinder::VariableFlags::OPTIONAL)) {
            OutDts("?");
        }
        OutDts(": ");
        GenType(paramType);
    }
}

void TSDeclGen::ProcessFuncParameters(const checker::Signature *sig)
{
    GenSeparated(sig->Params(), [this](varbinder::LocalVariable *param) { ProcessFuncParameter(param); });
}

void TSDeclGen::GenFunctionType(const checker::ETSFunctionType *etsFunctionType, const ir::MethodDefinition *methodDef)
{
    const bool isConstructor = methodDef != nullptr ? methodDef->IsConstructor() : false;
    const bool isSetter = methodDef != nullptr ? methodDef->Kind() == ir::MethodDefinitionKind::SET : false;
    // CC-OFFNXT(G.FMT.14-CPP) project code style
    const auto *sig = GetFuncSignature(etsFunctionType, methodDef);
    if (sig->HasFunction()) {
        GenTypeParameters(sig->Function()->TypeParams());
        const auto *funcBody = sig->Function()->Body();
        if (funcBody != nullptr && funcBody->IsBlockStatement() &&
            !funcBody->AsBlockStatement()->Statements().empty()) {
            for (const auto *statement : funcBody->AsBlockStatement()->Statements()) {
                ProcessParamDefaultToMap(statement);
            }
        }
    }
    OutDts("(");

    ProcessFuncParameters(sig);

    const auto *sigInfo = sig->GetSignatureInfo();
    if (sigInfo->restVar != nullptr) {
        if (!sig->Params().empty()) {
            OutDts(", ");
        }
        OutDts("...", sigInfo->restVar->Name().Mutf8(), ": ");
        GenType(sigInfo->restVar->TsType());
    }
    OutDts(")");
    if (!isSetter && !isConstructor) {
        OutDts(methodDef != nullptr ? ": " : " => ");
        GenType(sig->ReturnType());
    }
}

void TSDeclGen::GenEnumMember(const ir::TSEnumDeclaration *enumDecl)
{
    for (auto *member : enumDecl->Members()) {
        auto indent = GetIndent();
        OutDts(INDENT);
        OutTs(indent);
        if (!member->IsTSEnumMember()) {
            LogError(diagnostic::INCORRECT_ENUM_MEMBER, {}, member->Start());
        }

        const auto *enumMember = member->AsTSEnumMember();
        OutDts(GetKeyIdent(enumMember->Key())->Name().Mutf8());
        OutTs(GetKeyIdent(enumMember->Key())->Name().Mutf8());
        const auto *init = enumMember->Init();
        if (init != nullptr) {
            OutDts(" = ");
            OutTs(" = ");
            if (!init->IsLiteral()) {
                LogError(diagnostic::NOT_LITERAL_ENUM_INITIALIZER, {}, member->Start());
            }

            GenLiteral(init->AsLiteral());
        }
        OutTs(",");
        OutEndlTs();
        OutDts(",");
        OutEndlDts();
    }
}

void TSDeclGen::GenUnionType(const checker::ETSUnionType *unionType)
{
    state_.inUnionBodyStack.push(true);
    const auto originTypes = unionType->ConstituentTypes();
    bool hasNumber = false;
    bool hasString = false;
    std::vector<checker::Type *> filteredTypes;
    for (std::size_t i = 0; i < originTypes.size(); ++i) {
        std::string typeStr = originTypes[i]->ToString();
        if (stringTypes_.count(typeStr)) {
            if (hasString) {
                continue;
            }
            filteredTypes.push_back(originTypes[i]);
            hasString = true;
        } else if (numberTypes_.count(typeStr)) {
            if (hasNumber) {
                continue;
            }
            filteredTypes.push_back(originTypes[i]);
            hasNumber = true;
        } else {
            filteredTypes.push_back(originTypes[i]);
        }
    }
    GenSeparated(
        filteredTypes, [this](checker::Type *arg) { GenType(arg); }, " | ");
    state_.inUnionBodyStack.pop();
}

void TSDeclGen::GenTupleType(const checker::ETSTupleType *tupleType)
{
    OutDts("[");
    GenSeparated(
        tupleType->GetTupleTypesList(), [this](checker::Type *arg) { GenType(arg); }, " , ");
    OutDts("]");
}

void TSDeclGen::GenObjectType(const checker::ETSObjectType *objectType)
{
    if (objectType->IsETSStringType()) {
        OutDts("string");
        return;
    }
    if (objectType->IsETSBigIntType()) {
        OutDts("bigint");
        return;
    }
    if (objectType->IsETSUnboxableObject()) {
        OutDts("number");  // NOTE(ivagin): create precise builtin type
        return;
    }
    if (objectType->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL)) {
        const auto *invoke = objectType->GetFunctionalInterfaceInvokeType();
        ES2PANDA_ASSERT(invoke && invoke->IsETSFunctionType());
        GenType(invoke);
        return;
    }
    if (objectType->HasObjectFlag(checker::ETSObjectFlags::DYNAMIC)) {
        OutDts("any");
        return;
    }

    auto typeName = objectType->Name();
    if (typeName.Empty()) {
        LogWarning(diagnostic::EMPTY_TYPE_NAME);
        OutDts("any");
    } else {
        std::string typeStr = typeName.Mutf8();
        if (typeStr == "Exception") {
            OutDts("Error");
        } else if (size_t partialPos = typeStr.find("$partial"); partialPos != std::string::npos) {
            OutDts("Partial<", typeStr.substr(0, partialPos), ">");
        } else {
            OutDts(typeStr);
        }
        indirectDependencyObjects_.insert(typeStr);
    }

    const auto &typeArgs = objectType->TypeArguments();
    if (!typeArgs.empty()) {
        OutDts("<");
        GenSeparated(typeArgs, [this](checker::Type *arg) { GenType(arg); });
        OutDts(">");
    }
}

void TSDeclGen::GenTypeParameters(const ir::TSTypeParameterDeclaration *typeParams)
{
    if (typeParams != nullptr) {
        OutDts("<");
        GenSeparated(typeParams->Params(), [this](ir::TSTypeParameter *param) {
            OutDts(param->Name()->Name());
            auto *constraint = param->Constraint();
            if (constraint != nullptr) {
                OutDts(" extends ");
                GenType(constraint->GetType(checker_));
            }
        });
        OutDts(">");
    }
}

void TSDeclGen::GenTypeParameters(const ir::TSTypeParameterInstantiation *typeParams)
{
    if (typeParams != nullptr) {
        OutDts("<");
        GenSeparated(typeParams->Params(), [this](ir::TypeNode *param) {
            if (param->IsETSTypeReference()) {
                const auto paramName = param->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name();
                OutDts(paramName);
            } else {
                GenType(param->GetType(checker_));
            }
        });
        OutDts(">");
    }
}

void TSDeclGen::GenExport(const ir::Identifier *symbol)
{
    const auto symbolName = symbol->Name().Mutf8();
    OutDts("export {", symbolName, "};");
    OutEndlDts();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        OutDts("exports.", symbolName, " = ", symbolName, ";");
    }
    OutEndlDts();
}

void TSDeclGen::GenExport(const ir::Identifier *symbol, const std::string &alias)
{
    const auto symbolName = symbol->Name().Mutf8();
    OutDts("export {", symbolName, " as ", alias, "};");
    OutEndlDts();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        OutDts("exports.", alias, " = ", symbolName, ";");
    }
    OutEndlDts();
}

void TSDeclGen::GenDefaultExport(const ir::Identifier *symbol)
{
    const auto symbolName = symbol->Name().Mutf8();
    OutDts("export default ", symbolName, ";");
    OutEndlDts();
    if (!symbol->Parent()->IsTSTypeAliasDeclaration() && !symbol->Parent()->IsTSInterfaceDeclaration()) {
        OutDts("exports.default = ", symbolName, ";");
    }
    OutEndlDts();
}

bool TSDeclGen::ShouldEmitDeclarationSymbol(const ir::Identifier *symbol)
{
    if (declgenOptions_.exportAll) {
        return true;
    }
    if (symbol->Parent()->IsExported() || symbol->Parent()->IsExportedType() || symbol->Parent()->IsDefaultExported()) {
        return true;
    }
    if (indirectDependencyObjects_.find(symbol->Name().Mutf8()) != indirectDependencyObjects_.end()) {
        classNode_.isIndirect = true;
        return true;
    }

    return false;
}

template <class T>
void TSDeclGen::GenModifier(const T *node, bool isProp)
{
    if (state_.inInterface) {
        return;
    }

    if (state_.inNamespace && isProp) {
        OutDts("let ");
        return;
    }
    if (state_.inNamespace && !isProp) {
        OutDts("function ");
        return;
    }
    if (node->IsPublic()) {
        OutDts("public ");
    } else if (node->IsPrivate()) {
        OutDts("private ");
    } else if (node->IsProtected()) {
        OutDts("protected ");
    }
    if (node->IsStatic()) {
        OutDts("static ");
    }
    if (node->IsReadonly()) {
        OutDts("readonly ");
    }
}

void TSDeclGen::GenImportDeclaration(const ir::ETSImportDeclaration *importDeclaration)
{
    DebugPrint("GenImportDeclaration");
    if (importDeclaration->IsPureDynamic()) {
        return;
    }
    const auto &specifiers = importDeclaration->Specifiers();
    if (specifiers.empty()) {
        return;
    }
    auto source = importDeclaration->Source()->Str().Mutf8();
    const auto specifierFirst = specifiers[0];
    if (specifierFirst->IsImportNamespaceSpecifier()) {
        const auto local = specifierFirst->AsImportNamespaceSpecifier()->Local()->Name();
        OutDts("import * as ", local, " from \"", source, "\";");
        OutTs("import * as ", local, " from \"", source, "\";");
    } else if (specifierFirst->IsImportSpecifier()) {
        OutDts("import { ");
        OutTs("import { ");
        GenSeparated(
            specifiers,
            [this, &importDeclaration](ir::AstNode *specifier) {
                if (!specifier->IsImportSpecifier()) {
                    LogError(diagnostic::IMPORT_SPECIFIERS_SUPPORT, {}, importDeclaration->Start());
                }
                const auto local = specifier->AsImportSpecifier()->Local()->Name().Mutf8();
                const auto imported = specifier->AsImportSpecifier()->Imported()->Name().Mutf8();
                if (local != imported) {
                    OutDts(imported, " as ", local);
                    OutTs(imported, " as ", local);
                } else {
                    OutDts(local);
                    OutTs(local);
                }
            },
            ",", true);
        OutDts(" } from \"", source, "\";");
        OutTs(" } from \"", source, "\";");
    }
    OutEndlDts();
    OutEndlTs();
}

void TSDeclGen::GenReExportDeclaration(const ir::ETSReExportDeclaration *reExportDeclaration)
{
    DebugPrint("GenReExportDeclaration");
    auto importDeclaration = reExportDeclaration->GetETSImportDeclarations();
    if (importDeclaration->IsPureDynamic()) {
        return;
    }
    const auto &specifiers = importDeclaration->Specifiers();
    if (specifiers.size() == 1 && specifiers[0]->IsImportNamespaceSpecifier()) {
        const auto local = specifiers[0]->AsImportNamespaceSpecifier()->Local()->Name();
        if (local.Empty()) {
            OutDts("export * from \"", importDeclaration->Source()->Str().Mutf8(), "\";");
            OutEndlDts();
            OutTs("export * from \"", importDeclaration->Source()->Str().Mutf8(), "\";");
            OutEndlTs();
            return;
        }
    }
    OutDts("export { ");
    OutTs("export { ");
    GenSeparated(
        specifiers,
        [this, &importDeclaration](ir::AstNode *specifier) {
            if (specifier->IsImportSpecifier()) {
                const auto local = specifier->AsImportSpecifier()->Local()->Name().Mutf8();
                const auto imported = specifier->AsImportSpecifier()->Imported()->Name().Mutf8();
                if (local != imported) {
                    OutDts(imported, " as ", local);
                    OutTs(imported, " as ", local);
                } else {
                    OutDts(local);
                    OutTs(local);
                }
            } else if (specifier->IsImportNamespaceSpecifier()) {
                const auto local = specifier->AsImportNamespaceSpecifier()->Local()->Name();
                OutDts(local);
                OutTs(local);
            } else {
                LogError(diagnostic::IMPORT_SPECIFIERS_SUPPORT, {}, importDeclaration->Start());
            }
        },
        ", ", true);

    auto source = importDeclaration->Source()->Str().Mutf8();
    OutDts(" } from \"", source, "\";");
    OutEndlDts();
    OutTs(" } from \"", source, "\";");
    OutEndlTs();
}

std::string TSDeclGen::ReplaceETSGLOBAL(const std::string &typeName)
{
    if (typeName.empty()) {
        return globalDesc_;
    }
    const std::string target = "ETSGLOBAL";
    std::size_t pos = globalDesc_.find(target);
    if (pos != std::string::npos) {
        return globalDesc_.substr(0, pos) + typeName + globalDesc_.substr(pos + target.length());
    }
    return globalDesc_;
}

void TSDeclGen::GenTypeAliasDeclaration(const ir::TSTypeAliasDeclaration *typeAlias)
{
    const auto name = typeAlias->Id()->Name().Mutf8();
    DebugPrint("GenTypeAliasDeclaration: " + name);
    if (!ShouldEmitDeclarationSymbol(typeAlias->Id())) {
        return;
    }
    const auto typeAnnotation = typeAlias->TypeAnnotation();
    const auto *aliasedType = typeAnnotation->GetType(checker_);
    OutDts("export type ", name);
    GenTypeParameters(typeAlias->TypeParams());
    OutDts(" = ");
    if (typeAnnotation->IsETSTypeReference()) {
        const auto part = typeAnnotation->AsETSTypeReference()->Part();
        const auto partName = part->Name()->AsIdentifier()->Name().Mutf8();
        OutDts(partName);
        const auto partParams = part->TypeParams();
        if (partParams != nullptr) {
            GenTypeParameters(partParams->AsTSTypeParameterInstantiation());
        }
    } else {
        GenType(aliasedType);
    }
    OutDts(";");
    OutEndlDts();

    auto typeName = typeAliasMap_[name];
    const auto classDesc = ReplaceETSGLOBAL(typeName);
    OutTs("const ", name, " = (globalThis as any).Panda.getClass('", classDesc, "');");
    OutEndlTs();
    OutTs("export { ", name, " };");
    OutEndlTs();
}

void TSDeclGen::GenEnumDeclaration(const ir::TSEnumDeclaration *enumDecl)
{
    const auto enumIdent = GetKeyIdent(enumDecl->Key());
    const auto enumName = enumIdent->Name().Mutf8();
    DebugPrint("GenEnumDeclaration: " + enumName);
    if (!ShouldEmitDeclarationSymbol(enumIdent)) {
        return;
    }
    OutDts("export declare enum ", enumName, " {");
    OutEndlDts();
    OutTs("export const enum ", enumName, " {");
    OutEndlTs();
    ES2PANDA_ASSERT(enumDecl->TsType()->IsETSIntEnumType());
    GenEnumMember(enumDecl);
    OutTs("}");
    OutEndlTs();
    OutDts("}");
    OutEndlDts();
}

void TSDeclGen::GenInterfaceDeclaration(const ir::TSInterfaceDeclaration *interfaceDecl)
{
    state_.inInterface = true;
    const auto interfaceName = interfaceDecl->Id()->Name().Mutf8();
    DebugPrint("GenInterfaceDeclaration: " + interfaceName);
    if (interfaceName.find("$partial") != std::string::npos) {
        return;
    }
    if (!ShouldEmitDeclarationSymbol(interfaceDecl->Id())) {
        return;
    }
    if (classNode_.isIndirect) {
        OutDts("declare interface ", interfaceName);
    } else {
        OutDts("export declare interface ", interfaceName);
    }

    GenTypeParameters(interfaceDecl->TypeParams());

    OutDts(" {");
    OutEndlDts();
    ProcessInterfaceBody(interfaceDecl->Body());
    OutDts("}");
    OutEndlDts();
}

void TSDeclGen::ProcessInterfaceBody(const ir::TSInterfaceBody *body)
{
    std::unordered_set<std::string> processedMethods;
    for (auto *prop : body->Body()) {
        if (prop->IsMethodDefinition()) {
            ProcessMethodDefinition(prop->AsMethodDefinition(), processedMethods);
        } else if (prop->IsClassProperty()) {
            GenPropDeclaration(prop->AsClassProperty());
        }
    }
}

void TSDeclGen::ProcessMethodDefinition(const ir::MethodDefinition *methodDef,
                                        std::unordered_set<std::string> &processedMethods)
{
    const auto methodName = GetKeyIdent(methodDef->Key())->Name().Mutf8();
    if (methodDef->Kind() == ir::MethodDefinitionKind::SET) {
        if (processedMethods.find(methodName) != processedMethods.end()) {
            return;
        }
        processedMethods.insert(methodName);
    }
    GenMethodDeclaration(methodDef);
}

void TSDeclGen::PrepareClassDeclaration(const ir::ClassDefinition *classDef)
{
    std::string classDescriptor = "L" + classDef->InternalName().Mutf8() + ";";
    std::replace(classDescriptor.begin(), classDescriptor.end(), '.', '/');
    state_.currentClassDescriptor = classDescriptor;
    state_.inGlobalClass = classDef->IsGlobal();
    if (classDef->IsNamespaceTransformed()) {
        state_.inNamespace = true;
    }
    classNode_.isIndirect = false;
}

bool TSDeclGen::ShouldSkipClassDeclaration(const std::string_view &className) const
{
    return className == compiler::Signatures::DYNAMIC_MODULE_CLASS || className == compiler::Signatures::JSNEW_CLASS ||
           className == compiler::Signatures::JSCALL_CLASS || (className.find("$partial") != std::string::npos);
}

void TSDeclGen::EmitClassDeclaration(const ir::ClassDefinition *classDef, const std::string_view &className)
{
    if (classDef->IsNamespaceTransformed()) {
        OutDts(classNode_.indentLevel > 1 ? "namespace " : "export declare namespace ", className);
        OutTs("export namespace ", className, " {");
    } else if (classNode_.isIndirect) {
        OutDts("declare class ", className);
    } else if (classDef->IsAbstract()) {
        OutDts("export declare abstract class ", className);
    } else {
        OutDts("export declare class ", className);
    }
    OutEndlTs();
}

std::string TSDeclGen::GetIndent() const
{
    return std::string(classNode_.indentLevel * INDENT.size(), ' ');
}

void TSDeclGen::ProcessIndent()
{
    if (classNode_.hasNestedClass || state_.inNamespace) {
        auto indent = GetIndent();
        OutDts(indent);
        OutTs(indent);
    } else {
        OutDts(INDENT);
    }
}

void TSDeclGen::HandleClassDeclarationTypeInfo(const ir::ClassDefinition *classDef, const std::string_view &className)
{
    if (!ShouldEmitDeclarationSymbol(classDef->Ident())) {
        return;
    }
    EmitClassDeclaration(classDef, className);
    GenTypeParameters(classDef->TypeParams());

    const auto *super = classDef->Super();
    state_.super = super;
    if (super != nullptr) {
        OutDts(" extends ");
        GenType(super->TsType());
    }

    const auto &interfaces = classDef->TsType()->AsETSObjectType()->Interfaces();
    if (!interfaces.empty()) {
        OutDts(" implements ");
        ES2PANDA_ASSERT(classDef->TsType()->IsETSObjectType());
        GenSeparated(interfaces, [this](checker::ETSObjectType *interface) { GenType(interface); });
    }

    OutDts(" {");
    OutEndlDts();
}

void TSDeclGen::EmitClassGlueCode(const ir::ClassDefinition *classDef, const std::string &className)
{
    if (classNode_.isIndirect) {
        return;
    }
    const std::string exportPrefix = classDef->Parent()->IsDefaultExported() ? "const " : "export const ";
    OutTs(exportPrefix, className, " = (globalThis as any).Panda.getClass('", state_.currentClassDescriptor, "');");
    OutEndlTs();

    if (classDef->Parent()->IsDefaultExported()) {
        OutTs("export default ", className, ";");
        OutEndlTs();
    }
}

void TSDeclGen::ProcessClassBody(const ir::ClassDefinition *classDef)
{
    for (const auto *prop : classDef->Body()) {
        if (prop->IsMethodDefinition()) {
            GenMethodDeclaration(prop->AsMethodDefinition());
            for (const auto *methodDef : prop->AsMethodDefinition()->Overloads()) {
                GenMethodDeclaration(methodDef);
            }
        } else if (prop->IsClassProperty()) {
            const auto classProp = prop->AsClassProperty();
            const auto propName = GetKeyIdent(classProp->Key())->Name().Mutf8();
            if (propName.find("<property>") != std::string::npos) {
                continue;
            }
            GenPropDeclaration(classProp);
        } else if (prop->IsClassDeclaration() && classDef->IsNamespaceTransformed()) {
            classNode_.hasNestedClass = true;
            auto indent = GetIndent();
            OutDts(indent);
            OutTs(indent);
            classNode_.indentLevel++;
            GenClassDeclaration(prop->AsClassDeclaration());
        }
    }
}

void TSDeclGen::CloseClassBlock(const bool isDts)
{
    auto indent = GetIndent();
    if (isDts) {
        OutDts(indent, "}");
        OutEndlDts();
    } else {
        OutTs(indent, "}");
        OutEndlTs();
    }
}

void TSDeclGen::GenClassDeclaration(const ir::ClassDeclaration *classDecl)
{
    const auto *classDef = classDecl->Definition();
    PrepareClassDeclaration(classDef);
    const auto className = classDef->Ident()->Name().Mutf8();
    DebugPrint("GenClassDeclaration: " + className);
    if (ShouldSkipClassDeclaration(className)) {
        return;
    }
    if (state_.inGlobalClass) {
        classNode_.indentLevel = 1;
        ProcessClassBody(classDef);
    }
    if (!state_.inGlobalClass && ShouldEmitDeclarationSymbol(classDef->Ident())) {
        HandleClassDeclarationTypeInfo(classDef, className);
        if (!classDef->IsNamespaceTransformed()) {
            EmitClassGlueCode(classDef, className);
        }
        ProcessClassBody(classDef);
        classNode_.indentLevel > 0 ? classNode_.indentLevel-- : classNode_.indentLevel = 0;
        CloseClassBlock(true);
    }
    if (classNode_.hasNestedClass || state_.inNamespace) {
        ES2PANDA_ASSERT(classNode_.indentLevel != static_cast<decltype(classNode_.indentLevel)>(-1));
        CloseClassBlock(false);
    }
}

void TSDeclGen::EmitMethodGlueCode(const std::string &methodName, const ir::Identifier *methodIdentifier)
{
    if (!ShouldEmitDeclarationSymbol(methodIdentifier)) {
        return;
    }
    if (state_.inNamespace) {
        OutTs("export const ", methodName,
              " = (globalThis as any).Panda.getClass('" + state_.currentClassDescriptor + "')." + methodName + ";");
        OutEndlTs();
        return;
    }
    if (methodIdentifier->Parent()->IsDefaultExported()) {
        OutTs("const ", methodName, " = (globalThis as any).Panda.getFunction('", state_.currentClassDescriptor, "', '",
              methodName, "');");
        OutEndlTs();
        OutTs("export default ", methodName, ";");
        OutEndlTs();
    } else {
        OutTs("export const ", methodName, " = (globalThis as any).Panda.getFunction('", state_.currentClassDescriptor,
              "', '", methodName, "');");
        OutEndlTs();
    }
}

void TSDeclGen::GenMethodDeclaration(const ir::MethodDefinition *methodDef)
{
    const auto methodIdent = GetKeyIdent(methodDef->Key());
    const auto methodName = methodIdent->Name().Mutf8();
    if (methodName.find('#') != std::string::npos || methodName.find("$asyncimpl") != std::string::npos ||
        (!state_.inGlobalClass && methodName == compiler::Signatures::INIT_METHOD)) {
        return;
    }
    if (methodName == compiler::Signatures::INIT_METHOD) {
        OutTs("ETSGLOBAL.", methodName, "();");
        OutEndlTs();
        return;
    }
    if (state_.inGlobalClass) {
        if (!ShouldEmitDeclarationSymbol(methodIdent)) {
            return;
        }
        OutDts("export declare function ");
    } else {
        ProcessIndent();
        GenModifier(methodDef);
    }
    EmitMethodGlueCode(methodName, methodIdent);

    if (methodDef->IsAbstract() && !state_.inInterface) {
        OutDts("abstract ");
    }
    if (methodDef->Kind() == ir::MethodDefinitionKind::GET) {
        OutDts("get ");
    }
    if (methodDef->Kind() == ir::MethodDefinitionKind::SET) {
        OutDts("set ");
        OutDts(methodName, "(value: ");
        GenType(methodDef->TsType()->AsETSFunctionType()->CallSignatures()[0]->Params()[0]->TsType());
        OutDts(")");
    } else {
        DebugPrint("  GenMethodDeclaration: " + methodName);
        if (methodName.find("$_iterator") != std::string::npos) {
            OutDts("[Symbol.iterator]");
        } else {
            OutDts(methodName);
        }

        if (methodDef->TsType() == nullptr) {
            LogWarning(diagnostic::UNTYPED_METHOD, {methodName}, methodIdent->Start());
            OutDts(": any");
        } else {
            GenFunctionType(methodDef->TsType()->AsETSFunctionType(), methodDef);
        }
    }
    OutDts(";");
    OutEndlDts();
}

void TSDeclGen::EmitPropGlueCode(const ir::ClassProperty *classProp, const std::string &propName)
{
    std::string propAccess;
    if (state_.inGlobalClass) {
        propAccess = " = (globalThis as any).Panda.getClass('" + globalDesc_ + "')." + propName + ";";
    } else {
        propAccess = " = (globalThis as any).Panda.getClass('" + state_.currentClassDescriptor + "')." + propName + ";";
    }

    const bool isConst = classProp->IsConst();
    const bool isDefaultExported = classProp->IsDefaultExported();

    OutTs(isConst ? "export const " : "export let ", propName, propAccess);
    OutEndlTs();

    if (!isConst && isDefaultExported) {
        OutTs("export default ", propName, ";");
        OutEndlTs();
    }
}

void TSDeclGen::GenPropDeclaration(const ir::ClassProperty *classProp)
{
    if (state_.inGlobalClass) {
        GenGlobalVarDeclaration(classProp);
        return;
    }

    const auto propName = GetKeyIdent(classProp->Key())->Name().Mutf8();
    // The class property generated for enums starts with "#" are invalid properties, and should not be generated.
    if (propName.find('#') != std::string::npos) {
        DebugPrint("  Skip Generate enum PropDeclaration: " + propName);
        return;
    }
    DebugPrint("  GenPropDeclaration: " + propName);

    ProcessIndent();
    GenModifier(classProp, true);
    OutDts(propName);

    OutDts(": ");
    if (classProp->IsStatic()) {
        OutDts("any");
    } else {
        GenType(classProp->TsType());
    }
    OutDts(";");
    OutEndlDts();

    if (classNode_.hasNestedClass || state_.inNamespace) {
        EmitPropGlueCode(classProp, propName);
    }
}

void TSDeclGen::GenGlobalVarDeclaration(const ir::ClassProperty *globalVar)
{
    if (!globalVar->IsExported() && !globalVar->IsDefaultExported() && !declgenOptions_.exportAll) {
        return;
    }

    const auto symbol = GetKeyIdent(globalVar->Key());
    const auto varName = symbol->Name().Mutf8();
    const bool isConst = globalVar->IsConst();
    DebugPrint("GenGlobalVarDeclaration: " + varName);

    OutDts(isConst ? "export declare const " : "export declare let ", varName, ": ");
    GenType(globalVar->TsType());
    OutDts(";");
    OutEndlDts();

    EmitPropGlueCode(globalVar, varName);
}

bool WriteToFile(const std::string &path, const std::string &content, checker::ETSChecker *checker)
{
    std::ofstream outStream(path);
    if (outStream.fail()) {
        checker->DiagnosticEngine().LogFatalError(util::DiagnosticMessageParams {"Failed to open file: ", path});
        return false;
    }
    outStream << content;
    outStream.close();
    return true;
}

bool GenerateTsDeclarations(checker::ETSChecker *checker, const ark::es2panda::parser::Program *program,
                            const DeclgenOptions &declgenOptions)
{
    TSDeclGen declBuilder(checker, program);
    declBuilder.SetDeclgenOptions(declgenOptions);

    if ((declBuilder.GetDeclgenOptions().outputDeclEts.empty() && !declBuilder.GetDeclgenOptions().outputEts.empty()) ||
        (!declBuilder.GetDeclgenOptions().outputDeclEts.empty() && declBuilder.GetDeclgenOptions().outputEts.empty())) {
        checker->DiagnosticEngine().LogFatalError(util::DiagnosticMessageParams {
            "Genate dynamic declarations, outputDeclEts and outputEts must be set together."});
        return false;
    }
    if (declBuilder.GetDeclgenOptions().outputDeclEts.empty() && declBuilder.GetDeclgenOptions().outputEts.empty()) {
        checker->DiagnosticEngine().LogFatalError(
            util::DiagnosticMessageParams {"Output file path must be specified."});
        return false;
    }

    declBuilder.Generate();

    if (!declBuilder.GetDeclgenOptions().outputDeclEts.empty()) {
        auto outDtsPath = declBuilder.GetDeclgenOptions().outputDeclEts;
        if (!WriteToFile(outDtsPath, declBuilder.GetDtsOutput(), checker)) {
            return false;
        }
    }

    if (!declBuilder.GetDeclgenOptions().outputEts.empty()) {
        auto outTsPath = declBuilder.GetDeclgenOptions().outputEts;
        if (!WriteToFile(outTsPath, declBuilder.GetTsOutput(), checker)) {
            return false;
        }
    }

    return true;
}
}  // namespace ark::es2panda::declgen_ets2ts
