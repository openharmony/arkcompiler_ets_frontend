/*
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

#include "ETSchecker.h"

#include "es2panda.h"
#include "ir/base/classDefinition.h"
#include "ir/expression.h"
#include "ir/expressions/callExpression.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/statements/blockStatement.h"
#include "varbinder/ETSBinder.h"
#include "parser/program/program.h"
#include "checker/ets/aliveAnalyzer.h"
#include "checker/ets/assignAnalyzer.h"
#include "checker/ets/etsWarningAnalyzer.h"
#include "checker/types/globalTypesHolder.h"
#include "ir/base/scriptFunction.h"
#include "util/helpers.h"
#include "evaluate/scopedDebugInfoPlugin.h"

namespace ark::es2panda::checker {

static util::StringView InitBuiltin(ETSChecker *checker, std::string_view signature)
{
    const auto varMap = checker->VarBinder()->TopScope()->Bindings();
    const auto iterator = varMap.find(signature);
    ASSERT(iterator != varMap.end());
    auto *var = iterator->second;
    Type *type {nullptr};
    if (var->Declaration()->Node()->IsClassDefinition()) {
        type = checker->BuildBasicClassProperties(var->Declaration()->Node()->AsClassDefinition());
    } else {
        ASSERT(var->Declaration()->Node()->IsTSInterfaceDeclaration());
        type = checker->BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    }
    checker->GetGlobalTypesHolder()->InitializeBuiltin(iterator->first, type);
    return iterator->first;
}

static void SetupFunctionalInterface(ETSObjectType *type)
{
    type->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
    auto *invoke = type->GetOwnProperty<PropertyType::INSTANCE_METHOD>(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME);
    auto *invokeType = invoke->TsType()->AsETSFunctionType();
    ASSERT(invokeType->IsETSArrowType());
    auto *signature = invokeType->CallSignatures()[0];
    signature->AddSignatureFlag(SignatureFlags::FUNCTIONAL_INTERFACE_SIGNATURE);
}

static void SetupBuiltinMember(varbinder::Variable *var)
{
    auto *type = var->TsType();
    if (type == nullptr || !type->IsETSObjectType()) {
        return;
    }
}

// NOLINTNEXTLINE(modernize-avoid-c-arrays)
static constexpr std::string_view BUILTINS_TO_INIT[] = {
    compiler::Signatures::BUILTIN_BOOLEAN_CLASS,
    compiler::Signatures::BUILTIN_BYTE_CLASS,
    compiler::Signatures::BUILTIN_CHAR_CLASS,
    compiler::Signatures::BUILTIN_SHORT_CLASS,
    compiler::Signatures::BUILTIN_INT_CLASS,
    compiler::Signatures::BUILTIN_LONG_CLASS,
    compiler::Signatures::BUILTIN_FLOAT_CLASS,
    compiler::Signatures::BUILTIN_DOUBLE_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION0_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION1_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION2_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION3_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION4_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION5_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION6_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION7_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION8_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION9_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION10_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION11_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION12_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION13_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION14_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION15_CLASS,
    compiler::Signatures::BUILTIN_FUNCTION16_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONN_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION0_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION1_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION2_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION3_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION4_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION5_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION6_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION7_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION8_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION9_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION10_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION11_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION12_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION13_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION14_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION15_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTION16_CLASS,
    compiler::Signatures::BUILTIN_THROWING_FUNCTIONN_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION0_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION1_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION2_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION3_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION4_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION5_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION6_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION7_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION8_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION9_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION10_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION11_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION12_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION13_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION14_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION15_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTION16_CLASS,
    compiler::Signatures::BUILTIN_RETHROWING_FUNCTIONN_CLASS,
};

void ETSChecker::InitializeBuiltins(varbinder::ETSBinder *varbinder)
{
    if (HasStatus(CheckerStatus::BUILTINS_INITIALIZED)) {
        return;
    }

    const auto varMap = varbinder->TopScope()->Bindings();

    auto const objectName = InitBuiltin(this, compiler::Signatures::BUILTIN_OBJECT_CLASS);

    for (auto sig : BUILTINS_TO_INIT) {
        InitBuiltin(this, sig);
    }

    for (size_t id = static_cast<size_t>(GlobalTypeId::ETS_THROWING_FUNCTION0_CLASS), nargs = 0;
         id <= static_cast<size_t>(GlobalTypeId::ETS_THROWING_FUNCTIONN_CLASS); id++, nargs++) {
        auto *type = GetGlobalTypesHolder()
                         ->GlobalFunctionBuiltinType(nargs, ir::ScriptFunctionFlags::THROWS)
                         ->AsETSObjectType();
        SetupFunctionalInterface(type);
    }

    for (size_t id = static_cast<size_t>(GlobalTypeId::ETS_RETHROWING_FUNCTION0_CLASS), nargs = 0;
         id <= static_cast<size_t>(GlobalTypeId::ETS_RETHROWING_FUNCTIONN_CLASS); id++, nargs++) {
        auto *type = GetGlobalTypesHolder()
                         ->GlobalFunctionBuiltinType(nargs, ir::ScriptFunctionFlags::RETHROWS)
                         ->AsETSObjectType();
        SetupFunctionalInterface(type);
        // note(gergocs): type->Interfaces().front() should be the same as the type in throwing functions
        // and adding the functional flag to the interface should be deleted
        type->Interfaces().front()->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
    }

    for (size_t id = static_cast<size_t>(GlobalTypeId::ETS_FUNCTION0_CLASS), nargs = 0;
         id <= static_cast<size_t>(GlobalTypeId::ETS_FUNCTIONN_CLASS); id++, nargs++) {
        auto *type =
            GetGlobalTypesHolder()->GlobalFunctionBuiltinType(nargs, ir::ScriptFunctionFlags::NONE)->AsETSObjectType();
        SetupFunctionalInterface(type);
        // note(gergocs): type->Interfaces().front() should be the same as the type in rethrowing functions
        // and adding the functional flag to the interface should be deleted
        type->Interfaces().front()->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
        type->Interfaces().front()->Interfaces().front()->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
    }

    for (const auto &[name, var] : varMap) {
        (void)name;
        SetupBuiltinMember(var);
    }

    for (const auto &[name, var] : varMap) {
        if (name == objectName) {
            continue;
        }

        if (var->HasFlag(varbinder::VariableFlags::BUILTIN_TYPE)) {
            if (var->TsType() == nullptr) {
                InitializeBuiltin(var, name);
            } else {
                GetGlobalTypesHolder()->InitializeBuiltin(name, var->TsType());
            }
        }
    }

    AddStatus(CheckerStatus::BUILTINS_INITIALIZED);
}

void ETSChecker::InitializeBuiltin(varbinder::Variable *var, const util::StringView &name)
{
    Type *type {nullptr};
    if (var->Declaration()->Node()->IsClassDefinition()) {
        type = BuildBasicClassProperties(var->Declaration()->Node()->AsClassDefinition());
    } else {
        ASSERT(var->Declaration()->Node()->IsTSInterfaceDeclaration());
        type = BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    }
    GetGlobalTypesHolder()->InitializeBuiltin(name, type);
}

bool ETSChecker::StartChecker(varbinder::VarBinder *varbinder, const CompilerOptions &options)
{
    Initialize(varbinder);

    if (options.parseOnly) {
        return false;
    }

    auto *etsBinder = varbinder->AsETSBinder();
    InitializeBuiltins(etsBinder);

    for (auto &entry : etsBinder->DynamicImportVars()) {
        auto &data = entry.second;
        if (data.import->IsPureDynamic()) {
            data.variable->SetTsType(GlobalBuiltinDynamicType(data.import->Language()));
        }
    }

    bool isEvalMode = (debugInfoPlugin_ != nullptr);
    if (UNLIKELY(isEvalMode)) {
        debugInfoPlugin_->PreCheck();
    }

    CheckProgram(Program(), true);

    if (UNLIKELY(isEvalMode)) {
        debugInfoPlugin_->PostCheck();
    }

    BuildDynamicImportClass();

#ifndef NDEBUG
    for (auto *func : varbinder->Functions()) {
        ASSERT(!func->Node()->AsScriptFunction()->Scope()->Name().Empty());
    }
#endif

    if (options.dumpCheckedAst) {
        std::cout << Program()->Dump() << std::endl;
    }

    if (options.etsHasWarnings) {
        CheckWarnings(Program(), options);
    }

    return !ErrorLogger()->IsAnyError();
}

evaluate::ScopedDebugInfoPlugin *ETSChecker::GetDebugInfoPlugin()
{
    return debugInfoPlugin_;
}

const evaluate::ScopedDebugInfoPlugin *ETSChecker::GetDebugInfoPlugin() const
{
    return debugInfoPlugin_;
}

void ETSChecker::SetDebugInfoPlugin(evaluate::ScopedDebugInfoPlugin *debugInfo)
{
    debugInfoPlugin_ = debugInfo;
}

void ETSChecker::CheckProgram(parser::Program *program, bool runAnalysis)
{
    auto *savedProgram = Program();
    SetProgram(program);

    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            checker::SavedCheckerContext savedContext(this, Context().Status(), Context().ContainingClass());
            AddStatus(checker::CheckerStatus::IN_EXTERNAL);
            CheckProgram(extProg, VarBinder()->IsGenStdLib());
        }
    }

    ASSERT(Program()->Ast()->IsProgram());
    Program()->Ast()->Check(this);

    if (ErrorLogger()->IsAnyError()) {
        return;
    }

    if (runAnalysis) {
        AliveAnalyzer aliveAnalyzer(Program()->Ast(), this);
        AssignAnalyzer(this).Analyze(Program()->Ast());
    }

    ASSERT(VarBinder()->AsETSBinder()->GetExternalRecordTable().find(program)->second);

    SetProgram(savedProgram);
}

void ETSChecker::CheckWarnings(parser::Program *program, const CompilerOptions &options)
{
    const auto etsWarningCollection = options.etsWarningCollection;
    for (const auto warning : etsWarningCollection) {
        ETSWarningAnalyzer(Program()->Ast(), program, warning, options.etsWerror);
    }
}

Type *ETSChecker::CheckTypeCached(ir::Expression *expr)
{
    if (expr->TsType() == nullptr) {
        expr->SetTsType(expr->Check(this));
    }

    return expr->TsType();
}

template <typename... Args>
ETSObjectType *ETSChecker::AsETSObjectType(Type *(GlobalTypesHolder::*typeFunctor)(Args...), Args... args) const
{
    auto *ret = (GetGlobalTypesHolder()->*typeFunctor)(args...);
    return ret != nullptr ? ret->AsETSObjectType() : nullptr;
}

Type *ETSChecker::GlobalByteType() const
{
    return GetGlobalTypesHolder()->GlobalByteType();
}

Type *ETSChecker::GlobalShortType() const
{
    return GetGlobalTypesHolder()->GlobalShortType();
}

Type *ETSChecker::GlobalIntType() const
{
    return GetGlobalTypesHolder()->GlobalIntType();
}

Type *ETSChecker::GlobalLongType() const
{
    return GetGlobalTypesHolder()->GlobalLongType();
}

Type *ETSChecker::GlobalFloatType() const
{
    return GetGlobalTypesHolder()->GlobalFloatType();
}

Type *ETSChecker::GlobalDoubleType() const
{
    return GetGlobalTypesHolder()->GlobalDoubleType();
}

Type *ETSChecker::GlobalCharType() const
{
    return GetGlobalTypesHolder()->GlobalCharType();
}

Type *ETSChecker::GlobalETSBooleanType() const
{
    return GetGlobalTypesHolder()->GlobalETSBooleanType();
}

Type *ETSChecker::GlobalVoidType() const
{
    return GetGlobalTypesHolder()->GlobalETSVoidType();
}

Type *ETSChecker::GlobalETSNullType() const
{
    return GetGlobalTypesHolder()->GlobalETSNullType();
}

Type *ETSChecker::GlobalETSUndefinedType() const
{
    return GetGlobalTypesHolder()->GlobalETSUndefinedType();
}

Type *ETSChecker::GlobalETSNeverType() const
{
    return GetGlobalTypesHolder()->GlobalETSNeverType();
}

Type *ETSChecker::GlobalETSStringLiteralType() const
{
    return GetGlobalTypesHolder()->GlobalETSStringLiteralType();
}

Type *ETSChecker::GlobalETSBigIntType() const
{
    return GetGlobalTypesHolder()->GlobalETSBigIntBuiltinType();
}

Type *ETSChecker::GlobalWildcardType() const
{
    return GetGlobalTypesHolder()->GlobalWildcardType();
}

ETSObjectType *ETSChecker::GlobalETSObjectType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalETSObjectType);
}

ETSUnionType *ETSChecker::GlobalETSNullishType() const
{
    auto *ret = (GetGlobalTypesHolder()->*&GlobalTypesHolder::GlobalETSNullishType)();
    return ret != nullptr ? ret->AsETSUnionType() : nullptr;
}

ETSUnionType *ETSChecker::GlobalETSNullishObjectType() const
{
    auto *ret = (GetGlobalTypesHolder()->*&GlobalTypesHolder::GlobalETSNullishObjectType)();
    return ret != nullptr ? ret->AsETSUnionType() : nullptr;
}

ETSObjectType *ETSChecker::GlobalBuiltinETSStringType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalETSStringBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinETSBigIntType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalETSBigIntBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinTypeType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalTypeBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinExceptionType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalExceptionBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinErrorType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalErrorBuiltinType);
}

ETSObjectType *ETSChecker::GlobalStringBuilderBuiltinType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalStringBuilderBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinPromiseType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalPromiseBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinJSRuntimeType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalJSRuntimeBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinJSValueType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalJSValueBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinFunctionType(size_t nargs, ir::ScriptFunctionFlags flags) const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalFunctionBuiltinType, nargs, flags);
}

size_t ETSChecker::GlobalBuiltinFunctionTypeVariadicThreshold() const
{
    return GetGlobalTypesHolder()->VariadicFunctionTypeThreshold();
}

ETSObjectType *ETSChecker::GlobalBuiltinDynamicType(Language lang) const
{
    if (lang.GetId() == Language::Id::JS) {
        return GlobalBuiltinJSValueType();
    }
    return nullptr;
}

ETSObjectType *ETSChecker::GlobalBuiltinBoxType(Type *contents)
{
    switch (TypeKind(contents)) {
        case TypeFlag::ETS_BOOLEAN:
            return AsETSObjectType(&GlobalTypesHolder::GlobalBooleanBoxBuiltinType);
        case TypeFlag::BYTE:
            return AsETSObjectType(&GlobalTypesHolder::GlobalByteBoxBuiltinType);
        case TypeFlag::CHAR:
            return AsETSObjectType(&GlobalTypesHolder::GlobalCharBoxBuiltinType);
        case TypeFlag::SHORT:
            return AsETSObjectType(&GlobalTypesHolder::GlobalShortBoxBuiltinType);
        case TypeFlag::INT:
            return AsETSObjectType(&GlobalTypesHolder::GlobalIntBoxBuiltinType);
        case TypeFlag::LONG:
            return AsETSObjectType(&GlobalTypesHolder::GlobalLongBoxBuiltinType);
        case TypeFlag::FLOAT:
            return AsETSObjectType(&GlobalTypesHolder::GlobalFloatBoxBuiltinType);
        case TypeFlag::DOUBLE:
            return AsETSObjectType(&GlobalTypesHolder::GlobalDoubleBoxBuiltinType);
        default: {
            auto *base = AsETSObjectType(&GlobalTypesHolder::GlobalBoxBuiltinType);
            auto *substitution = NewSubstitution();
            substitution->emplace(base->TypeArguments()[0]->AsETSTypeParameter(), contents);
            return base->Substitute(Relation(), substitution);
        }
    }
}

GlobalArraySignatureMap &ETSChecker::GlobalArrayTypes()
{
    return globalArraySignatures_;
}

const GlobalArraySignatureMap &ETSChecker::GlobalArrayTypes() const
{
    return globalArraySignatures_;
}

Type *ETSChecker::GlobalTypeError() const
{
    return GetGlobalTypesHolder()->GlobalTypeError();
}

Type *ETSChecker::InvalidateType(ir::Typed<ir::AstNode> *node)
{
    node->SetTsType(GlobalTypeError());
    return node->TsType();
}

Type *ETSChecker::TypeError(ir::Typed<ir::AstNode> *node, std::string_view message, const lexer::SourcePosition &at)
{
    LogTypeError(message, at);
    return InvalidateType(node);
}

Type *ETSChecker::TypeError(varbinder::Variable *var, std::string_view message, const lexer::SourcePosition &at)
{
    LogTypeError(message, at);
    var->SetTsType(GlobalTypeError());
    return var->TsType();
}

void ETSChecker::HandleUpdatedCallExpressionNode(ir::CallExpression *callExpr)
{
    VarBinder()->AsETSBinder()->HandleCustomNodes(callExpr);
}

Type *ETSChecker::SelectGlobalIntegerTypeForNumeric(Type *type)
{
    switch (ETSType(type)) {
        case checker::TypeFlag::FLOAT: {
            return GlobalIntType();
        }
        case checker::TypeFlag::DOUBLE: {
            return GlobalLongType();
        }
        default: {
            return type;
        }
    }
}

}  // namespace ark::es2panda::checker
