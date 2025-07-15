/*
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

ETSChecker::ETSChecker(util::DiagnosticEngine &diagnosticEngine)
    // NOLINTNEXTLINE(readability-redundant-member-init)
    : Checker(diagnosticEngine),
      arrayTypes_(Allocator()->Adapter()),
      pendingConstraintCheckRecords_(Allocator()->Adapter()),
      globalArraySignatures_(Allocator()->Adapter()),
      dynamicIntrinsics_ {DynamicCallIntrinsicsMap {Allocator()->Adapter()},
                          DynamicCallIntrinsicsMap {Allocator()->Adapter()}},
      dynamicClasses_ {DynamicClassIntrinsicsMap(Allocator()->Adapter()),
                       DynamicClassIntrinsicsMap(Allocator()->Adapter())},
      dynamicLambdaSignatureCache_(Allocator()->Adapter()),
      functionalInterfaceCache_(Allocator()->Adapter()),
      apparentTypes_(Allocator()->Adapter()),
      dynamicCallNames_ {{DynamicCallNamesMap(Allocator()->Adapter()), DynamicCallNamesMap(Allocator()->Adapter())}},
      overloadSigContainer_(Allocator()->Adapter())
{
}

ETSChecker::ETSChecker(util::DiagnosticEngine &diagnosticEngine, ArenaAllocator *programAllocator)
    // NOLINTNEXTLINE(readability-redundant-member-init)
    : Checker(diagnosticEngine, programAllocator),
      arrayTypes_(Allocator()->Adapter()),
      pendingConstraintCheckRecords_(Allocator()->Adapter()),
      globalArraySignatures_(Allocator()->Adapter()),
      dynamicIntrinsics_ {DynamicCallIntrinsicsMap {Allocator()->Adapter()},
                          DynamicCallIntrinsicsMap {Allocator()->Adapter()}},
      dynamicClasses_ {DynamicClassIntrinsicsMap(Allocator()->Adapter()),
                       DynamicClassIntrinsicsMap(Allocator()->Adapter())},
      dynamicLambdaSignatureCache_(Allocator()->Adapter()),
      functionalInterfaceCache_(Allocator()->Adapter()),
      apparentTypes_(Allocator()->Adapter()),
      dynamicCallNames_ {{DynamicCallNamesMap(Allocator()->Adapter()), DynamicCallNamesMap(Allocator()->Adapter())}},
      overloadSigContainer_(Allocator()->Adapter())
{
}

static util::StringView InitBuiltin(ETSChecker *checker, std::string_view signature)
{
    const auto varMap = checker->VarBinder()->TopScope()->Bindings();
    const auto iterator = varMap.find(signature);
    ES2PANDA_ASSERT(iterator != varMap.end());
    auto *var = iterator->second;
    Type *type {nullptr};
    if (var->HasFlag(varbinder::VariableFlags::BUILTIN_TYPE)) {
        if (var->Declaration()->Node()->IsClassDefinition()) {
            type = checker->BuildBasicClassProperties(var->Declaration()->Node()->AsClassDefinition());
        } else {
            ES2PANDA_ASSERT(var->Declaration()->Node()->IsTSInterfaceDeclaration());
            type = checker->BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
        }
        checker->GetGlobalTypesHolder()->InitializeBuiltin(iterator->first, type);
    }
    return iterator->first;
}

void ETSChecker::CheckObjectLiteralKeys(const ArenaVector<ir::Expression *> &properties)
{
    static std::set<util::StringView> names;
    names.clear();

    for (auto property : properties) {
        if (!property->IsProperty()) {
            continue;
        }
        auto propertyDecl = property->AsProperty();
        auto propKey = propertyDecl->Key();
        if (!propKey->IsIdentifier() && !propKey->IsStringLiteral()) {
            continue;
        }

        // number kind only used here
        auto propName = propKey->IsIdentifier() ? propKey->AsIdentifier()->Name() : propKey->AsStringLiteral()->Str();
        if (names.find(propName) != names.end()) {
            LogError(diagnostic::OBJ_LIT_PROPERTY_REDECLARATION, {}, property->Start());
        }
        names.insert(propName);
    }
}

static void SetupBuiltinMember(varbinder::Variable *var)
{
    auto *type = var->TsType();
    if (type == nullptr || !type->IsETSObjectType()) {
        return;
    }
}

// clang-format off
// NOLINTNEXTLINE(modernize-avoid-c-arrays)
static constexpr std::string_view BUILTINS_TO_INIT[] = {
    compiler::Signatures::BUILTIN_OBJECT_CLASS,
    compiler::Signatures::BUILTIN_STRING_CLASS,
    compiler::Signatures::BUILTIN_BIGINT_CLASS,
    compiler::Signatures::BUILTIN_EXCEPTION_CLASS,
    compiler::Signatures::BUILTIN_ERROR_CLASS,
    compiler::Signatures::BUILTIN_TYPE_CLASS,
    compiler::Signatures::BUILTIN_PROMISE_CLASS,
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
    compiler::Signatures::BUILTIN_LAMBDA0_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA1_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA2_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA3_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA4_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA5_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA6_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA7_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA8_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA9_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA10_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA11_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA12_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA13_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA14_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA15_CLASS,
    compiler::Signatures::BUILTIN_LAMBDA16_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR0_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR1_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR2_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR3_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR4_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR5_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR6_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR7_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR8_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR9_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR10_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR11_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR12_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR13_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR14_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR15_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONR16_CLASS,
    compiler::Signatures::BUILTIN_FUNCTIONN_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR0_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR1_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR2_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR3_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR4_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR5_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR6_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR7_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR8_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR9_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR10_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR11_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR12_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR13_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR14_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR15_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAR16_CLASS,
    compiler::Signatures::BUILTIN_LAMBDAN_CLASS,
    compiler::Signatures::BUILTIN_TUPLE0_CLASS,
    compiler::Signatures::BUILTIN_TUPLE1_CLASS,
    compiler::Signatures::BUILTIN_TUPLE2_CLASS,
    compiler::Signatures::BUILTIN_TUPLE3_CLASS,
    compiler::Signatures::BUILTIN_TUPLE4_CLASS,
    compiler::Signatures::BUILTIN_TUPLE5_CLASS,
    compiler::Signatures::BUILTIN_TUPLE6_CLASS,
    compiler::Signatures::BUILTIN_TUPLE7_CLASS,
    compiler::Signatures::BUILTIN_TUPLE8_CLASS,
    compiler::Signatures::BUILTIN_TUPLE9_CLASS,
    compiler::Signatures::BUILTIN_TUPLE10_CLASS,
    compiler::Signatures::BUILTIN_TUPLE11_CLASS,
    compiler::Signatures::BUILTIN_TUPLE12_CLASS,
    compiler::Signatures::BUILTIN_TUPLE13_CLASS,
    compiler::Signatures::BUILTIN_TUPLE14_CLASS,
    compiler::Signatures::BUILTIN_TUPLE15_CLASS,
    compiler::Signatures::BUILTIN_TUPLE16_CLASS,
    compiler::Signatures::BUILTIN_TUPLEN_CLASS,
};
// clang-format on

static void IntializeFunctionInterfaces(GlobalTypesHolder *typeHolder)
{
    auto const getItf = [typeHolder](size_t arity, bool hasRest) {
        return typeHolder->GlobalFunctionBuiltinType(arity, hasRest)->AsETSObjectType();
    };

    for (size_t arity = 0; arity < typeHolder->VariadicFunctionTypeThreshold(); arity++) {
        getItf(arity, false)->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
        getItf(arity, true)->AddObjectFlag(ETSObjectFlags::FUNCTIONAL);
    }
}

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

    IntializeFunctionInterfaces(GetGlobalTypesHolder());

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
        ES2PANDA_ASSERT(var->Declaration()->Node()->IsTSInterfaceDeclaration());
        type = BuildBasicInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    }
    GetGlobalTypesHolder()->InitializeBuiltin(name, type);
}

bool ETSChecker::StartChecker(varbinder::VarBinder *varbinder, const util::Options &options)
{
    Initialize(varbinder);

    if (options.IsParseOnly()) {
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
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        debugInfoPlugin_->PreCheck();
    }

    CheckProgram(Program(), true);

    if (UNLIKELY(isEvalMode)) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        debugInfoPlugin_->PostCheck();
    }

#ifndef NDEBUG
    for (auto *func : varbinder->Functions()) {
        ES2PANDA_ASSERT(!func->Node()->AsScriptFunction()->Scope()->Name().Empty());
    }
#endif

    if (options.IsDumpDynamicAst()) {
        std::cout << Program()->Dump() << std::endl;
    }

    CheckWarnings(Program(), options);

    return !IsAnyError();
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
    if (program->IsASTChecked()) {
        return;
    }

    auto *savedProgram = Program();
    SetProgram(program);

    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            if (extProg->IsASTChecked()) {
                continue;
            }

            auto *savedProgram2 = VarBinder()->AsETSBinder()->Program();
            VarBinder()->AsETSBinder()->SetProgram(extProg);
            VarBinder()->AsETSBinder()->ResetTopScope(extProg->GlobalScope());
            checker::SavedCheckerContext savedContext(this, Context().Status(), Context().ContainingClass());
            AddStatus(checker::CheckerStatus::IN_EXTERNAL);
            CheckProgram(extProg, VarBinder()->IsGenStdLib());
            extProg->SetFlag(parser::ProgramFlags::AST_CHECK_PROCESSED);
            VarBinder()->AsETSBinder()->SetProgram(savedProgram2);
            VarBinder()->AsETSBinder()->ResetTopScope(savedProgram2->GlobalScope());
        }
    }

    ES2PANDA_ASSERT(Program()->Ast()->IsProgram());

    Program()->Ast()->Check(this);

    if (runAnalysis && !IsAnyError()) {
        AliveAnalyzer aliveAnalyzer(Program()->Ast(), this);
        AssignAnalyzer(this).Analyze(Program()->Ast());
    }

    ES2PANDA_ASSERT(VarBinder()->AsETSBinder()->GetExternalRecordTable().find(program)->second);

    SetProgram(savedProgram);
}

void ETSChecker::CheckWarnings(parser::Program *program, const util::Options &options)
{
    const auto &etsWarningCollection = options.GetEtsWarningCollection();
    for (const auto warning : etsWarningCollection) {
        ETSWarningAnalyzer(Program()->Ast(), program, warning, DiagnosticEngine());
    }
}

Type *ETSChecker::CheckTypeCached(ir::Expression *expr)
{
    if (expr->TsType() == nullptr) {
        expr->SetTsType(expr->Check(this));
    }

    return expr->TsType();
}

bool ETSChecker::IsClassStaticMethod(checker::ETSObjectType *objType, checker::Signature *signature)
{
    return objType->HasObjectFlag(checker::ETSObjectFlags::CLASS) &&
           signature->HasSignatureFlag(checker::SignatureFlags::STATIC);
}

[[nodiscard]] TypeFlag ETSChecker::TypeKind(const Type *const type) noexcept
{
    // These types were not present in the ETS_TYPE list. Some of them are omited intentionally, other are just bugs
    static constexpr auto TO_CLEAR = TypeFlag::CONSTANT | TypeFlag::GENERIC | TypeFlag::ETS_INT_ENUM |
                                     TypeFlag::ETS_STRING_ENUM | TypeFlag::READONLY | TypeFlag::BIGINT_LITERAL |
                                     TypeFlag::ETS_TYPE_ALIAS | TypeFlag::TYPE_ERROR;

    // Bugs: these types do not appear as a valid TypeKind, as the TypeKind has more then one bit set
    [[maybe_unused]] static constexpr auto NOT_A_TYPE_KIND = TypeFlag::ETS_DYNAMIC_FLAG;
    CHECK_NOT_NULL(type);
    auto res = static_cast<checker::TypeFlag>(type->TypeFlags() & ~(TO_CLEAR));
    ES2PANDA_ASSERT_POS(res == TypeFlag::NONE || helpers::math::IsPowerOfTwo(res & ~(NOT_A_TYPE_KIND)),
                        ark::es2panda::GetPositionForDiagnostic());
    return res;
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

Type *ETSChecker::GlobalByteBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalByteBuiltinType();
}

Type *ETSChecker::GlobalShortType() const
{
    return GetGlobalTypesHolder()->GlobalShortType();
}

Type *ETSChecker::GlobalShortBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalShortBuiltinType();
}

Type *ETSChecker::GlobalIntType() const
{
    return GetGlobalTypesHolder()->GlobalIntType();
}

Type *ETSChecker::GlobalIntBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalIntegerBuiltinType();
}

Type *ETSChecker::GlobalLongType() const
{
    return GetGlobalTypesHolder()->GlobalLongType();
}

Type *ETSChecker::GlobalLongBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalLongBuiltinType();
}

Type *ETSChecker::GlobalFloatType() const
{
    return GetGlobalTypesHolder()->GlobalFloatType();
}

Type *ETSChecker::GlobalFloatBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalFloatBuiltinType();
}

Type *ETSChecker::GlobalDoubleType() const
{
    return GetGlobalTypesHolder()->GlobalDoubleType();
}

Type *ETSChecker::GlobalDoubleBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalDoubleBuiltinType();
}

Type *ETSChecker::GlobalCharType() const
{
    return GetGlobalTypesHolder()->GlobalCharType();
}
Type *ETSChecker::GlobalCharBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalCharBuiltinType();
}

Type *ETSChecker::GlobalETSBooleanType() const
{
    return GetGlobalTypesHolder()->GlobalETSBooleanType();
}

Type *ETSChecker::GlobalETSBooleanBuiltinType() const
{
    return GetGlobalTypesHolder()->GlobalETSBooleanBuiltinType();
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

Type *ETSChecker::GlobalETSAnyType() const
{
    return GetGlobalTypesHolder()->GlobalETSAnyType();
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

ETSUnionType *ETSChecker::GlobalETSUnionUndefinedNull() const
{
    auto *ret = (GetGlobalTypesHolder()->*&GlobalTypesHolder::GlobalETSUnionUndefinedNull)();
    return ret != nullptr ? ret->AsETSUnionType() : nullptr;
}

ETSUnionType *ETSChecker::GlobalETSUnionUndefinedNullObject() const
{
    auto *ret = (GetGlobalTypesHolder()->*&GlobalTypesHolder::GlobalETSUnionUndefinedNullObject)();
    return ret != nullptr ? ret->AsETSUnionType() : nullptr;
}

ETSObjectType *ETSChecker::GlobalBuiltinETSResizableArrayType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalArrayBuiltinType);
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

ETSObjectType *ETSChecker::GlobalBuiltinFunctionType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalFunctionBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinJSRuntimeType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalJSRuntimeBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinJSValueType() const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalJSValueBuiltinType);
}

ETSObjectType *ETSChecker::GlobalBuiltinFunctionType(size_t nargs, bool hasRest) const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalFunctionBuiltinType, nargs, hasRest);
}

ETSObjectType *ETSChecker::GlobalBuiltinLambdaType(size_t nargs, bool hasRest) const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalLambdaBuiltinType, nargs, hasRest);
}

ETSObjectType *ETSChecker::GlobalBuiltinTupleType(size_t nargs) const
{
    return AsETSObjectType(&GlobalTypesHolder::GlobalTupleBuiltinType, nargs);
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
            ES2PANDA_ASSERT(base != nullptr);
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
    return node->SetTsType(GlobalTypeError());
}

Type *ETSChecker::TypeError(ir::Typed<ir::AstNode> *node, const diagnostic::DiagnosticKind &diagKind,
                            const lexer::SourcePosition &at)
{
    return TypeError(node, diagKind, util::DiagnosticMessageParams {}, at);
}

Type *ETSChecker::TypeError(ir::Typed<ir::AstNode> *node, const diagnostic::DiagnosticKind &diagKind,
                            const util::DiagnosticMessageParams &list, const lexer::SourcePosition &at)
{
    LogError(diagKind, list, at);
    return InvalidateType(node);
}

Type *ETSChecker::TypeError(varbinder::Variable *var, const diagnostic::DiagnosticKind &diagKind,
                            const lexer::SourcePosition &at)
{
    return TypeError(var, diagKind, {}, at);
}

Type *ETSChecker::TypeError(varbinder::Variable *var, const diagnostic::DiagnosticKind &diagKind,
                            const util::DiagnosticMessageParams &list, const lexer::SourcePosition &at)
{
    LogError(diagKind, list, at);
    var->SetTsType(GlobalTypeError());
    return var->TsType();
}

void ETSChecker::HandleUpdatedCallExpressionNode(ir::CallExpression *callExpr)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
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

Signature *ETSChecker::FindExtensionSetterInMap(util::StringView name, ETSObjectType *type)
{
    return GetGlobalTypesHolder()->FindExtensionSetterInMap(name, type);
}

Signature *ETSChecker::FindExtensionGetterInMap(util::StringView name, ETSObjectType *type)
{
    return GetGlobalTypesHolder()->FindExtensionGetterInMap(name, type);
}

void ETSChecker::InsertExtensionSetterToMap(util::StringView name, ETSObjectType *type, Signature *sig)
{
    GetGlobalTypesHolder()->InsertExtensionSetterToMap(name, type, sig);
}

void ETSChecker::InsertExtensionGetterToMap(util::StringView name, ETSObjectType *type, Signature *sig)
{
    GetGlobalTypesHolder()->InsertExtensionGetterToMap(name, type, sig);
}
}  // namespace ark::es2panda::checker
