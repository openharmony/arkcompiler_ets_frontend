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

#include "ETSGen.h"
#include "ETSGen-inl.h"

#include "generated/signatures.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classDefinition.h"
#include "ir/statement.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "varbinder/variableFlags.h"
#include "compiler/base/lreference.h"
#include "compiler/base/catchTable.h"
#include "compiler/core/dynamicContext.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"
#include "checker/types/type.h"
#include "checker/types/typeFlag.h"
#include "checker/checker.h"
#include "checker/ETSchecker.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/types/ets/etsTupleType.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"
#include "parser/program/program.h"
#include "checker/types/globalTypesHolder.h"
#include "public/public.h"

namespace ark::es2panda::compiler {

static inline bool IsWidePrimitiveType(checker::Type const *type)
{
    return type->IsLongType() || type->IsDoubleType();
}

ETSGen::ETSGen(ArenaAllocator *allocator, RegSpiller *spiller, public_lib::Context *context,
               std::tuple<varbinder::FunctionScope *, ProgramElement *, AstCompiler *> toCompile) noexcept
    : CodeGen(allocator, spiller, context, toCompile),
      containingObjectType_(util::Helpers::GetContainingObjectType(RootNode()))
{
    ETSFunction::Compile(this);
}

void ETSGen::SetAccumulatorType(const checker::Type *type)
{
    SetVRegType(acc_, type);
}

const checker::Type *ETSGen::GetAccumulatorType() const
{
    return GetVRegType(acc_);
}

void ETSGen::CompileAndCheck(const ir::Expression *expr)
{
    // NOTE: vpukhov. bad accumulator type leads to terrible bugs in codegen
    // make exact types match mandatory
    expr->Compile(this);

    auto const *const accType = GetAccumulatorType();
    auto const *const exprType = expr->TsType();

    if (Checker()->Relation()->IsIdenticalTo(accType, exprType) || exprType->IsETSTypeParameter() ||
        exprType->IsETSPartialTypeParameter() || exprType->IsETSNonNullishType()) {
        return;
    }

    ES2PANDA_ASSERT(accType != nullptr);
    if (accType->IsETSPrimitiveType() &&
        ((accType->TypeFlags() ^ exprType->TypeFlags()) & ~checker::TypeFlag::CONSTANT) == 0) {
        return;
    }

    ASSERT_PRINT(false, std::string("Type mismatch after Expression::Compile: ") + accType->ToString() +
                            " instead of " + exprType->ToString());
}

const checker::ETSChecker *ETSGen::Checker() const noexcept
{
    return Context()->checker->AsETSChecker();
}

const varbinder::ETSBinder *ETSGen::VarBinder() const noexcept
{
    return Context()->parserProgram->VarBinder()->AsETSBinder();
}

const checker::Type *ETSGen::ReturnType() const noexcept
{
    return RootNode()->AsScriptFunction()->Signature()->ReturnType();
}

const checker::ETSObjectType *ETSGen::ContainingObjectType() const noexcept
{
    return containingObjectType_;
}

VReg &ETSGen::Acc() noexcept
{
    return acc_;
}

VReg ETSGen::Acc() const noexcept
{
    return acc_;
}

void ETSGen::ApplyConversionAndStoreAccumulator(const ir::AstNode *const node, const VReg vreg,
                                                const checker::Type *const targetType)
{
    ApplyConversion(node, targetType);
    StoreAccumulator(node, vreg);
}

VReg ETSGen::StoreException(const ir::AstNode *node)
{
    VReg exception = AllocReg();
    Ra().Emit<StaObj>(node, exception);

    SetAccumulatorType(Checker()->GlobalBuiltinExceptionType());
    SetVRegType(exception, GetAccumulatorType());
    return exception;
}

void ETSGen::StoreAccumulator(const ir::AstNode *const node, const VReg vreg)
{
    const auto *const accType = GetAccumulatorType();

    ES2PANDA_ASSERT(accType != nullptr);
    if (accType->IsETSReferenceType()) {
        Ra().Emit<StaObj>(node, vreg);
    } else if (IsWidePrimitiveType(accType)) {
        Ra().Emit<StaWide>(node, vreg);
    } else {
        Ra().Emit<Sta>(node, vreg);
    }

    SetVRegType(vreg, accType);
}

void ETSGen::LoadAccumulator(const ir::AstNode *node, VReg vreg)
{
    const auto *const vregType = GetVRegType(vreg);

    ES2PANDA_ASSERT(vregType != nullptr);
    if (vregType->IsETSReferenceType()) {
        Ra().Emit<LdaObj>(node, vreg);
    } else if (IsWidePrimitiveType(vregType)) {
        Ra().Emit<LdaWide>(node, vreg);
    } else {
        Ra().Emit<Lda>(node, vreg);
    }

    SetAccumulatorType(vregType);
}

IRNode *ETSGen::AllocMov(const ir::AstNode *const node, const VReg vd, const VReg vs)
{
    const auto *const sourceType = GetVRegType(vs);
    // CC-OFFNXT(G.FMT.14-CPP) project code style
    auto *const mov = [this, sourceType, node, vd, vs]() -> IRNode * {
        if (sourceType->IsETSReferenceType()) {
            return Allocator()->New<MovObj>(node, vd, vs);
        }
        if (IsWidePrimitiveType(sourceType)) {
            return Allocator()->New<MovWide>(node, vd, vs);
        }
        return Allocator()->New<Mov>(node, vd, vs);
    }();

    SetVRegType(vd, sourceType);
    return mov;
}

IRNode *ETSGen::AllocMov(const ir::AstNode *const node, OutVReg vd, const VReg vs)
{
    ES2PANDA_ASSERT(vd.type != OperandType::ANY && vd.type != OperandType::NONE);

    switch (vd.type) {
        case OperandType::REF:
            return Allocator()->New<MovObj>(node, *vd.reg, vs);
        case OperandType::B64:
            return Allocator()->New<MovWide>(node, *vd.reg, vs);
        default:
            break;
    }

    return Allocator()->New<Mov>(node, *vd.reg, vs);
}

checker::Type const *ETSGen::TypeForVar(varbinder::Variable const *var) const noexcept
{
    return var->TsType();
}

void ETSGen::MoveVreg(const ir::AstNode *const node, const VReg vd, const VReg vs)
{
    const auto *const sourceType = GetVRegType(vs);
    ES2PANDA_ASSERT(sourceType != nullptr);

    if (sourceType->IsETSReferenceType()) {
        Ra().Emit<MovObj>(node, vd, vs);
    } else if (IsWidePrimitiveType(sourceType)) {
        Ra().Emit<MovWide>(node, vd, vs);
    } else {
        Ra().Emit<Mov>(node, vd, vs);
    }

    SetVRegType(vd, sourceType);
}

// indicates that initializer is meaningless and may lead to NPEs
void ETSGen::LoadAccumulatorPoison(const ir::AstNode *node, const checker::Type *type)
{
    ES2PANDA_ASSERT(type->IsETSReferenceType());
    LoadAccumulatorUndefined(node);
    SetAccumulatorType(type);
}

util::StringView ETSGen::FormDynamicModulePropReference(const varbinder::Variable *var)
{
    ES2PANDA_ASSERT(VarBinder()->IsDynamicModuleVariable(var) || VarBinder()->IsDynamicNamespaceVariable(var));

    auto *data = VarBinder()->DynamicImportDataForVar(var);
    ES2PANDA_ASSERT(data != nullptr);

    auto *import = data->import;

    return FormDynamicModulePropReference(import);
}

void ETSGen::LoadAccumulatorDynamicModule(const ir::AstNode *node, const ir::ETSImportDeclaration *import)
{
    ES2PANDA_ASSERT(import->Language().IsDynamic());
    LoadStaticProperty(node, Checker()->GlobalBuiltinDynamicType(import->Language()),
                       FormDynamicModulePropReference(import));
}

util::StringView ETSGen::FormDynamicModulePropReference(const ir::ETSImportDeclaration *import)
{
    std::stringstream ss;
    ss << VarBinder()->Program()->ModulePrefix();
    ss << compiler::Signatures::DYNAMIC_MODULE_CLASS;
    ss << '.';
    ss << import->AssemblerName();
    return util::UString(ss.str(), Allocator()).View();
}

void ETSGen::LoadDynamicModuleVariable(const ir::AstNode *node, varbinder::Variable const *const var)
{
    RegScope rs(this);

    auto *data = VarBinder()->DynamicImportDataForVar(var);
    ES2PANDA_ASSERT(data != nullptr);

    auto *import = data->import;

    LoadStaticProperty(node, var->TsType(), FormDynamicModulePropReference(var));

    auto objReg = AllocReg();
    StoreAccumulator(node, objReg);

    auto *id = data->specifier->AsImportSpecifier()->Imported();
    auto lang = import->Language();
    LoadPropertyDynamic(node, Checker()->GlobalBuiltinDynamicType(lang), objReg, id->Name());

    ApplyConversion(node);
}

void ETSGen::LoadDynamicNamespaceVariable(const ir::AstNode *node, varbinder::Variable const *const var)
{
    LoadStaticProperty(node, var->TsType(), FormDynamicModulePropReference(var));
}

void ETSGen::LoadVar(const ir::Identifier *node, varbinder::Variable const *const var)
{
    if (VarBinder()->IsDynamicModuleVariable(var)) {
        LoadDynamicModuleVariable(node, var);
        return;
    }

    if (VarBinder()->IsDynamicNamespaceVariable(var)) {
        LoadDynamicNamespaceVariable(node, var);
        return;
    }

    auto *local = var->AsLocalVariable();

    switch (ETSLReference::ResolveReferenceKind(var)) {
        case ReferenceKind::STATIC_FIELD: {
            auto fullName = FormClassPropReference(var);
            LoadStaticProperty(node, var->TsType(), fullName);
            break;
        }
        case ReferenceKind::FIELD: {
            ES2PANDA_ASSERT(GetVRegType(GetThisReg()) != nullptr);
            const auto fullName = FormClassPropReference(GetVRegType(GetThisReg())->AsETSObjectType(), var->Name());
            LoadProperty(node, var->TsType(), GetThisReg(), fullName);
            break;
        }
        case ReferenceKind::METHOD:
        case ReferenceKind::STATIC_METHOD:
        case ReferenceKind::CLASS:
        case ReferenceKind::STATIC_CLASS: {
            SetAccumulatorType(var->TsType());
            break;
        }
        case ReferenceKind::LOCAL: {
            LoadAccumulator(node, local->Vreg());
            SetAccumulatorType(GetVRegType(local->Vreg()));
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::StoreVar(const ir::Identifier *node, const varbinder::ConstScopeFindResult &result)
{
    auto *local = result.variable->AsLocalVariable();
    ApplyConversion(node, local->TsType());

    switch (ETSLReference::ResolveReferenceKind(result.variable)) {
        case ReferenceKind::STATIC_FIELD: {
            auto fullName = FormClassPropReference(result.variable);
            StoreStaticProperty(node, result.variable->TsType(), fullName);
            break;
        }
        case ReferenceKind::FIELD: {
            StoreProperty(node, result.variable->TsType(), GetThisReg(), result.name);
            break;
        }
        case ReferenceKind::LOCAL: {
            StoreAccumulator(node, local->Vreg());
            SetVRegType(local->Vreg(), GetAccumulatorType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

util::StringView ETSGen::FormClassPropReference(const checker::ETSObjectType *classType, const util::StringView &name)
{
    std::stringstream ss;
    ES2PANDA_ASSERT(classType != nullptr);
    ss << classType->AssemblerName().Mutf8() << Signatures::METHOD_SEPARATOR << name;
    return util::StringView(*ProgElement()->Strings().emplace(ss.str()).first);
}

util::StringView ETSGen::FormClassPropReference(varbinder::Variable const *const var)
{
    auto containingObjectType = util::Helpers::GetContainingObjectType(var->Declaration()->Node());
    return FormClassPropReference(containingObjectType, var->Name());
}

void ETSGen::StoreStaticOwnProperty(const ir::AstNode *node, const checker::Type *propType,
                                    const util::StringView &name)
{
    util::StringView fullName = FormClassPropReference(containingObjectType_, name);
    StoreStaticProperty(node, propType, fullName);
}

void ETSGen::StoreStaticProperty(const ir::AstNode *const node, const checker::Type *propType,
                                 const util::StringView &fullName)
{
    if (propType->IsETSReferenceType()) {
        Sa().Emit<StstaticObj>(node, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Sa().Emit<StstaticWide>(node, fullName);
    } else {
        Sa().Emit<Ststatic>(node, fullName);
    }
}

void ETSGen::LoadStaticProperty(const ir::AstNode *const node, const checker::Type *propType,
                                const util::StringView &fullName)
{
    ES2PANDA_ASSERT(propType != nullptr);
    if (propType->IsETSReferenceType()) {
        Sa().Emit<LdstaticObj>(node, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Sa().Emit<LdstaticWide>(node, fullName);
    } else {
        Sa().Emit<Ldstatic>(node, fullName);
    }

    SetAccumulatorType(propType);
}

void ETSGen::StoreProperty(const ir::AstNode *const node, const checker::Type *propType, const VReg objReg,
                           const util::StringView &name)
{
    ES2PANDA_ASSERT(Checker()->GetApparentType(GetVRegType(objReg)) != nullptr);
    auto *objType = Checker()->GetApparentType(GetVRegType(objReg))->AsETSObjectType();
    const auto fullName = FormClassPropReference(objType, name);

    if (propType->IsETSReferenceType()) {
        Ra().Emit<StobjObj>(node, objReg, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Ra().Emit<StobjWide>(node, objReg, fullName);
    } else {
        Ra().Emit<Stobj>(node, objReg, fullName);
    }
}

void ETSGen::LoadProperty(const ir::AstNode *const node, const checker::Type *propType, const VReg objReg,
                          const util::StringView &fullName)
{
    if (propType->IsETSReferenceType()) {
        Ra().Emit<LdobjObj>(node, objReg, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Ra().Emit<LdobjWide>(node, objReg, fullName);
    } else {
        Ra().Emit<Ldobj>(node, objReg, fullName);
    }

    SetAccumulatorType(propType);
}

void ETSGen::StorePropertyByName([[maybe_unused]] const ir::AstNode *node, [[maybe_unused]] VReg objReg,
                                 [[maybe_unused]] checker::ETSChecker::NamedAccessMeta const &fieldMeta)
{
#ifdef PANDA_WITH_ETS
    auto [metaObj, propType, propName] = fieldMeta;
    const auto fullName = FormClassPropReference(metaObj, propName);

    if (propType->IsETSReferenceType()) {
        Ra().Emit<EtsStobjNameObj>(node, objReg, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Ra().Emit<EtsStobjNameWide>(node, objReg, fullName);
    } else {
        Ra().Emit<EtsStobjName>(node, objReg, fullName);
    }
#else
    ES2PANDA_UNREACHABLE();
#endif  // PANDA_WITH_ETS
}

void ETSGen::LoadPropertyByName([[maybe_unused]] const ir::AstNode *const node, [[maybe_unused]] VReg objReg,
                                [[maybe_unused]] checker::ETSChecker::NamedAccessMeta const &fieldMeta)
{
#ifdef PANDA_WITH_ETS
    auto [metaObj, propType, propName] = fieldMeta;
    const auto fullName = FormClassPropReference(metaObj, propName);

    if (propType->IsETSReferenceType()) {
        Ra().Emit<EtsLdobjNameObj>(node, objReg, fullName);
    } else if (IsWidePrimitiveType(propType)) {
        Ra().Emit<EtsLdobjNameWide>(node, objReg, fullName);
    } else {
        Ra().Emit<EtsLdobjName>(node, objReg, fullName);
    }
    SetAccumulatorType(propType);
#else
    ES2PANDA_UNREACHABLE();
#endif  // PANDA_WITH_ETS
}

void ETSGen::StorePropertyDynamic(const ir::AstNode *node, const checker::Type *propType, VReg objReg,
                                  const util::StringView &propName)
{
    ES2PANDA_ASSERT(GetVRegType(objReg) != nullptr);
    auto const lang = GetVRegType(objReg)->AsETSDynamicType()->Language();
    std::string_view methodName {};
    if (propType->IsETSBooleanType()) {
        methodName = Signatures::Dynamic::SetPropertyBooleanBuiltin(lang);
    } else if (propType->IsByteType()) {
        methodName = Signatures::Dynamic::SetPropertyByteBuiltin(lang);
    } else if (propType->IsCharType()) {
        methodName = Signatures::Dynamic::SetPropertyCharBuiltin(lang);
    } else if (propType->IsShortType()) {
        methodName = Signatures::Dynamic::SetPropertyShortBuiltin(lang);
    } else if (propType->IsIntType()) {
        methodName = Signatures::Dynamic::SetPropertyIntBuiltin(lang);
    } else if (propType->IsLongType()) {
        methodName = Signatures::Dynamic::SetPropertyLongBuiltin(lang);
    } else if (propType->IsFloatType()) {
        methodName = Signatures::Dynamic::SetPropertyFloatBuiltin(lang);
    } else if (propType->IsDoubleType()) {
        methodName = Signatures::Dynamic::SetPropertyDoubleBuiltin(lang);
    } else if (propType->IsETSStringType()) {
        methodName = Signatures::Dynamic::SetPropertyStringBuiltin(lang);
    } else if (propType->IsETSObjectType() || propType->IsETSTypeParameter()) {
        methodName = Signatures::Dynamic::SetPropertyDynamicBuiltin(lang);
        // NOTE: vpukhov. add non-dynamic builtin
        if (!propType->IsETSDynamicType()) {
            CastToDynamic(node, Checker()->GlobalBuiltinDynamicType(lang)->AsETSDynamicType());
        }
    } else {
        ASSERT_PRINT(false, "Unsupported property type");
    }

    RegScope rs(this);
    VReg propValueReg = AllocReg();
    VReg propNameReg = AllocReg();

    StoreAccumulator(node, propValueReg);

    // Load property name
    LoadAccumulatorString(node, propName);
    StoreAccumulator(node, propNameReg);

    // Set property by name
    Ra().Emit<Call, 3U>(node, methodName, objReg, propNameReg, propValueReg, dummyReg_);
    SetAccumulatorType(Checker()->GlobalBuiltinJSValueType());
}

void ETSGen::LoadPropertyDynamic(const ir::AstNode *node, const checker::Type *propType, VReg objReg,
                                 std::variant<util::StringView, const ark::es2panda::ir::Expression *> property)
{
    ES2PANDA_ASSERT(propType != nullptr && GetVRegType(objReg) != nullptr);
    auto const lang = GetVRegType(objReg)->AsETSDynamicType()->Language();
    auto *type = propType;
    std::string_view methodName {};
    if (propType->IsETSBooleanType()) {
        methodName = Signatures::Dynamic::GetPropertyBooleanBuiltin(lang);
    } else if (propType->IsByteType()) {
        methodName = Signatures::Dynamic::GetPropertyByteBuiltin(lang);
    } else if (propType->IsCharType()) {
        methodName = Signatures::Dynamic::GetPropertyCharBuiltin(lang);
    } else if (propType->IsShortType()) {
        methodName = Signatures::Dynamic::GetPropertyShortBuiltin(lang);
    } else if (propType->IsIntType()) {
        methodName = Signatures::Dynamic::GetPropertyIntBuiltin(lang);
    } else if (propType->IsLongType()) {
        methodName = Signatures::Dynamic::GetPropertyLongBuiltin(lang);
    } else if (propType->IsFloatType()) {
        methodName = Signatures::Dynamic::GetPropertyFloatBuiltin(lang);
    } else if (propType->IsDoubleType()) {
        methodName = Signatures::Dynamic::GetPropertyDoubleBuiltin(lang);
    } else if (propType->IsETSStringType()) {
        methodName = Signatures::Dynamic::GetPropertyStringBuiltin(lang);
    } else if (propType->IsETSObjectType() || propType->IsETSTypeParameter()) {
        methodName = Signatures::Dynamic::GetPropertyDynamicBuiltin(lang);
        type = Checker()->GlobalBuiltinDynamicType(lang);
    } else {
        ASSERT_PRINT(false, "Unsupported property type");
    }

    RegScope rs(this);

    VReg propNameObject;

    if (node->IsMemberExpression() && node->AsMemberExpression()->IsComputed()) {
        (std::get<const ark::es2panda::ir::Expression *>(property))->Compile(this);
    } else {
        // Load property name
        LoadAccumulatorString(node, std::get<util::StringView>(property));
    }

    propNameObject = AllocReg();
    StoreAccumulator(node, propNameObject);

    // Get property
    Ra().Emit<CallShort, 2U>(node, methodName, objReg, propNameObject);

    SetAccumulatorType(type);

    if (propType != type && !propType->IsETSDynamicType()) {
        CastDynamicToObject(node, propType);
    }
}

void ETSGen::StoreElementDynamic(const ir::AstNode *node, VReg objectReg, VReg index)
{
    ES2PANDA_ASSERT(GetVRegType(objectReg) != nullptr);
    auto const lang = GetVRegType(objectReg)->AsETSDynamicType()->Language();
    std::string_view methodName = Signatures::Dynamic::SetElementDynamicBuiltin(lang);

    RegScope rs(this);

    VReg valueReg = AllocReg();
    StoreAccumulator(node, valueReg);

    // Set property by index
    Ra().Emit<Call, 3U>(node, methodName, objectReg, index, valueReg, dummyReg_);
    SetAccumulatorType(Checker()->GlobalVoidType());
}

void ETSGen::LoadElementDynamic(const ir::AstNode *node, VReg objectReg)
{
    ES2PANDA_ASSERT(GetVRegType(objectReg) != nullptr);
    auto const lang = GetVRegType(objectReg)->AsETSDynamicType()->Language();
    std::string_view methodName = Signatures::Dynamic::GetElementDynamicBuiltin(lang);

    RegScope rs(this);

    VReg indexReg = AllocReg();
    StoreAccumulator(node, indexReg);

    // Get property by index
    Ra().Emit<CallShort, 2U>(node, methodName, objectReg, indexReg);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(lang));
}

void ETSGen::CallRangeFillUndefined(const ir::AstNode *const node, checker::Signature *const signature,
                                    const VReg thisReg)
{
    RegScope rs(this);
    ES2PANDA_ASSERT(signature->MinArgCount() == 0);

    auto undef = AllocReg();
    LoadAccumulatorUndefined(node);
    StoreAccumulator(node, undef);

    VReg const argStart = NextReg();
    Ra().Emit<MovObj>(node, AllocReg(), thisReg);

    for (size_t idx = 0; idx < signature->ArgCount(); idx++) {
        Ra().Emit<MovObj>(node, AllocReg(), undef);
    }
    Rra().Emit<CallRange>(node, argStart, signature->ArgCount() + 1, signature->InternalName(), argStart);
}

void ETSGen::LoadUndefinedDynamic(const ir::AstNode *node, Language lang)
{
    RegScope rs(this);
    Ra().Emit<CallShort, 0>(node, Signatures::Dynamic::GetUndefinedBuiltin(lang), dummyReg_, dummyReg_);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(lang));
}

void ETSGen::LoadThis(const ir::AstNode *node)
{
    LoadAccumulator(node, GetThisReg());
}

void ETSGen::CreateBigIntObject(const ir::AstNode *node, VReg arg0, std::string_view signature)
{
    Ra().Emit<InitobjShort>(node, signature, arg0, dummyReg_);
}

VReg ETSGen::GetThisReg() const
{
    const auto res = Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS);
    return res.variable->AsLocalVariable()->Vreg();
}

const checker::Type *ETSGen::LoadDefaultValue(const ir::AstNode *node, const checker::Type *type)
{
    if (type->IsETSAsyncFuncReturnType()) {
        LoadDefaultValue(node, type->AsETSAsyncFuncReturnType()->GetPromiseTypeArg());
        return type;
    }

    auto const checker = const_cast<checker::ETSChecker *>(Checker());

    if (type->IsETSReferenceType()) {
        if (checker->Relation()->IsSupertypeOf(type, checker->GlobalETSUndefinedType())) {
            LoadAccumulatorUndefined(node);
        } else {
            LoadAccumulatorPoison(node, type);
        }
        return type;
    }

    if (type->IsETSBooleanType()) {
        LoadAccumulatorBoolean(node, type->AsETSBooleanType()->GetValue());
    } else {
        const auto ttctx = TargetTypeContext(this, type);
        LoadAccumulatorInt(node, 0);
    }
    return type;
}

void ETSGen::EmitReturnVoid(const ir::AstNode *node)
{
    Sa().Emit<ReturnVoid>(node);
}

void ETSGen::ReturnAcc(const ir::AstNode *node)
{
    const auto *const accType = GetAccumulatorType();
    ES2PANDA_ASSERT(accType != nullptr);

    if (accType->IsETSReferenceType()) {
        Sa().Emit<ReturnObj>(node);
    } else if (IsWidePrimitiveType(accType)) {
        Sa().Emit<ReturnWide>(node);
    } else {
        Sa().Emit<Return>(node);
    }
}

static bool IsNullUnsafeObjectType(checker::Type const *type)
{
    ES2PANDA_ASSERT(type != nullptr);
    return type->IsETSObjectType() && type->AsETSObjectType()->IsGlobalETSObjectType();
}

void ETSGen::IsInstanceDynamic(const ir::BinaryExpression *const node, const VReg srcReg,
                               [[maybe_unused]] const VReg tgtReg)
{
    ES2PANDA_ASSERT(node->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF);
    const checker::Type *lhsType = node->Left()->TsType();
    const checker::Type *rhsType = node->Right()->TsType();
    ES2PANDA_ASSERT(rhsType->IsETSDynamicType() || lhsType->IsETSDynamicType());

    const RegScope rs(this);
    if (rhsType->IsETSDynamicType()) {
        ES2PANDA_ASSERT(node->Right()->TsType()->AsETSDynamicType()->HasDecl());
        if (lhsType->IsETSDynamicType()) {
            VReg dynTypeReg = MoveAccToReg(node);
            // Semantics:
            //      let dyn_val: JSValue = ...
            //      dyn_value instanceof DynamicDecl
            // Bytecode:
            //      call runtime intrinsic_dynamic
            CallExact(node, Signatures::BUILTIN_JSRUNTIME_INSTANCE_OF_DYNAMIC, srcReg, dynTypeReg);
        } else if (lhsType == Checker()->GlobalETSObjectType()) {
            // Semantics:
            //      let obj: Object = ...
            //      obj instanceof DynamicDecl
            // Bytecode:
            //      if isinstance <dynamic type name>:
            //          checkcast <dynamic type name>
            //          return call runtime intrinsic_dynamic
            //      return false
            Label *ifFalse = AllocLabel();
            Language lang = rhsType->AsETSDynamicType()->Language();
            ES2PANDA_ASSERT(Checker()->GlobalBuiltinDynamicType(lang) != nullptr);
            VReg dynTypeReg = MoveAccToReg(node);
            LoadAccumulator(node, srcReg);
            EmitIsInstance(node, Checker()->GlobalBuiltinDynamicType(lang)->AssemblerName());
            BranchIfFalse(node, ifFalse);
            LoadAccumulator(node, srcReg);
            EmitCheckCast(node, Checker()->GlobalBuiltinDynamicType(lang)->AssemblerName());
            CallExact(node, Signatures::BUILTIN_JSRUNTIME_INSTANCE_OF_DYNAMIC, srcReg, dynTypeReg);
            SetLabel(node, ifFalse);
        } else {
            // Semantics:
            //      let obj: EtsType = ...
            //      obj instanceof DynamicDecl
            // Bytecode:
            //      False
            Sa().Emit<Ldai>(node, 0);
        }
    } else {
        if (lhsType->IsETSDynamicType()) {
            if (rhsType == Checker()->GlobalETSObjectType()) {
                // Semantics:
                //      let dyn_val: JSValue = ...
                //      dyn_val instanceof Object
                // Bytecode:
                //      True
                Sa().Emit<Ldai>(node, 1);
            } else {
                // Semantics:
                //      let dyn_val: JSValue = ...
                //      dyn_val instanceof EtsType
                // Bytecode:
                //      lda.type + call runtime instrinsic_static
                Sa().Emit<LdaType>(node, rhsType->AsETSObjectType()->AssemblerName());
                VReg typeReg = MoveAccToReg(node);
                CallExact(node, Signatures::BUILTIN_JSRUNTIME_INSTANCE_OF_STATIC, srcReg, typeReg);
            }
        } else {
            ES2PANDA_UNREACHABLE();
        }
    }
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

// Implemented on top of the runtime type system, do not relax checks, do not introduce new types
void ETSGen::TestIsInstanceConstituent(const ir::AstNode *const node, std::tuple<Label *, Label *> label,
                                       checker::Type const *target, bool acceptNull)
{
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(!target->IsETSDynamicType());
    auto [ifTrue, ifFalse] = label;

    switch (checker::ETSChecker::ETSType(target)) {
        case checker::TypeFlag::ETS_UNDEFINED:
        case checker::TypeFlag::ETS_VOID:
            BranchIfUndefined(node, ifTrue);
            break;
        case checker::TypeFlag::ETS_NULL:
            BranchIfNull(node, ifTrue);
            break;
        case checker::TypeFlag::ETS_OBJECT:
            if (!IsNullUnsafeObjectType(target)) {
                EmitIsInstance(node, ToAssemblerType(target));
                BranchIfTrue(node, ifTrue);
                break;
            }
            if (!acceptNull) {
                BranchIfNull(node, ifFalse);
            }
            JumpTo(node, ifTrue);
            break;
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_TUPLE:
        case checker::TypeFlag::FUNCTION: {
            EmitIsInstance(node, ToAssemblerType(target));
            BranchIfTrue(node, ifTrue);
            break;
        }
        default:
            ES2PANDA_UNREACHABLE();  // other types must not appear here
    }
    SetAccumulatorType(nullptr);
}

// Implemented on top of the runtime type system, do not relax checks, do not introduce new types
void ETSGen::BranchIfIsInstance(const ir::AstNode *const node, const VReg srcReg, const checker::Type *target,
                                Label *ifTrue)
{
    ES2PANDA_ASSERT(target == Checker()->GetApparentType(target));
    auto ifFalse = AllocLabel();

    if (!target->PossiblyETSUndefined()) {
        LoadAccumulator(node, srcReg);
        BranchIfUndefined(node, ifFalse);
    }

    auto const checkType = [this, srcReg, ifTrue, ifFalse, acceptNull = target->PossiblyETSNull()](
                               const ir::AstNode *const n, checker::Type const *t) {
        LoadAccumulator(n, srcReg);
        // #21835: type-alias in ApparentType
        t = t->IsETSTypeAliasType() ? t->AsETSTypeAliasType()->GetTargetType() : t;
        TestIsInstanceConstituent(n, std::tie(ifTrue, ifFalse), t, acceptNull);
    };

    if (target->IsETSUnionType()) {
        for (auto *ct : target->AsETSUnionType()->ConstituentTypes()) {
            checkType(node, ct);
        }
    } else if (!target->IsETSNeverType()) {
        checkType(node, target);
    }

    SetLabel(node, ifFalse);
    SetAccumulatorType(nullptr);
}

// Implemented on top of the runtime type system, do not relax checks, do not introduce new types
void ETSGen::IsInstance(const ir::AstNode *const node, const VReg srcReg, const checker::Type *target)
{
    target = Checker()->GetApparentType(target);
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(target->IsETSReferenceType() && GetAccumulatorType() != nullptr);

    if (target->IsETSAnyType()) {  // should be IsSupertypeOf(target, source)
        LoadAccumulatorBoolean(node, true);
        return;
    }
    if (target->IsETSArrayType() ||
        (target->IsETSObjectType() && !(IsNullUnsafeObjectType(target) && GetAccumulatorType()->PossiblyETSNull()))) {
        InternalIsInstance(node, target);
        return;
    }

    auto ifTrue = AllocLabel();
    auto end = AllocLabel();

    BranchIfIsInstance(node, srcReg, target, ifTrue);
    LoadAccumulatorBoolean(node, false);
    JumpTo(node, end);

    SetLabel(node, ifTrue);
    LoadAccumulatorBoolean(node, true);
    SetLabel(node, end);
}

// isinstance can only be used for Object and [] types, ensure source is not null!
void ETSGen::InternalIsInstance(const ir::AstNode *node, const es2panda::checker::Type *target)
{
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(target->IsETSObjectType() || target->IsETSArrayType());
    if (!IsNullUnsafeObjectType(target)) {
        EmitIsInstance(node, ToAssemblerType(target));
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    } else {
        LoadAccumulatorBoolean(node, true);
    }
}

// checkcast can only be used for Object and [] types, ensure source is not nullish!
void ETSGen::InternalCheckCast(const ir::AstNode *node, const es2panda::checker::Type *target)
{
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(target->IsETSObjectType() || target->IsETSArrayType() || target->IsETSTupleType());
    if (!IsNullUnsafeObjectType(target)) {
        EmitCheckCast(node, ToAssemblerType(target));
    }
    SetAccumulatorType(target);
}

// optimized specialization for object and [] targets
void ETSGen::CheckedReferenceNarrowingObject(const ir::AstNode *node, const checker::Type *target)
{
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(target->IsETSObjectType() || target->IsETSArrayType() || target->IsETSTupleType());
    const RegScope rs(this);
    const auto srcReg = AllocReg();
    StoreAccumulator(node, srcReg);

    auto isNullish = AllocLabel();
    auto end = AllocLabel();
    bool nullishCheck = false;

    auto *source = GetAccumulatorType();
    ES2PANDA_ASSERT(source != nullptr);
    if (source->PossiblyETSUndefined()) {
        nullishCheck = true;
        BranchIfUndefined(node, isNullish);
    }
    if (source->PossiblyETSNull() && IsNullUnsafeObjectType(target)) {
        nullishCheck = true;
        BranchIfNull(node, isNullish);
    }

    if (!nullishCheck) {
        InternalCheckCast(node, target);
    } else {
        LoadAccumulator(node, srcReg);
        InternalCheckCast(node, target);
        JumpTo(node, end);

        SetLabel(node, isNullish);
        EmitFailedTypeCastException(node, srcReg, target);

        SetLabel(node, end);
        SetAccumulatorType(target);
    }
}

// Implemented on top of the runtime type system, do not relax checks, do not introduce new types
void ETSGen::CheckedReferenceNarrowing(const ir::AstNode *node, const checker::Type *target)
{
    ES2PANDA_ASSERT(target != nullptr);
    // NOTE(vpukhov): #19701 void refactoring
    if (target->IsETSVoidType()) {
        SetAccumulatorType(target);
        return;
    }

    target = Checker()->GetApparentType(target);
    ES2PANDA_ASSERT(target != nullptr);
    ES2PANDA_ASSERT(target->IsETSReferenceType());
    if (target->IsETSAnyType()) {  // should be IsSupertypeOf(target, source)
        SetAccumulatorType(target);
        return;
    }
    if (target->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT | checker::TypeFlag::ETS_TUPLE) &&
        !target->IsConstantType()) {
        CheckedReferenceNarrowingObject(node, target);
        return;
    }

    const RegScope rs(this);
    const auto srcReg = AllocReg();
    auto ifTrue = AllocLabel();

    StoreAccumulator(node, srcReg);
    BranchIfIsInstance(node, srcReg, target, ifTrue);

    EmitFailedTypeCastException(node, srcReg, target);

    SetLabel(node, ifTrue);
    LoadAccumulator(node, srcReg);
    // Verifier can't infer type if isinstance met, help him
    EmitCheckCast(node, ToAssemblerType(target));
    SetAccumulatorType(target);
}

void ETSGen::GuardUncheckedType(const ir::AstNode *node, const checker::Type *unchecked, const checker::Type *target)
{
    if (unchecked != nullptr) {
        SetAccumulatorType(unchecked);
        // this check guards possible type violations, **do not relax it**
        CheckedReferenceNarrowing(node, Checker()->MaybeBoxType(target));
    }
    SetAccumulatorType(target);
}

void ETSGen::EmitFailedTypeCastException(const ir::AstNode *node, const VReg src, checker::Type const *target)
{
    const RegScope rs(this);
    const auto errorReg = AllocReg();

    LoadAccumulatorString(node, util::UString(target->ToString(), Allocator()).View());
    Ra().Emit<CallAccShort, 1>(node, Signatures::BUILTIN_RUNTIME_FAILED_TYPE_CAST_EXCEPTION, src, 1);
    StoreAccumulator(node, errorReg);
    EmitThrow(node, errorReg);
    SetAccumulatorType(nullptr);
}

void ETSGen::LoadConstantObject(const ir::Expression *node, const checker::Type *type)
{
    if (type->HasTypeFlag(checker::TypeFlag::BIGINT_LITERAL)) {
        LoadAccumulatorBigInt(node, type->AsETSObjectType()->AsETSBigIntType()->GetValue());
        const VReg value = AllocReg();
        StoreAccumulator(node, value);
        CreateBigIntObject(node, value);
    } else {
        LoadAccumulatorString(node, type->AsETSObjectType()->AsETSStringType()->GetValue());
        SetAccumulatorType(node->TsType());
    }
}

void ETSGen::ApplyConversionCast(const ir::AstNode *node, const checker::Type *targetType)
{
    switch (checker::ETSChecker::TypeKind(targetType)) {
        case checker::TypeFlag::DOUBLE: {
            CastToDouble(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            CastToFloat(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            CastToLong(node);
            break;
        }
        case checker::TypeFlag::INT: {
            CastToInt(node);
            break;
        }
        case checker::TypeFlag::CHAR: {
            CastToChar(node);
            break;
        }
        case checker::TypeFlag::SHORT: {
            CastToShort(node);
            break;
        }
        case checker::TypeFlag::BYTE: {
            CastToByte(node);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_TYPE_PARAMETER: {
            ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
            if (GetAccumulatorType() != nullptr && GetAccumulatorType()->IsETSDynamicType()) {
                CastDynamicToObject(node, targetType);
            }
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastToDynamic(node, targetType->AsETSDynamicType());
            break;
        }
        default: {
            break;
        }
    }
}

void ETSGen::ApplyBoxingConversion(const ir::AstNode *node)
{
    EmitBoxingConversion(node);
    node->SetBoxingUnboxingFlags(
        static_cast<ir::BoxingUnboxingFlags>(node->GetBoxingUnboxingFlags() & ~(ir::BoxingUnboxingFlags::BOXING_FLAG)));
}

void ETSGen::ApplyUnboxingConversion(const ir::AstNode *node)
{
    auto const callUnbox = [this, node](std::string_view sig, checker::Type const *unboxedType) {
        auto boxedType = Checker()->MaybeBoxType(unboxedType)->AsETSObjectType();
        EmitUnboxedCall(node, sig, unboxedType, boxedType);
    };

    auto const unboxFlags =
        ir::BoxingUnboxingFlags(node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG);
    node->RemoveBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOXING_FLAG);

    switch (unboxFlags) {
        case ir::BoxingUnboxingFlags::UNBOX_TO_BOOLEAN:
            callUnbox(Signatures::BUILTIN_BOOLEAN_UNBOXED, Checker()->GlobalETSBooleanType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_BYTE:
            callUnbox(Signatures::BUILTIN_BYTE_UNBOXED, Checker()->GlobalByteType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_CHAR:
            callUnbox(Signatures::BUILTIN_CHAR_UNBOXED, Checker()->GlobalCharType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_SHORT:
            callUnbox(Signatures::BUILTIN_SHORT_UNBOXED, Checker()->GlobalShortType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_INT:
            callUnbox(Signatures::BUILTIN_INT_UNBOXED, Checker()->GlobalIntType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_LONG:
            callUnbox(Signatures::BUILTIN_LONG_UNBOXED, Checker()->GlobalLongType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_FLOAT:
            callUnbox(Signatures::BUILTIN_FLOAT_UNBOXED, Checker()->GlobalFloatType());
            return;
        case ir::BoxingUnboxingFlags::UNBOX_TO_DOUBLE:
            callUnbox(Signatures::BUILTIN_DOUBLE_UNBOXED, Checker()->GlobalDoubleType());
            return;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

void ETSGen::ApplyConversion(const ir::AstNode *node, const checker::Type *targetType)
{
    auto ttctx = TargetTypeContext(this, targetType);

    const bool hasBoxingflags = (node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG) != 0U;
    const bool hasUnboxingflags = (node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U;
    if (hasBoxingflags && !hasUnboxingflags) {
        ApplyBoxingConversion(node);
        return;
    }

    if (hasUnboxingflags) {
        ApplyUnboxingConversion(node);
    }

    if (targetType == nullptr) {
        return;
    }

    ApplyConversionCast(node, targetType);

    if (hasBoxingflags) {
        ApplyBoxingConversion(node);
    }
}

void ETSGen::ApplyCast(const ir::AstNode *node, const checker::Type *targetType)
{
    auto typeKind = checker::ETSChecker::TypeKind(targetType);

    switch (typeKind) {
        case checker::TypeFlag::DOUBLE: {
            CastToDouble(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            CastToFloat(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            CastToLong(node);
            break;
        }
        case checker::TypeFlag::INT: {
            CastToInt(node);
            break;
        }
        case checker::TypeFlag::SHORT: {
            CastToShort(node);
            break;
        }
        case checker::TypeFlag::BYTE: {
            CastToByte(node);
            break;
        }
        case checker::TypeFlag::CHAR: {
            CastToChar(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastToDynamic(node, targetType->AsETSDynamicType());
            break;
        }
        default: {
            break;
        }
    }
}

void ETSGen::ApplyCastToBoxingFlags(const ir::AstNode *node, const ir::BoxingUnboxingFlags targetType)
{
    switch (targetType) {
        case ir::BoxingUnboxingFlags::BOX_TO_DOUBLE: {
            CastToDouble(node);
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_FLOAT: {
            CastToFloat(node);
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_LONG: {
            CastToLong(node);
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_INT: {
            CastToInt(node);
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_BYTE: {
            CastToByte(node);
            break;
        }
        default: {
            break;
        }
    }
}

void ETSGen::EmitUnboxedCall(const ir::AstNode *node, std::string_view signatureFlag,
                             const checker::Type *const targetType, const checker::Type *const boxedType)
{
    RegScope rs(this);
    // NOTE(vpukhov): #20510 lowering
    if (node->HasAstNodeFlags(ir::AstNodeFlags::CHECKCAST)) {
        CheckedReferenceNarrowing(node, boxedType);
    }

    // to cast to primitive types we probably have to cast to corresponding boxed built-in types first.
    auto *const checker = Checker()->AsETSChecker();
    auto const *accumulatorType = GetAccumulatorType();
    ES2PANDA_ASSERT(accumulatorType != nullptr);
    if (accumulatorType->IsETSObjectType() &&  //! accumulatorType->DefinitelyNotETSNullish() &&
        !checker->Relation()->IsIdenticalTo(const_cast<checker::Type *>(accumulatorType),
                                            const_cast<checker::Type *>(boxedType))) {
        CastToReftype(node, boxedType, false);
    }

    Ra().Emit<CallAccShort, 0>(node, signatureFlag, dummyReg_, 0);
    SetAccumulatorType(targetType);
    if (node->IsExpression()) {
        const_cast<ir::Expression *>(node->AsExpression())->SetTsType(const_cast<checker::Type *>(targetType));
    }
}

// NOTE(vpukhov): #20510 should be available only as a part of ApplyBoxingConversion
void ETSGen::EmitBoxingConversion(ir::BoxingUnboxingFlags boxingFlag, const ir::AstNode *node)
{
    auto const callBox = [this, node](std::string_view sig, checker::Type const *unboxedType) {
        Ra().Emit<CallAccShort, 0>(node, sig, dummyReg_, 0);
        SetAccumulatorType(Checker()->MaybeBoxType(unboxedType)->AsETSObjectType());
    };

    switch (boxingFlag) {
        case ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN:
            callBox(Signatures::BUILTIN_BOOLEAN_VALUE_OF, Checker()->GlobalETSBooleanType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_BYTE:
            callBox(Signatures::BUILTIN_BYTE_VALUE_OF, Checker()->GlobalByteType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_CHAR:
            callBox(Signatures::BUILTIN_CHAR_VALUE_OF, Checker()->GlobalCharType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_SHORT:
            callBox(Signatures::BUILTIN_SHORT_VALUE_OF, Checker()->GlobalShortType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_INT:
            callBox(Signatures::BUILTIN_INT_VALUE_OF, Checker()->GlobalIntType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_LONG:
            callBox(Signatures::BUILTIN_LONG_VALUE_OF, Checker()->GlobalLongType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_FLOAT:
            callBox(Signatures::BUILTIN_FLOAT_VALUE_OF, Checker()->GlobalFloatType());
            return;
        case ir::BoxingUnboxingFlags::BOX_TO_DOUBLE:
            callBox(Signatures::BUILTIN_DOUBLE_VALUE_OF, Checker()->GlobalDoubleType());
            return;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

// NOTE(vpukhov): #20510 should be available only as a part of ApplyBoxingConversion
void ETSGen::EmitBoxingConversion(const ir::AstNode *node)
{
    auto boxingFlag =
        static_cast<ir::BoxingUnboxingFlags>(ir::BoxingUnboxingFlags::BOXING_FLAG & node->GetBoxingUnboxingFlags());

    RegScope rs(this);

    ApplyCastToBoxingFlags(node, boxingFlag);

    EmitBoxingConversion(boxingFlag, node);

    if (node->IsExpression()) {
        auto boxedType = const_cast<checker::Type *>(GetAccumulatorType());
        const_cast<ir::Expression *>(node->AsExpression())->SetTsType(boxedType);
    }
}

void ETSGen::SwapBinaryOpArgs(const ir::AstNode *const node, const VReg lhs)
{
    const RegScope rs(this);
    const auto tmp = AllocReg();

    StoreAccumulator(node, tmp);
    LoadAccumulator(node, lhs);
    MoveVreg(node, lhs, tmp);
}

VReg ETSGen::MoveAccToReg(const ir::AstNode *const node)
{
    const auto newReg = AllocReg();
    StoreAccumulator(node, newReg);
    return newReg;
}

void ETSGen::CastToBoolean([[maybe_unused]] const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            return;
        }
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32tou1>(node);
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32tou1>(node);
            return;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64tou1>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi32>(node);
            Sa().Emit<I32tou1>(node);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32tou1>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::ETS_BOOLEAN);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalETSBooleanType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::CastToByte([[maybe_unused]] const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::BYTE: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32toi8>(node);
            break;
        }
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64toi32>(node);
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi32>(node);
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalByteType());
}

void ETSGen::CastToChar([[maybe_unused]] const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::CHAR: {
            if (node->IsCharLiteral()) {
                auto type = node->AsCharLiteral()->TsType();
                if (type->TypeFlags() == (checker::TypeFlag::CONSTANT | checker::TypeFlag::BYTE)) {
                    SetAccumulatorType(type);
                }
            }
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN: {
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64toi32>(node);
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi32>(node);
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalCharType());
}

void ETSGen::CastToShort([[maybe_unused]] const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::SHORT: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32toi16>(node);
            break;
        }
        case checker::TypeFlag::BYTE: {
            break;
        }
        case checker::TypeFlag::INT: {
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64toi32>(node);
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi32>(node);
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalShortType());
}

void ETSGen::CastToDouble(const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::DOUBLE: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32tof64>(node);
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32tof64>(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64tof64>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32tof64>(node);
            break;
        }
        case checker::TypeFlag::ETS_NEVER:
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalDoubleType());
}

void ETSGen::CastToFloat(const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::FLOAT: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32tof32>(node);
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32tof32>(node);
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64tof32>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64tof32>(node);
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalFloatType());
}

void ETSGen::CastToLong(const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::LONG: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR: {
            Sa().Emit<U32toi64>(node);
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Sa().Emit<I32toi64>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi64>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi64>(node);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalLongType());
}

void ETSGen::CastToInt(const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::INT: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT: {
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<I64toi32>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<F32toi32>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ES2PANDA_ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            [[fallthrough]];
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::CastToReftype(const ir::AstNode *const node, const checker::Type *const targetType, const bool unchecked)
{
    ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
    ES2PANDA_ASSERT(GetAccumulatorType()->IsETSReferenceType());

    const auto *const sourceType = GetAccumulatorType();
    ES2PANDA_ASSERT(sourceType != nullptr);

    if (sourceType->IsETSDynamicType()) {
        CastDynamicToObject(node, targetType);
        return;
    }
    if (targetType->IsETSDynamicType()) {
        CastToDynamic(node, targetType->AsETSDynamicType());
        return;
    }

    if (targetType->IsETSStringType() && !sourceType->IsETSStringType()) {
        CastToString(node);
    }

    if (!unchecked) {
        CheckedReferenceNarrowing(node, targetType);
        return;
    }

    ES2PANDA_ASSERT(!targetType->IsETSTypeParameter() && !targetType->IsETSNonNullishType() &&
                    !targetType->IsETSPartialTypeParameter());
    CheckedReferenceNarrowing(node, targetType);
    SetAccumulatorType(targetType);
}

void ETSGen::CastDynamicToObject(const ir::AstNode *node, const checker::Type *targetType)
{
    if (targetType->IsETSStringType()) {
        CastDynamicTo(node, checker::TypeFlag::STRING);
        CheckedReferenceNarrowing(node, targetType);
        SetAccumulatorType(targetType);
        return;
    }

    // NOTE(vpukhov): #14626 remove, replace targetType with interface
    if (targetType->IsLambdaObject()) {
        RegScope rs(this);
        VReg dynObjReg = AllocReg();
        StoreAccumulator(node, dynObjReg);
        Ra().Emit<InitobjShort>(node, targetType->AsETSObjectType()->ConstructSignatures()[0]->InternalName(),
                                dynObjReg, dummyReg_);
        SetAccumulatorType(targetType);
        return;
    }

    if (targetType == Checker()->GlobalETSObjectType()) {
        SetAccumulatorType(targetType);
        return;
    }

    if (targetType->IsETSDynamicType()) {
        SetAccumulatorType(targetType);
        return;
    }

    // should be valid only for Object and [] types, other are workarounds
    // the DefinitelyETSNullish function has been used to add handling for null and undefined cases,
    // and this function will need to be refactored in the future.
    if (targetType->IsETSArrayType() || targetType->IsETSObjectType() || targetType->IsETSTypeParameter() ||
        targetType->IsETSUnionType() || targetType->IsETSFunctionType() || targetType->DefinitelyETSNullish() ||
        targetType->IsETSTupleType() || targetType->IsETSAnyType()) {
        ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
        auto lang = GetAccumulatorType()->AsETSDynamicType()->Language();
        auto methodName = compiler::Signatures::Dynamic::GetObjectBuiltin(lang);

        RegScope rs(this);
        VReg dynObjReg = AllocReg();
        StoreAccumulator(node, dynObjReg);

        // try internal checkcast
        VReg typeReg = AllocReg();
        auto assemblerType = ToAssemblerType(targetType);
        Sa().Emit<LdaType>(node, assemblerType);
        StoreAccumulator(node, typeReg);

        Ra().Emit<CallShort, 2U>(node, methodName, dynObjReg, typeReg);
        EmitCheckCast(node, assemblerType);  // trick verifier
        SetAccumulatorType(targetType);
        return;
    }

    ES2PANDA_UNREACHABLE();
}

void ETSGen::CastToString(const ir::AstNode *const node)
{
    const auto *const sourceType = GetAccumulatorType();
    ES2PANDA_ASSERT(sourceType != nullptr);
    if (sourceType->IsETSStringType()) {
        return;
    }

    ES2PANDA_ASSERT(sourceType->IsETSReferenceType());

    // caller must ensure parameter is not null
    Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_OBJECT_TO_STRING, dummyReg_, 0);
    SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalETSStringBuiltinType());
}

void ETSGen::CastToDynamic(const ir::AstNode *node, const checker::ETSDynamicType *type)
{
    std::string_view methodName {};
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (typeKind) {
        case checker::TypeFlag::ETS_BOOLEAN:
            methodName = compiler::Signatures::Dynamic::NewBooleanBuiltin(type->Language());
            break;
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT:
        case checker::TypeFlag::LONG:
        case checker::TypeFlag::FLOAT:
        case checker::TypeFlag::DOUBLE:
            CastToDouble(node);
            methodName = compiler::Signatures::Dynamic::NewDoubleBuiltin(type->Language());
            break;
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_NONNULLISH:
        case checker::TypeFlag::ETS_PARTIAL_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_UNION:  // NOTE(vpukhov): refine dynamic type cast rules
        case checker::TypeFlag::ETS_ANY:
            ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
            if (GetAccumulatorType()->IsETSStringType()) {
                methodName = compiler::Signatures::Dynamic::NewStringBuiltin(type->Language());
                break;
            }
            [[fallthrough]];
        case checker::TypeFlag::FUNCTION:
            ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
            ES2PANDA_ASSERT(!GetAccumulatorType()->IsETSMethodType());
            [[fallthrough]];
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_TUPLE:
            methodName = compiler::Signatures::Dynamic::NewObjectBuiltin(type->Language());
            break;
        case checker::TypeFlag::ETS_DYNAMIC_TYPE:
            SetAccumulatorType(type);
            return;
        default:
            ES2PANDA_UNREACHABLE();
    }

    ES2PANDA_ASSERT(!methodName.empty());

    RegScope rs(this);
    // Load value
    VReg valReg = AllocReg();
    StoreAccumulator(node, valReg);

    // Create new JSValue and initialize it
    Ra().Emit<CallShort, 1>(node, methodName, valReg, dummyReg_);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(type->Language()));
}

void ETSGen::CastDynamicTo(const ir::AstNode *node, enum checker::TypeFlag typeFlag)
{
    std::string_view methodName {};
    checker::Type *objectType {};
    ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
    auto type = GetAccumulatorType()->AsETSDynamicType();
    switch (typeFlag) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            methodName = compiler::Signatures::Dynamic::GetBooleanBuiltin(type->Language());
            objectType = Checker()->GlobalETSBooleanType();
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            methodName = compiler::Signatures::Dynamic::GetDoubleBuiltin(type->Language());
            objectType = Checker()->GlobalDoubleType();
            break;
        }
        case checker::TypeFlag::STRING: {
            methodName = compiler::Signatures::Dynamic::GetStringBuiltin(type->Language());
            objectType = Checker()->GlobalBuiltinETSStringType();
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    RegScope rs(this);
    // Load dynamic object
    VReg dynObjReg = AllocReg();
    StoreAccumulator(node, dynObjReg);

    // Get value from dynamic object
    Ra().Emit<CallShort, 1>(node, methodName, dynObjReg, dummyReg_);
    SetAccumulatorType(objectType);
}

void ETSGen::ToBinaryResult(const ir::AstNode *node, Label *ifFalse)
{
    Label *end = AllocLabel();
    Sa().Emit<Ldai>(node, 1);
    Sa().Emit<Jmp>(node, end);
    SetLabel(node, ifFalse);
    Sa().Emit<Ldai>(node, 0);
    SetLabel(node, end);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::BinaryLogic(const ir::AstNode *node, lexer::TokenType op, VReg lhs)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryArithmetic<Mod2, Mod2Wide, Fmod2, Fmod2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryBitwiseArithmetic<Shl2, Shl2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryBitwiseArithmetic<Ashr2, Ashr2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryBitwiseArithmetic<Shr2, Shr2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL: {
            BinaryBitwiseArithmetic<And2, And2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL: {
            BinaryBitwiseArithmetic<Or2, Or2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL: {
            BinaryBitwiseArithmetic<Xor2, Xor2Wide>(node, lhs);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    ES2PANDA_ASSERT(node->IsAssignmentExpression() || node->IsBinaryExpression());
    ES2PANDA_ASSERT(Checker()->Relation()->IsIdenticalTo(GetAccumulatorType(), node->AsExpression()->TsType()));
}

void ETSGen::BinaryArithmLogic(const ir::AstNode *node, lexer::TokenType op, VReg lhs)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryArithmetic<Add2, Add2Wide, Fadd2, Fadd2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryArithmetic<Sub2, Sub2Wide, Fsub2, Fsub2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryArithmetic<Mul2, Mul2Wide, Fmul2, Fmul2Wide>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL: {
            SwapBinaryOpArgs(node, lhs);
            BinaryArithmetic<Div2, Div2Wide, Fdiv2, Fdiv2Wide>(node, lhs);
            break;
        }
        default: {
            BinaryLogic(node, op, lhs);
            break;
        }
    }

    ES2PANDA_ASSERT(node->IsAssignmentExpression() || node->IsBinaryExpression());
    ES2PANDA_ASSERT(Checker()->Relation()->IsIdenticalTo(GetAccumulatorType(), node->AsExpression()->TsType()));
}

void ETSGen::Binary(const ir::AstNode *node, lexer::TokenType op, VReg lhs)
{
    Label *ifFalse = AllocLabel();
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL: {
            BinaryEquality<Jne, Jnez, Jeqz, true>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            BinaryEquality<Jne, Jnez, Jeqz>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            BinaryEquality<Jeq, Jeqz, Jnez, true>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            BinaryEquality<Jeq, Jeqz, Jnez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            BinaryRelation<Jle, Jlez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            BinaryRelation<Jlt, Jltz>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            BinaryRelation<Jge, Jgez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            BinaryRelation<Jgt, Jgtz>(node, lhs, ifFalse);
            break;
        }
        default: {
            BinaryArithmLogic(node, op, lhs);
            break;
        }
    }

    ES2PANDA_ASSERT(node->IsAssignmentExpression() || node->IsBinaryExpression());
    ES2PANDA_ASSERT(Checker()->Relation()->IsIdenticalTo(GetAccumulatorType(), node->AsExpression()->TsType()));
}

void ETSGen::Condition(const ir::AstNode *node, lexer::TokenType op, VReg lhs, Label *ifFalse)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL: {
            BinaryEqualityCondition<Jne, Jnez, true>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            BinaryEqualityCondition<Jne, Jnez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            BinaryEqualityCondition<Jeq, Jeqz, true>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            BinaryEqualityCondition<Jeq, Jeqz>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            BinaryRelationCondition<Jle, Jlez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            BinaryRelationCondition<Jlt, Jltz>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            BinaryRelationCondition<Jge, Jgez>(node, lhs, ifFalse);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            BinaryRelationCondition<Jgt, Jgtz>(node, lhs, ifFalse);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template <typename CondCompare, bool BEFORE_LOGICAL_NOT>
void ETSGen::ResolveConditionalResultFloat(const ir::AstNode *node, Label *realEndLabel)
{
    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
    VReg tmpReg = AllocReg();
    StoreAccumulator(node, tmpReg);
    if (type->IsFloatType()) {
        FloatIsNaN(node);
    } else {
        DoubleIsNaN(node);
    }
    Sa().Emit<Xori>(node, 1);

    BranchIfFalse(node, realEndLabel);
    LoadAccumulator(node, tmpReg);
    VReg zeroReg = AllocReg();

    if (type->IsFloatType()) {
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::FLOAT, 0);
        BinaryNumberComparison<Fcmpl, Jeqz>(node, zeroReg, realEndLabel);
    } else {
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::DOUBLE, 0);
        BinaryNumberComparison<FcmplWide, Jeqz>(node, zeroReg, realEndLabel);
    }
}

template <typename CondCompare, bool BEFORE_LOGICAL_NOT, bool USE_FALSE_LABEL>
void ETSGen::ResolveConditionalResultNumeric(const ir::AstNode *node, [[maybe_unused]] Label *ifFalse, Label **end)
{
    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
    auto realEndLabel = [end, ifFalse, this](bool useFalseLabel) {
        if (useFalseLabel) {
            return ifFalse;
        }
        if ((*end) == nullptr) {
            (*end) = AllocLabel();
        }
        return (*end);
    }(USE_FALSE_LABEL);
    if (type->IsDoubleType() || type->IsFloatType()) {
        ResolveConditionalResultFloat<CondCompare, BEFORE_LOGICAL_NOT>(node, realEndLabel);
    }
    if (type->IsLongType()) {
        VReg zeroReg = AllocReg();
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::LONG, 0);
        BinaryNumberComparison<CmpWide, CondCompare>(node, zeroReg, realEndLabel);
    }
    if constexpr (BEFORE_LOGICAL_NOT) {
        Label *zeroPrimitive = AllocLabel();
        BranchIfFalse(node, zeroPrimitive);
        ToBinaryResult(node, zeroPrimitive);
    }
}

template <typename CondCompare, bool BEFORE_LOGICAL_NOT>
void ETSGen::ResolveConditionalResultReference(const ir::AstNode *node)
{
    auto const testString = [this, node]() {
        LoadStringLength(node);
        if constexpr (BEFORE_LOGICAL_NOT) {
            Label *zeroLenth = AllocLabel();
            BranchIfFalse(node, zeroLenth);
            ToBinaryResult(node, zeroLenth);
        }
    };

    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
    if (!type->PossiblyETSString()) {
        Sa().Emit<Ldai>(node, 1);
        return;
    }
    if (type->IsETSStringType()) {  // should also be valid for string|null|undefined
        testString();
        return;
    }

    Label *isString = AllocLabel();
    Label *end = AllocLabel();
    compiler::VReg objReg = AllocReg();
    StoreAccumulator(node, objReg);

    ES2PANDA_ASSERT(Checker()->GlobalBuiltinETSStringType() != nullptr);
    EmitIsInstance(node, Checker()->GlobalBuiltinETSStringType()->AssemblerName());
    BranchIfTrue(node, isString);
    Sa().Emit<Ldai>(node, 1);
    Branch(node, end);
    SetLabel(node, isString);
    LoadAccumulator(node, objReg);
    InternalCheckCast(node, Checker()->GlobalBuiltinETSStringType());  // help verifier
    testString();
    SetLabel(node, end);
}

template <typename CondCompare, bool BEFORE_LOGICAL_NOT, bool USE_FALSE_LABEL>
void ETSGen::ResolveConditionalResult(const ir::AstNode *node, [[maybe_unused]] Label *ifFalse)
{
    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
#ifdef PANDA_WITH_ETS
    if (type->IsETSReferenceType()) {
        VReg valReg = AllocReg();
        StoreAccumulator(node, valReg);
        EmitEtsIstrue(node, valReg);
        return;
    }
#endif  // PANDA_WITH_ETS
    if (type->IsETSBooleanType()) {
        return;
    }
    Label *ifNullish {nullptr};
    Label *end {nullptr};
    if (type->PossiblyETSNullish()) {
        if constexpr (USE_FALSE_LABEL) {
            BranchIfNullish(node, ifFalse);
        } else {
            ifNullish = AllocLabel();
            end = AllocLabel();
            BranchIfNullish(node, ifNullish);
        }
    }
    if (type->DefinitelyETSNullish()) {
        // skip
    } else if (type->IsETSReferenceType()) {
        ResolveConditionalResultReference<CondCompare, BEFORE_LOGICAL_NOT>(node);
    } else {
        ResolveConditionalResultNumeric<CondCompare, BEFORE_LOGICAL_NOT, USE_FALSE_LABEL>(node, ifFalse, &end);
    }
    if (ifNullish != nullptr) {
        Branch(node, end);
        SetLabel(node, ifNullish);
        Sa().Emit<Ldai>(node, 0);
    }
    if (end != nullptr) {
        SetLabel(node, end);
    }
}

template <bool BEFORE_LOGICAL_NOT, bool FALSE_LABEL_EXISTED>
void ETSGen::ResolveConditionalResultIfFalse(const ir::AstNode *node, Label *ifFalse)
{
    ResolveConditionalResult<Jeqz, BEFORE_LOGICAL_NOT, FALSE_LABEL_EXISTED>(node, ifFalse);
}

template void ETSGen::ResolveConditionalResultIfFalse<false, true>(const ir::AstNode *node, Label *ifFalse);
template void ETSGen::ResolveConditionalResultIfFalse<true, false>(const ir::AstNode *node, Label *ifFalse);
template void ETSGen::ResolveConditionalResultIfFalse<false, false>(const ir::AstNode *node, Label *ifFalse);

template <bool BEFORE_LOGICAL_NOT, bool FALSE_LABEL_EXISTED>
void ETSGen::ResolveConditionalResultIfTrue(const ir::AstNode *node, Label *ifFalse)
{
    ResolveConditionalResult<Jnez, BEFORE_LOGICAL_NOT, FALSE_LABEL_EXISTED>(node, ifFalse);
}

template void ETSGen::ResolveConditionalResultIfTrue<false, true>(const ir::AstNode *node, Label *ifFalse);
template void ETSGen::ResolveConditionalResultIfTrue<false, false>(const ir::AstNode *node, Label *ifFalse);

template <typename CondCompare, typename NegCondCompare>
void ETSGen::BranchConditional(const ir::AstNode *node, Label *endLabel)
{
    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
    if (type->IsETSReferenceType()) {
        VReg valReg = AllocReg();
        StoreAccumulator(node, valReg);
        EmitEtsIstrue(node, valReg);
    } else if (type->IsDoubleType() || type->IsFloatType()) {
        ConditionalFloat(node);
    } else if (type->IsLongType()) {
        VReg zeroReg = AllocReg();
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::LONG, 0);
        Ra().Emit<CmpWide>(node, zeroReg);
    }

    Sa().Emit<CondCompare>(node, endLabel);
}

void ETSGen::ConditionalFloat(const ir::AstNode *node)
{
    auto type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);
    VReg tmpReg = AllocReg();
    VReg isNaNReg = AllocReg();

    StoreAccumulator(node, tmpReg);
    if (type->IsFloatType()) {
        FloatIsNaN(node);
    } else {
        DoubleIsNaN(node);
    }
    Sa().Emit<Xori>(node, 1);
    StoreAccumulator(node, isNaNReg);
    LoadAccumulator(node, tmpReg);

    VReg zeroReg = AllocReg();

    if (type->IsFloatType()) {
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::FLOAT, 0);
        Ra().Emit<Fcmpl>(node, zeroReg);
    } else {
        MoveImmediateToRegister(node, zeroReg, checker::TypeFlag::DOUBLE, 0);
        Ra().Emit<FcmplWide>(node, zeroReg);
    }
    Sa().Emit<Xori>(node, 0);
    Sa().Emit<And2>(node, isNaNReg);
}

void ETSGen::BranchConditionalIfFalse(const ir::AstNode *node, Label *endLabel)
{
    BranchConditional<Jeqz, Jnez>(node, endLabel);
}

void ETSGen::BranchConditionalIfTrue(const ir::AstNode *node, Label *endLabel)
{
    BranchConditional<Jnez, Jeqz>(node, endLabel);
}

void ETSGen::BranchIfNullish(const ir::AstNode *node, Label *ifNullish)
{
    auto *const type = GetAccumulatorType();
    ES2PANDA_ASSERT(type != nullptr);

    if (type->IsETSVoidType()) {
        // NOTE(): #19701 need void refactoring
        Sa().Emit<Jmp>(node, ifNullish);
    } else if (type->DefinitelyNotETSNullish()) {
        // no action
    } else if (type->DefinitelyETSNullish()) {
        Sa().Emit<Jmp>(node, ifNullish);
    } else if (!type->PossiblyETSNull()) {
        Sa().Emit<JeqzObj>(node, ifNullish);
    } else {
        RegScope rs(this);
        auto tmpObj = AllocReg();
        auto notTaken = AllocLabel();

        if (type->PossiblyETSUndefined()) {
            Sa().Emit<JeqzObj>(node, ifNullish);
        }

        Sa().Emit<StaObj>(node, tmpObj);
        EmitIsNull(node);
        Sa().Emit<Jeqz>(node, notTaken);

        Sa().Emit<LdaObj>(node, tmpObj);
        Sa().Emit<Jmp>(node, ifNullish);

        SetLabel(node, notTaken);
        Sa().Emit<LdaObj>(node, tmpObj);
    }
}

void ETSGen::BranchIfNotNullish(const ir::AstNode *node, Label *ifNotNullish)
{
    auto notTaken = AllocLabel();
    BranchIfNullish(node, notTaken);
    JumpTo(node, ifNotNullish);
    SetLabel(node, notTaken);
}

void ETSGen::AssumeNonNullish(const ir::AstNode *node, checker::Type const *targetType)
{
    auto const *nullishType = GetAccumulatorType();
    ES2PANDA_ASSERT(nullishType != nullptr);
    if (nullishType->PossiblyETSNull()) {
        // clear 'null' dataflow
        EmitCheckCast(node, ToAssemblerType(targetType));
    }
    SetAccumulatorType(targetType);
}

void ETSGen::EmitNullishException(const ir::AstNode *node)
{
    RegScope ra(this);
    VReg undef = AllocReg();
    LoadAccumulatorUndefined(node);
    StoreAccumulator(node, undef);
    VReg exception = AllocReg();
    NewObject(node, Signatures::BUILTIN_NULLPOINTER_ERROR, exception);
    CallExact(node, Signatures::BUILTIN_NULLPOINTER_ERROR_CTOR, exception, undef, undef);
    EmitThrow(node, exception);
    SetAccumulatorType(nullptr);
}

template <bool IS_STRICT>
void ETSGen::RefEqualityLooseDynamic(const ir::AstNode *node, VReg lhs, VReg rhs, Label *ifFalse)
{
    // NOTE(vpukhov): implement
    EmitEtsEquals<IS_STRICT>(node, lhs, rhs);
    BranchIfFalse(node, ifFalse);
}

template <typename IntCompare, typename CondCompare, typename DynCompare, bool IS_STRICT>
void ETSGen::BinaryEquality(const ir::AstNode *node, VReg lhs, Label *ifFalse)
{
    BinaryEqualityCondition<IntCompare, CondCompare, IS_STRICT>(node, lhs, ifFalse);
    ToBinaryResult(node, ifFalse);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

template <typename IntCompare, typename CondCompare, bool IS_STRICT>
void ETSGen::BinaryEqualityCondition(const ir::AstNode *node, VReg lhs, Label *ifFalse)
{
    if (targetType_->IsETSReferenceType()) {
        RegScope rs(this);
        VReg arg0 = AllocReg();
        StoreAccumulator(node, arg0);
        InverseCondition(
            node, [this, node, lhs, arg0](Label *tgt) { RefEqualityLoose<IS_STRICT>(node, lhs, arg0, tgt); }, ifFalse,
            std::is_same_v<CondCompare, Jeqz>);
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
        return;
    }

    auto typeKind = checker::ETSChecker::TypeKind(targetType_);

    switch (typeKind) {
        case checker::TypeFlag::DOUBLE: {
            BinaryFloatingPointComparison<FcmpgWide, FcmplWide, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            BinaryFloatingPointComparison<Fcmpg, Fcmpl, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::LONG: {
            BinaryNumberComparison<CmpWide, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::INT: {
            Ra().Emit<IntCompare>(node, lhs, ifFalse);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

template <typename IntCompare, typename CondCompare>
void ETSGen::BinaryRelation(const ir::AstNode *node, VReg lhs, Label *ifFalse)
{
    BinaryRelationCondition<IntCompare, CondCompare>(node, lhs, ifFalse);
    ToBinaryResult(node, ifFalse);
}

template <typename IntCompare, typename CondCompare>
void ETSGen::BinaryRelationCondition(const ir::AstNode *node, VReg lhs, Label *ifFalse)
{
    auto typeKind = checker::ETSChecker::TypeKind(targetType_);

    switch (typeKind) {
        case checker::TypeFlag::DOUBLE: {
            BinaryFloatingPointComparison<FcmpgWide, FcmplWide, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            BinaryFloatingPointComparison<Fcmpg, Fcmpl, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::LONG: {
            BinaryNumberComparison<CmpWide, CondCompare>(node, lhs, ifFalse);
            break;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::INT: {
            Ra().Emit<IntCompare>(node, lhs, ifFalse);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

template <typename IntOp, typename LongOp, typename FloatOp, typename DoubleOp>
void ETSGen::BinaryArithmetic(const ir::AstNode *node, VReg lhs)
{
    auto typeKind = checker::ETSChecker::TypeKind(targetType_);

    switch (typeKind) {
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<DoubleOp>(node, lhs);
            SetAccumulatorType(Checker()->GlobalDoubleType());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<FloatOp>(node, lhs);
            SetAccumulatorType(Checker()->GlobalFloatType());
            break;
        }
        default: {
            BinaryBitwiseArithmetic<IntOp, LongOp>(node, lhs);
            break;
        }
    }

    ApplyCast(node, node->AsExpression()->TsType());
}

template <typename IntOp, typename LongOp>
void ETSGen::BinaryBitwiseArithmetic(const ir::AstNode *node, VReg lhs)
{
    auto typeKind = checker::ETSChecker::TypeKind(targetType_);

    switch (typeKind) {
        case checker::TypeFlag::LONG: {
            Ra().Emit<LongOp>(node, lhs);
            SetAccumulatorType(Checker()->GlobalLongType());
            break;
        }
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::INT: {
            Ra().Emit<IntOp>(node, lhs);
            SetAccumulatorType(Checker()->GlobalIntType());
            break;
        }
        case checker::TypeFlag::ETS_BOOLEAN: {
            Ra().Emit<IntOp>(node, lhs);
            SetAccumulatorType(Checker()->GlobalETSBooleanType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    ApplyCast(node, node->AsExpression()->TsType());
}

template <bool IS_STRICT>
void ETSGen::HandleDefinitelyNullishEquality(const ir::AstNode *node, VReg lhs, VReg rhs, Label *ifFalse)
{
    if constexpr (IS_STRICT) {
        LoadAccumulator(node, lhs);
        Ra().Emit<JneObj>(node, rhs, ifFalse);
    } else {
        auto *checker = const_cast<checker::ETSChecker *>(Checker());
        auto ltype = checker->GetNonConstantType(const_cast<checker::Type *>(GetVRegType(lhs)));
        ES2PANDA_ASSERT(ltype != nullptr);
        LoadAccumulator(node, ltype->DefinitelyETSNullish() ? rhs : lhs);
        BranchIfNotNullish(node, ifFalse);
    }
}

template <bool IS_STRICT>
void ETSGen::HandlePossiblyNullishEquality(const ir::AstNode *node, VReg lhs, VReg rhs, Label *ifFalse, Label *ifTrue)
{
    Label *ifLhsNullish = AllocLabel();
    Label *out = AllocLabel();

    LoadAccumulator(node, lhs);
    BranchIfNullish(node, ifLhsNullish);

    LoadAccumulator(node, rhs);
    BranchIfNullish(node, ifFalse);
    JumpTo(node, out);

    SetLabel(node, ifLhsNullish);
    if constexpr (IS_STRICT) {
        Ra().Emit<JneObj>(node, rhs, ifFalse);
    } else {
        LoadAccumulator(node, rhs);
        BranchIfNotNullish(node, ifFalse);
    }
    JumpTo(node, ifTrue);

    SetLabel(node, out);
    SetAccumulatorType(nullptr);
}

static std::optional<std::pair<checker::Type const *, util::StringView>> SelectLooseObjComparator(
    checker::ETSChecker *checker, checker::Type *lhs, checker::Type *rhs)
{
    auto alhs = checker->GetApparentType(checker->GetNonNullishType(lhs));
    auto arhs = checker->GetApparentType(checker->GetNonNullishType(rhs));
    ES2PANDA_ASSERT(alhs != nullptr && arhs != nullptr);
    alhs = alhs->IsETSStringType() ? checker->GlobalBuiltinETSStringType() : alhs;
    arhs = arhs->IsETSStringType() ? checker->GlobalBuiltinETSStringType() : arhs;
    if (!alhs->IsETSObjectType() || !arhs->IsETSObjectType()) {
        return std::nullopt;
    }
    if (!checker->Relation()->IsIdenticalTo(alhs, arhs)) {
        return std::nullopt;
    }
    auto obj = alhs->AsETSObjectType();
    if (!obj->HasObjectFlag(checker::ETSObjectFlags::VALUE_TYPED)) {
        return std::nullopt;
    }
    // NOTE(vpukhov): emit faster code
    auto methodSig =
        util::UString(std::string(obj->AssemblerName()) + ".equals:std.core.Object;u1;", checker->Allocator()).View();
    return std::make_pair(checker->GetNonConstantType(obj), methodSig);
}

template <typename LongOp, typename IntOp, typename DoubleOp, typename FloatOp>
void ETSGen::UpdateOperator(const ir::AstNode *node)
{
    switch (checker::ETSChecker::ETSType(GetAccumulatorType())) {
        case checker::TypeFlag::LONG: {
            RegScope scope(this);
            VReg reg = AllocReg();
            Ra().Emit<MoviWide>(node, reg, 1LL);
            Ra().Emit<LongOp>(node, reg);
            break;
        }
        case checker::TypeFlag::INT: {
            Sa().Emit<IntOp>(node, 1);
            break;
        }
        case checker::TypeFlag::CHAR: {
            Sa().Emit<IntOp>(node, 1);
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::SHORT: {
            Sa().Emit<IntOp>(node, 1);
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::BYTE: {
            Sa().Emit<IntOp>(node, 1);
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            RegScope scope(this);
            VReg reg = AllocReg();
            Ra().Emit<FmoviWide>(node, reg, 1.0);
            Ra().Emit<DoubleOp>(node, reg);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            RegScope scope(this);
            VReg reg = AllocReg();
            Ra().Emit<Fmovi>(node, reg, 1.0F);
            Ra().Emit<FloatOp>(node, reg);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template <bool IS_STRICT>
void ETSGen::RefEqualityLoose(const ir::AstNode *node, VReg lhs, VReg rhs, Label *ifFalse)
{
    auto *checker = const_cast<checker::ETSChecker *>(Checker());
    auto ltype = checker->GetNonConstantType(const_cast<checker::Type *>(GetVRegType(lhs)));
    auto rtype = checker->GetNonConstantType(const_cast<checker::Type *>(GetVRegType(rhs)));
    ES2PANDA_ASSERT(ltype != nullptr && rtype != nullptr);
    if (ltype->IsETSDynamicType() || rtype->IsETSDynamicType()) {
        RefEqualityLooseDynamic<IS_STRICT>(node, lhs, rhs, ifFalse);
        return;
    }

    if (ltype->DefinitelyETSNullish() || rtype->DefinitelyETSNullish()) {
        HandleDefinitelyNullishEquality<IS_STRICT>(node, lhs, rhs, ifFalse);
    } else if (!ltype->PossiblyETSValueTypedExceptNullish() || !rtype->PossiblyETSValueTypedExceptNullish()) {
        auto ifTrue = AllocLabel();
        if ((ltype->PossiblyETSUndefined() && rtype->PossiblyETSNull()) ||
            (rtype->PossiblyETSUndefined() && ltype->PossiblyETSNull())) {
            HandlePossiblyNullishEquality(node, lhs, rhs, ifFalse, ifTrue);
        }
        LoadAccumulator(node, lhs);
        Ra().Emit<JneObj>(node, rhs, ifFalse);
        SetLabel(node, ifTrue);
    } else if (auto spec = SelectLooseObjComparator(  // try to select specific type
                                                      // CC-OFFNXT(G.FMT.06-CPP) project code style
                   const_cast<checker::ETSChecker *>(Checker()), const_cast<checker::Type *>(ltype),
                   const_cast<checker::Type *>(rtype));  // CC-OFF(G.FMT.02) project code style
               spec.has_value()) {                       // CC-OFF(G.FMT.02-CPP) project code style
        auto ifTrue = AllocLabel();
        if (ltype->PossiblyETSNullish() || rtype->PossiblyETSNullish()) {
            HandlePossiblyNullishEquality<IS_STRICT>(node, lhs, rhs, ifFalse, ifTrue);
        }
        LoadAccumulator(node, rhs);
        AssumeNonNullish(node, spec->first);
        StoreAccumulator(node, rhs);
        LoadAccumulator(node, lhs);
        AssumeNonNullish(node, spec->first);
        CallExact(node, spec->second, lhs, rhs);
        BranchIfFalse(node, ifFalse);
        SetLabel(node, ifTrue);
    } else {
        EmitEtsEquals<IS_STRICT>(node, lhs, rhs);
        BranchIfFalse(node, ifFalse);
    }
    SetAccumulatorType(nullptr);
}

void ETSGen::CompileStatements(const ArenaVector<ir::Statement *> &statements)
{
    for (const auto *stmt : statements) {
        stmt->Compile(this);
    }
}

void ETSGen::Negate(const ir::AstNode *node)
{
    auto typeKind = checker::ETSChecker::TypeKind(GetAccumulatorType());

    switch (typeKind) {
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::INT: {
            Sa().Emit<Neg>(node);
            return;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<NegWide>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<Fneg>(node);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<FnegWide>(node);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::LogicalNot(const ir::AstNode *node)
{
    ResolveConditionalResultIfFalse<true, false>(node);
    Sa().Emit<Xori>(node, 1);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::LoadAccumulatorByte(const ir::AstNode *node, int8_t number)
{
    LoadAccumulatorNumber<int8_t>(node, number, checker::TypeFlag::BYTE);
}

void ETSGen::LoadAccumulatorShort(const ir::AstNode *node, int16_t number)
{
    LoadAccumulatorNumber<int16_t>(node, number, checker::TypeFlag::SHORT);
}

void ETSGen::LoadAccumulatorInt(const ir::AstNode *node, int32_t number)
{
    LoadAccumulatorNumber<int32_t>(node, number, checker::TypeFlag::INT);
}

void ETSGen::LoadAccumulatorWideInt(const ir::AstNode *node, int64_t number)
{
    LoadAccumulatorNumber<int64_t>(node, number, checker::TypeFlag::LONG);
}

void ETSGen::LoadAccumulatorFloat(const ir::AstNode *node, float number)
{
    LoadAccumulatorNumber<float>(node, number, checker::TypeFlag::FLOAT);
}

void ETSGen::LoadAccumulatorDouble(const ir::AstNode *node, double number)
{
    LoadAccumulatorNumber<double>(node, number, checker::TypeFlag::DOUBLE);
}

void ETSGen::LoadAccumulatorBoolean(const ir::AstNode *node, bool value)
{
    Sa().Emit<Ldai>(node, value ? 1 : 0);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
    ApplyConversion(node, Checker()->GlobalETSBooleanType());
}

void ETSGen::LoadAccumulatorString(const ir::AstNode *node, util::StringView str)
{
    Sa().Emit<LdaStr>(node, str);
    SetAccumulatorType(Checker()->GlobalETSStringLiteralType());
}

void ETSGen::LoadAccumulatorBigInt(const ir::AstNode *node, util::StringView str)
{
    Sa().Emit<LdaStr>(node, str);
    SetAccumulatorType(Checker()->GlobalETSBigIntType());
}

void ETSGen::LoadAccumulatorUndefined(const ir::AstNode *node)
{
    Sa().Emit<LdaNull>(node);
    SetAccumulatorType(Checker()->GlobalETSUndefinedType());
}

void ETSGen::LoadAccumulatorNull([[maybe_unused]] const ir::AstNode *node)
{
#ifdef PANDA_WITH_ETS
    Sa().Emit<EtsLdnullvalue>(node);
    SetAccumulatorType(Checker()->GlobalETSNullType());
#else
    ES2PANDA_UNREACHABLE();
#endif  // PANDA_WITH_ETS
}

void ETSGen::LoadAccumulatorChar(const ir::AstNode *node, char16_t value)
{
    Sa().Emit<Ldai>(node, value);
    SetAccumulatorType(Checker()->GlobalCharType());
    ApplyConversion(node, Checker()->GlobalCharType());
}

void ETSGen::Unary(const ir::AstNode *node, lexer::TokenType op)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
            break;  // NOP -> Unary numeric promotion is performed
        case lexer::TokenType::PUNCTUATOR_MINUS:
            UnaryMinus(node);
            break;
        case lexer::TokenType::PUNCTUATOR_TILDE:
            UnaryTilde(node);
            break;
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK:
            LogicalNot(node);
            break;
        default:
            ES2PANDA_UNREACHABLE();
    }
}

void ETSGen::UnaryMinus(const ir::AstNode *node)
{
    ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
    if (GetAccumulatorType()->IsETSBigIntType()) {
        const VReg value = AllocReg();
        StoreAccumulator(node, value);
        CallExact(node, Signatures::BUILTIN_BIGINT_NEGATE, value);
        return;
    }

    switch (checker::ETSChecker::ETSType(GetAccumulatorType())) {
        case checker::TypeFlag::LONG: {
            Sa().Emit<NegWide>(node);
            break;
        }
        case checker::TypeFlag::INT:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::BYTE: {
            Sa().Emit<Neg>(node);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<FnegWide>(node);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<Fneg>(node);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::UnaryTilde(const ir::AstNode *node)
{
    ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
    if (GetAccumulatorType()->IsETSBigIntType()) {
        const VReg value = AllocReg();
        StoreAccumulator(node, value);
        CallExact(node, Signatures::BUILTIN_BIGINT_OPERATOR_BITWISE_NOT, value);
        SetAccumulatorType(Checker()->GlobalETSBigIntType());
        return;
    }

    switch (checker::ETSChecker::ETSType(GetAccumulatorType())) {
        case checker::TypeFlag::LONG: {
            Sa().Emit<NotWide>(node);
            break;
        }
        case checker::TypeFlag::INT:
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::BYTE: {
            Sa().Emit<Not>(node);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::Update(const ir::AstNode *node, lexer::TokenType op)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS: {
            UpdateOperator<Add2Wide, Addi, Fadd2Wide, Fadd2>(node);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS: {
            UpdateOperator<Sub2Wide, Subi, Fsub2Wide, Fsub2>(node);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::UpdateBigInt(const ir::Expression *node, VReg arg, lexer::TokenType op)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS: {
            CallBigIntUnaryOperator(node, arg, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_INCREMENT);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS: {
            CallBigIntUnaryOperator(node, arg, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_DECREMENT);
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

void ETSGen::StringBuilderAppend(const ir::AstNode *node, VReg builder)
{
    RegScope rs(this);
    util::StringView signature {};

    node->Compile(this);

    std::unordered_map<checker::TypeFlag, std::string_view> typeFlagToSignaturesMap {
        {checker::TypeFlag::ETS_BOOLEAN, Signatures::BUILTIN_STRING_BUILDER_APPEND_BOOLEAN},
        {checker::TypeFlag::CHAR, Signatures::BUILTIN_STRING_BUILDER_APPEND_CHAR},
        {checker::TypeFlag::SHORT, Signatures::BUILTIN_STRING_BUILDER_APPEND_INT},
        {checker::TypeFlag::BYTE, Signatures::BUILTIN_STRING_BUILDER_APPEND_INT},
        {checker::TypeFlag::INT, Signatures::BUILTIN_STRING_BUILDER_APPEND_INT},
        {checker::TypeFlag::LONG, Signatures::BUILTIN_STRING_BUILDER_APPEND_LONG},
        {checker::TypeFlag::FLOAT, Signatures::BUILTIN_STRING_BUILDER_APPEND_FLOAT},
        {checker::TypeFlag::DOUBLE, Signatures::BUILTIN_STRING_BUILDER_APPEND_DOUBLE},
    };

    auto search = typeFlagToSignaturesMap.find(checker::ETSChecker::ETSType(GetAccumulatorType()));
    if (search != typeFlagToSignaturesMap.end()) {
        signature = search->second;
    } else {
        signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_BUILTIN_STRING;
    }

    ES2PANDA_ASSERT(GetAccumulatorType() != nullptr);
    if (GetAccumulatorType()->IsETSReferenceType() && !GetAccumulatorType()->IsETSStringType()) {
        if (GetAccumulatorType()->PossiblyETSUndefined()) {
            Label *ifUndefined = AllocLabel();
            Label *end = AllocLabel();
            BranchIfUndefined(node, ifUndefined);
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_OBJECT_TO_STRING, dummyReg_, 0);
            JumpTo(node, end);

            SetLabel(node, ifUndefined);
            LoadAccumulatorString(node, "undefined");

            SetLabel(node, end);
        } else {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_OBJECT_TO_STRING, dummyReg_, 0);
        }
    }

    VReg arg0 = AllocReg();
    StoreAccumulator(node, arg0);

    CallExact(node, signature, builder, arg0);
    SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalStringBuilderBuiltinType());
}

void ETSGen::AppendString(const ir::Expression *const expr, const VReg builder)
{
    ES2PANDA_ASSERT((expr->IsBinaryExpression() &&
                     expr->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS) ||
                    (expr->IsAssignmentExpression() &&
                     expr->AsAssignmentExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS_EQUAL));

    if (expr->IsBinaryExpression()) {
        StringBuilder(expr->AsBinaryExpression()->Left(), expr->AsBinaryExpression()->Right(), builder);
    } else {
        StringBuilder(expr->AsAssignmentExpression()->Left(), expr->AsAssignmentExpression()->Right(), builder);
    }
}

void ETSGen::StringBuilder(const ir::Expression *const left, const ir::Expression *const right, const VReg builder)
{
    if (left->IsBinaryExpression() && left->TsType()->IsETSStringType()) {
        AppendString(left->AsBinaryExpression(), builder);
    } else {
        StringBuilderAppend(left, builder);
    }

    StringBuilderAppend(right, builder);
}

void ETSGen::BuildString(const ir::Expression *node)
{
    RegScope rs(this);

    Ra().Emit<InitobjShort, 0>(node, Signatures::BUILTIN_STRING_BUILDER_CTOR, dummyReg_, dummyReg_);
    SetAccumulatorType(Checker()->GlobalStringBuilderBuiltinType());

    auto builder = AllocReg();
    StoreAccumulator(node, builder);

    AppendString(node, builder);
    CallExact(node, Signatures::BUILTIN_STRING_BUILDER_TO_STRING, builder);

    SetAccumulatorType(node->TsType());
}

void ETSGen::CallBigIntUnaryOperator(const ir::Expression *node, VReg arg, const util::StringView signature)
{
    LoadAccumulator(node, arg);
    CallExact(node, signature, arg);
    SetAccumulatorType(Checker()->GlobalETSBigIntType());
}

void ETSGen::CallBigIntBinaryOperator(const ir::Expression *node, VReg lhs, VReg rhs, const util::StringView signature)
{
    LoadAccumulator(node, lhs);
    CallExact(node, signature, lhs, rhs);
    SetAccumulatorType(Checker()->GlobalETSBigIntType());
}

void ETSGen::CallBigIntBinaryComparison(const ir::Expression *node, VReg lhs, VReg rhs,
                                        const util::StringView signature)
{
    LoadAccumulator(node, lhs);
    CallExact(node, signature, lhs, rhs);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::BuildTemplateString(const ir::TemplateLiteral *node)
{
    RegScope rs(this);

    Ra().Emit<InitobjShort, 0>(node, Signatures::BUILTIN_STRING_BUILDER_CTOR, dummyReg_, dummyReg_);
    SetAccumulatorType(Checker()->GlobalStringBuilderBuiltinType());

    auto builder = AllocReg();
    StoreAccumulator(node, builder);

    // Just to reduce extra nested level(s):
    auto const appendExpressions = [this, &builder](ArenaVector<ir::Expression *> const &expressions,
                                                    ArenaVector<ir::TemplateElement *> const &quasis) -> void {
        auto const num = expressions.size();
        std::size_t i = 0U;

        while (i < num) {
            StringBuilderAppend(expressions[i], builder);
            if (!quasis[++i]->Raw().Empty()) {
                StringBuilderAppend(quasis[i], builder);
            }
        }
    };

    if (auto const &quasis = node->Quasis(); !quasis.empty()) {
        if (!quasis[0]->Raw().Empty()) {
            StringBuilderAppend(quasis[0], builder);
        }

        if (auto const &expressions = node->Expressions(); !expressions.empty()) {
            appendExpressions(expressions, quasis);
        }
    }

    CallExact(node, Signatures::BUILTIN_STRING_BUILDER_TO_STRING, builder);

    SetAccumulatorType(node->TsType());
}

void ETSGen::NewObject(const ir::AstNode *const node, const util::StringView name, VReg athis)
{
    Ra().Emit<Newobj>(node, athis, name);
    SetVRegType(athis, Checker()->GlobalETSObjectType());
}

void ETSGen::NewArray(const ir::AstNode *const node, const VReg arr, const VReg dim, const checker::Type *const arrType)
{
    std::stringstream ss;
    arrType->ToAssemblerTypeWithRank(ss);
    const auto res = ProgElement()->Strings().emplace(ss.str());

    Ra().Emit<Newarr>(node, arr, dim, util::StringView(*res.first));
    SetVRegType(arr, arrType);
}

void ETSGen::LoadResizableArrayLength(const ir::AstNode *node)
{
    Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_ARRAY_LENGTH, dummyReg_, 0);
    Sa().Emit<F64toi32>(node);
    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::LoadResizableArrayElement(const ir::AstNode *node, const VReg arrObj, const VReg arrIndex)
{
    auto *vRegType = GetVRegType(arrObj);
    ES2PANDA_ASSERT(vRegType != nullptr);
    auto *elementType = vRegType->AsETSResizableArrayType()->ElementType();
    Ra().Emit<CallVirtShort>(node, Signatures::BUILTIN_ARRAY_GET_ELEMENT, arrObj, arrIndex);
    SetAccumulatorType(elementType);
}

void ETSGen::LoadArrayLength(const ir::AstNode *node, VReg arrayReg)
{
    Ra().Emit<Lenarr>(node, arrayReg);
    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::LoadArrayElement(const ir::AstNode *node, VReg objectReg)
{
    ES2PANDA_ASSERT(GetVRegType(objectReg) != nullptr);
    auto *elementType = GetVRegType(objectReg)->AsETSArrayType()->ElementType();
    if (elementType->IsETSReferenceType()) {
        Ra().Emit<LdarrObj>(node, objectReg);
        SetAccumulatorType(elementType);
        return;
    }
    switch (checker::ETSChecker::ETSType(elementType)) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Ldarr8>(node, objectReg);
            break;
        }
        case checker::TypeFlag::CHAR: {
            Ra().Emit<Ldarru16>(node, objectReg);
            break;
        }
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Ldarr16>(node, objectReg);
            break;
        }
        case checker::TypeFlag::INT: {
            Ra().Emit<Ldarr>(node, objectReg);
            break;
        }
        case checker::TypeFlag::LONG: {
            Ra().Emit<LdarrWide>(node, objectReg);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<Fldarr32>(node, objectReg);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<FldarrWide>(node, objectReg);
            break;
        }

        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(elementType);
}

void ETSGen::StoreArrayElement(const ir::AstNode *node, VReg objectReg, VReg index, const checker::Type *elementType)
{
    if (elementType->IsETSReferenceType()) {
        Ra().Emit<StarrObj>(node, objectReg, index);
        SetAccumulatorType(elementType);
        return;
    }
    switch (checker::ETSChecker::ETSType(elementType)) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Starr8>(node, objectReg, index);
            break;
        }
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Starr16>(node, objectReg, index);
            break;
        }
        case checker::TypeFlag::INT: {
            Ra().Emit<Starr>(node, objectReg, index);
            break;
        }
        case checker::TypeFlag::LONG: {
            Ra().Emit<StarrWide>(node, objectReg, index);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<Fstarr32>(node, objectReg, index);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<FstarrWide>(node, objectReg, index);
            break;
        }

        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    SetAccumulatorType(elementType);
}

util::StringView ETSGen::GetTupleMemberNameForIndex(const std::size_t index) const
{
    return util::UString("$" + std::to_string(index), Allocator()).View();
}

void ETSGen::LoadTupleElement(const ir::AstNode *node, VReg objectReg, const checker::Type *elementType,
                              std::size_t index)
{
    ES2PANDA_ASSERT(GetVRegType(objectReg) != nullptr && GetVRegType(objectReg)->IsETSTupleType());
    const auto propName = FormClassPropReference(GetVRegType(objectReg)->AsETSTupleType()->GetWrapperType(),
                                                 GetTupleMemberNameForIndex(index));

    // NOTE (smartin): remove after generics without type erasure is possible
    const auto *const boxedElementType = Checker()->MaybeBoxType(elementType);
    LoadProperty(node, boxedElementType, objectReg, propName);
}

void ETSGen::StoreTupleElement(const ir::AstNode *node, VReg objectReg, const checker::Type *elementType,
                               std::size_t index)
{
    ES2PANDA_ASSERT(GetVRegType(objectReg) != nullptr && GetVRegType(objectReg)->IsETSTupleType());
    const auto *const tupleType = GetVRegType(objectReg)->AsETSTupleType();
    SetVRegType(objectReg, tupleType->GetWrapperType());

    // NOTE (smartin): remove after generics without type erasure is possible
    const auto *const boxedElementType = Checker()->MaybeBoxType(elementType);
    StoreProperty(node, boxedElementType, objectReg, GetTupleMemberNameForIndex(index));
}

template <typename T>
void ETSGen::IncrementImmediateRegister(const ir::AstNode *node, VReg reg, const checker::TypeFlag valueType,
                                        T const value)
{
    switch (valueType) {
        // NOTE: operand of increment instruction (INCI) is defined in spec as 32-bit integer,
        // but its current implementation actually can work with 64-bit integers as well.
        case checker::TypeFlag::INT: {
            Ra().Emit<Inci>(node, reg, static_cast<checker::IntType::UType>(value));
            break;
        }
        case checker::TypeFlag::CHAR: {
            Ra().Emit<Inci>(node, reg, static_cast<checker::CharType::UType>(value));
            break;
        }
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Inci>(node, reg, static_cast<checker::ShortType::UType>(value));
            break;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
            [[fallthrough]];
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Inci>(node, reg, static_cast<checker::ByteType::UType>(value));
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template void ETSGen::IncrementImmediateRegister<int32_t>(const ir::AstNode *node, VReg reg,
                                                          const checker::TypeFlag valueType, int32_t const value);

void ETSGen::LoadStringLength(const ir::AstNode *node)
{
    Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_STRING_LENGTH, dummyReg_, 0);
    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::FloatIsNaN(const ir::AstNode *node)
{
    Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_FLOAT_IS_NAN, dummyReg_, 0);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::DoubleIsNaN(const ir::AstNode *node)
{
    Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_DOUBLE_IS_NAN, dummyReg_, 0);
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::LoadStringChar(const ir::AstNode *node, const VReg stringObj, const VReg charIndex)
{
    Ra().Emit<CallShort>(node, Signatures::BUILTIN_STRING_CHAR_AT, stringObj, charIndex);
    SetAccumulatorType(Checker()->GlobalCharType());
}

void ETSGen::ThrowException(const ir::Expression *expr)
{
    RegScope rs(this);

    expr->Compile(this);
    VReg arg = AllocReg();
    StoreAccumulator(expr, arg);
    EmitThrow(expr, arg);
}

bool ETSGen::ExtendWithFinalizer(ir::AstNode const *node, const ir::AstNode *originalNode, Label *prevFinnaly)
{
    ES2PANDA_ASSERT(originalNode != nullptr);

    if (node == nullptr || !node->IsStatement()) {
        return false;
    }

    if ((originalNode->IsContinueStatement() && originalNode->AsContinueStatement()->Target() == node) ||
        (originalNode->IsBreakStatement() && originalNode->AsBreakStatement()->Target() == node)) {
        return false;
    }

    if (node->IsTryStatement() && node->AsTryStatement()->HasFinalizer()) {
        Label *beginLabel = nullptr;

        if (prevFinnaly == nullptr) {
            beginLabel = AllocLabel();
            Branch(originalNode, beginLabel);
        } else {
            beginLabel = prevFinnaly;
        }

        Label *endLabel = AllocLabel();

        if (node->Parent() != nullptr && node->Parent()->IsStatement()) {
            if (!ExtendWithFinalizer(node->Parent(), originalNode, endLabel)) {
                endLabel = nullptr;
            }
        } else {
            endLabel = nullptr;
        }

        LabelPair insertion = compiler::LabelPair(beginLabel, endLabel);

        auto *tryStatement = const_cast<ir::AstNode *>(node)->AsTryStatement();
        tryStatement->AddFinalizerInsertion(insertion, originalNode->AsStatement());

        return true;
    }

    auto *parent = node->Parent();

    if (parent == nullptr || !parent->IsStatement()) {
        return false;
    }

    if (parent->IsTryStatement() && node->IsBlockStatement() &&
        parent->AsTryStatement()->FinallyBlock() == node->AsBlockStatement()) {
        parent = parent->Parent();
    }

    return ExtendWithFinalizer(parent, originalNode, prevFinnaly);
}

util::StringView ETSGen::ToAssemblerType(const es2panda::checker::Type *type) const
{
    ES2PANDA_ASSERT(type != nullptr && type->IsETSReferenceType());

    std::stringstream ss;
    type->ToAssemblerTypeWithRank(ss);
    return util::UString(ss.str(), Allocator()).View();
}

template <typename T>
void ETSGen::SetAccumulatorTargetType(const ir::AstNode *node, checker::TypeFlag typeKind, T number)
{
    switch (typeKind) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Sa().Emit<Ldai>(node, static_cast<checker::ByteType::UType>(number));
            SetAccumulatorType(Checker()->GlobalByteType());
            break;
        }
        case checker::TypeFlag::CHAR: {
            Sa().Emit<Ldai>(node, static_cast<checker::CharType::UType>(number));
            SetAccumulatorType(Checker()->GlobalCharType());
            break;
        }
        case checker::TypeFlag::SHORT: {
            Sa().Emit<Ldai>(node, static_cast<checker::ShortType::UType>(number));
            SetAccumulatorType(Checker()->GlobalShortType());
            break;
        }
        case checker::TypeFlag::INT: {
            Sa().Emit<Ldai>(node, static_cast<checker::IntType::UType>(number));
            SetAccumulatorType(Checker()->GlobalIntType());
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<LdaiWide>(node, static_cast<checker::LongType::UType>(number));
            SetAccumulatorType(Checker()->GlobalLongType());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<Fldai>(node, static_cast<checker::FloatType::UType>(number));
            SetAccumulatorType(Checker()->GlobalFloatType());
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<FldaiWide>(node, static_cast<checker::DoubleType::UType>(number));
            SetAccumulatorType(Checker()->GlobalDoubleType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

template <typename T>
void ETSGen::LoadAccumulatorNumber(const ir::AstNode *node, T number, checker::TypeFlag targetType)
{
    // NOTE (smartin): refactor this to do at a more appropriate place
    const bool isContextTargetTypeValid =
        targetType_ != nullptr &&
        (!targetType_->IsETSObjectType() && !targetType_->IsETSUnionType() && !targetType_->IsETSArrayType() &&
         !targetType_->IsETSTupleType() && !targetType_->IsETSTypeParameter());

    auto typeKind = isContextTargetTypeValid ? checker::ETSChecker::TypeKind(targetType_) : targetType;

    SetAccumulatorTargetType(node, typeKind, number);

    if (targetType_ && (targetType_->IsETSObjectType() || targetType_->IsETSUnionType())) {
        ApplyConversion(node, targetType_);
    }
}
}  // namespace ark::es2panda::compiler
