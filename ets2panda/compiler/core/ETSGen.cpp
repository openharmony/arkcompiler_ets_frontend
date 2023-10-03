/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ETSGen.h"

#include "ir/base/scriptFunction.h"
#include "ir/base/classDefinition.h"
#include "ir/statement.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "binder/variableFlags.h"
#include "compiler/base/lreference.h"
#include "compiler/base/catchTable.h"
#include "compiler/core/dynamicContext.h"
#include "compiler/core/compilerContext.h"
#include "binder/ETSBinder.h"
#include "binder/variable.h"
#include "checker/types/type.h"
#include "checker/types/typeFlag.h"
#include "checker/checker.h"
#include "checker/ETSchecker.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/types/ets/types.h"
#include "parser/program/program.h"

namespace panda::es2panda::compiler {

ETSGen::ETSGen(ArenaAllocator *allocator, RegSpiller *spiller, CompilerContext *context, binder::FunctionScope *scope,
               ProgramElement *program_element) noexcept
    : CodeGen(allocator, spiller, context, scope, program_element),
      containing_object_type_(util::Helpers::GetContainingObjectType(RootNode()))
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

const checker::ETSChecker *ETSGen::Checker() const noexcept
{
    return Context()->Checker()->AsETSChecker();
}

const binder::ETSBinder *ETSGen::Binder() const noexcept
{
    return Context()->Binder()->AsETSBinder();
}

const checker::Type *ETSGen::ReturnType() const noexcept
{
    return RootNode()->AsScriptFunction()->Signature()->ReturnType();
}

const checker::ETSObjectType *ETSGen::ContainingObjectType() const noexcept
{
    return containing_object_type_;
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
                                                const checker::Type *const target_type)
{
    ApplyConversion(node, target_type);
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
    const auto *const acc_type = GetAccumulatorType();

    if (acc_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Ra().Emit<StaObj>(node, vreg);
    } else if (acc_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Ra().Emit<StaWide>(node, vreg);
    } else {
        Ra().Emit<Sta>(node, vreg);
    }

    SetVRegType(vreg, acc_type);
}

void ETSGen::LoadAccumulator(const ir::AstNode *node, VReg vreg)
{
    const auto *const vreg_type = GetVRegType(vreg);

    if (vreg_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Ra().Emit<LdaObj>(node, vreg);
    } else if (vreg_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Ra().Emit<LdaWide>(node, vreg);
    } else {
        Ra().Emit<Lda>(node, vreg);
    }

    SetAccumulatorType(vreg_type);
}

IRNode *ETSGen::AllocMov(const ir::AstNode *const node, const VReg vd, const VReg vs)
{
    const auto *const source_type = GetVRegType(vs);

    auto *const mov = [this, source_type, node, vd, vs]() -> IRNode * {
        if (source_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            return Allocator()->New<MovObj>(node, vd, vs);
        }
        if (source_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
            return Allocator()->New<MovWide>(node, vd, vs);
        }
        return Allocator()->New<Mov>(node, vd, vs);
    }();

    SetVRegType(vd, source_type);
    return mov;
}

IRNode *ETSGen::AllocMov(const ir::AstNode *const node, OutVReg vd, const VReg vs)
{
    ASSERT(vd.type != OperandType::ANY && vd.type != OperandType::NONE);

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

checker::Type const *ETSGen::TypeForVar(binder::Variable const *var) const noexcept
{
    return Checker()->MaybeBoxedType(var, Allocator());
}

void ETSGen::MoveVreg(const ir::AstNode *const node, const VReg vd, const VReg vs)
{
    const auto *const source_type = GetVRegType(vs);

    if (source_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Ra().Emit<MovObj>(node, vd, vs);
    } else if (source_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Ra().Emit<MovWide>(node, vd, vs);
    } else {
        Ra().Emit<Mov>(node, vd, vs);
    }

    SetVRegType(vd, source_type);
}

util::StringView ETSGen::FormDynamicModulePropReference(const binder::Variable *var)
{
    ASSERT(util::Helpers::IsDynamicModuleVariable(var) || util::Helpers::IsDynamicNamespaceVariable(var));

    auto *import = var->Declaration()->Node()->Parent()->AsETSImportDeclaration();

    return FormDynamicModulePropReference(import);
}

void ETSGen::LoadAccumulatorDynamicModule(const ir::AstNode *node, const ir::ETSImportDeclaration *import)
{
    ASSERT(import->Language().IsDynamic());
    LoadStaticProperty(node, Checker()->GlobalBuiltinDynamicType(import->Language()),
                       FormDynamicModulePropReference(import));
}

util::StringView ETSGen::FormDynamicModulePropReference(const ir::ETSImportDeclaration *import)
{
    std::stringstream ss;
    auto pkg_name = Binder()->Program()->GetPackageName();
    if (!pkg_name.Empty()) {
        ss << pkg_name << '.';
    }
    ss << compiler::Signatures::DYNAMIC_MODULE_CLASS;
    ss << '.';
    ss << import->AssemblerName();

    return util::UString(ss.str(), Allocator()).View();
}

void ETSGen::LoadDynamicModuleVariable(const ir::AstNode *node, binder::Variable const *const var)
{
    RegScope rs(this);

    auto *import = util::Helpers::ImportDeclarationForDynamicVar(var);

    LoadStaticProperty(node, var->TsType(), FormDynamicModulePropReference(var));

    auto obj_reg = AllocReg();
    StoreAccumulator(node, obj_reg);

    auto *id = var->Declaration()->Node()->AsImportSpecifier()->Imported();
    auto lang = import->Language();
    LoadPropertyDynamic(node, Checker()->GlobalBuiltinDynamicType(lang), obj_reg, id->Name(), lang);

    if (target_type_ != nullptr) {
        ApplyConversion(node, target_type_);
    }
}

void ETSGen::LoadDynamicNamespaceVariable(const ir::AstNode *node, binder::Variable const *const var)
{
    LoadStaticProperty(node, var->TsType(), FormDynamicModulePropReference(var));
}

void ETSGen::LoadVar(const ir::AstNode *node, binder::Variable const *const var)
{
    if (util::Helpers::IsDynamicModuleVariable(var)) {
        LoadDynamicModuleVariable(node, var);
        return;
    }

    if (util::Helpers::IsDynamicNamespaceVariable(var)) {
        LoadDynamicNamespaceVariable(node, var);
        return;
    }

    auto *local = var->AsLocalVariable();

    switch (ETSLReference::ResolveReferenceKind(var)) {
        case ReferenceKind::STATIC_FIELD: {
            auto full_name = FormClassPropReference(var);
            LoadStaticProperty(node, var->TsType(), full_name);
            break;
        }
        case ReferenceKind::FIELD: {
            const auto full_name = FormClassPropReference(GetVRegType(GetThisReg())->AsETSObjectType(), var->Name());
            LoadProperty(node, var->TsType(), GetThisReg(), full_name);
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
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    if (var->HasFlag(binder::VariableFlags::BOXED) && !node->AsIdentifier()->IsIgnoreBox()) {
        EmitLocalBoxGet(node, var->TsType());
    }

    if (target_type_ != nullptr) {
        ApplyConversion(node, target_type_);
    }
}

void ETSGen::StoreVar(const ir::AstNode *node, const binder::ConstScopeFindResult &result)
{
    auto *local = result.variable->AsLocalVariable();
    ApplyConversion(node, local->TsType());

    switch (ETSLReference::ResolveReferenceKind(result.variable)) {
        case ReferenceKind::STATIC_FIELD: {
            auto full_name = FormClassPropReference(result.variable);
            StoreStaticProperty(node, result.variable->TsType(), full_name);
            break;
        }
        case ReferenceKind::FIELD: {
            StoreProperty(node, result.variable->TsType(), GetThisReg(), result.name);
            break;
        }
        case ReferenceKind::LOCAL: {
            if (local->HasFlag(binder::VariableFlags::BOXED)) {
                EmitLocalBoxSet(node, local);
            } else {
                StoreAccumulator(node, local->Vreg());
            }
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSGen::EmitGetter(const ir::AstNode *node, const VReg vreg, ir::ScriptFunction *script_func)
{
    auto *signature = script_func->Signature();
    CallThisVirtual(node, vreg, signature, script_func->Params());
    SetAccumulatorType(signature->ReturnType());
}

util::StringView ETSGen::FormClassPropReference(const checker::ETSObjectType *class_type, const util::StringView &name)
{
    std::stringstream ss;

    auto *iter = class_type;
    std::string full_name = class_type->AssemblerName().Mutf8();
    while (iter->EnclosingType() != nullptr) {
        auto enclosing_name = iter->EnclosingType()->Name().Mutf8().append(".").append(full_name);
        full_name = enclosing_name;
        iter = iter->EnclosingType();
    }

    if (full_name != class_type->AssemblerName().Mutf8()) {
        full_name.append(".").append(Signatures::ETS_GLOBAL);
    }
    ss << full_name << '.' << name;
    auto res = ProgElement()->Strings().emplace(ss.str());

    return util::StringView(*res.first);
}

util::StringView ETSGen::FormClassPropReference(binder::Variable const *const var)
{
    auto containing_object_type = util::Helpers::GetContainingObjectType(var->Declaration()->Node());
    return FormClassPropReference(containing_object_type, var->Name());
}

void ETSGen::StoreStaticOwnProperty(const ir::AstNode *node, const checker::Type *prop_type,
                                    const util::StringView &name)
{
    util::StringView full_name = FormClassPropReference(containing_object_type_, name);
    StoreStaticProperty(node, prop_type, full_name);
}

void ETSGen::StoreStaticProperty(const ir::AstNode *const node, const checker::Type *prop_type,
                                 const util::StringView &full_name)
{
    if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Sa().Emit<StstaticObj>(node, full_name);
    } else if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Sa().Emit<StstaticWide>(node, full_name);
    } else {
        Sa().Emit<Ststatic>(node, full_name);
    }
}

void ETSGen::LoadStaticProperty(const ir::AstNode *const node, const checker::Type *prop_type,
                                const util::StringView &full_name)
{
    if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Sa().Emit<LdstaticObj>(node, full_name);
    } else if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Sa().Emit<LdstaticWide>(node, full_name);
    } else {
        Sa().Emit<Ldstatic>(node, full_name);
    }

    SetAccumulatorType(prop_type);
}

void ETSGen::StoreProperty(const ir::AstNode *const node, const checker::Type *prop_type, const VReg obj_reg,
                           const util::StringView &name)
{
    const auto full_name = FormClassPropReference(GetVRegType(obj_reg)->AsETSObjectType(), name);

    if (node->IsIdentifier() && node->AsIdentifier()->Variable()->HasFlag(binder::VariableFlags::BOXED)) {
        prop_type = Checker()->GlobalBuiltinBoxType(prop_type);
    }
    if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Ra().Emit<StobjObj>(node, obj_reg, full_name);
    } else if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Ra().Emit<StobjWide>(node, obj_reg, full_name);
    } else {
        Ra().Emit<Stobj>(node, obj_reg, full_name);
    }
}

void ETSGen::LoadProperty(const ir::AstNode *const node, const checker::Type *prop_type, const VReg obj_reg,
                          const util::StringView &full_name)
{
    if (node->IsIdentifier() && node->AsIdentifier()->Variable()->HasFlag(binder::VariableFlags::BOXED)) {
        prop_type = Checker()->GlobalBuiltinBoxType(prop_type);
    }
    if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Ra().Emit<LdobjObj>(node, obj_reg, full_name);
    } else if (prop_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Ra().Emit<LdobjWide>(node, obj_reg, full_name);
    } else {
        Ra().Emit<Ldobj>(node, obj_reg, full_name);
    }

    SetAccumulatorType(prop_type);
}

void ETSGen::StorePropertyDynamic(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                                  const util::StringView &prop_name, Language lang)
{
    std::string_view method_name {};
    if (prop_type->IsETSBooleanType()) {
        method_name = Signatures::Dynamic::SetPropertyBooleanBuiltin(lang);
    } else if (prop_type->IsByteType()) {
        method_name = Signatures::Dynamic::SetPropertyByteBuiltin(lang);
    } else if (prop_type->IsCharType()) {
        method_name = Signatures::Dynamic::SetPropertyCharBuiltin(lang);
    } else if (prop_type->IsShortType()) {
        method_name = Signatures::Dynamic::SetPropertyShortBuiltin(lang);
    } else if (prop_type->IsIntType()) {
        method_name = Signatures::Dynamic::SetPropertyIntBuiltin(lang);
    } else if (prop_type->IsLongType()) {
        method_name = Signatures::Dynamic::SetPropertyLongBuiltin(lang);
    } else if (prop_type->IsFloatType()) {
        method_name = Signatures::Dynamic::SetPropertyFloatBuiltin(lang);
    } else if (prop_type->IsDoubleType()) {
        method_name = Signatures::Dynamic::SetPropertyDoubleBuiltin(lang);
    } else if (prop_type->IsETSStringType()) {
        method_name = Signatures::Dynamic::SetPropertyStringBuiltin(lang);
    } else if (prop_type->IsETSObjectType()) {
        ASSERT(prop_type->IsETSDynamicType());
        method_name = Signatures::Dynamic::SetPropertyDynamicBuiltin(lang);
    } else {
        ASSERT_PRINT(false, "Unsupported property type");
    }

    RegScope rs(this);

    // Load property value
    VReg prop_value_reg = AllocReg();
    StoreAccumulator(node, prop_value_reg);

    // Load property name
    LoadAccumulatorString(node, prop_name);
    VReg prop_name_reg = AllocReg();
    StoreAccumulator(node, prop_name_reg);

    // Set property by name
    Ra().Emit<Call, 3>(node, method_name, obj_reg, prop_name_reg, prop_value_reg, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalVoidType());
}

void ETSGen::LoadPropertyDynamic(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                                 const util::StringView &prop_name, Language lang)
{
    std::string_view method_name {};
    if (prop_type->IsETSBooleanType()) {
        method_name = Signatures::Dynamic::GetPropertyBooleanBuiltin(lang);
    } else if (prop_type->IsByteType()) {
        method_name = Signatures::Dynamic::GetPropertyByteBuiltin(lang);
    } else if (prop_type->IsCharType()) {
        method_name = Signatures::Dynamic::GetPropertyCharBuiltin(lang);
    } else if (prop_type->IsShortType()) {
        method_name = Signatures::Dynamic::GetPropertyShortBuiltin(lang);
    } else if (prop_type->IsIntType()) {
        method_name = Signatures::Dynamic::GetPropertyIntBuiltin(lang);
    } else if (prop_type->IsLongType()) {
        method_name = Signatures::Dynamic::GetPropertyLongBuiltin(lang);
    } else if (prop_type->IsFloatType()) {
        method_name = Signatures::Dynamic::GetPropertyFloatBuiltin(lang);
    } else if (prop_type->IsDoubleType()) {
        method_name = Signatures::Dynamic::GetPropertyDoubleBuiltin(lang);
    } else if (prop_type->IsETSStringType()) {
        method_name = Signatures::Dynamic::GetPropertyStringBuiltin(lang);
    } else if (prop_type->IsETSObjectType()) {
        ASSERT(prop_type->IsETSDynamicType());
        method_name = Signatures::Dynamic::GetPropertyDynamicBuiltin(lang);
    } else {
        ASSERT_PRINT(false, "Unsupported property type");
    }

    RegScope rs(this);

    // Load property name
    LoadAccumulatorString(node, prop_name);
    VReg prop_name_object = AllocReg();
    StoreAccumulator(node, prop_name_object);

    // Get property by name
    Ra().Emit<CallShort, 2>(node, method_name, obj_reg, prop_name_object);
    SetAccumulatorType(prop_type);
}

void ETSGen::StoreElementDynamic(const ir::AstNode *node, VReg object_reg, VReg index, Language lang)
{
    std::string_view method_name = Signatures::Dynamic::SetElementDynamicBuiltin(lang);

    RegScope rs(this);

    VReg value_reg = AllocReg();
    StoreAccumulator(node, value_reg);

    // Set property by index
    Ra().Emit<Call, 3>(node, method_name, object_reg, index, value_reg, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalVoidType());
}

void ETSGen::LoadElementDynamic(const ir::AstNode *node, VReg object_reg, Language lang)
{
    std::string_view method_name = Signatures::Dynamic::GetElementDynamicBuiltin(lang);

    RegScope rs(this);

    VReg index_reg = AllocReg();
    StoreAccumulator(node, index_reg);

    // Get property by index
    Ra().Emit<CallShort, 2>(node, method_name, object_reg, index_reg);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(lang));
}

void ETSGen::LoadUndefinedDynamic(const ir::AstNode *node, Language lang)
{
    RegScope rs(this);
    Ra().Emit<CallShort, 0>(node, Signatures::Dynamic::GetUndefinedBuiltin(lang), dummy_reg_, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(lang));
}

void ETSGen::LoadThis(const ir::AstNode *node)
{
    LoadAccumulator(node, GetThisReg());
}

void ETSGen::CreateLambdaObjectFromIdentReference(const ir::AstNode *node, ir::ClassDefinition *lambda_obj)
{
    auto *ctor = lambda_obj->TsType()->AsETSObjectType()->ConstructSignatures()[0];

    if (ctor->Params().empty()) {
        Ra().Emit<InitobjShort>(node, ctor->InternalName(), VReg::RegStart(), VReg::RegStart());
    } else {
        Ra().Emit<InitobjShort>(node, ctor->InternalName(), GetThisReg(), VReg::RegStart());
    }

    SetAccumulatorType(lambda_obj->TsType());
}

void ETSGen::CreateLambdaObjectFromMemberReference(const ir::AstNode *node, ir::Expression *obj,
                                                   ir::ClassDefinition *lambda_obj)
{
    auto *ctor = lambda_obj->TsType()->AsETSObjectType()->ConstructSignatures()[0];
    ArenaVector<ir::Expression *> args(Allocator()->Adapter());

    if (!ctor->Params().empty()) {
        args.push_back(obj);
    }

    InitObject(node, ctor, args);
    SetAccumulatorType(lambda_obj->TsType());
}

// NOLINTBEGIN(cppcoreguidelines-macro-usage, readability-container-size-empty)
#define CONV_LAMBDA_CTOR_ARG(idx)                              \
    ASSERT(idx < arguments.size());                            \
    auto *paramType##idx = signature->Params()[idx]->TsType(); \
    auto ttctx##idx = TargetTypeContext(this, paramType##idx); \
    ApplyConversion(node, paramType##idx)

void ETSGen::InitLambdaObject(const ir::AstNode *node, checker::Signature *signature, std::vector<VReg> &arguments)
{
    RegScope rs(this);
    util::StringView name = signature->InternalName();

    switch (arguments.size()) {
        case 0: {
            Ra().Emit<InitobjShort>(node, name, VReg::RegStart(), VReg::RegStart());
            break;
        }
        case 1: {
            CONV_LAMBDA_CTOR_ARG(0);
            Ra().Emit<InitobjShort>(node, name, arguments[0], VReg::RegStart());
            break;
        }
        case 2: {
            CONV_LAMBDA_CTOR_ARG(0);
            CONV_LAMBDA_CTOR_ARG(1);
            Ra().Emit<InitobjShort>(node, name, arguments[0], arguments[1]);
            break;
        }
        case 3: {
            CONV_LAMBDA_CTOR_ARG(0);
            CONV_LAMBDA_CTOR_ARG(1);
            CONV_LAMBDA_CTOR_ARG(2);
            Ra().Emit<Initobj>(node, name, arguments[0], arguments[1], arguments[2], VReg::RegStart());
            break;
        }
        case 4: {
            CONV_LAMBDA_CTOR_ARG(0);
            CONV_LAMBDA_CTOR_ARG(1);
            CONV_LAMBDA_CTOR_ARG(2);
            CONV_LAMBDA_CTOR_ARG(3);
            Ra().Emit<Initobj>(node, name, arguments[0], arguments[1], arguments[2], arguments[3]);
            break;
        }
        default: {
            VReg arg_start = NextReg();

            for (size_t i = 0; i < arguments.size(); i++) {
                auto ttctx = TargetTypeContext(this, signature->Params()[i]->TsType());
                StoreAccumulator(node, arguments[i]);
            }

            Rra().Emit<InitobjRange>(node, arg_start, arguments.size(), name, arg_start);
            break;
        }
    }
}

#undef CONV_LAMBDA_CTOR_ARG
// NOLINTEND(cppcoreguidelines-macro-usage, readability-container-size-empty)

VReg ETSGen::GetThisReg() const
{
    const auto res = Scope()->Find(binder::Binder::MANDATORY_PARAM_THIS);
    return res.variable->AsLocalVariable()->Vreg();
}

void ETSGen::LoadDefaultValue([[maybe_unused]] const ir::AstNode *node, [[maybe_unused]] const checker::Type *type)
{
    if (type->IsETSObjectType() || type->IsETSArrayType()) {
        LoadAccumulatorNull(node, type);
    } else if (type->IsETSBooleanType()) {
        LoadAccumulatorBoolean(node, type->AsETSBooleanType()->GetValue());
    } else {
        const auto ttctx = TargetTypeContext(this, type);
        LoadAccumulatorInt(node, 0);
    }
}

void ETSGen::EmitReturnVoid(const ir::AstNode *node)
{
    Sa().Emit<ReturnVoid>(node);
}

void ETSGen::LoadBuiltinVoid(const ir::AstNode *node)
{
    LoadStaticProperty(node, Checker()->GlobalBuiltinVoidType(),
                       FormClassPropReference(Checker()->GlobalBuiltinVoidType(), "void_instance"));
}

void ETSGen::ReturnAcc(const ir::AstNode *node)
{
    const auto *const acc_type = GetAccumulatorType();

    if (acc_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        Sa().Emit<ReturnObj>(node);
    } else if (acc_type->HasTypeFlag(checker::TypeFlag::ETS_WIDE_NUMERIC)) {
        Sa().Emit<ReturnWide>(node);
    } else {
        Sa().Emit<Return>(node);
    }
}

void ETSGen::EmitIsInstance(const ir::AstNode *const node, const VReg lhs)
{
    if (GetAccumulatorType()->IsETSDynamicType() || GetVRegType(lhs)->IsETSDynamicType()) {
        ASSERT(GetAccumulatorType()->IsETSDynamicType() && GetVRegType(lhs)->IsETSDynamicType());
        Ra().Emit<CallShort, 2>(node, Signatures::BUILTIN_JSRUNTIME_INSTANCE_OF, lhs, MoveAccToReg(node));
    } else {
        SwapBinaryOpArgs(node, lhs);
        Sa().Emit<Isinstance>(node, GetVRegType(lhs)->AsETSObjectType()->AssemblerName());
    }
    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::EmitSetter(const ir::MemberExpression *member, ir::Expression *right)
{
    compiler::VReg callee_reg = AllocReg();
    auto ottctx = compiler::TargetTypeContext(this, member->Object()->TsType());
    ArenaVector<ir::Expression *> args(Allocator()->Adapter());
    args.push_back(right);

    const auto &func_type = member->TsType()->AsETSFunctionType();
    for (const auto &sig : func_type->CallSignatures()) {
        if (!sig->Function()->IsSetter()) {
            continue;
        }

        if (!sig->Function()->IsStatic()) {
            member->Object()->Compile(this);
            StoreAccumulator(member, callee_reg);
            CallThisVirtual(member, callee_reg, sig, args);
        } else {
            CallStatic(member, sig, args);
        }

        SetAccumulatorType(sig->ReturnType());
    }
}

bool ETSGen::TryLoadConstantExpression(const ir::Expression *node)
{
    const auto *type = node->TsType();

    if (!type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return false;
    }

    auto type_kind = checker::ETSChecker::TypeKind(type);

    switch (type_kind) {
        case checker::TypeFlag::CHAR: {
            LoadAccumulatorChar(node, type->AsCharType()->GetValue());
            break;
        }
        case checker::TypeFlag::ETS_BOOLEAN: {
            LoadAccumulatorBoolean(node, type->AsETSBooleanType()->GetValue());
            break;
        }
        case checker::TypeFlag::BYTE: {
            LoadAccumulatorByte(node, type->AsByteType()->GetValue());
            break;
        }
        case checker::TypeFlag::SHORT: {
            LoadAccumulatorShort(node, type->AsShortType()->GetValue());
            break;
        }
        case checker::TypeFlag::INT: {
            LoadAccumulatorInt(node, type->AsIntType()->GetValue());
            break;
        }
        case checker::TypeFlag::LONG: {
            LoadAccumulatorWideInt(node, type->AsLongType()->GetValue());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            LoadAccumulatorFloat(node, type->AsFloatType()->GetValue());
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            LoadAccumulatorDouble(node, type->AsDoubleType()->GetValue());
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            LoadAccumulatorString(node, type->AsETSObjectType()->AsETSStringType()->GetValue());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    return true;
}

void ETSGen::ApplyConversion(const ir::AstNode *node, const checker::Type *target_type)
{
    auto ttctx = TargetTypeContext(this, target_type);

    if ((node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG) != 0U) {
        EmitBoxingConversion(node);
        const auto boxing_flags =
            static_cast<ir::BoxingUnboxingFlags>(node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG);
        node->SetBoxingUnboxingFlags(
            static_cast<ir::BoxingUnboxingFlags>(node->GetBoxingUnboxingFlags() & ~boxing_flags));
        return;
    }

    if ((node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U) {
        EmitUnboxingConversion(node);
        const auto unboxing_flags = static_cast<ir::BoxingUnboxingFlags>(node->GetBoxingUnboxingFlags() &
                                                                         ir::BoxingUnboxingFlags::UNBOXING_FLAG);
        node->SetBoxingUnboxingFlags(
            static_cast<ir::BoxingUnboxingFlags>(node->GetBoxingUnboxingFlags() & ~unboxing_flags));
        return;
    }

    if (target_type == nullptr) {
        return;
    }

    auto type_kind = checker::ETSChecker::TypeKind(target_type);

    switch (type_kind) {
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
        case checker::TypeFlag::ETS_OBJECT: {
            if (GetAccumulatorType() != nullptr && GetAccumulatorType()->IsETSDynamicType()) {
                CastDynamicToObject(node, target_type);
            }
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastToDynamic(node, target_type->AsETSDynamicType());
            break;
        }
        default: {
            break;
        }
    }
}

void ETSGen::ApplyCast(const ir::AstNode *node, const checker::Type *target_type)
{
    auto type_kind = checker::ETSChecker::TypeKind(target_type);

    switch (type_kind) {
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
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastToDynamic(node, target_type->AsETSDynamicType());
            break;
        }
        default: {
            break;
        }
    }
}

void ETSGen::EmitUnboxingConversion(const ir::AstNode *node)
{
    auto unboxing_flag =
        static_cast<ir::BoxingUnboxingFlags>(ir::BoxingUnboxingFlags::UNBOXING_FLAG & node->GetBoxingUnboxingFlags());

    RegScope rs(this);

    switch (unboxing_flag) {
        case ir::BoxingUnboxingFlags::UNBOX_TO_BOOLEAN: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_BOOLEAN_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalETSBooleanType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_BYTE: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_BYTE_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalByteType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_CHAR: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_CHAR_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalCharType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_SHORT: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_SHORT_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalShortType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_INT: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_INT_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalIntType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_LONG: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_LONG_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalLongType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_FLOAT: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_FLOAT_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalFloatType());
            break;
        }
        case ir::BoxingUnboxingFlags::UNBOX_TO_DOUBLE: {
            Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_DOUBLE_UNBOXED, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GlobalDoubleType());
            break;
        }
        default:
            UNREACHABLE();
    }
}

void ETSGen::EmitBoxingConversion(const ir::AstNode *node)
{
    auto boxing_flag =
        static_cast<ir::BoxingUnboxingFlags>(ir::BoxingUnboxingFlags::BOXING_FLAG & node->GetBoxingUnboxingFlags());

    RegScope rs(this);

    switch (boxing_flag) {
        case ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BOOLEAN_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalETSBooleanBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_BYTE: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BYTE_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalByteBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_CHAR: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_CHAR_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalCharBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_SHORT: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_SHORT_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalShortBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_INT: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_INT_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalIntegerBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_LONG: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_LONG_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalLongBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_FLOAT: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_FLOAT_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalFloatBuiltinType());
            break;
        }
        case ir::BoxingUnboxingFlags::BOX_TO_DOUBLE: {
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_DOUBLE_VALUE_OF, dummy_reg_, 0);
            SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
            break;
        }
        default:
            UNREACHABLE();
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
    const auto new_reg = AllocReg();
    StoreAccumulator(node, new_reg);
    return new_reg;
}

void ETSGen::EmitLocalBoxCtor(ir::AstNode const *node)
{
    auto *content_type = node->AsIdentifier()->Variable()->TsType();
    switch (checker::ETSChecker::TypeKind(content_type)) {
        case checker::TypeFlag::ETS_BOOLEAN:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_BOOLEAN_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::BYTE:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_BYTE_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::CHAR:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_CHAR_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::SHORT:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_SHORT_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::INT:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_INT_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::LONG:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_LONG_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::FLOAT:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_FLOAT_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        case checker::TypeFlag::DOUBLE:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_DOUBLE_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
        default:
            Ra().Emit<InitobjShort>(node, Signatures::BUILTIN_BOX_CTOR, dummy_reg_, dummy_reg_);
            break;
    }
    SetAccumulatorType(Checker()->GlobalBuiltinBoxType(content_type));
}

void ETSGen::EmitLocalBoxGet(ir::AstNode const *node, checker::Type const *content_type)
{
    switch (checker::ETSChecker::TypeKind(content_type)) {
        case checker::TypeFlag::ETS_BOOLEAN:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BOOLEAN_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::BYTE:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BYTE_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::CHAR:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_CHAR_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::SHORT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_SHORT_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::INT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_INT_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::LONG:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_LONG_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::FLOAT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_FLOAT_BOX_GET, dummy_reg_, 0);
            break;
        case checker::TypeFlag::DOUBLE:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_DOUBLE_BOX_GET, dummy_reg_, 0);
            break;
        default:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BOX_GET, dummy_reg_, 0);
            Ra().Emit<Checkcast>(node, content_type->AsETSObjectType()->AssemblerName());
            break;
    }
    SetAccumulatorType(content_type);
}

void ETSGen::EmitLocalBoxSet(ir::AstNode const *node, binder::LocalVariable *lhs_var)
{
    auto *content_type = lhs_var->TsType();
    auto vreg = lhs_var->Vreg();
    switch (checker::ETSChecker::TypeKind(content_type)) {
        case checker::TypeFlag::ETS_BOOLEAN:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BOOLEAN_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::BYTE:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BYTE_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::CHAR:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_CHAR_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::SHORT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_SHORT_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::INT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_INT_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::LONG:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_LONG_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::FLOAT:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_FLOAT_BOX_SET, vreg, 1);
            break;
        case checker::TypeFlag::DOUBLE:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_DOUBLE_BOX_SET, vreg, 1);
            break;
        default:
            Ra().Emit<CallAccShort, 0>(node, Signatures::BUILTIN_BOX_SET, vreg, 1);
            break;
    }
    SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalVoidType());
}

void ETSGen::CastToBoolean([[maybe_unused]] const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
            CastDynamicTo(node, checker::TypeFlag::BOOLEAN);
            ASSERT(GetAccumulatorType() == Checker()->GlobalETSBooleanType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalETSBooleanType());
}

void ETSGen::CastToByte([[maybe_unused]] const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32toi8>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::BYTE);
            ASSERT(GetAccumulatorType() == Checker()->GlobalByteType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalByteType());
}

void ETSGen::CastToChar([[maybe_unused]] const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
        case checker::TypeFlag::CHAR: {
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32tou16>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::CHAR);
            ASSERT(GetAccumulatorType() == Checker()->GlobalCharType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalCharType());
}

void ETSGen::CastToShort([[maybe_unused]] const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            Sa().Emit<I32toi16>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::SHORT);
            ASSERT(GetAccumulatorType() == Checker()->GlobalShortType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalShortType());
}

void ETSGen::CastToDouble(const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::DOUBLE);
            ASSERT(GetAccumulatorType() == Checker()->GlobalDoubleType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalDoubleType());
}

void ETSGen::CastToFloat(const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64tof32>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::FLOAT);
            ASSERT(GetAccumulatorType() == Checker()->GlobalFloatType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalFloatType());
}

void ETSGen::CastToLong(const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi64>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::LONG);
            ASSERT(GetAccumulatorType() == Checker()->GlobalLongType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalLongType());
}

void ETSGen::CastToInt(const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
        case checker::TypeFlag::INT: {
            return;
        }
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::ETS_ENUM:
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
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<F64toi32>(node);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            CastDynamicTo(node, checker::TypeFlag::INT);
            ASSERT(GetAccumulatorType() == Checker()->GlobalIntType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::CastToArrayOrObject(const ir::AstNode *const node, const checker::Type *const target_type,
                                 const bool unchecked)
{
    ASSERT(GetAccumulatorType()->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT));

    const auto *const source_type = GetAccumulatorType();
    if (source_type->IsETSDynamicType()) {
        CastDynamicToObject(node, target_type);
        return;
    }

    if (unchecked) {
        SetAccumulatorType(target_type);
        return;
    }

    EmitCheckedNarrowingReferenceConversion(node, target_type);
}

void ETSGen::CastDynamicToObject(const ir::AstNode *node, const checker::Type *target_type)
{
    if (target_type->IsETSStringType()) {
        CastDynamicTo(node, checker::TypeFlag::STRING);
        return;
    }

    // TODO(itrubachev) Introduce checker::TypeFlag::LAMBDA_OBJECT and lambda object type itself in es2panda.
    // Now lambda object is any class with invoke method, that seems strange
    if (target_type->IsLambdaObject()) {
        VReg dyn_obj_reg = AllocReg();
        StoreAccumulator(node, dyn_obj_reg);
        Ra().Emit<InitobjShort>(node, target_type->AsETSObjectType()->ConstructSignatures()[0]->InternalName(),
                                dyn_obj_reg, dummy_reg_);
        SetAccumulatorType(Checker()->GlobalETSObjectType());
        return;
    }

    if (target_type->IsETSObjectType()) {
        CastDynamicTo(node, checker::TypeFlag::OBJECT);
        return;
    }

    UNREACHABLE();
}

void ETSGen::CastToString(const ir::AstNode *const node)
{
    const auto *const source_type = GetAccumulatorType();
    if (source_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        EmitBoxingConversion(node);
    } else {
        ASSERT(source_type->HasTypeFlag(checker::TypeFlag::ETS_OBJECT));
    }
    Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_OBJECT_TO_STRING, dummy_reg_, 0);
    SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalETSStringBuiltinType());
}

void ETSGen::CastToDynamic(const ir::AstNode *node, const checker::ETSDynamicType *type)
{
    std::string_view method_name {};
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());
    switch (type_kind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            method_name = compiler::Signatures::Dynamic::NewBooleanBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::BYTE: {
            method_name = compiler::Signatures::Dynamic::NewByteBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::CHAR: {
            method_name = compiler::Signatures::Dynamic::NewCharBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::SHORT: {
            method_name = compiler::Signatures::Dynamic::NewShortBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::INT: {
            method_name = compiler::Signatures::Dynamic::NewIntBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::LONG: {
            method_name = compiler::Signatures::Dynamic::NewLongBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            method_name = compiler::Signatures::Dynamic::NewFloatBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            method_name = compiler::Signatures::Dynamic::NewDoubleBuiltin(type->Language());
            break;
        }
        case checker::TypeFlag::ETS_OBJECT: {
            if (GetAccumulatorType()->IsETSStringType()) {
                method_name = compiler::Signatures::Dynamic::NewStringBuiltin(type->Language());
            }
            if (GetAccumulatorType()->IsLambdaObject()) {
                method_name = Signatures::BUILTIN_JSRUNTIME_CREATE_LAMBDA_PROXY;
            }
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            return;
        }
        default: {
            UNREACHABLE();
        }
    }

    RegScope rs(this);
    // Load value
    VReg val_reg = AllocReg();
    StoreAccumulator(node, val_reg);

    // Create new JSValue and initialize it
    Ra().Emit<CallShort, 1>(node, method_name, val_reg, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalBuiltinDynamicType(type->Language()));
}

void ETSGen::CastDynamicTo(const ir::AstNode *node, enum checker::TypeFlag type_flag)
{
    std::string_view method_name {};
    checker::Type *object_type {};
    auto type = GetAccumulatorType()->AsETSDynamicType();
    switch (type_flag) {
        case checker::TypeFlag::BOOLEAN:
            [[fallthrough]];
        case checker::TypeFlag::ETS_BOOLEAN: {
            method_name = compiler::Signatures::Dynamic::GetBooleanBuiltin(type->Language());
            object_type = Checker()->GlobalETSBooleanType();
            break;
        }
        case checker::TypeFlag::BYTE: {
            method_name = compiler::Signatures::Dynamic::GetByteBuiltin(type->Language());
            object_type = Checker()->GlobalByteType();
            break;
        }
        case checker::TypeFlag::CHAR: {
            method_name = compiler::Signatures::Dynamic::GetCharBuiltin(type->Language());
            object_type = Checker()->GlobalCharType();
            break;
        }
        case checker::TypeFlag::SHORT: {
            method_name = compiler::Signatures::Dynamic::GetShortBuiltin(type->Language());
            object_type = Checker()->GlobalShortType();
            break;
        }
        case checker::TypeFlag::INT: {
            method_name = compiler::Signatures::Dynamic::GetIntBuiltin(type->Language());
            object_type = Checker()->GlobalIntType();
            break;
        }
        case checker::TypeFlag::LONG: {
            method_name = compiler::Signatures::Dynamic::GetLongBuiltin(type->Language());
            object_type = Checker()->GlobalLongType();
            break;
        }
        case checker::TypeFlag::FLOAT: {
            method_name = compiler::Signatures::Dynamic::GetFloatBuiltin(type->Language());
            object_type = Checker()->GlobalFloatType();
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            method_name = compiler::Signatures::Dynamic::GetDoubleBuiltin(type->Language());
            object_type = Checker()->GlobalDoubleType();
            break;
        }
        case checker::TypeFlag::STRING: {
            method_name = compiler::Signatures::Dynamic::GetStringBuiltin(type->Language());
            object_type = Checker()->GlobalBuiltinETSStringType();
            break;
        }
        case checker::TypeFlag::OBJECT: {
            SetAccumulatorType(Checker()->GlobalETSObjectType());
            return;
        }
        default: {
            UNREACHABLE();
        }
    }

    RegScope rs(this);
    // Load dynamic object
    VReg dyn_obj_reg = AllocReg();
    StoreAccumulator(node, dyn_obj_reg);

    // Get value from dynamic object
    Ra().Emit<CallShort, 1>(node, method_name, dyn_obj_reg, dummy_reg_);
    SetAccumulatorType(object_type);
}

void ETSGen::EmitCheckedNarrowingReferenceConversion(const ir::AstNode *const node,
                                                     const checker::Type *const target_type)
{
    ASSERT(target_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT));

    if (target_type->IsETSObjectType()) {
        Sa().Emit<Checkcast>(node, target_type->AsETSObjectType()->AssemblerName());
    } else {
        std::stringstream ss;
        target_type->AsETSArrayType()->ToAssemblerTypeWithRank(ss);
        Sa().Emit<Checkcast>(node, util::UString(ss.str(), Allocator()).View());
    }
    SetAccumulatorType(target_type);
}

void ETSGen::ToBinaryResult(const ir::AstNode *node, Label *if_false)
{
    Label *end = AllocLabel();
    Sa().Emit<Ldai>(node, 1);
    Sa().Emit<Jmp>(node, end);
    SetLabel(node, if_false);
    Sa().Emit<Ldai>(node, 0);
    SetLabel(node, end);
}

void ETSGen::Binary(const ir::AstNode *node, lexer::TokenType op, VReg lhs)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryEquality<JneObj, Jne, Jnez, Jeqz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryEquality<JeqObj, Jeq, Jeqz, Jnez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryStrictEquality<JneObj, Jeqz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryStrictEquality<JeqObj, Jnez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            Label *if_false = AllocLabel();
            BinaryRelation<Jle, Jlez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryRelation<Jlt, Jltz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            Label *if_false = AllocLabel();
            BinaryRelation<Jge, Jgez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            Label *if_false = AllocLabel();
            BinaryRelation<Jgt, Jgtz>(node, lhs, if_false);
            break;
        }
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
        case lexer::TokenType::KEYW_INSTANCEOF: {
            EmitIsInstance(node, lhs);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
    ASSERT(node->IsAssignmentExpression() || node->IsBinaryExpression());
    ApplyConversion(node, node->AsExpression()->TsType());
}

void ETSGen::Condition(const ir::AstNode *node, lexer::TokenType op, VReg lhs, Label *if_false)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            BinaryEqualityCondition<JneObj, Jne, Jnez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            BinaryEqualityCondition<JeqObj, Jeq, Jeqz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            BinaryRelationCondition<Jle, Jlez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            BinaryRelationCondition<Jlt, Jltz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            BinaryRelationCondition<Jge, Jgez>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            BinaryRelationCondition<Jgt, Jgtz>(node, lhs, if_false);
            break;
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            EmitIsInstance(node, lhs);
            BranchIfFalse(node, if_false);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSGen::EmitNullPointerException(const ir::AstNode *node)
{
    VReg exception = StoreException(node);
    NewObject(node, exception, Signatures::BUILTIN_NULLPOINTER_EXCEPTION);
    CallThisStatic0(node, exception, Signatures::BUILTIN_NULLPOINTER_EXCEPTION_CTOR);
    EmitThrow(node, exception);
}

void ETSGen::CompileStatements(const ArenaVector<ir::Statement *> &statements)
{
    for (const auto *stmt : statements) {
        stmt->Compile(this);
    }
}

void ETSGen::Negate(const ir::AstNode *node)
{
    auto type_kind = checker::ETSChecker::TypeKind(GetAccumulatorType());

    switch (type_kind) {
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
            UNREACHABLE();
        }
    }
}

void ETSGen::LogicalNot(const ir::AstNode *node)
{
    ASSERT(GetAccumulatorType()->IsETSBooleanType());
    Sa().Emit<Neg>(node);
    Sa().Emit<Addi>(node, 1);
}

void ETSGen::Unary(const ir::AstNode *node, lexer::TokenType op)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            break;  // NOP -> Unary numeric promotion is performed
        }
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            UnaryMinus(node);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            UnaryTilde(node);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            LogicalNot(node);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSGen::UnaryMinus(const ir::AstNode *node)
{
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
            UNREACHABLE();
        }
    }
}

void ETSGen::UnaryTilde(const ir::AstNode *node)
{
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
            UNREACHABLE();
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
            UNREACHABLE();
        }
    }
}

void ETSGen::StringBuilderAppend(const ir::AstNode *node, VReg builder)
{
    RegScope rs(this);
    util::StringView signature {};

    node->Compile(this);

    switch (checker::ETSChecker::ETSType(GetAccumulatorType())) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_BOOLEAN;
            break;
        }
        case checker::TypeFlag::CHAR: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_CHAR;
            break;
        }
        case checker::TypeFlag::SHORT:
        case checker::TypeFlag::BYTE:
        case checker::TypeFlag::INT: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_INT;
            break;
        }
        case checker::TypeFlag::LONG: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_LONG;
            break;
        }
        case checker::TypeFlag::FLOAT: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_FLOAT;
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_DOUBLE;
            break;
        }
        default: {
            signature = Signatures::BUILTIN_STRING_BUILDER_APPEND_BUILTIN_STRING;
            break;
        }
    }

    if (GetAccumulatorType()->IsETSObjectType() && !GetAccumulatorType()->IsETSStringType()) {
        Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_OBJECT_TO_STRING, dummy_reg_, 0);
    }

    VReg arg0 = AllocReg();
    StoreAccumulator(node, arg0);

    CallThisStatic1(node, builder, signature, arg0);
    SetAccumulatorType(Checker()->GetGlobalTypesHolder()->GlobalStringBuilderBuiltinType());
}

void ETSGen::AppendString(const ir::Expression *const expr, const VReg builder)
{
    ASSERT((expr->IsBinaryExpression() &&
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
    if (left->IsBinaryExpression()) {
        AppendString(left->AsBinaryExpression(), builder);
    } else {
        StringBuilderAppend(left, builder);
    }

    StringBuilderAppend(right, builder);
}

void ETSGen::BuildString(const ir::Expression *node)
{
    RegScope rs(this);

    Ra().Emit<InitobjShort, 0>(node, Signatures::BUILTIN_STRING_BUILDER_CTOR, dummy_reg_, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalStringBuilderBuiltinType());

    auto builder = AllocReg();
    StoreAccumulator(node, builder);

    AppendString(node, builder);
    CallThisStatic0(node, builder, Signatures::BUILTIN_STRING_BUILDER_TO_STRING);

    SetAccumulatorType(Checker()->GlobalBuiltinETSStringType());
}

void ETSGen::BuildTemplateString(const ir::TemplateLiteral *node)
{
    RegScope rs(this);

    Ra().Emit<InitobjShort, 0>(node, Signatures::BUILTIN_STRING_BUILDER_CTOR, dummy_reg_, dummy_reg_);
    SetAccumulatorType(Checker()->GlobalStringBuilderBuiltinType());

    auto builder = AllocReg();
    StoreAccumulator(node, builder);

    if (auto const &quasis = node->Quasis(); !quasis.empty()) {
        if (!quasis[0]->Raw().Empty()) {
            StringBuilderAppend(quasis[0], builder);
        }

        if (auto const &expressions = node->Expressions(); !expressions.empty()) {
            auto const num = expressions.size();
            std::size_t i = 0U;

            while (i < num) {
                StringBuilderAppend(expressions[i], builder);
                if (!quasis[++i]->Raw().Empty()) {
                    StringBuilderAppend(quasis[i], builder);
                }
            }
        }
    }

    CallThisStatic0(node, builder, Signatures::BUILTIN_STRING_BUILDER_TO_STRING);

    SetAccumulatorType(Checker()->GlobalBuiltinETSStringType());
}

void ETSGen::NewObject(const ir::AstNode *const node, const VReg ctor, const util::StringView name)
{
    Ra().Emit<Newobj>(node, ctor, name);
    SetVRegType(ctor, Checker()->GlobalETSObjectType());
}

void ETSGen::NewArray(const ir::AstNode *const node, const VReg arr, const VReg dim,
                      const checker::Type *const arr_type)
{
    std::stringstream ss;
    arr_type->ToAssemblerTypeWithRank(ss);
    const auto res = ProgElement()->Strings().emplace(ss.str());

    Ra().Emit<Newarr>(node, arr, dim, util::StringView(*res.first));
    SetVRegType(arr, arr_type);
}

void ETSGen::LoadArrayLength(const ir::AstNode *node, VReg array_reg)
{
    Ra().Emit<Lenarr>(node, array_reg);
    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::LoadArrayElement(const ir::AstNode *node, VReg object_reg)
{
    auto *element_type = GetVRegType(object_reg)->AsETSArrayType()->ElementType();

    switch (checker::ETSChecker::ETSType(element_type)) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Ldarr8>(node, object_reg);
            break;
        }
        case checker::TypeFlag::CHAR: {
            Ra().Emit<Ldarru16>(node, object_reg);
            break;
        }
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Ldarr16>(node, object_reg);
            break;
        }
        case checker::TypeFlag::ETS_ENUM:
        case checker::TypeFlag::INT: {
            Ra().Emit<Ldarr>(node, object_reg);
            break;
        }
        case checker::TypeFlag::LONG: {
            Ra().Emit<LdarrWide>(node, object_reg);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<Fldarr32>(node, object_reg);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<FldarrWide>(node, object_reg);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            Ra().Emit<LdarrObj>(node, object_reg);
            break;
        }

        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(element_type);
}

void ETSGen::StoreArrayElement(const ir::AstNode *node, VReg object_reg, VReg index, const checker::Type *element_type)
{
    switch (checker::ETSChecker::ETSType(element_type)) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Starr8>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::CHAR:
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Starr16>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::ETS_ENUM:
        case checker::TypeFlag::INT: {
            Ra().Emit<Starr>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::LONG: {
            Ra().Emit<StarrWide>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<Fstarr32>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<FstarrWide>(node, object_reg, index);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            Ra().Emit<StarrObj>(node, object_reg, index);
            break;
        }

        default: {
            UNREACHABLE();
        }
    }

    SetAccumulatorType(element_type);
}

void ETSGen::LoadStringLength(const ir::AstNode *node)
{
    Ra().Emit<CallVirtAccShort, 0>(node, Signatures::BUILTIN_STRING_LENGTH, dummy_reg_, 0);
    SetAccumulatorType(Checker()->GlobalIntType());
}

void ETSGen::LoadStringChar(const ir::AstNode *node, const VReg string_obj, const VReg char_index)
{
    Ra().Emit<CallVirtShort>(node, Signatures::BUILTIN_STRING_CHAR_AT, string_obj, char_index);
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

bool ETSGen::ExtendWithFinalizer(ir::AstNode *node, const ir::AstNode *original_node, Label *prev_finnaly)
{
    ASSERT(original_node != nullptr);

    if (node == nullptr || !node->IsStatement()) {
        return false;
    }

    if ((original_node->IsContinueStatement() && original_node->AsContinueStatement()->Target() == node) ||
        (original_node->IsBreakStatement() && original_node->AsBreakStatement()->Target() == node)) {
        return false;
    }

    if (node->IsTryStatement() && node->AsTryStatement()->HasFinalizer()) {
        auto *try_stm = node->AsTryStatement();

        Label *begin_label = nullptr;

        if (prev_finnaly == nullptr) {
            begin_label = AllocLabel();
            Branch(original_node, begin_label);
        } else {
            begin_label = prev_finnaly;
        }

        Label *end_label = AllocLabel();

        if (node->Parent() != nullptr && node->Parent()->IsStatement()) {
            if (!ExtendWithFinalizer(node->Parent(), original_node, end_label)) {
                end_label = nullptr;
            }
        } else {
            end_label = nullptr;
        }

        LabelPair insertion = compiler::LabelPair(begin_label, end_label);

        try_stm->AddFinalizerInsertion(insertion, original_node->AsStatement());

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

    return ExtendWithFinalizer(parent, original_node, prev_finnaly);
}

}  // namespace panda::es2panda::compiler
