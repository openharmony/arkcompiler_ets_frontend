/**
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

#include "memberExpression.h"

#include "checker/types/typeRelation.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/function.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/types/ets/etsExtensionFuncHelperType.h"
#include "checker/types/ets/etsFunctionType.h"
#include "checker/types/signature.h"
#include "ir/astDump.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/ts/tsEnumMember.h"
#include "util/helpers.h"

namespace panda::es2panda::ir {
MemberExpression::MemberExpression([[maybe_unused]] Tag const tag, Expression *const object, Expression *const property)
    : MemberExpression(*this)
{
    object_ = object;
    if (object_ != nullptr) {
        object_->SetParent(this);
    }

    property_ = property;
    if (property_ != nullptr) {
        property_->SetParent(this);
    }
}

bool MemberExpression::IsPrivateReference() const noexcept
{
    return property_->IsIdentifier() && property_->AsIdentifier()->IsPrivateIdent();
}

void MemberExpression::TransformChildren(const NodeTransformer &cb)
{
    object_ = cb(object_)->AsExpression();
    property_ = cb(property_)->AsExpression();
}

void MemberExpression::Iterate(const NodeTraverser &cb) const
{
    cb(object_);
    cb(property_);
}

void MemberExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "MemberExpression"},
                 {"object", object_},
                 {"property", property_},
                 {"computed", computed_},
                 {"optional", IsOptional()}});
}

void MemberExpression::LoadRhs(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    bool is_super = object_->IsSuperExpression();
    compiler::Operand prop = pg->ToPropertyKey(property_, computed_, is_super);

    if (is_super) {
        pg->LoadSuperProperty(this, prop);
    } else if (IsPrivateReference()) {
        const auto &name = property_->AsIdentifier()->Name();
        compiler::VReg obj_reg = pg->AllocReg();
        pg->StoreAccumulator(this, obj_reg);
        compiler::VReg ctor = pg->AllocReg();
        compiler::Function::LoadClassContexts(this, pg, ctor, name);
        pg->ClassPrivateFieldGet(this, ctor, obj_reg, name);
    } else {
        pg->LoadObjProperty(this, prop);
    }
}

void MemberExpression::CompileToRegs(compiler::PandaGen *pg, compiler::VReg object, compiler::VReg property) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, object);

    pg->OptionalChainCheck(IsOptional(), object);

    if (!computed_) {
        pg->LoadAccumulatorString(this, property_->AsIdentifier()->Name());
    } else {
        property_->Compile(pg);
    }

    pg->StoreAccumulator(this, property);
}

void MemberExpression::Compile(compiler::PandaGen *pg) const
{
    object_->Compile(pg);
    pg->OptionalChainCheck(IsOptional(), compiler::VReg::Invalid());
    LoadRhs(pg);
}

void MemberExpression::CompileToReg(compiler::PandaGen *pg, compiler::VReg obj_reg) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, obj_reg);
    pg->OptionalChainCheck(IsOptional(), obj_reg);
    LoadRhs(pg);
}

bool MemberExpression::CompileComputed(compiler::ETSGen *etsg) const
{
    if (computed_) {
        auto *const object_type = etsg->Checker()->GetNonNullishType(object_->TsType());

        auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
        etsg->CompileAndCheck(object_);

        auto const load_element = [this, etsg, object_type]() {
            compiler::VReg obj_reg = etsg->AllocReg();
            etsg->StoreAccumulator(this, obj_reg);

            etsg->CompileAndCheck(property_);
            etsg->ApplyConversion(property_, property_->TsType());

            auto ttctx = compiler::TargetTypeContext(etsg, OptionalType());

            if (object_type->IsETSDynamicType()) {
                auto lang = object_type->AsETSDynamicType()->Language();
                etsg->LoadElementDynamic(this, obj_reg, lang);
            } else {
                etsg->LoadArrayElement(this, obj_reg);
            }
        };

        etsg->EmitMaybeOptional(this, load_element, IsOptional());
        return true;
    }
    return false;
}

void MemberExpression::Compile(compiler::ETSGen *etsg) const
{
    auto lambda = etsg->VarBinder()->LambdaObjects().find(this);
    if (lambda != etsg->VarBinder()->LambdaObjects().end()) {
        etsg->CreateLambdaObjectFromMemberReference(this, object_, lambda->second.first);
        etsg->SetAccumulatorType(TsType());
        return;
    }

    compiler::RegScope rs(etsg);

    auto *const object_type = etsg->Checker()->GetNonNullishType(object_->TsType());

    if (CompileComputed(etsg)) {
        return;
    }

    auto &prop_name = property_->AsIdentifier()->Name();

    if (object_type->IsETSArrayType() && prop_name.Is("length")) {
        auto ottctx = compiler::TargetTypeContext(etsg, object_type);
        etsg->CompileAndCheck(object_);

        auto const load_length = [this, etsg]() {
            compiler::VReg obj_reg = etsg->AllocReg();
            etsg->StoreAccumulator(this, obj_reg);

            auto ttctx = compiler::TargetTypeContext(etsg, OptionalType());
            etsg->LoadArrayLength(this, obj_reg);
            etsg->ApplyConversion(this, TsType());
        };

        etsg->EmitMaybeOptional(this, load_length, IsOptional());
        return;
    }

    if (object_type->IsETSEnumType() || object_type->IsETSStringEnumType()) {
        auto const *const enum_interface = [object_type, this]() -> checker::ETSEnumInterface const * {
            if (object_type->IsETSEnumType()) {
                return OptionalType()->AsETSEnumType();
            }
            return OptionalType()->AsETSStringEnumType();
        }();

        auto ottctx = compiler::TargetTypeContext(etsg, object_type);
        auto ttctx = compiler::TargetTypeContext(etsg, OptionalType());
        etsg->LoadAccumulatorInt(this, enum_interface->GetOrdinal());
        return;
    }

    if (etsg->Checker()->IsVariableStatic(prop_var_)) {
        auto ttctx = compiler::TargetTypeContext(etsg, OptionalType());

        if (prop_var_->TsType()->HasTypeFlag(checker::TypeFlag::GETTER_SETTER)) {
            checker::Signature *sig = prop_var_->TsType()->AsETSFunctionType()->FindGetter();
            etsg->CallStatic0(this, sig->InternalName());
            etsg->SetAccumulatorType(TsType());
            return;
        }

        util::StringView full_name = etsg->FormClassPropReference(object_->TsType()->AsETSObjectType(), prop_name);
        etsg->LoadStaticProperty(this, OptionalType(), full_name);
        return;
    }

    auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
    etsg->CompileAndCheck(object_);

    auto const load_property = [this, etsg, prop_name, object_type]() {
        etsg->ApplyConversion(object_);
        compiler::VReg obj_reg = etsg->AllocReg();
        etsg->StoreAccumulator(this, obj_reg);

        auto ttctx = compiler::TargetTypeContext(etsg, OptionalType());

        if (prop_var_->TsType()->HasTypeFlag(checker::TypeFlag::GETTER_SETTER)) {
            checker::Signature *sig = prop_var_->TsType()->AsETSFunctionType()->FindGetter();
            etsg->CallThisVirtual0(this, obj_reg, sig->InternalName());
            etsg->SetAccumulatorType(TsType());
        } else if (object_type->IsETSDynamicType()) {
            auto lang = object_type->AsETSDynamicType()->Language();
            etsg->LoadPropertyDynamic(this, OptionalType(), obj_reg, prop_name, lang);
        } else if (object_type->IsETSUnionType()) {
            etsg->LoadUnionProperty(this, OptionalType(), obj_reg, prop_name);
        } else {
            const auto full_name = etsg->FormClassPropReference(object_type->AsETSObjectType(), prop_name);
            etsg->LoadProperty(this, OptionalType(), obj_reg, full_name);
        }
    };

    etsg->EmitMaybeOptional(this, load_property, IsOptional());
}

checker::Type *MemberExpression::Check(checker::TSChecker *checker)
{
    checker::Type *base_type = checker->CheckNonNullType(object_->Check(checker), object_->Start());

    if (computed_) {
        checker::Type *index_type = property_->Check(checker);
        checker::Type *indexed_access_type = checker->GetPropertyTypeForIndexType(base_type, index_type);

        if (indexed_access_type != nullptr) {
            return indexed_access_type;
        }

        if (!index_type->HasTypeFlag(checker::TypeFlag::STRING_LIKE | checker::TypeFlag::NUMBER_LIKE)) {
            checker->ThrowTypeError({"Type ", index_type, " cannot be used as index type"}, property_->Start());
        }

        if (index_type->IsNumberType()) {
            checker->ThrowTypeError("No index signature with a parameter of type 'string' was found on type this type",
                                    Start());
        }

        if (index_type->IsStringType()) {
            checker->ThrowTypeError("No index signature with a parameter of type 'number' was found on type this type",
                                    Start());
        }

        switch (property_->Type()) {
            case ir::AstNodeType::IDENTIFIER: {
                checker->ThrowTypeError(
                    {"Property ", property_->AsIdentifier()->Name(), " does not exist on this type."},
                    property_->Start());
            }
            case ir::AstNodeType::NUMBER_LITERAL: {
                checker->ThrowTypeError(
                    {"Property ", property_->AsNumberLiteral()->Str(), " does not exist on this type."},
                    property_->Start());
            }
            case ir::AstNodeType::STRING_LITERAL: {
                checker->ThrowTypeError(
                    {"Property ", property_->AsStringLiteral()->Str(), " does not exist on this type."},
                    property_->Start());
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    varbinder::Variable *prop = checker->GetPropertyOfType(base_type, property_->AsIdentifier()->Name());

    if (prop != nullptr) {
        checker::Type *prop_type = checker->GetTypeOfVariable(prop);
        if (prop->HasFlag(varbinder::VariableFlags::READONLY)) {
            prop_type->AddTypeFlag(checker::TypeFlag::READONLY);
        }

        return prop_type;
    }

    if (base_type->IsObjectType()) {
        checker::ObjectType *obj_type = base_type->AsObjectType();

        if (obj_type->StringIndexInfo() != nullptr) {
            checker::Type *index_type = obj_type->StringIndexInfo()->GetType();
            if (obj_type->StringIndexInfo()->Readonly()) {
                index_type->AddTypeFlag(checker::TypeFlag::READONLY);
            }

            return index_type;
        }
    }

    checker->ThrowTypeError({"Property ", property_->AsIdentifier()->Name(), " does not exist on this type."},
                            property_->Start());
    return nullptr;
}

std::pair<checker::Type *, varbinder::LocalVariable *> MemberExpression::ResolveEnumMember(checker::ETSChecker *checker,
                                                                                           checker::Type *type) const
{
    auto const *const enum_interface = [type]() -> checker::ETSEnumInterface const * {
        if (type->IsETSEnumType()) {
            return type->AsETSEnumType();
        }
        return type->AsETSStringEnumType();
    }();

    if (parent_->Type() == ir::AstNodeType::CALL_EXPRESSION && parent_->AsCallExpression()->Callee() == this) {
        return {enum_interface->LookupMethod(checker, object_, property_->AsIdentifier()), nullptr};
    }

    auto *const literal_type = enum_interface->LookupConstant(checker, object_, property_->AsIdentifier());
    return {literal_type, literal_type->GetMemberVar()};
}

std::pair<checker::Type *, varbinder::LocalVariable *> MemberExpression::ResolveObjectMember(
    checker::ETSChecker *checker) const
{
    auto resolve_res = checker->ResolveMemberReference(this, obj_type_);
    switch (resolve_res.size()) {
        case 1U: {
            if (resolve_res[0]->Kind() == checker::ResolvedKind::PROPERTY) {
                auto var = resolve_res[0]->Variable()->AsLocalVariable();
                checker->ValidatePropertyAccess(var, obj_type_, property_->Start());
                return {checker->GetTypeOfVariable(var), var};
            }
            return {checker->GetTypeOfVariable(resolve_res[0]->Variable()), nullptr};
        }
        case 2U: {
            // ETSExtensionFuncHelperType(class_method_type, extension_method_type)
            auto *resolved_type = checker->CreateETSExtensionFuncHelperType(
                checker->GetTypeOfVariable(resolve_res[1]->Variable())->AsETSFunctionType(),
                checker->GetTypeOfVariable(resolve_res[0]->Variable())->AsETSFunctionType());
            return {resolved_type, nullptr};
        }
        default: {
            UNREACHABLE();
        }
    }
}

checker::Type *MemberExpression::CheckUnionMember(checker::ETSChecker *checker, checker::Type *base_type)
{
    auto *const union_type = base_type->AsETSUnionType();
    checker::Type *common_prop_type = nullptr;
    auto const add_prop_type = [this, checker, &common_prop_type](checker::Type *member_type) {
        if (common_prop_type != nullptr && common_prop_type != member_type) {
            checker->ThrowTypeError("Member type must be the same for all union objects.", Start());
        }
        common_prop_type = member_type;
    };
    for (auto *const type : union_type->ConstituentTypes()) {
        if (type->IsETSObjectType()) {
            SetObjectType(type->AsETSObjectType());
            add_prop_type(ResolveObjectMember(checker).first);
        } else if (type->IsETSEnumType() || base_type->IsETSStringEnumType()) {
            add_prop_type(ResolveEnumMember(checker, type).first);
        } else {
            UNREACHABLE();
        }
    }
    SetObjectType(union_type->GetLeastUpperBoundType(checker)->AsETSObjectType());
    return common_prop_type;
}

checker::Type *MemberExpression::AdjustOptional(checker::ETSChecker *checker, checker::Type *type)
{
    SetOptionalType(type);
    if (IsOptional() && Object()->TsType()->IsNullishOrNullLike()) {
        checker->Relation()->SetNode(this);
        type = checker->CreateOptionalResultType(type);
        checker->Relation()->SetNode(nullptr);
    }
    SetTsType(type);
    return TsType();
}

checker::Type *MemberExpression::CheckComputed(checker::ETSChecker *checker, checker::Type *base_type)
{
    if (!base_type->IsETSArrayType() && !base_type->IsETSDynamicType()) {
        checker->ThrowTypeError("Indexed access expression can only be used in array type.", Object()->Start());
    }
    checker->ValidateArrayIndex(Property());

    if (Property()->IsIdentifier()) {
        SetPropVar(Property()->AsIdentifier()->Variable()->AsLocalVariable());
    } else if (auto var = Property()->Variable(); (var != nullptr) && var->IsLocalVariable()) {
        SetPropVar(var->AsLocalVariable());
    }

    // NOTE: apply capture conversion on this type
    if (base_type->IsETSArrayType()) {
        return base_type->AsETSArrayType()->ElementType();
    }

    // Dynamic
    return checker->GlobalBuiltinDynamicType(base_type->AsETSDynamicType()->Language());
}

checker::Type *MemberExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }
    auto *const left_type = object_->Check(checker);
    auto *const base_type = IsOptional() ? checker->GetNonNullishType(left_type) : left_type;
    if (!IsOptional()) {
        checker->CheckNonNullishType(left_type, object_->Start());
    }

    if (computed_) {
        return AdjustOptional(checker, CheckComputed(checker, base_type));
    }

    if (base_type->IsETSArrayType() && property_->AsIdentifier()->Name().Is("length")) {
        return AdjustOptional(checker, checker->GlobalIntType());
    }

    if (base_type->IsETSObjectType()) {
        SetObjectType(base_type->AsETSObjectType());
        auto [res_type, res_var] = ResolveObjectMember(checker);
        SetPropVar(res_var);
        return AdjustOptional(checker, res_type);
    }

    if (base_type->IsETSEnumType() || base_type->IsETSStringEnumType()) {
        auto [member_type, member_var] = ResolveEnumMember(checker, base_type);
        SetPropVar(member_var);
        return AdjustOptional(checker, member_type);
    }

    if (base_type->IsETSUnionType()) {
        return AdjustOptional(checker, CheckUnionMember(checker, base_type));
    }

    checker->ThrowTypeError({"Cannot access property of non-object or non-enum type"}, object_->Start());
}

// NOLINTNEXTLINE(google-default-arguments)
MemberExpression *MemberExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const object = object_ != nullptr ? object_->Clone(allocator)->AsExpression() : nullptr;
    auto *const property = property_ != nullptr ? property_->Clone(allocator)->AsExpression() : nullptr;

    if (auto *const clone = allocator->New<MemberExpression>(Tag {}, object, property); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
