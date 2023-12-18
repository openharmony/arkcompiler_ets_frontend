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

#include "checker/TSchecker.h"
#include "checker/ets/castingContext.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
MemberExpression::MemberExpression([[maybe_unused]] Tag const tag, MemberExpression const &other,
                                   Expression *const object, Expression *const property)
    : MemberExpression(other)
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

void MemberExpression::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(object_ != nullptr);
    ASSERT(property_ != nullptr);

    object_->Dump(dumper);
    if (IsOptional()) {
        dumper->Add("?");
    }
    if ((MemberExpressionKind::ELEMENT_ACCESS & kind_) != 0U) {
        dumper->Add("[");
        property_->Dump(dumper);
        dumper->Add("]");
    } else {
        dumper->Add(".");
        property_->Dump(dumper);
    }
    if ((parent_ != nullptr) && (parent_->IsBlockStatement() || parent_->IsBlockExpression())) {
        dumper->Add(";");
        dumper->Endl();
    }
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
    pg->GetAstCompiler()->Compile(this);
}

void MemberExpression::CompileToReg(compiler::PandaGen *pg, compiler::VReg obj_reg) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, obj_reg);
    pg->OptionalChainCheck(IsOptional(), obj_reg);
    LoadRhs(pg);
}

void MemberExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *MemberExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
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

void MemberExpression::CheckArrayIndexValue(checker::ETSChecker *checker) const
{
    std::size_t index;

    auto const &number = property_->AsNumberLiteral()->Number();

    if (number.IsInteger()) {
        auto const value = number.GetLong();
        if (value < 0) {
            checker->ThrowTypeError("Index value cannot be less than zero.", property_->Start());
        }
        index = static_cast<std::size_t>(value);
    } else if (number.IsReal()) {
        double value = number.GetDouble();
        double fraction = std::modf(value, &value);
        if (value < 0.0 || fraction >= std::numeric_limits<double>::epsilon()) {
            checker->ThrowTypeError("Index value cannot be less than zero or fractional.", property_->Start());
        }
        index = static_cast<std::size_t>(value);
    } else {
        UNREACHABLE();
    }

    if (object_->IsArrayExpression() && object_->AsArrayExpression()->Elements().size() <= index) {
        checker->ThrowTypeError("Index value cannot be greater than or equal to the array size.", property_->Start());
    }

    if (object_->IsIdentifier() &&
        object_->AsIdentifier()->Variable()->Declaration()->Node()->Parent()->IsVariableDeclarator()) {
        auto const var_decl =
            object_->AsIdentifier()->Variable()->Declaration()->Node()->Parent()->AsVariableDeclarator();
        if (var_decl->Init() != nullptr && var_decl->Init()->IsArrayExpression() &&
            var_decl->Init()->AsArrayExpression()->Elements().size() <= index) {
            checker->ThrowTypeError("Index value cannot be greater than or equal to the array size.",
                                    property_->Start());
        }
    }
}

checker::Type *MemberExpression::CheckIndexAccessMethod(checker::ETSChecker *checker)
{
    checker::PropertySearchFlags search_flag =
        checker::PropertySearchFlags::SEARCH_METHOD | checker::PropertySearchFlags::IS_FUNCTIONAL;
    search_flag |= checker::PropertySearchFlags::SEARCH_IN_BASE | checker::PropertySearchFlags::SEARCH_IN_INTERFACES;
    // NOTE(DZ) maybe we need to exclude static methods: search_flag &= ~(checker::PropertySearchFlags::SEARCH_STATIC);

    if (obj_type_->HasTypeFlag(checker::TypeFlag::GENERIC)) {
        search_flag |= checker::PropertySearchFlags::SEARCH_ALL;
    }

    bool const is_setter = Parent()->IsAssignmentExpression() && Parent()->AsAssignmentExpression()->Left() == this;
    std::string_view const method_name =
        is_setter ? compiler::Signatures::SET_INDEX_METHOD : compiler::Signatures::GET_INDEX_METHOD;

    auto *const method = obj_type_->GetProperty(method_name, search_flag);
    if (method == nullptr || !method->HasFlag(varbinder::VariableFlags::METHOD)) {
        checker->ThrowTypeError("Object type doesn't have proper index access method.", Start());
    }

    ArenaVector<Expression *> arguments {checker->Allocator()->Adapter()};
    arguments.emplace_back(property_);
    if (is_setter) {
        arguments.emplace_back(Parent()->AsAssignmentExpression()->Right());
    }

    auto &signatures = checker->GetTypeOfVariable(method)->AsETSFunctionType()->CallSignatures();

    checker::Signature *signature = checker->ValidateSignatures(signatures, nullptr, arguments, Start(), "indexing",
                                                                checker::TypeRelationFlag::NO_THROW);
    if (signature == nullptr) {
        checker->ThrowTypeError("Cannot find index access method with the required signature.", Property()->Start());
    }
    checker->ValidateSignatureAccessibility(obj_type_, nullptr, signature, Start(),
                                            "Index access method is not visible here.");

    ASSERT(signature->Function() != nullptr);

    if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
        checker->CheckThrowingStatements(this);
    }

    return is_setter ? signature->Params()[1]->TsType() : signature->ReturnType();
}

checker::Type *MemberExpression::CheckTupleAccessMethod(checker::ETSChecker *checker, checker::Type *base_type)
{
    ASSERT(base_type->IsETSTupleType());

    auto *const tuple_type_at_idx =
        base_type->AsETSTupleType()->GetTypeAtIndex(checker->GetTupleElementAccessValue(Property()->TsType()));

    if ((!Parent()->IsAssignmentExpression() || Parent()->AsAssignmentExpression()->Left() != this) &&
        (!Parent()->IsUpdateExpression())) {
        // Error never should be thrown by this call, because LUB of types can be converted to any type which
        // LUB was calculated by casting
        const checker::CastingContext cast(checker->Relation(), this, base_type->AsETSArrayType()->ElementType(),
                                           tuple_type_at_idx, Start(), {"Tuple type couldn't be converted "});

        // NOTE(mmartin): this can be replaced with the general type mapper, once implemented
        if ((GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U) {
            auto *const saved_node = checker->Relation()->GetNode();
            if (saved_node == nullptr) {
                checker->Relation()->SetNode(this);
            }

            SetTupleConvertedType(checker->PrimitiveTypeAsETSBuiltinType(tuple_type_at_idx));

            checker->Relation()->SetNode(saved_node);
        }

        if (tuple_type_at_idx->IsETSObjectType() && base_type->AsETSArrayType()->ElementType()->IsETSObjectType()) {
            SetTupleConvertedType(tuple_type_at_idx);
        }
    }

    return tuple_type_at_idx;
}

checker::Type *MemberExpression::CheckComputed(checker::ETSChecker *checker, checker::Type *base_type)
{
    if (base_type->IsETSArrayType() || base_type->IsETSDynamicType()) {
        checker->ValidateArrayIndex(property_);

        if (base_type->IsETSTupleType()) {
            checker->ValidateTupleIndex(base_type->AsETSTupleType(), this);
        } else if (base_type->IsETSArrayType() && property_->IsNumberLiteral()) {
            // Check if the index value is inside array bounds if it is defined explicitly
            CheckArrayIndexValue(checker);
        }

        if (property_->IsIdentifier()) {
            SetPropVar(property_->AsIdentifier()->Variable()->AsLocalVariable());
        } else if (auto var = property_->Variable(); (var != nullptr) && var->IsLocalVariable()) {
            SetPropVar(var->AsLocalVariable());
        }

        // NOTE: apply capture conversion on this type
        if (base_type->IsETSArrayType()) {
            if (base_type->IsETSTupleType()) {
                return CheckTupleAccessMethod(checker, base_type);
            }

            if (object_->IsArrayExpression() && property_->IsNumberLiteral()) {
                auto const number = property_->AsNumberLiteral()->Number().GetLong();
                return object_->AsArrayExpression()->Elements()[number]->Check(checker);
            }

            return base_type->AsETSArrayType()->ElementType();
        }

        // Dynamic
        return checker->GlobalBuiltinDynamicType(base_type->AsETSDynamicType()->Language());
    }

    if (base_type->IsETSObjectType()) {
        SetObjectType(base_type->AsETSObjectType());
        return CheckIndexAccessMethod(checker);
    }

    checker->ThrowTypeError("Indexed access is not supported for such expression type.", Object()->Start());
}

checker::Type *MemberExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
MemberExpression *MemberExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const object = object_ != nullptr ? object_->Clone(allocator)->AsExpression() : nullptr;
    auto *const property = property_ != nullptr ? property_->Clone(allocator)->AsExpression() : nullptr;

    if (auto *const clone =
            allocator->New<MemberExpression>(object, property, kind_, computed_, MaybeOptionalExpression::IsOptional());
        clone != nullptr) {
        if (object != nullptr) {
            object->SetParent(clone);
        }
        if (property != nullptr) {
            property->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

bool MemberExpression::IsGenericField() const
{
    const auto obj_t = object_->TsType();
    if (!obj_t->IsETSObjectType()) {
        return false;
    }
    auto base_class_t = obj_t->AsETSObjectType()->GetBaseType();
    if (base_class_t == nullptr) {
        return false;
    }
    const auto &prop_name = property_->AsIdentifier()->Name();
    auto base_prop = base_class_t->GetProperty(prop_name, checker::PropertySearchFlags::SEARCH_FIELD);
    if (base_prop == nullptr || base_prop->TsType() == nullptr) {
        return false;
    }
    return TsType()->ToAssemblerName().str() != base_prop->TsType()->ToAssemblerName().str();
}
}  // namespace panda::es2panda::ir
