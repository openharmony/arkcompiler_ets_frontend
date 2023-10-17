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

#include "memberExpression.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/function.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
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
bool MemberExpression::IsPrivateReference() const
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
                 {"optional", optional_}});
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

    pg->OptionalChainCheck(optional_, object);

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
    pg->OptionalChainCheck(optional_, compiler::VReg::Invalid());
    LoadRhs(pg);
}

void MemberExpression::CompileToReg(compiler::PandaGen *pg, compiler::VReg obj_reg) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, obj_reg);
    pg->OptionalChainCheck(optional_, obj_reg);
    LoadRhs(pg);
}

void MemberExpression::Compile(compiler::ETSGen *etsg) const
{
    auto lambda = etsg->Binder()->LambdaObjects().find(this);
    if (lambda != etsg->Binder()->LambdaObjects().end()) {
        etsg->CreateLambdaObjectFromMemberReference(this, object_, lambda->second.first);
        return;
    }

    compiler::RegScope rs(etsg);

    if (computed_) {
        auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
        object_->Compile(etsg);

        if (etsg->GetAccumulatorType()->IsETSNullType()) {
            if (optional_) {
                return;
            }

            etsg->EmitNullPointerException(this);
            return;
        }

        // Helper function to avoid branching in non optional cases
        auto compile_and_load_elements = [this, etsg]() {
            compiler::VReg obj_reg = etsg->AllocReg();
            etsg->StoreAccumulator(this, obj_reg);
            auto pttctx = compiler::TargetTypeContext(etsg, property_->TsType());
            property_->Compile(etsg);
            etsg->ApplyConversion(property_);

            auto ttctx = compiler::TargetTypeContext(etsg, TsType());

            if (TsType()->IsETSDynamicType()) {
                auto lang = TsType()->AsETSDynamicType()->Language();
                etsg->LoadElementDynamic(this, obj_reg, lang);
            } else {
                etsg->LoadArrayElement(this, obj_reg);
            }

            etsg->ApplyConversion(this);
        };

        if (optional_) {
            compiler::Label *end_label = etsg->AllocLabel();
            etsg->BranchIfNull(this, end_label);
            compile_and_load_elements();
            etsg->SetLabel(this, end_label);
        } else {
            compile_and_load_elements();
        }

        return;
    }

    auto &prop_name = property_->AsIdentifier()->Name();

    if (object_->TsType()->IsETSArrayType() && prop_name.Is("length")) {
        auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
        object_->Compile(etsg);
        compiler::VReg obj_reg = etsg->AllocReg();
        etsg->StoreAccumulator(this, obj_reg);

        auto ttctx = compiler::TargetTypeContext(etsg, TsType());
        etsg->LoadArrayLength(this, obj_reg);
        etsg->ApplyConversion(this);
        return;
    }

    if (object_->TsType()->IsETSEnumType()) {
        ASSERT(TsType()->IsETSEnumType());
        auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
        auto ttctx = compiler::TargetTypeContext(etsg, TsType());
        etsg->LoadAccumulatorInt(this, TsType()->AsETSEnumType()->GetOrdinal());
        return;
    }

    if (prop_var_->HasFlag(binder::VariableFlags::STATIC)) {
        auto ttctx = compiler::TargetTypeContext(etsg, TsType());

        util::StringView full_name = etsg->FormClassPropReference(object_->TsType()->AsETSObjectType(), prop_name);
        etsg->LoadStaticProperty(this, TsType(), full_name);
        etsg->ApplyConversion(this);
        return;
    }

    if (object_->TsType()->IsETSObjectType() &&
        HasMemberKind(MemberExpressionKind::GETTER | MemberExpressionKind::SETTER)) {
        const auto &get_set = object_->TsType()->AsETSObjectType()->InstanceMethods();
        const auto res = get_set.find(prop_name);
        if (res != get_set.end()) {
            auto *decl = res->second->Declaration();
            ASSERT(decl != nullptr);
            if (decl->Node()->IsMethodDefinition()) {
                compiler::VReg callee_reg = etsg->AllocReg();
                auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
                object_->Compile(etsg);
                etsg->StoreAccumulator(this, callee_reg);

                if (decl->Node()->AsMethodDefinition()->Kind() == ir::MethodDefinitionKind::GET) {
                    etsg->EmitGetter(this, callee_reg, decl->Node()->AsMethodDefinition()->Function());
                } else {
                    etsg->EmitGetter(this, callee_reg, decl->Node()->AsMethodDefinition()->Overloads()[0]->Function());
                }
                return;
            }
        } else {
            const auto &static_get_set = object_->TsType()->AsETSObjectType()->StaticMethods();
            const auto static_res = static_get_set.find(prop_name);
            if (static_res != static_get_set.end()) {
                auto *decl = static_res->second->Declaration();
                ASSERT(decl != nullptr);
                if (decl->Node()->IsMethodDefinition()) {
                    auto *script = decl->Node()->AsMethodDefinition()->Function();
                    if (decl->Node()->AsMethodDefinition()->Kind() == ir::MethodDefinitionKind::SET) {
                        script = decl->Node()->AsMethodDefinition()->Overloads()[0]->AsMethodDefinition()->Function();
                    }

                    etsg->CallStatic(this, script->Signature(), script->Params());
                    etsg->SetAccumulatorType(script->Signature()->ReturnType());
                    return;
                }
            }
        }
    }

    auto ottctx = compiler::TargetTypeContext(etsg, object_->TsType());
    object_->Compile(etsg);

    // TODO(rsipka): it should be CTE if object type is non nullable type

    if (etsg->GetAccumulatorType()->IsETSNullType()) {
        if (optional_) {
            etsg->LoadAccumulatorNull(this, etsg->Checker()->GlobalETSNullType());
            return;
        }

        etsg->EmitNullPointerException(this);
        etsg->LoadAccumulatorNull(this, etsg->Checker()->GlobalETSNullType());
        return;
    }

    etsg->ApplyConversion(object_);
    compiler::VReg obj_reg = etsg->AllocReg();
    etsg->StoreAccumulator(this, obj_reg);

    auto ttctx = compiler::TargetTypeContext(etsg, TsType());

    auto load_property = [this, etsg, obj_reg, prop_name]() {
        if (object_->TsType()->IsETSDynamicType()) {
            auto lang = object_->TsType()->AsETSDynamicType()->Language();
            etsg->LoadPropertyDynamic(this, TsType(), obj_reg, prop_name, lang);
        } else {
            const auto full_name = etsg->FormClassPropReference(object_->TsType()->AsETSObjectType(), prop_name);
            etsg->LoadProperty(this, TsType(), obj_reg, full_name);
        }
        etsg->ApplyConversion(this);
    };

    if (optional_) {
        compiler::Label *if_not_null = etsg->AllocLabel();
        compiler::Label *end_label = etsg->AllocLabel();

        etsg->BranchIfNotNull(this, if_not_null);
        etsg->LoadAccumulatorNull(this, TsType());
        etsg->Branch(this, end_label);
        etsg->SetLabel(this, if_not_null);
        load_property();
        etsg->SetLabel(this, end_label);
    } else {
        load_property();
    }
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

    binder::Variable *prop = checker->GetPropertyOfType(base_type, property_->AsIdentifier()->Name());

    if (prop != nullptr) {
        checker::Type *prop_type = checker->GetTypeOfVariable(prop);
        if (prop->HasFlag(binder::VariableFlags::READONLY)) {
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

checker::Type *MemberExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    if (computed_) {
        SetTsType(checker->CheckArrayElementAccess(this));
        return TsType();
    }

    checker::Type *const base_type = object_->Check(checker);

    if (!base_type->IsETSObjectType()) {
        if (base_type->IsETSArrayType() && property_->AsIdentifier()->Name().Is("length")) {
            SetTsType(checker->GlobalIntType());
            return TsType();
        }

        if (base_type->IsETSEnumType()) {
            const auto *const enum_type = base_type->AsETSEnumType();

            if (parent_->Type() == ir::AstNodeType::CALL_EXPRESSION && parent_->AsCallExpression()->Callee() == this) {
                auto *const enum_method_type = enum_type->LookupMethod(checker, object_, property_->AsIdentifier());
                SetTsType(enum_method_type);
                return TsType();
            }

            auto *const enum_literal_type = enum_type->LookupConstant(checker, object_, property_->AsIdentifier());
            SetTsType(enum_literal_type);
            SetPropVar(enum_literal_type->GetMemberVar());
            return TsType();
        }

        checker->ThrowTypeError({"Cannot access property of non-object or non-enum type"}, object_->Start());
    }

    obj_type_ = base_type->AsETSObjectType();

    if (Property()->IsIdentifier()) {
        const auto *prop = ObjType()->GetProperty(Property()->AsIdentifier()->Name(),
                                                  checker::PropertySearchFlags::SEARCH_INSTANCE_METHOD |
                                                      checker::PropertySearchFlags::SEARCH_STATIC_METHOD);

        if (prop != nullptr && prop->TsType() != nullptr && prop->TsType()->IsETSFunctionType()) {
            const auto &func_type = prop->TsType()->AsETSFunctionType();

            for (auto *sig : func_type->CallSignatures()) {
                if (sig->Function()->IsSetter()) {
                    AddMemberKind(ir::MemberExpressionKind::SETTER);
                    checker->ValidateSignatureAccessibility(obj_type_, sig, Start());
                } else if (sig->Function()->IsGetter()) {
                    AddMemberKind(ir::MemberExpressionKind::GETTER);
                    checker->ValidateSignatureAccessibility(obj_type_, sig, Start());
                }
            }
        }
    }

    prop_var_ = checker->ResolveMemberReference(this, obj_type_);
    checker->ValidatePropertyAccess(prop_var_, obj_type_, property_->Start());
    SetTsType(checker->GetTypeOfVariable(prop_var_));
    return TsType();
}
}  // namespace panda::es2panda::ir
