/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "lreference.h"

#include "binder/declaration.h"
#include "binder/variableFlags.h"
#include "compiler/base/destructuring.h"
#include "compiler/core/function.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astNode.h"
#include "ir/base/spreadElement.h"
#include "ir/base/classProperty.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "util/helpers.h"

namespace panda::es2panda::compiler {

LReference::LReferenceBase LReference::CreateBase(CodeGen *cg, const ir::AstNode *node, bool is_declaration)
{
    switch (node->Type()) {
        // NOTE: This case is never reached in case of ETS
        case ir::AstNodeType::IDENTIFIER: {
            const util::StringView &name = node->AsIdentifier()->Name();
            auto res = cg->Scope()->Find(name, binder::ResolveBindingOptions::ALL);

            if (res.variable == nullptr) {
                res.variable = node->AsIdentifier()->Variable();
            }

            return {cg, node, ReferenceKind::VAR_OR_GLOBAL, res, is_declaration};
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            return {cg, node, ReferenceKind::MEMBER, {}, false};
        }
        case ir::AstNodeType::VARIABLE_DECLARATION: {
            ASSERT(node->AsVariableDeclaration()->Declarators().size() == 1);
            return CreateBase(cg, node->AsVariableDeclaration()->Declarators()[0]->Id(), true);
        }
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            return CreateBase(cg, node->AsVariableDeclarator()->Id(), true);
        }
        case ir::AstNodeType::ARRAY_PATTERN:
        case ir::AstNodeType::OBJECT_PATTERN: {
            return {cg, node, ReferenceKind::DESTRUCTURING, {}, is_declaration};
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            return CreateBase(cg, node->AsAssignmentPattern()->Left(), true);
        }
        case ir::AstNodeType::REST_ELEMENT: {
            return CreateBase(cg, node->AsRestElement()->Argument(), true);
        }
        default: {
            UNREACHABLE();
        }
    }
}

JSLReference::JSLReference(CodeGen *cg, const ir::AstNode *node, ReferenceKind ref_kind,
                           binder::ConstScopeFindResult res, bool is_declaration)
    : LReference(node, ref_kind, res, is_declaration), pg_(static_cast<PandaGen *>(cg))
{
    if (Kind() != ReferenceKind::MEMBER) {
        return;
    }

    const auto *member_expr = Node()->AsMemberExpression();

    if (member_expr->Object()->IsSuperExpression()) {
        SetKind(ReferenceKind::SUPER);
    } else if (member_expr->IsPrivateReference()) {
        SetKind(ReferenceKind::PRIVATE);
        private_ctor_ = pg_->AllocReg();
        Function::LoadClassContexts(Node(), pg_, private_ctor_, member_expr->Property()->AsIdentifier()->Name());
    }

    obj_ = pg_->AllocReg();
    member_expr->Object()->Compile(pg_);
    pg_->StoreAccumulator(Node(), obj_);

    prop_ = pg_->ToNamedPropertyKey(member_expr->Property(), member_expr->IsComputed());
    if (std::holds_alternative<util::StringView>(prop_)) {
        return;
    }

    if (std::holds_alternative<int64_t>(prop_) && Kind() != ReferenceKind::SUPER) {
        return;
    }

    member_expr->Property()->Compile(pg_);

    VReg prop_reg = pg_->AllocReg();
    pg_->StoreAccumulator(Node(), prop_reg);
    prop_ = prop_reg;
}

void JSLReference::GetValue() const
{
    switch (Kind()) {
        case ReferenceKind::VAR_OR_GLOBAL: {
            pg_->LoadVar(Node()->AsIdentifier(), Result());
            break;
        }
        case ReferenceKind::MEMBER: {
            if (std::holds_alternative<VReg>(prop_)) {
                pg_->LoadObjProperty(Node(), obj_);
                break;
            }
            [[fallthrough]];
        }
        case ReferenceKind::SUPER: {
            pg_->LoadObjProperty(Node(), prop_);
            break;
        }
        case ReferenceKind::PRIVATE: {
            pg_->ClassPrivateFieldGet(Node(), private_ctor_, obj_, std::get<util::StringView>(prop_));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void JSLReference::SetValue() const
{
    switch (Kind()) {
        case ReferenceKind::VAR_OR_GLOBAL: {
            pg_->StoreVar(Node(), Result(), IsDeclaration());
            break;
        }
        case ReferenceKind::SUPER: {
            pg_->StoreSuperProperty(Node(), obj_, prop_);

            break;
        }
        case ReferenceKind::MEMBER: {
            pg_->StoreObjProperty(Node(), obj_, prop_);

            break;
        }
        case ReferenceKind::PRIVATE: {
            pg_->ClassPrivateFieldSet(Node(), private_ctor_, obj_, std::get<util::StringView>(prop_));
            break;
        }
        case ReferenceKind::DESTRUCTURING: {
            Destructuring::Compile(pg_, Node()->AsExpression());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

ETSLReference::ETSLReference(CodeGen *cg, const ir::AstNode *node, ReferenceKind ref_kind,
                             binder::ConstScopeFindResult res, bool is_declaration)
    : LReference(node, ref_kind, res, is_declaration), etsg_(static_cast<ETSGen *>(cg))
{
    if (Kind() != ReferenceKind::MEMBER) {
        SetKind(ResolveReferenceKind(res.variable));
        return;
    }

    const auto *member_expr = Node()->AsMemberExpression();
    static_obj_ref_ = member_expr->Object()->TsType();

    if (!member_expr->IsComputed() && etsg_->Checker()->IsVariableStatic(member_expr->PropVar()) &&
        !static_obj_ref_->IsETSDynamicType()) {
        return;
    }

    TargetTypeContext ttctx(etsg_, member_expr->Object()->TsType());
    member_expr->Object()->Compile(etsg_);
    base_reg_ = etsg_->AllocReg();
    etsg_->StoreAccumulator(node, base_reg_);

    if (member_expr->IsComputed()) {
        TargetTypeContext pttctx(etsg_, member_expr->Property()->TsType());
        member_expr->Property()->Compile(etsg_);
        prop_reg_ = etsg_->AllocReg();
        etsg_->ApplyConversionAndStoreAccumulator(node, prop_reg_, member_expr->Property()->TsType());
    }
}

ETSLReference ETSLReference::Create(CodeGen *const cg, const ir::AstNode *const node, const bool is_declaration)
{
    if (node->Type() == ir::AstNodeType::IDENTIFIER) {
        const auto &name = node->AsIdentifier()->Name();
        auto res = cg->Scope()->FindInFunctionScope(name, binder::ResolveBindingOptions::ALL);
        if (res.variable == nullptr) {
            res = cg->Scope()->FindInGlobal(name, binder::ResolveBindingOptions::ALL_VARIABLES |
                                                      binder::ResolveBindingOptions::ALL_METHOD);
            if (res.variable == nullptr) {
                res.variable = node->AsIdentifier()->Variable();
            }
        }

        return {cg, node, ReferenceKind::VAR_OR_GLOBAL, res, is_declaration};
    }
    return std::make_from_tuple<ETSLReference>(CreateBase(cg, node, is_declaration));
}

ReferenceKind ETSLReference::ResolveReferenceKind(const binder::Variable *variable)
{
    if (variable->HasFlag(binder::VariableFlags::SYNTHETIC)) {
        return ReferenceKind::METHOD;
    }
    if (variable->HasFlag(binder::VariableFlags::LOCAL)) {
        return ReferenceKind::LOCAL;
    }

    auto *decl_node = variable->Declaration()->Node();

    switch (decl_node->Type()) {
        case ir::AstNodeType::CLASS_PROPERTY: {
            auto *class_field = decl_node->AsClassProperty();
            return class_field->IsStatic() ? ReferenceKind::STATIC_FIELD : ReferenceKind::FIELD;
        }
        case ir::AstNodeType::CLASS_DEFINITION: {
            auto *class_def = decl_node->AsClassDefinition();
            return class_def->IsStatic() ? ReferenceKind::STATIC_CLASS : ReferenceKind::CLASS;
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            return ReferenceKind::METHOD;
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return ReferenceKind::CLASS;
        }
        default: {
            break;
        }
    }

    return ReferenceKind::LOCAL;
}

void ETSLReference::GetValue() const
{
    switch (Kind()) {
        case ReferenceKind::MEMBER: {
            Node()->AsMemberExpression()->Compile(etsg_);
            break;
        }
        default: {
            etsg_->LoadVar(Node()->AsIdentifier(), Variable());
            break;
        }
    }
}

void ETSLReference::SetValue() const
{
    switch (Kind()) {
        case ReferenceKind::MEMBER: {
            auto *member_expr = Node()->AsMemberExpression();
            if (!member_expr->IsIgnoreBox()) {
                etsg_->ApplyConversion(Node(), member_expr->TsType());
            }

            if (member_expr->IsComputed()) {
                auto object_type = member_expr->Object()->TsType();
                if (object_type->IsETSDynamicType()) {
                    auto lang = object_type->AsETSDynamicType()->Language();
                    etsg_->StoreElementDynamic(Node(), base_reg_, prop_reg_, lang);
                } else {
                    etsg_->StoreArrayElement(Node(), base_reg_, prop_reg_,
                                             etsg_->GetVRegType(base_reg_)->AsETSArrayType()->ElementType());
                }
                break;
            }

            if (member_expr->PropVar()->TsType()->HasTypeFlag(checker::TypeFlag::GETTER_SETTER)) {
                const auto *sig = member_expr->PropVar()->TsType()->AsETSFunctionType()->FindSetter();

                auto arg_reg = etsg_->AllocReg();
                etsg_->StoreAccumulator(Node(), arg_reg);

                if (sig->Function()->IsStatic()) {
                    etsg_->CallThisStatic0(Node(), arg_reg, sig->InternalName());
                } else {
                    etsg_->CallThisVirtual1(Node(), base_reg_, sig->InternalName(), arg_reg);
                }
                break;
            }

            auto &prop_name = member_expr->Property()->AsIdentifier()->Name();
            if (member_expr->PropVar()->HasFlag(binder::VariableFlags::STATIC)) {
                util::StringView full_name =
                    etsg_->FormClassPropReference(static_obj_ref_->AsETSObjectType(), prop_name);
                if (static_obj_ref_->IsETSDynamicType()) {
                    auto lang = static_obj_ref_->AsETSDynamicType()->Language();
                    etsg_->StorePropertyDynamic(Node(), member_expr->TsType(), base_reg_, prop_name, lang);
                } else {
                    etsg_->StoreStaticProperty(Node(), member_expr->TsType(), full_name);
                }
                break;
            }

            if (static_obj_ref_->IsETSDynamicType()) {
                auto lang = static_obj_ref_->AsETSDynamicType()->Language();
                etsg_->StorePropertyDynamic(Node(), member_expr->TsType(), base_reg_, prop_name, lang);
            } else {
                auto type = etsg_->Checker()->MaybeBoxedType(member_expr->PropVar(), etsg_->Allocator());
                etsg_->StoreProperty(Node(), type, base_reg_, prop_name);
            }
            break;
        }
        default: {
            etsg_->StoreVar(Node()->AsIdentifier(), Result());
            break;
        }
    }
}

}  // namespace panda::es2panda::compiler
