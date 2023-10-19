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
