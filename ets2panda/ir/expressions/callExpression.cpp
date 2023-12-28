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

#include "callExpression.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
void CallExpression::TransformChildren(const NodeTransformer &cb)
{
    callee_ = cb(callee_)->AsExpression();

    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterInstantiation();
    }

    for (auto *&it : arguments_) {
        it = cb(it)->AsExpression();
    }
}

void CallExpression::Iterate(const NodeTraverser &cb) const
{
    cb(callee_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : arguments_) {
        cb(it);
    }

    if (trailing_block_ != nullptr) {
        cb(trailing_block_);
    }
}

void CallExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "CallExpression"},
                 {"callee", callee_},
                 {"arguments", arguments_},
                 {"optional", IsOptional()},
                 {"typeParameters", AstDumper::Optional(type_params_)}});
}

void CallExpression::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(callee_);
    callee_->Dump(dumper);
    dumper->Add("(");
    for (auto arg : arguments_) {
        arg->Dump(dumper);
        if (arg != arguments_.back()) {
            dumper->Add(", ");
        }
    }
    dumper->Add(")");
}

void CallExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void CallExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *CallExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

bool CallExpression::IsETSConstructorCall() const
{
    return callee_->IsThisExpression() || callee_->IsSuperExpression();
}

checker::Type *CallExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

CallExpression::CallExpression(CallExpression const &other, ArenaAllocator *const allocator)
    : MaybeOptionalExpression(static_cast<MaybeOptionalExpression const &>(other)),
      arguments_(allocator->Adapter()),
      signature_(other.signature_),
      trailing_comma_(other.trailing_comma_),
      is_trailing_block_in_new_line_(other.is_trailing_block_in_new_line_)
{
    callee_ = other.callee_->Clone(allocator, this)->AsExpression();
    type_params_ = other.type_params_->Clone(allocator, this);

    for (auto *const argument : other.arguments_) {
        arguments_.emplace_back(argument->Clone(allocator, this)->AsExpression());
    }

    if (other.trailing_block_ != nullptr) {
        trailing_block_ = other.trailing_block_->Clone(allocator, this)->AsBlockStatement();
    }
}

// NOLINTNEXTLINE(google-default-arguments)
CallExpression *CallExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<CallExpression>(*this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
