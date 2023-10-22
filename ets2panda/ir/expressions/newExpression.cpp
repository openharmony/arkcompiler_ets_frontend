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

#include "newExpression.h"

#include "util/helpers.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
NewExpression::NewExpression([[maybe_unused]] Tag const tag, NewExpression const &other,
                             ArenaAllocator *const allocator)
    : Expression(static_cast<Expression const &>(other)), arguments_(allocator->Adapter())
{
    if (other.callee_ != nullptr) {
        callee_ = other.callee_->Clone(allocator, this);
    }

    for (auto *argument : other.arguments_) {
        arguments_.emplace_back(argument->Clone(allocator, this));
    }
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *NewExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<NewExpression>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void NewExpression::TransformChildren(const NodeTransformer &cb)
{
    callee_ = cb(callee_)->AsExpression();

    for (auto *&it : arguments_) {
        it = cb(it)->AsExpression();
    }
}

void NewExpression::Iterate(const NodeTraverser &cb) const
{
    cb(callee_);

    for (auto *it : arguments_) {
        cb(it);
    }
}

void NewExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "NewExpression"}, {"callee", callee_}, {"arguments", arguments_}});
}

void NewExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg ctor = pg->AllocReg();
    compiler::VReg new_target = pg->AllocReg();

    callee_->Compile(pg);
    pg->StoreAccumulator(this, ctor);

    // new.Target will be the same as ctor
    pg->StoreAccumulator(this, new_target);

    if (!util::Helpers::ContainSpreadElement(arguments_) &&
        arguments_.size() < compiler::PandaGen::MAX_RANGE_CALL_ARG) {
        for (const auto *it : arguments_) {
            compiler::VReg arg = pg->AllocReg();
            it->Compile(pg);
            pg->StoreAccumulator(this, arg);
        }

        pg->NewObject(this, ctor, arguments_.size() + 2);
    } else {
        compiler::VReg args_obj = pg->AllocReg();

        pg->CreateArray(this, arguments_, args_obj);
        pg->NewObjSpread(this, ctor, new_target);
    }
}

void NewExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *NewExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::Type *callee_type = callee_->Check(checker);

    if (callee_type->IsObjectType()) {
        checker::ObjectType *callee_obj = callee_type->AsObjectType();
        return checker->ResolveCallOrNewExpression(callee_obj->ConstructSignatures(), arguments_, Start());
    }

    checker->ThrowTypeError("This expression is not callable.", Start());
    return nullptr;
}

checker::Type *NewExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
