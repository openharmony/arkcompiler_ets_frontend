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

#include "assertStatement.h"

#include "binder/ETSBinder.h"
#include "compiler/base/condition.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void AssertStatement::TransformChildren(const NodeTransformer &cb)
{
    test_ = cb(test_)->AsExpression();

    if (second_ != nullptr) {
        second_ = cb(second_)->AsExpression();
    }
}

void AssertStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);

    if (second_ != nullptr) {
        cb(second_);
    }
}

void AssertStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "AssertStatement"}, {"test", test_}, {"second", AstDumper::Nullable(second_)}});
}

void AssertStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void AssertStatement::ThrowError(compiler::ETSGen *const etsg) const
{
    const compiler::RegScope rs(etsg);

    if (second_ != nullptr) {
        second_->Compile(etsg);
    } else {
        etsg->LoadAccumulatorString(this, "Assertion failed.");
    }

    const auto message = etsg->AllocReg();
    etsg->StoreAccumulator(this, message);

    const auto assertion_error = etsg->AllocReg();
    etsg->NewObject(this, assertion_error, compiler::Signatures::BUILTIN_ASSERTION_ERROR);
    etsg->CallThisStatic1(this, assertion_error, compiler::Signatures::BUILTIN_ASSERTION_ERROR_CTOR, message);
    etsg->EmitThrow(this, assertion_error);
}

void AssertStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    auto res = compiler::Condition::CheckConstantExpr(etsg, test_);

    if (res == compiler::Condition::Result::CONST_TRUE) {
        return;
    }

    if (res == compiler::Condition::Result::CONST_FALSE) {
        ThrowError(etsg);
        return;
    }

    compiler::Label *end_label = etsg->AllocLabel();

    test_->Compile(etsg);
    etsg->BranchIfTrue(this, end_label);
    ThrowError(etsg);
    etsg->SetLabel(this, end_label);
}

checker::Type *AssertStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *AssertStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker->CheckTruthinessOfType(test_);

    if (second_ != nullptr) {
        auto *msg_type = second_->Check(checker);

        if (!msg_type->IsETSStringType()) {
            checker->ThrowTypeError("Assert message must be string", second_->Start());
        }
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
