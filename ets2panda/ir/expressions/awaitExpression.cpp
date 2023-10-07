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

#include "awaitExpression.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/arrowFunctionExpression.h"

namespace panda::es2panda::ir {
void AwaitExpression::TransformChildren(const NodeTransformer &cb)
{
    if (argument_ != nullptr) {
        argument_ = cb(argument_)->AsExpression();
    }
}

void AwaitExpression::Iterate(const NodeTraverser &cb) const
{
    if (argument_ != nullptr) {
        cb(argument_);
    }
}

void AwaitExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "AwaitExpression"}, {"argument", AstDumper::Nullable(argument_)}});
}

void AwaitExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);

    if (argument_ != nullptr) {
        argument_->Compile(pg);
    } else {
        pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
    }

    pg->EmitAwait(this);
}

void AwaitExpression::Compile(compiler::ETSGen *etsg) const
{
    static constexpr bool IS_UNCHECKED_CAST = false;
    compiler::RegScope rs(etsg);
    compiler::VReg argument_reg = etsg->AllocReg();
    argument_->Compile(etsg);
    etsg->StoreAccumulator(this, argument_reg);
    etsg->CallThisVirtual0(argument_, argument_reg, compiler::Signatures::BUILTIN_PROMISE_AWAIT_RESOLUTION);
    etsg->CastToArrayOrObject(argument_, TsType(), IS_UNCHECKED_CAST);
    etsg->SetAccumulatorType(TsType());
}

checker::Type *AwaitExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *AwaitExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker::Type *arg_type = argument_->Check(checker);
    // Check the argument type of await expression
    if (!arg_type->IsETSObjectType() ||
        (arg_type->AsETSObjectType()->AssemblerName() != compiler::Signatures::BUILTIN_PROMISE)) {
        checker->ThrowTypeError("'await' expressions require Promise object as argument.", argument_->Start());
    }

    SetTsType(arg_type->AsETSObjectType()->TypeArguments().at(0));
    return TsType();
}
}  // namespace panda::es2panda::ir
