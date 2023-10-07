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

#include "etsNewArrayInstanceExpression.h"

#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "compiler/core/ETSGen.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::ir {
void ETSNewArrayInstanceExpression::TransformChildren(const NodeTransformer &cb)
{
    type_reference_ = static_cast<TypeNode *>(cb(type_reference_));
    dimension_ = cb(dimension_)->AsExpression();
}

void ETSNewArrayInstanceExpression::Iterate(const NodeTraverser &cb) const
{
    cb(type_reference_);
    cb(dimension_);
}

void ETSNewArrayInstanceExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add(
        {{"type", "ETSNewArrayInstanceExpression"}, {"typeReference", type_reference_}, {"dimension", dimension_}});
}

void ETSNewArrayInstanceExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ETSNewArrayInstanceExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    compiler::RegScope rs(etsg);
    compiler::TargetTypeContext ttctx(etsg, etsg->Checker()->GlobalIntType());

    dimension_->Compile(etsg);

    compiler::VReg arr = etsg->AllocReg();
    compiler::VReg dim = etsg->AllocReg();
    etsg->ApplyConversionAndStoreAccumulator(this, dim, dimension_->TsType());
    etsg->NewArray(this, arr, dim, TsType());
    etsg->SetVRegType(arr, TsType());
    etsg->LoadAccumulator(this, arr);
}

checker::Type *ETSNewArrayInstanceExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSNewArrayInstanceExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    auto *element_type = type_reference_->GetType(checker);
    checker->ValidateArrayIndex(dimension_);

    SetTsType(checker->CreateETSArrayType(element_type));
    checker->CreateBuiltinArraySignature(TsType()->AsETSArrayType(), 1);
    return TsType();
}
}  // namespace panda::es2panda::ir
