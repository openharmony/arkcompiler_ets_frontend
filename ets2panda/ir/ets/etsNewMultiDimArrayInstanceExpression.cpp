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

#include "etsNewMultiDimArrayInstanceExpression.h"

#include "plugins/ecmascript/es2panda/binder/ETSBinder.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/types/signature.h"

namespace panda::es2panda::ir {
void ETSNewMultiDimArrayInstanceExpression::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(type_reference_);
    for (auto *dim : dimensions_) {
        cb(dim);
    }
}

void ETSNewMultiDimArrayInstanceExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSNewMultiDimArrayInstanceExpression"},
                 {"typeReference", type_reference_},
                 {"dimensions", dimensions_}});
}

void ETSNewMultiDimArrayInstanceExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ETSNewMultiDimArrayInstanceExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->InitObject(this, signature_, dimensions_);
    etsg->SetAccumulatorType(TsType());
}

checker::Type *ETSNewMultiDimArrayInstanceExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSNewMultiDimArrayInstanceExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    auto *element_type = type_reference_->GetType(checker);

    for (auto *dim : dimensions_) {
        checker->ValidateArrayIndex(dim);
        element_type = checker->CreateETSArrayType(element_type);
    }

    SetTsType(element_type);
    signature_ = checker->CreateBuiltinArraySignature(element_type->AsETSArrayType(), dimensions_.size());
    return TsType();
}
}  // namespace panda::es2panda::ir
