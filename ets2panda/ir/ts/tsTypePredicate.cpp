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

#include "tsTypePredicate.h"

#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void TSTypePredicate::Iterate(const NodeTraverser &cb) const
{
    cb(parameter_name_);
    if (type_annotation_ != nullptr) {
        cb(type_annotation_);
    }
}

void TSTypePredicate::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSTypePredicate"},
                 {"parameterName", parameter_name_},
                 {"typeAnnotation", AstDumper::Nullable(type_annotation_)},
                 {"asserts", asserts_}});
}

void TSTypePredicate::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSTypePredicate::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSTypePredicate::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSTypePredicate::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
