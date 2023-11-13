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

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/typeNode.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void TSTypePredicate::TransformChildren(const NodeTransformer &cb)
{
    parameter_name_ = cb(parameter_name_)->AsExpression();
    if (type_annotation_ != nullptr) {
        type_annotation_ = static_cast<TypeNode *>(cb(type_annotation_));
    }
}

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
                 {"typeAnnotation", AstDumper::Nullish(type_annotation_)},
                 {"asserts", asserts_}});
}
void TSTypePredicate::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("TSTypePredicate");
}

void TSTypePredicate::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void TSTypePredicate::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSTypePredicate::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSTypePredicate::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSTypePredicate::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
