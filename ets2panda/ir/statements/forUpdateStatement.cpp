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

#include "forUpdateStatement.h"
#include <cstddef>

#include "varbinder/scope.h"
#include "compiler/base/condition.h"
#include "compiler/base/lreference.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/dynamicContext.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void ForUpdateStatement::TransformChildren(const NodeTransformer &cb)
{
    if (init_ != nullptr) {
        init_ = cb(init_);
    }

    if (test_ != nullptr) {
        test_ = cb(test_)->AsExpression();
    }

    if (update_ != nullptr) {
        update_ = cb(update_)->AsExpression();
    }

    body_ = cb(body_)->AsStatement();
}

void ForUpdateStatement::Iterate(const NodeTraverser &cb) const
{
    if (init_ != nullptr) {
        cb(init_);
    }
    if (test_ != nullptr) {
        cb(test_);
    }
    if (update_ != nullptr) {
        cb(update_);
    }

    cb(body_);
}

void ForUpdateStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ForUpdateStatement"},
                 {"init", AstDumper::Nullish(init_)},
                 {"test", AstDumper::Nullish(test_)},
                 {"update", AstDumper::Nullish(update_)},
                 {"body", body_}});
}

void ForUpdateStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("for ");
    dumper->Add("(");
    if (init_ != nullptr) {
        init_->Dump(dumper);
    }
    dumper->Add(";");
    if (test_ != nullptr) {
        test_->Dump(dumper);
    }
    dumper->Add(";");
    if (update_ != nullptr) {
        update_->Dump(dumper);
    }
    dumper->Add(") ");
    dumper->Add("{");
    if (body_ != nullptr) {
        dumper->IncrIndent();
        dumper->Endl();
        body_->Dump(dumper);
        dumper->DecrIndent();
        dumper->Endl();
    }
    dumper->Add("}");
}

void ForUpdateStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ForUpdateStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ForUpdateStatement::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ForUpdateStatement::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir
