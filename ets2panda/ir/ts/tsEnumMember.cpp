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

#include "tsEnumMember.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
void TSEnumMember::TransformChildren(const NodeTransformer &cb)
{
    key_ = cb(key_)->AsExpression();

    if (init_ != nullptr) {
        init_ = cb(init_)->AsExpression();
    }
}

void TSEnumMember::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (init_ != nullptr) {
        cb(init_);
    }
}

void TSEnumMember::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSEnumMember"}, {"id", key_}, {"initializer", AstDumper::Optional(init_)}});
}

void TSEnumMember::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(key_ != nullptr);
    key_->Dump(dumper);
    if (init_ != nullptr) {
        dumper->Add(" = ");
        init_->Dump(dumper);
    }
}

util::StringView TSEnumMember::Name() const
{
    ASSERT(key_->IsIdentifier());
    return key_->AsIdentifier()->Name();
}

void TSEnumMember::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSEnumMember::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSEnumMember::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSEnumMember::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
