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

#include "tsAnyKeyword.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void TSAnyKeyword::TransformChildren([[maybe_unused]] const NodeTransformer &cb) {}
void TSAnyKeyword::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void TSAnyKeyword::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSAnyKeyword"}});
}

void TSAnyKeyword::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("TSAnyKeyword");
}

void TSAnyKeyword::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSAnyKeyword::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSAnyKeyword::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSAnyKeyword::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GlobalAnyType();
}

checker::Type *TSAnyKeyword::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir