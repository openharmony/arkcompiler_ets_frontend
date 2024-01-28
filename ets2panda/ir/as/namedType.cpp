/*
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

#include "namedType.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void NamedType::TransformChildren(const NodeTransformer &cb)
{
    name_ = cb(name_)->AsIdentifier();

    if (typeParams_ != nullptr) {
        typeParams_ = cb(typeParams_)->AsTSTypeParameterInstantiation();
    }

    if (next_ != nullptr) {
        next_ = cb(next_)->AsNamedType();
    }
}

void NamedType::Iterate(const NodeTraverser &cb) const
{
    cb(name_);

    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    if (next_ != nullptr) {
        cb(next_);
    }
}

void NamedType::Dump(AstDumper *dumper) const
{
    dumper->Add({{"type", "NamedType"},
                 {"name", name_},
                 {"typeParameters", AstDumper::Optional(typeParams_)},
                 {"next", AstDumper::Optional(next_)},
                 {"isNullable", nullable_}});
}

void NamedType::Dump(SrcDumper *dumper) const
{
    dumper->Add("NamedType");
}

void NamedType::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void NamedType::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *NamedType::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *NamedType::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir
