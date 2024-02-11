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

#include "tsMappedType.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/typeNode.h"
#include "ir/ts/tsTypeParameter.h"

namespace ark::es2panda::ir {
void TSMappedType::TransformChildren(const NodeTransformer &cb)
{
    typeParameter_ = cb(typeParameter_)->AsTSTypeParameter();
    if (typeAnnotation_ != nullptr) {
        typeAnnotation_ = static_cast<TypeNode *>(cb(typeAnnotation_));
    }
}

void TSMappedType::Iterate(const NodeTraverser &cb) const
{
    cb(typeParameter_);
    if (typeAnnotation_ != nullptr) {
        cb(typeAnnotation_);
    }
}

void TSMappedType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSMappedType"},
                 {"typeParameter", typeParameter_},
                 {"typeAnnotation", AstDumper::Optional(typeAnnotation_)},
                 {"readonly", readonly_ == MappedOption::NO_OPTS ? AstDumper::Optional(false)
                              : readonly_ == MappedOption::PLUS  ? AstDumper::Optional("+")
                                                                 : AstDumper::Optional("-")},
                 {"optional", optional_ == MappedOption::NO_OPTS ? AstDumper::Optional(false)
                              : optional_ == MappedOption::PLUS  ? AstDumper::Optional("+")
                                                                 : AstDumper::Optional("-")}});
}

void TSMappedType::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("TSMappedType");
}

void TSMappedType::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void TSMappedType::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSMappedType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSMappedType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSMappedType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir