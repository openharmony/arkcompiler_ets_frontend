/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "metaProperty.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
void MetaProperty::TransformChildren([[maybe_unused]] const NodeTransformer &cb,
                                     [[maybe_unused]] std::string_view const transformationName)
{
}

void MetaProperty::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void MetaProperty::Dump(ir::AstDumper *dumper) const
{
    const char *kind = nullptr;

    switch (kind_) {
        case MetaPropertyKind::NEW_TARGET: {
            kind = "new.Target";
            break;
        }
        case MetaPropertyKind::IMPORT_META: {
            kind = "import.Meta";
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    dumper->Add({{"type", "MetaProperty"}, {"kind", kind}});
}

void MetaProperty::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void MetaProperty::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("MetaProperty");
}

void MetaProperty::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *MetaProperty::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType MetaProperty::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

MetaProperty *MetaProperty::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<MetaProperty>(kind_);
    ES2PANDA_ASSERT(clone != nullptr);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }
    return clone;
}
}  // namespace ark::es2panda::ir
