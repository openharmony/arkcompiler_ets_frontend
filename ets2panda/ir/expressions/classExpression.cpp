/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "classExpression.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void ClassExpression::TransformChildren(const NodeTransformer &cb)
{
    def_ = cb(def_)->AsClassDefinition();
}

void ClassExpression::Iterate(const NodeTraverser &cb) const
{
    cb(def_);
}

void ClassExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ClassExpression"}, {"definition", def_}});
}

void ClassExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ClassExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ClassExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ClassExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
ClassExpression *ClassExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const def = def_ != nullptr ? def_->Clone(allocator)->AsClassDefinition() : nullptr;

    if (auto *const clone = allocator->New<ClassExpression>(def); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        if (def != nullptr) {
            def->SetParent(clone);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
