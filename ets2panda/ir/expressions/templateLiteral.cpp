/**
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

#include "templateLiteral.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/base/templateElement.h"

namespace panda::es2panda::ir {
TemplateLiteral::TemplateLiteral([[maybe_unused]] Tag const tag, TemplateLiteral const &other,
                                 ArenaAllocator *const allocator)
    : Expression(static_cast<Expression const &>(other)),
      quasis_(allocator->Adapter()),
      expressions_(allocator->Adapter())
{
    for (auto *quasy : other.quasis_) {
        quasis_.emplace_back(quasy->Clone(allocator, this));
    }

    for (auto *expression : other.expressions_) {
        expressions_.emplace_back(expression->Clone(allocator, this)->AsExpression());
    }
}

// NOLINTNEXTLINE(google-default-arguments)
TemplateLiteral *TemplateLiteral::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<TemplateLiteral>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void TemplateLiteral::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : expressions_) {
        it = cb(it)->AsExpression();
    }

    for (auto *&it : quasis_) {
        it = cb(it)->AsTemplateElement();
    }
}

void TemplateLiteral::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : expressions_) {
        cb(it);
    }

    for (auto *it : quasis_) {
        cb(it);
    }
}

void TemplateLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TemplateLiteral"}, {"expressions", expressions_}, {"quasis", quasis_}});
}

void TemplateLiteral::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

checker::Type *TemplateLiteral::Check([[maybe_unused]] checker::TSChecker *checker)
{
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

void TemplateLiteral::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TemplateLiteral::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
