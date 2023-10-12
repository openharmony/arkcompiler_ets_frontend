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

#include "taggedTemplateExpression.h"

#include "varbinder/variable.h"
#include "compiler/base/literals.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::ir {
void TaggedTemplateExpression::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterInstantiation();
    }

    tag_ = cb(tag_)->AsExpression();
    quasi_ = cb(quasi_)->AsTemplateLiteral();
}

void TaggedTemplateExpression::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    cb(tag_);
    cb(quasi_);
}

void TaggedTemplateExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TaggedTemplateExpression"},
                 {"tag", tag_},
                 {"quasi", quasi_},
                 {"typeParameters", AstDumper::Optional(type_params_)}});
}

void TaggedTemplateExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TaggedTemplateExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TaggedTemplateExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TaggedTemplateExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
TaggedTemplateExpression *TaggedTemplateExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const tag = tag_ != nullptr ? tag_->Clone(allocator)->AsExpression() : nullptr;
    auto *const quasi = quasi_ != nullptr ? quasi_->Clone(allocator) : nullptr;
    auto *const type_params = type_params_ != nullptr ? type_params_->Clone(allocator) : nullptr;

    if (auto *const clone = allocator->New<TaggedTemplateExpression>(tag, quasi, type_params); clone != nullptr) {
        if (tag != nullptr) {
            tag->SetParent(clone);
        }
        if (quasi != nullptr) {
            quasi->SetParent(clone);
        }
        if (type_params != nullptr) {
            type_params->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
