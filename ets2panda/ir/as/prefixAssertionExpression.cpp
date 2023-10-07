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

#include "prefixAssertionExpression.h"

#include "ir/astDump.h"
#include "ir/typeNode.h"

namespace panda::es2panda::ir {
void PrefixAssertionExpression::TransformChildren(const NodeTransformer &cb)
{
    type_ = static_cast<TypeNode *>(cb(type_));
    expr_ = cb(expr_)->AsExpression();
}

void PrefixAssertionExpression::Iterate(const NodeTraverser &cb) const
{
    cb(type_);
    cb(expr_);
}

void PrefixAssertionExpression::Dump(AstDumper *dumper) const
{
    dumper->Add({{"type", "PrefixAssertionExpression"}, {"expression", expr_}, {"type", type_}});
}

void PrefixAssertionExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *PrefixAssertionExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *PrefixAssertionExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
