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

#include "tsInterfaceHeritage.h"

#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsTypeReference.h"

namespace panda::es2panda::ir {
void TSInterfaceHeritage::TransformChildren(const NodeTransformer &cb)
{
    expr_ = static_cast<TypeNode *>(cb(expr_));
}

void TSInterfaceHeritage::Iterate(const NodeTraverser &cb) const
{
    cb(expr_);
}

void TSInterfaceHeritage::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({
        {"type", "TSInterfaceHeritage"},
        {"expression", expr_},
    });
}

void TSInterfaceHeritage::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSInterfaceHeritage::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSInterfaceHeritage::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
