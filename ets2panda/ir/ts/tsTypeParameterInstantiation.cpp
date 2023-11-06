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

#include "es2panda.h"
#include "tsTypeParameterInstantiation.h"

#include "ir/astDump.h"
#include "ir/expression.h"
#include "ir/typeNode.h"

namespace panda::es2panda::ir {
TSTypeParameterInstantiation::TSTypeParameterInstantiation([[maybe_unused]] Tag const tag,
                                                           TSTypeParameterInstantiation const &other,
                                                           ArenaAllocator *const allocator)
    : Expression(static_cast<Expression const &>(other)), params_(allocator->Adapter())
{
    for (auto *param : other.params_) {
        params_.emplace_back(param->Clone(allocator, this)->AsTypeNode());
    }
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *TSTypeParameterInstantiation::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<TSTypeParameterInstantiation>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void TSTypeParameterInstantiation::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : params_) {
        it = static_cast<TypeNode *>(cb(it));
    }
}

void TSTypeParameterInstantiation::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : params_) {
        cb(it);
    }
}

void TSTypeParameterInstantiation::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSTypeParameterInstantiation"}, {"params", params_}});
}

void TSTypeParameterInstantiation::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSTypeParameterInstantiation::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSTypeParameterInstantiation::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}

}  // namespace panda::es2panda::ir
