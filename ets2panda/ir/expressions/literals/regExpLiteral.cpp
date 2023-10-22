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

#include "regExpLiteral.h"

#include "binder/variable.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void RegExpLiteral::TransformChildren([[maybe_unused]] const NodeTransformer &cb) {}
void RegExpLiteral::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void RegExpLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "RegExpLiteral"}, {"source", pattern_}, {"flags", flags_str_}});
}

void RegExpLiteral::Compile(compiler::PandaGen *pg) const
{
    pg->CreateRegExpWithLiteral(this, pattern_, static_cast<uint8_t>(flags_));
}

checker::Type *RegExpLiteral::Check(checker::TSChecker *checker)
{
    // TODO(aszilagyi);
    return checker->GlobalAnyType();
}

checker::Type *RegExpLiteral::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *RegExpLiteral::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<RegExpLiteral>(pattern_, flags_, flags_str_); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
