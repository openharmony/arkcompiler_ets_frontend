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

#include "tsEnumMember.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"

namespace panda::es2panda::ir {
void TSEnumMember::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (init_ != nullptr) {
        cb(init_);
    }
}

void TSEnumMember::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSEnumMember"}, {"id", key_}, {"initializer", AstDumper::Optional(init_)}});
}

util::StringView TSEnumMember::Name() const
{
    ASSERT(key_->IsIdentifier());
    return key_->AsIdentifier()->Name();
}

void TSEnumMember::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSEnumMember::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSEnumMember::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
