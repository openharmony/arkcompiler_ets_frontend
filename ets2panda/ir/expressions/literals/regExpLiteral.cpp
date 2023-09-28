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

#include "regExpLiteral.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/regScope.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"

namespace panda::es2panda::ir {
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
}  // namespace panda::es2panda::ir
