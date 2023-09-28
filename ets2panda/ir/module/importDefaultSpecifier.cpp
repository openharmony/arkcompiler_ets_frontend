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

#include "importDefaultSpecifier.h"

#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/module/importDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"

namespace panda::es2panda::ir {
void ImportDefaultSpecifier::Iterate(const NodeTraverser &cb) const
{
    cb(local_);
}

void ImportDefaultSpecifier::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ImportDefaultSpecifier"}, {"local", local_}});
}

void ImportDefaultSpecifier::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *ImportDefaultSpecifier::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ImportDefaultSpecifier::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
