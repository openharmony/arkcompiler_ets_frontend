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

#include "etsPackageDeclaration.h"

#include "ir/astDump.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ETSPackageDeclaration::TransformChildren(const NodeTransformer &cb)
{
    name_ = cb(name_)->AsExpression();
}

void ETSPackageDeclaration::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(name_);
}

void ETSPackageDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSPackageDeclaration"}, {"name", name_}});
}

void ETSPackageDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ETSPackageDeclaration::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ETSPackageDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSPackageDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
