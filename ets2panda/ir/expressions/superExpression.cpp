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

#include "superExpression.h"

#include "util/helpers.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void SuperExpression::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void SuperExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "Super"}});
}

void SuperExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetThis(this);

    const ir::ScriptFunction *func = util::Helpers::GetContainingConstructor(this);

    if (func != nullptr) {
        pg->ThrowIfSuperNotCorrectCall(this, 0);
    }
}

void SuperExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->LoadThis(this);
}

checker::Type *SuperExpression::Check(checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *SuperExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    SetTsType(checker->CheckThisOrSuperAccess(this, checker->Context().ContainingClass()->SuperType(), "super"));
    return TsType();
}

}  // namespace panda::es2panda::ir
