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

#include "classDeclaration.h"

#include "plugins/ecmascript/es2panda/compiler/base/lreference.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"

namespace panda::es2panda::ir {
void ClassDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(def_);
}

void ClassDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ClassDeclaration"}, {"definition", def_}, {"decorators", AstDumper::Optional(decorators_)}});
}

void ClassDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    auto lref = compiler::JSLReference::Create(pg, def_->Ident(), true);
    def_->Compile(pg);
    lref.SetValue();
}

void ClassDeclaration::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ClassDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ClassDeclaration::Check(checker::ETSChecker *checker)
{
    def_->Check(checker);
    return nullptr;
}
}  // namespace panda::es2panda::ir
