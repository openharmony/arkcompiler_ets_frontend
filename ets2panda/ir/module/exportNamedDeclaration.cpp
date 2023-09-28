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

#include "exportNamedDeclaration.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/module/exportSpecifier.h"

namespace panda::es2panda::ir {
void ExportNamedDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    if (decl_ != nullptr) {
        cb(decl_);
    } else {
        if (source_ != nullptr) {
            cb(source_);
        }

        for (auto *it : specifiers_) {
            cb(it);
        }
    }
}

void ExportNamedDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ExportNamedDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"declaration", AstDumper::Nullable(decl_)},
                 {"source", AstDumper::Nullable(source_)},
                 {"specifiers", specifiers_}});
}

void ExportNamedDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    if (decl_ == nullptr) {
        return;
    }

    decl_->Compile(pg);
}

void ExportNamedDeclaration::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ExportNamedDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ExportNamedDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
