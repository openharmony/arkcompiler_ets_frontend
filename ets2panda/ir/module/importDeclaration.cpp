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

#include "importDeclaration.h"

#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/module/importNamespaceSpecifier.h"
#include "plugins/ecmascript/es2panda/ir/module/importSpecifier.h"

namespace panda::es2panda::ir {
void ImportDeclaration::Iterate(const NodeTraverser &cb) const
{
    cb(source_);

    for (auto *it : specifiers_) {
        cb(it);
    }
}

void ImportDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ImportDeclaration"}, {"source", source_}, {"specifiers", specifiers_}});
}

void ImportDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ImportDeclaration::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ImportDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ImportDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::Type *type = nullptr;
    for (auto *spec : specifiers_) {
        if (spec->IsImportNamespaceSpecifier()) {
            type = spec->AsImportNamespaceSpecifier()->Check(checker);
        }
    }

    return type;
}
}  // namespace panda::es2panda::ir
