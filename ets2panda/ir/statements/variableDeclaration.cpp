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

#include "variableDeclaration.h"

#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"

namespace panda::es2panda::ir {
void VariableDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    for (auto *it : declarators_) {
        cb(it);
    }
}

void VariableDeclaration::Dump(ir::AstDumper *dumper) const
{
    const char *kind = nullptr;

    switch (kind_) {
        case VariableDeclarationKind::CONST: {
            kind = "const";
            break;
        }
        case VariableDeclarationKind::LET: {
            kind = "let";
            break;
        }
        case VariableDeclarationKind::VAR: {
            kind = "var";
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    dumper->Add({{"type", "VariableDeclaration"},
                 {"declarations", declarators_},
                 {"kind", kind},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"declare", AstDumper::Optional(declare_)}});
}

void VariableDeclaration::Compile(compiler::PandaGen *pg) const
{
    for (const auto *it : declarators_) {
        it->Compile(pg);
    }
}

void VariableDeclaration::Compile(compiler::ETSGen *etsg) const
{
    for (const auto *it : declarators_) {
        it->Compile(etsg);
    }
}

checker::Type *VariableDeclaration::Check(checker::TSChecker *checker)
{
    for (auto *it : declarators_) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *VariableDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    for (auto *it : declarators_) {
        it->Check(checker);
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
