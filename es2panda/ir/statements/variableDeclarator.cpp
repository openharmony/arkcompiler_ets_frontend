/**
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "variableDeclarator.h"

#include <compiler/base/lreference.h>
#include <compiler/core/pandagen.h>
#include <ir/astDump.h>
#include <ir/typeNode.h>
#include <ir/statements/variableDeclaration.h>
#include <ir/expressions/arrayExpression.h>
#include <ir/expressions/identifier.h>
#include <ir/expressions/objectExpression.h>

namespace panda::es2panda::ir {

void VariableDeclarator::Iterate(const NodeTraverser &cb) const
{
    cb(id_);

    if (init_) {
        cb(init_);
    }
}

void VariableDeclarator::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "VariableDeclarator"},
                 {"id", id_},
                 {"definite", AstDumper::Optional(definite_)},
                 {"init", AstDumper::Nullable(init_)}});
}

void VariableDeclarator::Compile(compiler::PandaGen *pg) const
{
    const ir::VariableDeclaration *decl = parent_->AsVariableDeclaration();
    if (decl->Declare()) {
        return;
    }

    compiler::LReference lref = compiler::LReference::CreateLRef(pg, id_, true);

    if (init_) {
        init_->Compile(pg);
    } else {
        if (decl->Kind() == ir::VariableDeclaration::VariableDeclarationKind::VAR) {
            return;
        }
        if (decl->Kind() == ir::VariableDeclaration::VariableDeclarationKind::LET && !decl->Parent()->IsCatchClause()) {
            pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
        }
    }

    lref.SetValue();
}

void VariableDeclarator::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    id_ = std::get<ir::AstNode *>(cb(id_))->AsExpression();

    if (init_) {
        init_ = std::get<ir::AstNode *>(cb(init_))->AsExpression();
    }
}

}  // namespace panda::es2panda::ir
