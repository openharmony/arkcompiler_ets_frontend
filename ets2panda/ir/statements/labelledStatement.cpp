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

#include "labelledStatement.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/labelTarget.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"

namespace panda::es2panda::ir {
void LabelledStatement::Iterate(const NodeTraverser &cb) const
{
    cb(ident_);
    cb(body_);
}

void LabelledStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "LabelledStatement"}, {"label", ident_}, {"body", body_}});
}

template <typename CodeGen>
void CompileImpl(const LabelledStatement *self, CodeGen *cg)
{
    compiler::LabelContext label_ctx(cg, self);
    self->Body()->Compile(cg);
}

const ir::AstNode *LabelledStatement::GetReferencedStatement() const
{
    const auto *iter = body_;
    while (iter->IsLabelledStatement()) {
        iter = iter->AsLabelledStatement()->Body();
    }

    switch (iter->Type()) {
        case ir::AstNodeType::DO_WHILE_STATEMENT:
        case ir::AstNodeType::SWITCH_STATEMENT:
        case ir::AstNodeType::FOR_UPDATE_STATEMENT:
        case ir::AstNodeType::FOR_IN_STATEMENT:
        case ir::AstNodeType::WHILE_STATEMENT: {
            return iter;
        }
        default: {
            return this;
        }
    }
}

void LabelledStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    CompileImpl(this, pg);
}

void LabelledStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    CompileImpl(this, etsg);
}

checker::Type *LabelledStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *LabelledStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    body_->Check(checker);
    return nullptr;
}
}  // namespace panda::es2panda::ir
