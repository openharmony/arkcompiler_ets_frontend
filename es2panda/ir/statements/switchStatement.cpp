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

#include "switchStatement.h"

#include <compiler/core/switchBuilder.h>
#include <compiler/core/pandagen.h>
#include <ir/astDump.h>
#include <ir/statements/switchCaseStatement.h>

namespace panda::es2panda::ir {

void SwitchStatement::Iterate(const NodeTraverser &cb) const
{
    cb(discriminant_);

    for (auto *it : cases_) {
        cb(it);
    }
}

void SwitchStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "SwitchStatement"}, {"discriminant", discriminant_}, {"cases", cases_}});
}

void SwitchStatement::Compile(compiler::PandaGen *pg) const
{
    compiler::SwitchBuilder builder(pg, this);
    compiler::VReg tag = pg->AllocReg();

    builder.CompileTagOfSwitch(tag);

    compiler::LocalRegScope lrs(pg, scope_);
    uint32_t defaultIndex = 0;

    if (cases_.size() == 0) {
        return;
    }

    for (size_t i = 0; i < cases_.size(); i++) {
        const auto *clause = cases_[i];

        if (!clause->Test()) {
            defaultIndex = i;
            continue;
        }

        builder.JumpIfCase(tag, i);
    }

    if (!cases_[defaultIndex]->Test()) {
        builder.JumpToDefault(defaultIndex);
    } else {
        builder.Break();
    }

    for (size_t i = 0; i < cases_.size(); i++) {
        builder.SetCaseTarget(i);
        builder.CompileCaseStatements(i);
    }
}


void SwitchStatement::UpdateSelf(const NodeUpdater &cb, binder::Binder *binder)
{
    auto scopeCtx = binder::LexicalScope<binder::LocalScope>::Enter(binder, scope_);

    discriminant_ = std::get<ir::AstNode *>(cb(discriminant_))->AsExpression();

    for (auto iter = cases_.begin(); iter != cases_.end(); iter++) {
        *iter = std::get<ir::AstNode *>(cb(*iter))->AsSwitchCaseStatement();
    }
}

}  // namespace panda::es2panda::ir
