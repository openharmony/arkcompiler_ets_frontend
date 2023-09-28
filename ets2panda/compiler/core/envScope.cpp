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

#include "envScope.h"

#include "plugins/ecmascript/es2panda/compiler/core/codeGen.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/ir/statement.h"

namespace panda::es2panda::compiler {
ScopeContext::ScopeContext(CodeGen *cg, binder::Scope *new_scope) : cg_(cg), prev_scope_(cg_->scope_)
{
    cg->scope_ = new_scope;
}

ScopeContext::~ScopeContext()
{
    cg_->scope_ = prev_scope_;
}

void EnvScope::Initialize(PandaGen *pg, VReg lex_env)
{
    pg_ = pg;
    prev_ = pg_->env_scope_;
    lex_env_ = lex_env;
    pg_->env_scope_ = this;
}

EnvScope::~EnvScope()
{
    if (pg_ == nullptr) {
        return;
    }

    pg_->env_scope_ = prev_;
}

void LoopEnvScope::CopyBindings(PandaGen *pg, binder::VariableScope *scope, binder::VariableFlags flag)
{
    if (!HasEnv()) {
        return;
    }

    Initialize(pg, pg->AllocReg());

    pg_->NewLexEnv(scope_->Node(), scope->LexicalSlots());
    pg_->StoreAccumulator(scope_->Node(), lex_env_);

    ASSERT(scope->NeedLexEnv());

    for (const auto &[_, variable] : scope_->Bindings()) {
        (void)_;
        if (!variable->HasFlag(flag)) {
            continue;
        }

        pg->LoadLexicalVar(scope_->Node(), 1, variable->AsLocalVariable()->LexIdx());
        pg->StoreLexicalVar(scope_->Parent()->Node(), 0, variable->AsLocalVariable()->LexIdx());
    }
}

void LoopEnvScope::CopyPetIterationCtx()
{
    if (!HasEnv()) {
        return;
    }

    pg_->CopyLexEnv(scope_->Node());
    pg_->StoreAccumulator(scope_->Node(), lex_env_);
}
}  // namespace panda::es2panda::compiler
