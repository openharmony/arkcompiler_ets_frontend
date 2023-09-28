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

#include "regScope.h"

#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/compiler/base/hoisting.h"
#include "plugins/ecmascript/es2panda/compiler/core/codeGen.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/moduleContext.h"

namespace panda::es2panda::compiler {
// RegScope

RegScope::RegScope(CodeGen *cg) : cg_(cg), reg_base_(cg_->used_regs_) {}

RegScope::~RegScope()
{
    cg_->total_regs_ = std::min(cg_->total_regs_, cg_->used_regs_);
    cg_->used_regs_ = reg_base_;
}

void RegScope::DebuggerCloseScope()
{
    if (!cg_->IsDebug()) {
        return;
    }

    cg_->scope_->SetScopeEnd(cg_->insns_.back());
}

// LocalRegScope

LocalRegScope::LocalRegScope(PandaGen *pg) : RegScope(pg) {}

LocalRegScope::LocalRegScope(CodeGen *cg, binder::Scope *scope) : RegScope(cg)
{
    prev_scope_ = cg_->scope_;
    cg_->scope_ = scope;

    for (const auto &[_, var] : scope->Bindings()) {
        (void)_;
        if (!var->LexicalBound() && var->IsLocalVariable()) {
            var->AsLocalVariable()->BindVReg(cg_->AllocReg());
        }
    }

    if (cg_->IsDebug() && !cg_->insns_.empty()) {
        cg_->scope_->SetScopeStart(cg_->insns_.back());
        cg_->debug_info_.VariableDebugInfo().push_back(cg_->scope_);
    }
}

LocalRegScope::LocalRegScope(PandaGen *pg, binder::Scope *scope) : LocalRegScope(static_cast<CodeGen *>(pg), scope)
{
    Hoisting::Hoist(pg);
}

LocalRegScope::~LocalRegScope()
{
    if (prev_scope_ == nullptr) {
        return;
    }

    DebuggerCloseScope();

    cg_->scope_ = prev_scope_;
}

// FunctionRegScope

FunctionRegScope::FunctionRegScope(CodeGen *cg) : RegScope(cg)
{
    InitializeParams([](binder::LocalVariable *const param, const VReg param_reg) { param->BindVReg(param_reg); });
}

void FunctionRegScope::InitializeParams(const StoreParamCb &cb)
{
    const auto *func_scope = cg_->Scope()->AsFunctionVariableScope();

    VReg param_reg = VReg(VReg::PARAM_START);
    for (auto *param : func_scope->ParamScope()->Params()) {
        cg_->SetVRegType(param_reg, cg_->TypeForVar(param));
        cb(param, param_reg);
        param_reg++;
    }

    for (const auto it : func_scope->Bindings()) {
        auto *const var = std::get<1>(it);
        if (var->Declaration()->IsParameterDecl() || var->Declaration()->IsTypeAliasDecl()) {
            continue;
        }

        if (!var->LexicalBound() && var->IsLocalVariable()) {
            const auto vreg = cg_->AllocReg();
            var->AsLocalVariable()->BindVReg(vreg);
        }
    }

    if (cg_->IsDebug()) {
        cg_->debug_info_.VariableDebugInfo().push_back(func_scope);
    }
}

FunctionRegScope::FunctionRegScope(PandaGen *pg) : RegScope(pg), env_scope_(pg->Allocator()->New<EnvScope>())
{
    ASSERT(cg_->Scope()->IsFunctionVariableScope());
    ASSERT(cg_->NextReg().GetIndex() == VReg::REG_START);

    VReg lex_env = pg->AllocReg();
    env_scope_->Initialize(pg, lex_env);

    const auto *func_scope = pg->Scope()->AsFunctionVariableScope();
    const auto *node = pg->RootNode();

    if (func_scope->NeedLexEnv()) {
        pg->NewLexEnv(node, func_scope->LexicalSlots());
    } else {
        pg->LdLexEnv(node);
    }

    pg->StoreAccumulator(node, lex_env);

    InitializeParams([pg, node](binder::LocalVariable *const param, const VReg param_reg) {
        if (param->LexicalBound()) {
            pg->LoadAccumulator(node, param_reg);
            pg->StoreLexicalVar(node, 0, param->LexIdx());
        } else {
            param->BindVReg(param_reg);
        }
    });

    pg->LoadAccFromArgs(pg->root_node_);

    if (func_scope->IsModuleScope()) {
        ModuleContext::Compile(pg, pg->scope_->AsModuleScope());
    }

    Hoisting::Hoist(pg);
}

FunctionRegScope::~FunctionRegScope()
{
    if (cg_->IsDebug()) {
        cg_->top_scope_->SetScopeStart(cg_->insns_.front());
    }

    DebuggerCloseScope();

    if (env_scope_ != nullptr) {
        env_scope_->~EnvScope();
    }
}
}  // namespace panda::es2panda::compiler
