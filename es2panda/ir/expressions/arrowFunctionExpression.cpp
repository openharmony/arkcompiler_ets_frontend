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

#include "arrowFunctionExpression.h"

#include <compiler/core/pandagen.h>
#include <ir/astDump.h>
#include <ir/base/scriptFunction.h>
#include <ir/statements/variableDeclarator.h>

namespace panda::es2panda::ir {

void ArrowFunctionExpression::Iterate(const NodeTraverser &cb) const
{
    cb(func_);
}

void ArrowFunctionExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ArrowFunctionExpression"}, {"function", func_}});
}

void ArrowFunctionExpression::Compile(compiler::PandaGen *pg) const
{
    pg->DefineFunction(func_, func_, func_->Scope()->InternalName());
}

void ArrowFunctionExpression::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    func_ = std::get<ir::AstNode *>(cb(func_))->AsScriptFunction();
}

}  // namespace panda::es2panda::ir
