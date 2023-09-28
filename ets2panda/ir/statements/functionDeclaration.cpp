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

#include "functionDeclaration.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsFunctionType.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/base/spreadElement.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"

namespace panda::es2panda::ir {
void FunctionDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(func_);
}

void FunctionDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", func_->IsOverload() ? "TSDeclareFunction" : "FunctionDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"function", func_}});
}

void FunctionDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void FunctionDeclaration::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *FunctionDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (func_->IsOverload()) {
        return nullptr;
    }

    const util::StringView &func_name = func_->Id()->Name();
    auto result = checker->Scope()->Find(func_name);
    ASSERT(result.variable);

    checker::ScopeContext scope_ctx(checker, func_->Scope());

    if (result.variable->TsType() == nullptr) {
        checker->InferFunctionDeclarationType(result.variable->Declaration()->AsFunctionDecl(), result.variable);
    }

    func_->Body()->Check(checker);

    return nullptr;
}

checker::Type *FunctionDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    UNREACHABLE();
    return nullptr;
}
}  // namespace panda::es2panda::ir
