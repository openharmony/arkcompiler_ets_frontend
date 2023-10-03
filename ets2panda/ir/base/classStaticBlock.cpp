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

#include "classStaticBlock.h"

#include "binder/scope.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/base/scriptFunction.h"
#include "ir/expression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "checker/ETSchecker.h"

#include <cstdint>
#include <string>

namespace panda::es2panda::ir {
void ClassStaticBlock::Iterate(const NodeTraverser &cb) const
{
    cb(value_);
}

void ClassStaticBlock::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ClassStaticBlock"}, {"value", value_}});
}

void ClassStaticBlock::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ClassStaticBlock::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ClassStaticBlock::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ClassStaticBlock::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    if (checker->HasStatus(checker::CheckerStatus::INNER_CLASS)) {
        checker->ThrowTypeError("Static initializer is not allowed in inner class.", Start());
    }

    auto *func = Function();
    SetTsType(checker->BuildFunctionSignature(func));
    checker::ScopeContext scope_ctx(checker, func->Scope());
    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_STATIC_BLOCK | checker::CheckerStatus::IN_STATIC_CONTEXT);
    func->Body()->Check(checker);
    return TsType();
}

ir::ScriptFunction *ClassStaticBlock::Function()
{
    return value_->AsFunctionExpression()->Function();
}

const ir::ScriptFunction *ClassStaticBlock::Function() const
{
    return value_->AsFunctionExpression()->Function();
}

const util::StringView &ClassStaticBlock::Name() const
{
    return Function()->Id()->Name();
}

}  // namespace panda::es2panda::ir
