/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "thisExpression.h"

#include "util/helpers.h"
#include "binder/binder.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/statements/blockStatement.h"
#include "ir/astDump.h"
#include "ir/expressions/callExpression.h"

namespace panda::es2panda::ir {
void ThisExpression::TransformChildren([[maybe_unused]] const NodeTransformer &cb) {}
void ThisExpression::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void ThisExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ThisExpression"}});
}

void ThisExpression::Compile(compiler::PandaGen *pg) const
{
    auto res = pg->Scope()->Find(binder::Binder::MANDATORY_PARAM_THIS);

    ASSERT(res.variable && res.variable->IsLocalVariable());
    pg->LoadAccFromLexEnv(this, res);

    const ir::ScriptFunction *func = util::Helpers::GetContainingConstructor(this);

    if (func != nullptr) {
        pg->ThrowIfSuperNotCorrectCall(this, 0);
    }
}

void ThisExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->LoadThis(this);
}

checker::Type *ThisExpression::Check(checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *ThisExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    /*
    example code:
    ```
        class A {
            prop
        }
        function A.method() {
            let a = () => {
                console.println(this.prop)
            }
        }
        is identical to
        function method(this: A) {
            let a = () => {
                console.println(this.prop)
            }
        }
    ```
    here when "this" is used inside an extension function, we need to bind "this" to the first
    parameter(MANDATORY_PARAM_THIS), and capture the paramter's variable other than containing class's variable
    */
    auto *variable = checker->AsETSChecker()->Scope()->Find(binder::Binder::MANDATORY_PARAM_THIS).variable;
    if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
        ASSERT(variable != nullptr);
        SetTsType(variable->TsType());
    } else {
        SetTsType(checker->CheckThisOrSuperAccess(this, checker->Context().ContainingClass(), "this"));
    }

    if (checker->HasStatus(checker::CheckerStatus::IN_LAMBDA)) {
        if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
            checker->Context().AddCapturedVar(variable, this->Start());
        } else {
            checker->Context().AddCapturedVar(checker->Context().ContainingClass()->Variable(), this->Start());
        }
    }

    return TsType();
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *ThisExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<ThisExpression>(); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
