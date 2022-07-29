/*
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

#include "chainExpression.h"
#include <compiler/core/pandagen.h>

#include <ir/astDump.h>
#include <ir/expressions/memberExpression.h>
#include <ir/expressions/callExpression.h>

namespace panda::es2panda::ir {

void ChainExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expression_);
}

void ChainExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ChainExpression"}, {"expression", expression_}});
}

void ChainExpression::Compile(compiler::PandaGen *pg) const
{
    // TODO: support continuous optional chain expression
    compiler::RegScope rs(pg);
    const MemberExpression *memberExpr = nullptr;
    if (this->GetExpression()->IsMemberExpression()) {
        memberExpr = this->GetExpression()->AsMemberExpression();
    } else {
        auto callExpr = this->GetExpression()->AsCallExpression();
        memberExpr = callExpr->Callee()->AsMemberExpression();
    }

    compiler::VReg objReg = pg->AllocReg();
    auto *isNullOrUndefinedLabel = pg->AllocLabel();
    auto *endLabel = pg->AllocLabel();

    memberExpr->CompileObject(pg, objReg);
    pg->LoadConst(this, compiler::Constant::JS_NULL);
    pg->Condition(this, lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL, objReg, isNullOrUndefinedLabel);
    pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
    pg->Condition(this, lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL, objReg, isNullOrUndefinedLabel);

    // obj (ahead ?.) is not null/undefined, continue to compile sub-expression)
    this->GetExpression()->Compile(pg);
    pg->Branch(this, endLabel);

    // obj (ahead ?.) is null/undefined, return undefined)
    pg->SetLabel(this, isNullOrUndefinedLabel);
    pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);

    pg->SetLabel(this, endLabel);
}

checker::Type *ChainExpression::Check([[maybe_unused]] checker::Checker *checker) const
{
    return expression_->Check(checker);
}

}  // namespace panda::es2panda::ir
