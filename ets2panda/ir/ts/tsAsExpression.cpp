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

#include "tsAsExpression.h"

#include "varbinder/scope.h"
#include "checker/TSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/types/ets/etsUnionType.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literal.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/typeNode.h"
#include "ir/ets/etsFunctionType.h"

namespace panda::es2panda::ir {
Expression *TSAsExpression::Expr()
{
    return expression_;
}

void TSAsExpression::SetExpr(Expression *expr)
{
    expression_ = expr;
    SetStart(expression_->Start());
}

void TSAsExpression::TransformChildren(const NodeTransformer &cb)
{
    expression_ = cb(expression_)->AsExpression();
    SetTsTypeAnnotation(static_cast<TypeNode *>(cb(TypeAnnotation())));
}

void TSAsExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expression_);
    cb(TypeAnnotation());
}

void TSAsExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSAsExpression"}, {"expression", expression_}, {"typeAnnotation", TypeAnnotation()}});
}

void TSAsExpression::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("TSAsExpression");
}

void TSAsExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSAsExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSAsExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSAsExpression::Check(checker::ETSChecker *const checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
