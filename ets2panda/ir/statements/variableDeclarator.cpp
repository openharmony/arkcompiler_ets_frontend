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

#include "variableDeclarator.h"

#include "varbinder/variableFlags.h"
#include "compiler/base/lreference.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/astNode.h"
#include "ir/typeNode.h"
#include "ir/expression.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/identifier.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ts/destructuringContext.h"

namespace ark::es2panda::ir {
void VariableDeclarator::TransformChildren(const NodeTransformer &cb)
{
    id_ = cb(id_)->AsExpression();

    if (init_ != nullptr) {
        init_ = cb(init_)->AsExpression();
    }
}

void VariableDeclarator::Iterate(const NodeTraverser &cb) const
{
    cb(id_);

    if (init_ != nullptr) {
        cb(init_);
    }
}

void VariableDeclarator::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "VariableDeclarator"}, {"id", id_}, {"init", AstDumper::Nullish(init_)}});
}

void VariableDeclarator::Dump(ir::SrcDumper *dumper) const
{
    if (id_ != nullptr) {
        id_->Dump(dumper);
        if (id_->IsAnnotatedExpression()) {
            auto *type = id_->AsAnnotatedExpression()->TypeAnnotation();
            if (type != nullptr) {
                dumper->Add(": ");
                type->Dump(dumper);
            }
        }
    }
    if (init_ != nullptr) {
        dumper->Add(" = ");
        init_->Dump(dumper);
    }
}

void VariableDeclarator::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void VariableDeclarator::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *VariableDeclarator::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *VariableDeclarator::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir