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

#include "catchClause.h"

#include "binder/scope.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/base/lreference.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"
#include "ir/typeNode.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/statements/blockStatement.h"

namespace panda::es2panda::ir {
void CatchClause::TransformChildren(const NodeTransformer &cb)
{
    if (param_ != nullptr) {
        param_ = cb(param_)->AsExpression();
    }

    body_ = cb(body_)->AsBlockStatement();
}

void CatchClause::Iterate(const NodeTraverser &cb) const
{
    if (param_ != nullptr) {
        cb(param_);
    }

    cb(body_);
}

void CatchClause::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "CatchClause"}, {"body", body_}, {"param", AstDumper::Nullable(param_)}});
}

bool CatchClause::IsDefaultCatchClause() const
{
    return param_->AsIdentifier()->TypeAnnotation() == nullptr;
}

void CatchClause::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    compiler::LocalRegScope lrs(pg, scope_->ParamScope());

    if (param_ != nullptr) {
        auto lref = compiler::JSLReference::Create(pg, param_, true);
        lref.SetValue();
    }

    ASSERT(scope_ == body_->Scope());
    body_->Compile(pg);
}

void CatchClause::Compile(compiler::ETSGen *etsg) const
{
    compiler::LocalRegScope lrs(etsg, scope_->ParamScope());
    etsg->SetAccumulatorType(etsg->Checker()->GlobalETSObjectType());
    auto lref = compiler::ETSLReference::Create(etsg, param_, true);
    lref.SetValue();
    body_->Compile(etsg);
}

checker::Type *CatchClause::Check([[maybe_unused]] checker::TSChecker *checker)
{
    ir::Expression *type_annotation = param_->AsAnnotatedExpression()->TypeAnnotation();

    if (type_annotation != nullptr) {
        checker::Type *catch_param_type = type_annotation->Check(checker);

        if (!catch_param_type->HasTypeFlag(checker::TypeFlag::ANY_OR_UNKNOWN)) {
            checker->ThrowTypeError("Catch clause variable type annotation must be 'any' or 'unknown' if specified",
                                    Start());
        }
    }

    body_->Check(checker);

    return nullptr;
}

checker::Type *CatchClause::Check(checker::ETSChecker *checker)
{
    checker::ETSObjectType *exception_type = checker->GlobalETSObjectType();

    Identifier *param_ident = param_->AsIdentifier();

    if (param_ident->TypeAnnotation() != nullptr) {
        checker::Type *catch_param_annotation_type = param_ident->TypeAnnotation()->GetType(checker);

        exception_type = checker->CheckExceptionOrErrorType(catch_param_annotation_type, param_->Start());
    }

    param_ident->Variable()->SetTsType(exception_type);

    body_->Check(checker);

    SetTsType(exception_type);
    return exception_type;
}
}  // namespace panda::es2panda::ir
