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

#include "etsLaunchExpression.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"

namespace panda::es2panda::ir {
ETSLaunchExpression::ETSLaunchExpression(CallExpression *expr)
    : Expression(AstNodeType::ETS_LAUNCH_EXPRESSION), expr_(expr)
{
}

void ETSLaunchExpression::TransformChildren(const NodeTransformer &cb)
{
    expr_ = cb(expr_)->AsCallExpression();
}

void ETSLaunchExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expr_);
}

void ETSLaunchExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSLaunchExpression"}, {"expr", expr_}});
}

void ETSLaunchExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ETSLaunchExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
#ifdef PANDA_WITH_ETS
    compiler::RegScope rs(etsg);
    compiler::VReg callee_reg = etsg->AllocReg();
    checker::Signature *signature = expr_->Signature();
    bool is_static = signature->HasSignatureFlag(checker::SignatureFlags::STATIC);
    bool is_reference = signature->HasSignatureFlag(checker::SignatureFlags::TYPE);

    if (!is_reference && expr_->Callee()->IsIdentifier()) {
        if (!is_static) {
            etsg->LoadThis(expr_);
            etsg->StoreAccumulator(this, callee_reg);
        }
    } else if (!is_reference && expr_->Callee()->IsMemberExpression()) {
        if (!is_static) {
            expr_->Callee()->AsMemberExpression()->Object()->Compile(etsg);
            etsg->StoreAccumulator(this, callee_reg);
        }
    } else {
        expr_->Callee()->Compile(etsg);
        etsg->StoreAccumulator(this, callee_reg);
    }

    if (is_static) {
        etsg->LaunchStatic(this, signature, expr_->Arguments());
    } else if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE)) {
        etsg->LaunchThisStatic(this, callee_reg, signature, expr_->Arguments());
    } else {
        etsg->LaunchThisVirtual(this, callee_reg, signature, expr_->Arguments());
    }

    etsg->SetAccumulatorType(TsType());
#endif  // PANDA_WITH_ETS
}

checker::Type *ETSLaunchExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSLaunchExpression::Check(checker::ETSChecker *checker)
{
    expr_->Check(checker);
    auto *const launch_promise_type =
        checker->GlobalBuiltinPromiseType()
            ->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder())
            ->AsETSObjectType();
    launch_promise_type->AddTypeFlag(checker::TypeFlag::GENERIC);

    // Launch expression returns a Promise<T> type, so we need to insert the expression's type as type parameter for the
    // Promise class. If we are in a generic class declaration, then it's type parameters are inserted at class
    // declaration check, so we need to clear them first, to avoid duplicate insertion.

    launch_promise_type->TypeArguments().clear();
    auto *expr_type =
        expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) && !expr_->TsType()->IsETSVoidType()
            ? checker->PrimitiveTypeAsETSBuiltinType(expr_->TsType())
            : expr_->TsType();
    launch_promise_type->TypeArguments().emplace_back(expr_type);

    SetTsType(launch_promise_type);
    return TsType();
}

bool ETSLaunchExpression::IsStaticCall() const
{
    return expr_->Signature()->HasSignatureFlag(checker::SignatureFlags::STATIC);
}
}  // namespace panda::es2panda::ir
