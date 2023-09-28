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

#include "etsClassLiteral.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ETSClassLiteral::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(expr_);
}

void ETSClassLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSClassLiteral"}});
}

void ETSClassLiteral::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ETSClassLiteral::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    if (expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        expr_->Compile(etsg);
        etsg->GetType(this, false);
    } else {
        ASSERT(expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE));
        etsg->SetAccumulatorType(expr_->TsType());
        etsg->GetType(this, true);
    }
}

checker::Type *ETSClassLiteral::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSClassLiteral::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker->ThrowTypeError("Class literal is not yet supported.", expr_->Start());

    expr_->Check(checker);
    auto *expr_type = expr_->GetType(checker);

    if (expr_type->IsETSVoidType()) {
        checker->ThrowTypeError("Invalid .class reference", expr_->Start());
    }

    ArenaVector<checker::Type *> type_arg_types(checker->Allocator()->Adapter());
    type_arg_types.push_back(expr_type);  // TODO(user): Box it if it's a primitive type

    checker::InstantiationContext ctx(checker, checker->GlobalBuiltinTypeType(), type_arg_types, range_.start);
    SetTsType(ctx.Result());
    return TsType();
}
}  // namespace panda::es2panda::ir
