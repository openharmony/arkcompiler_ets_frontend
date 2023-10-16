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

#include "returnStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void ReturnStatement::TransformChildren(const NodeTransformer &cb)
{
    if (argument_ != nullptr) {
        argument_ = cb(argument_)->AsExpression();
    }
}

void ReturnStatement::Iterate(const NodeTraverser &cb) const
{
    if (argument_ != nullptr) {
        cb(argument_);
    }
}

void ReturnStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ReturnStatement"}, {"argument", AstDumper::Nullable(argument_)}});
}

void ReturnStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ReturnStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ReturnStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ReturnStatement::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

void ReturnStatement::SetReturnType(checker::ETSChecker *checker, checker::Type *type)
{
    return_type_ = type;
    if (argument_ != nullptr) {
        checker::Type *argument_type = argument_->Check(checker);
        if (type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) &&
            !argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            auto *const relation = checker->Relation();
            relation->SetNode(argument_);
            relation->SetFlags(checker::TypeRelationFlag::NONE);

            argument_type = checker->PrimitiveTypeAsETSBuiltinType(argument_type);
            if (argument_type == nullptr) {
                checker->ThrowTypeError("Invalid return statement expression", argument_->Start());
            }
            // argument_->SetTsType(argument_type);
            argument_->AddBoxingUnboxingFlag(checker->GetBoxingFlag(argument_type));

            relation->SetNode(nullptr);
        }
    }
}
}  // namespace panda::es2panda::ir
