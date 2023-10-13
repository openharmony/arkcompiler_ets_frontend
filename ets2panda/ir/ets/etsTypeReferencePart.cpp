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

#include "etsTypeReferencePart.h"

#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void ETSTypeReferencePart::TransformChildren(const NodeTransformer &cb)
{
    name_ = cb(name_)->AsExpression();

    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterInstantiation();
    }

    if (prev_ != nullptr) {
        prev_ = cb(prev_)->AsETSTypeReferencePart();
    }
}

void ETSTypeReferencePart::Iterate(const NodeTraverser &cb) const
{
    cb(name_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (prev_ != nullptr) {
        cb(prev_);
    }
}

void ETSTypeReferencePart::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSTypeReferencePart"},
                 {"name", name_},
                 {"typeParams", AstDumper::Optional(type_params_)},
                 {"previous", AstDumper::Optional(prev_)}});
}

void ETSTypeReferencePart::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void ETSTypeReferencePart::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSTypeReferencePart::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSTypeReferencePart::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSTypeReferencePart::GetType(checker::ETSChecker *checker)
{
    if (prev_ == nullptr) {
        checker::Type *base_type = checker->GetReferencedTypeBase(name_);

        if (base_type->IsETSObjectType()) {
            checker::InstantiationContext ctx(checker, base_type->AsETSObjectType(), type_params_, Start());
            return ctx.Result();
        }

        return base_type;
    }

    checker::Type *base_type = prev_->GetType(checker);
    return checker->GetReferencedTypeFromBase(base_type, name_);
}
}  // namespace panda::es2panda::ir
