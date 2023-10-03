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

#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ETSTypeReferencePart::Iterate([[maybe_unused]] const NodeTraverser &cb) const
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

void ETSTypeReferencePart::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ETSTypeReferencePart::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    name_->Compile(etsg);
}

checker::Type *ETSTypeReferencePart::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSTypeReferencePart::Check(checker::ETSChecker *checker)
{
    return GetType(checker);
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
