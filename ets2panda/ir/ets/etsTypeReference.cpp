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

#include "etsTypeReference.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsQualifiedName.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsTypeReferencePart.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ETSTypeReference::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(part_);
}

ir::Identifier *ETSTypeReference::BaseName()
{
    ir::ETSTypeReferencePart *part_iter = part_;

    while (part_iter->Previous() != nullptr) {
        part_iter = part_iter->Previous();
    }

    ir::Expression *base_name = part_iter->Name();

    if (base_name->IsIdentifier()) {
        return base_name->AsIdentifier();
    }

    ir::TSQualifiedName *name_iter = base_name->AsTSQualifiedName();

    while (name_iter->Left()->IsTSQualifiedName()) {
        name_iter = name_iter->Left()->AsTSQualifiedName();
    }

    return name_iter->Left()->AsIdentifier();
}

void ETSTypeReference::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSTypeReference"}, {"part", part_}});
}

void ETSTypeReference::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}
void ETSTypeReference::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    part_->Compile(etsg);
}

checker::Type *ETSTypeReference::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSTypeReference::Check(checker::ETSChecker *checker)
{
    return GetType(checker);
}

checker::Type *ETSTypeReference::GetType(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker::Type *type = part_->GetType(checker);
    if (IsNullable()) {
        type = type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
        type->AddTypeFlag(checker::TypeFlag::NULLABLE);
    }

    SetTsType(type);
    return type;
}
}  // namespace panda::es2panda::ir
