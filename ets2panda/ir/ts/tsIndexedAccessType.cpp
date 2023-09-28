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

#include "tsIndexedAccessType.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"

#include "plugins/ecmascript/es2panda/checker/TSchecker.h"

namespace panda::es2panda::ir {
void TSIndexedAccessType::Iterate(const NodeTraverser &cb) const
{
    cb(object_type_);
    cb(index_type_);
}

void TSIndexedAccessType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSIndexedAccessType"}, {"objectType", object_type_}, {"indexType", index_type_}});
}

void TSIndexedAccessType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSIndexedAccessType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    object_type_->Check(checker);
    index_type_->Check(checker);
    checker::Type *resolved = GetType(checker);

    if (resolved != nullptr) {
        return nullptr;
    }

    checker::Type *index_type = checker->CheckTypeCached(index_type_);

    if (!index_type->HasTypeFlag(checker::TypeFlag::STRING_LIKE | checker::TypeFlag::NUMBER_LIKE)) {
        checker->ThrowTypeError({"Type ", index_type, " cannot be used as index type"}, index_type_->Start());
    }

    if (index_type->IsNumberType()) {
        checker->ThrowTypeError("Type has no matching signature for type 'number'", Start());
    }

    checker->ThrowTypeError("Type has no matching signature for type 'string'", Start());
    return nullptr;
}

checker::Type *TSIndexedAccessType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker::Type *base_type = object_type_->GetType(checker);
    checker::Type *index_type = index_type_->GetType(checker);
    checker::Type *resolved = checker->GetPropertyTypeForIndexType(base_type, index_type);

    SetTsType(resolved);
    return TsType();
}

checker::Type *TSIndexedAccessType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
