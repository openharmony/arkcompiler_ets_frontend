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

#include "etsUnionType.h"

#include "checker/ETSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void ETSUnionType::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : types_) {
        it = static_cast<TypeNode *>(cb(it));
    }
}

void ETSUnionType::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : types_) {
        cb(it);
    }
}

void ETSUnionType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSUnionType"}, {"types", types_}});
}

void ETSUnionType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *ETSUnionType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSUnionType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    for (auto *it : types_) {
        it->Check(checker);
    }

    return GetType(checker);
}

checker::Type *ETSUnionType::GetType([[maybe_unused]] checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    ArenaVector<checker::Type *> types(checker->Allocator()->Adapter());

    for (auto *it : types_) {
        types.push_back(it->GetType(checker));
    }

    SetTsType(checker->CreateETSUnionType(std::move(types)));
    return TsType();
}
}  // namespace panda::es2panda::ir
