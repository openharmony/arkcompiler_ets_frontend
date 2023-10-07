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

#include "tsArrayType.h"

#include "ir/astDump.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::ir {
void TSArrayType::TransformChildren(const NodeTransformer &cb)
{
    element_type_ = static_cast<TypeNode *>(cb(element_type_));
}

void TSArrayType::Iterate(const NodeTraverser &cb) const
{
    cb(element_type_);
}

void TSArrayType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSArrayType"}, {"elementType", element_type_}});
}

void TSArrayType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSArrayType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    element_type_->Check(checker);
    return nullptr;
}

checker::Type *TSArrayType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->Allocator()->New<checker::ArrayType>(element_type_->GetType(checker));
}

checker::Type *TSArrayType::Check(checker::ETSChecker *checker)
{
    element_type_->Check(checker);
    return nullptr;
}

checker::Type *TSArrayType::GetType(checker::ETSChecker *checker)
{
    auto *const element_type = checker->GetTypeFromTypeAnnotation(element_type_);

    return checker->CreateETSArrayType(element_type);
}

}  // namespace panda::es2panda::ir
