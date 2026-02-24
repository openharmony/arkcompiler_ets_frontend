/**
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "tsTypeReference.h"

#include <ir/astDump.h>
#include <ir/expressions/identifier.h>
#include <ir/ts/tsTypeParameterInstantiation.h>

namespace panda::es2panda::ir {

void TSTypeReference::Iterate(const NodeTraverser &cb) const
{
    if (typeParams_) {
        cb(typeParams_);
    }

    cb(typeName_);
}

void TSTypeReference::Dump(ir::AstDumper *dumper) const
{
    dumper->Add(
        {{"type", "TSTypeReference"}, {"typeName", typeName_}, {"typeParameters", AstDumper::Optional(typeParams_)}});
}

void TSTypeReference::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void TSTypeReference::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    if (typeParams_) {
        typeParams_ = std::get<ir::AstNode *>(cb(typeParams_))->AsTSTypeParameterInstantiation();
    }

    typeName_ = std::get<ir::AstNode *>(cb(typeName_))->AsExpression();
}

}  // namespace panda::es2panda::ir
