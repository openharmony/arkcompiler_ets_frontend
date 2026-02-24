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

#include "tsInterfaceDeclaration.h"

#include <ir/astDump.h>
#include <ir/expressions/identifier.h>
#include <ir/ts/tsInterfaceBody.h>
#include <ir/ts/tsInterfaceHeritage.h>
#include <ir/ts/tsTypeParameterDeclaration.h>

namespace panda::es2panda::ir {

void TSInterfaceDeclaration::Iterate(const NodeTraverser &cb) const
{
    cb(id_);

    if (typeParams_) {
        cb(typeParams_);
    }

    for (auto *it : extends_) {
        cb(it);
    }

    cb(body_);
}

void TSInterfaceDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSInterfaceDeclaration"},
                 {"body", body_},
                 {"id", id_},
                 {"extends", extends_},
                 {"typeParameters", AstDumper::Optional(typeParams_)}});
}

void TSInterfaceDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void TSInterfaceDeclaration::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    id_ = std::get<ir::AstNode *>(cb(id_))->AsIdentifier();

    if (typeParams_) {
        typeParams_ = std::get<ir::AstNode *>(cb(typeParams_))->AsTSTypeParameterDeclaration();
    }

    for (auto iter = extends_.begin(); iter != extends_.end(); iter++) {
        *iter = std::get<ir::AstNode *>(cb(*iter))->AsTSInterfaceHeritage();
    }

    body_ = std::get<ir::AstNode *>(cb(body_))->AsTSInterfaceBody();
}

}  // namespace panda::es2panda::ir
