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

#include "tsMethodSignature.h"

#include <ir/astDump.h>
#include <ir/typeNode.h>
#include <ir/ts/tsTypeParameterDeclaration.h>

namespace panda::es2panda::ir {

void TSMethodSignature::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (typeParams_) {
        cb(typeParams_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    if (returnTypeAnnotation_) {
        cb(returnTypeAnnotation_);
    }
}

void TSMethodSignature::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSMethodSignature"},
                 {"computed", computed_},
                 {"optional", optional_},
                 {"isGetAccessor", isGetAccessor_},
                 {"isSetAccessor", isSetAccessor_},
                 {"key", key_},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(typeParams_)},
                 {"typeAnnotation", AstDumper::Optional(returnTypeAnnotation_)}});
}

void TSMethodSignature::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}


void TSMethodSignature::UpdateSelf(const NodeUpdater &cb, binder::Binder *binder)
{
    auto scopeCtx = binder::LexicalScope<binder::Scope>::Enter(binder, scope_);

    key_ = std::get<ir::AstNode *>(cb(key_))->AsExpression();

    if (typeParams_) {
        typeParams_ = std::get<ir::AstNode *>(cb(typeParams_))->AsTSTypeParameterDeclaration();
    }

    for (auto iter = params_.begin(); iter != params_.end(); iter++) {
        *iter = std::get<ir::AstNode *>(cb(*iter))->AsExpression();
    }

    if (returnTypeAnnotation_) {
        returnTypeAnnotation_ = std::get<ir::AstNode *>(cb(returnTypeAnnotation_))->AsExpression();
    }
}

}  // namespace panda::es2panda::ir
