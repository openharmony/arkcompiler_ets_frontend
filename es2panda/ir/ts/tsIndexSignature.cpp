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

#include "tsIndexSignature.h"

#include <ir/astDump.h>
#include <ir/typeNode.h>
#include <ir/expressions/identifier.h>

namespace panda::es2panda::ir {

TSIndexSignature::TSIndexSignatureKind TSIndexSignature::Kind() const
{
    return param_->AsIdentifier()->TypeAnnotation()->IsTSNumberKeyword() ? TSIndexSignatureKind::NUMBER
                                                                         : TSIndexSignatureKind::STRING;
}

void TSIndexSignature::Iterate(const NodeTraverser &cb) const
{
    cb(param_);
    cb(typeAnnotation_);
}

void TSIndexSignature::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSIndexSignature"},
                 {"parameters", param_},
                 {"typeAnnotation", typeAnnotation_},
                 {"readonly", readonly_},
                 {"static", static_}});
}

void TSIndexSignature::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void TSIndexSignature::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    param_ = std::get<ir::AstNode *>(cb(param_))->AsExpression();
    typeAnnotation_ = std::get<ir::AstNode *>(cb(typeAnnotation_))->AsExpression();
}

}  // namespace panda::es2panda::ir
