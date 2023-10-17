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

#include "optionalChain.h"

#include "compiler/core/pandagen.h"

namespace panda::es2panda::compiler {
OptionalChain::OptionalChain(PandaGen *pg, const ir::AstNode *node) : pg_(pg), node_(node), prev_(pg->optional_chain_)
{
    pg->optional_chain_ = this;
}

OptionalChain::~OptionalChain()
{
    if (label_ != nullptr) {
        pg_->SetLabel(node_, label_);
    }

    pg_->optional_chain_ = prev_;
}

void OptionalChain::Check(compiler::VReg obj)
{
    if (label_ == nullptr) {
        label_ = pg_->AllocLabel();
    }

    RegScope rs(pg_);

    if (obj.IsInvalid()) {
        obj = pg_->AllocReg();
        pg_->StoreAccumulator(node_, obj);
    }

    auto *coercible_label = pg_->AllocLabel();

    pg_->BranchIfCoercible(node_, coercible_label);

    pg_->LoadConst(node_, compiler::Constant::JS_UNDEFINED);
    pg_->Branch(node_, label_);

    pg_->SetLabel(node_, coercible_label);
    pg_->LoadAccumulator(node_, obj);
}
}  // namespace panda::es2panda::compiler
