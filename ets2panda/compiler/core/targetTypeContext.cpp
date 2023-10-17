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

#include "targetTypeContext.h"

#include "compiler/core/ETSGen.h"

namespace panda::es2panda::compiler {
TargetTypeContext::TargetTypeContext(ETSGen *etsg, const checker::Type *target_type)
    : etsg_(etsg), prev_(etsg->target_type_)
{
    etsg->target_type_ = target_type;
}

TargetTypeContext::~TargetTypeContext()
{
    etsg_->target_type_ = prev_;
}
}  // namespace panda::es2panda::compiler
