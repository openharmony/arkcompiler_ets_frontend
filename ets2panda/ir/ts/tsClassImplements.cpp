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

#include "tsClassImplements.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::ir {
void TSClassImplements::Iterate(const NodeTraverser &cb) const
{
    cb(expression_);

    if (type_parameters_ != nullptr) {
        cb(type_parameters_);
    }
}

void TSClassImplements::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSClassImplements"},
                 {"expression", expression_},
                 {"typeParameters", AstDumper::Optional(type_parameters_)}});
}

void TSClassImplements::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSClassImplements::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSClassImplements::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
