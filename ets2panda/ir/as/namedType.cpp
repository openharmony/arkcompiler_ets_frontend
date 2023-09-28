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

#include "namedType.h"

#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterInstantiation.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"

namespace panda::es2panda::ir {
void NamedType::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(name_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (next_ != nullptr) {
        cb(next_);
    }
}

void NamedType::Dump(AstDumper *dumper) const
{
    dumper->Add({{"type", "NamedType"},
                 {"name", name_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"next", AstDumper::Optional(next_)},
                 {"isNullable", nullable_}});
}

void NamedType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void NamedType::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *NamedType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *NamedType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
