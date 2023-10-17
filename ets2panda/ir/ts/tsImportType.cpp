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

#include "tsImportType.h"

#include "ir/astDump.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::ir {
void TSImportType::TransformChildren(const NodeTransformer &cb)
{
    param_ = cb(param_)->AsExpression();

    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterInstantiation();
    }

    if (qualifier_ != nullptr) {
        qualifier_ = cb(qualifier_)->AsExpression();
    }
}

void TSImportType::Iterate(const NodeTraverser &cb) const
{
    cb(param_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (qualifier_ != nullptr) {
        cb(qualifier_);
    }
}

void TSImportType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSImportType"},
                 {"parameter", param_},
                 {"qualifier", AstDumper::Optional(qualifier_)},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"isTypeOf", is_typeof_}});
}

void TSImportType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSImportType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSImportType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSImportType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
