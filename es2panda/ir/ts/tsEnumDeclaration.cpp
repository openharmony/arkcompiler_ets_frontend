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

#include "tsEnumDeclaration.h"

#include <ir/astDump.h>
#include <ir/expressions/identifier.h>
#include <ir/expressions/memberExpression.h>
#include <ir/expressions/unaryExpression.h>
#include <ir/expressions/binaryExpression.h>
#include <ir/expressions/templateLiteral.h>
#include <ir/expressions/literals/stringLiteral.h>
#include <ir/expressions/literals/numberLiteral.h>
#include <ir/ts/tsEnumMember.h>

namespace panda::es2panda::ir {

void TSEnumDeclaration::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    for (auto *it : members_) {
        cb(it);
    }
}

void TSEnumDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSEnumDeclaration"}, {"id", key_}, {"members", members_}, {"const", isConst_}});
}

void TSEnumDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

int32_t ToInt(double num)
{
    if (num >= std::numeric_limits<int32_t>::min() && num <= std::numeric_limits<int32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

uint32_t ToUInt(double num)
{
    if (num >= std::numeric_limits<uint32_t>::min() && num <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

void TSEnumDeclaration::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    key_ = std::get<ir::AstNode *>(cb(key_))->AsIdentifier();

    for (auto iter = members_.begin(); iter != members_.end(); iter++) {
        *iter = std::get<ir::AstNode *>(cb(*iter))->AsTSEnumMember();
    }
}

}  // namespace panda::es2panda::ir
