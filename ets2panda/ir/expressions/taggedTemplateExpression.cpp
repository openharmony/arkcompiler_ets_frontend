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

#include "taggedTemplateExpression.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/regScope.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/templateLiteral.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::ir {
void TaggedTemplateExpression::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    cb(tag_);
    cb(quasi_);
}

void TaggedTemplateExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TaggedTemplateExpression"},
                 {"tag", tag_},
                 {"quasi", quasi_},
                 {"typeParameters", AstDumper::Optional(type_params_)}});
}

void TaggedTemplateExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg callee = pg->AllocReg();
    compiler::VReg this_reg = compiler::VReg::Invalid();

    if (tag_->IsMemberExpression()) {
        this_reg = pg->AllocReg();
        compiler::RegScope mrs(pg);
        tag_->AsMemberExpression()->CompileToReg(pg, this_reg);
    } else {
        tag_->Compile(pg);
    }

    pg->CallTagged(this, callee, this_reg, quasi_->Expressions());
}

checker::Type *TaggedTemplateExpression::Check(checker::TSChecker *checker)
{
    // TODO(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *TaggedTemplateExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
