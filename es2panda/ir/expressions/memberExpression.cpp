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

#include "memberExpression.h"

#include <compiler/core/pandagen.h>
#include <ir/astDump.h>
#include <ir/expressions/identifier.h>
#include <ir/expressions/privateIdentifier.h>
#include <ir/expressions/literals/numberLiteral.h>
#include <ir/expressions/literals/stringLiteral.h>

namespace panda::es2panda::ir {

void MemberExpression::Iterate(const NodeTraverser &cb) const
{
    cb(object_);
    cb(property_);
}

void MemberExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "MemberExpression"},
                 {"object", object_},
                 {"property", property_},
                 {"computed", computed_},
                 {"optional", optional_}});
}

void MemberExpression::CompileObject(compiler::PandaGen *pg, compiler::VReg dest) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, dest);
    pg->GetOptionalChain()->CheckNullish(optional_, dest);
}

compiler::Operand MemberExpression::CompileKey(compiler::PandaGen *pg) const
{
    return pg->ToPropertyKey(property_, computed_);
}

void MemberExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg objReg = pg->AllocReg();
    Compile(pg, objReg);
}

void MemberExpression::Compile(compiler::PandaGen *pg, compiler::VReg objReg) const
{
    CompileObject(pg, objReg);
    if (AccessPrivateProperty()) {
        auto name = property_->AsPrivateIdentifier()->Name();
        auto result = pg->Scope()->FindPrivateName(name);
        if (!result.result.isMethod) {
            pg->LoadAccumulator(this, objReg);
            pg->LoadPrivateProperty(this, result.lexLevel, result.result.slot);
            return;
        }
        if (result.result.isSetter) {
            pg->ThrowTypeError(this, "Property is not defined with Getter");
        }
        if (result.result.isStatic) {
            pg->LoadLexicalVar(this, result.lexLevel, result.result.validateMethodSlot);
            pg->Equal(this, objReg);
            pg->ThrowTypeErrorIfFalse(this, "Object does not have private property");
        } else {
            pg->LoadAccumulator(this, objReg);
            pg->LoadPrivateProperty(this, result.lexLevel, result.result.validateMethodSlot);
        }
        
        if (result.result.isGetter) {
            pg->LoadAccumulator(this, objReg);
            pg->LoadPrivateProperty(this, result.lexLevel, result.result.slot);
            return;
        }
        pg->LoadLexicalVar(this, result.lexLevel, result.result.slot);
        return;
    }
    compiler::Operand prop = CompileKey(pg);

    if (object_->IsSuperExpression()) {
        pg->LoadSuperProperty(property_, objReg, prop);
    } else {
        pg->LoadObjProperty(property_, objReg, prop);
    }
}

void MemberExpression::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    object_ = std::get<ir::AstNode *>(cb(object_))->AsExpression();
    property_ = std::get<ir::AstNode *>(cb(property_))->AsExpression();
}

}  // namespace panda::es2panda::ir
