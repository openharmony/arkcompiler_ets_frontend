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

#include "classProperty.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsObjectType.h"

#include <cstdint>
#include <string>

namespace panda::es2panda::ir {
void ClassProperty::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (value_ != nullptr) {
        cb(value_);
    }

    if (type_annotation_ != nullptr) {
        cb(type_annotation_);
    }

    for (auto *it : decorators_) {
        cb(it);
    }
}

void ClassProperty::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ClassProperty"},
                 {"key", key_},
                 {"value", AstDumper::Optional(value_)},
                 {"accessibility", AstDumper::Optional(AstDumper::ModifierToString(flags_))},
                 {"abstract", AstDumper::Optional(IsAbstract())},
                 {"static", IsStatic()},
                 {"readonly", IsReadonly()},
                 {"declare", IsDeclare()},
                 {"optional", IsOptional()},
                 {"computed", is_computed_},
                 {"typeAnnotation", AstDumper::Optional(type_annotation_)},
                 {"definite", IsDefinite()},
                 {"decorators", decorators_}});
}

void ClassProperty::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ClassProperty::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    if (value_ == nullptr || (IsStatic() && TsType()->HasTypeFlag(checker::TypeFlag::CONSTANT))) {
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, TsType());
    compiler::RegScope rs(etsg);

    if (!etsg->TryLoadConstantExpression(value_)) {
        value_->Compile(etsg);
        etsg->ApplyConversion(value_, nullptr);
    }

    if (IsStatic()) {
        etsg->StoreStaticOwnProperty(this, TsType(), key_->AsIdentifier()->Name());
    } else {
        etsg->StoreProperty(this, TsType(), etsg->GetThisReg(), key_->AsIdentifier()->Name());
    }
}

checker::Type *ClassProperty::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ClassProperty::Check(checker::ETSChecker *checker)
{
    ASSERT(key_->IsIdentifier());

    if (TsType() != nullptr) {
        return TsType();
    }

    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass(),
                                               checker->Context().ContainingSignature());

    if (IsStatic()) {
        checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    SetTsType(checker->CheckVariableDeclaration(key_->AsIdentifier(), type_annotation_, value_, flags_));

    return TsType();
}
}  // namespace panda::es2panda::ir
