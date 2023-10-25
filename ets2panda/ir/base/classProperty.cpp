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

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "checker/types/ets/etsObjectType.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/typeNode.h"
#include "ir/expression.h"
#include "ir/expressions/identifier.h"

#include <cstdint>
#include <string>

namespace panda::es2panda::ir {
void ClassProperty::TransformChildren(const NodeTransformer &cb)
{
    key_ = cb(key_)->AsExpression();

    if (value_ != nullptr) {
        value_ = cb(value_)->AsExpression();
    }

    if (type_annotation_ != nullptr) {
        type_annotation_ = static_cast<TypeNode *>(cb(type_annotation_));
    }

    for (auto *&it : decorators_) {
        it = cb(it)->AsDecorator();
    }
}

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

void ClassProperty::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ClassProperty::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ClassProperty::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ClassProperty::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
