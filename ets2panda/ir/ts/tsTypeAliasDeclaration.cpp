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

#include "tsTypeAliasDeclaration.h"

#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/base/decorator.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace panda::es2panda::ir {
void TSTypeAliasDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(id_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void TSTypeAliasDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSTypeAliasDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"id", id_},
                 {"typeAnnotation", TypeAnnotation()},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"declare", AstDumper::Optional(declare_)}});
}

void TSTypeAliasDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSTypeAliasDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    TypeAnnotation()->Check(checker);
    return nullptr;
}

checker::Type *TSTypeAliasDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    TypeAnnotation()->Check(checker);
    return nullptr;
}
}  // namespace panda::es2panda::ir
