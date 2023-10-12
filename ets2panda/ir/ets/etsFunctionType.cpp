/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "etsFunctionType.h"

#include "varbinder/scope.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
// #include "ir/astDump.h"

namespace panda::es2panda::ir {
void ETSFunctionType::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    if (return_type_ != nullptr) {
        return_type_ = static_cast<TypeNode *>(cb(return_type_));
    }
}

void ETSFunctionType::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    if (return_type_ != nullptr) {
        cb(return_type_);
    }
}

void ETSFunctionType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSFunctionType"},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"returnType", return_type_}});

    if (IsThrowing()) {
        dumper->Add({"throwMarker", "throws"});
    }
}

void ETSFunctionType::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ETSFunctionType::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSFunctionType::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSFunctionType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSFunctionType::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSFunctionType::GetType(checker::ETSChecker *checker)
{
    return Check(checker);
}
}  // namespace panda::es2panda::ir
