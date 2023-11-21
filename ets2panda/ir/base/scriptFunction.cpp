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

#include "scriptFunction.h"

#include "varbinder/scope.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace panda::es2panda::ir {

std::size_t ScriptFunction::FormalParamsLength() const noexcept
{
    std::size_t length = 0U;

    for (const auto *param : ir_signature_.Params()) {
        if (param->IsRestElement() || param->IsAssignmentPattern()) {
            break;
        }

        ++length;
    }

    return length;
}

void ScriptFunction::TransformChildren(const NodeTransformer &cb)
{
    if (id_ != nullptr) {
        id_ = cb(id_)->AsIdentifier();
    }
    ir_signature_.TransformChildren(cb);
    if (body_ != nullptr) {
        body_ = cb(body_);
    }
}

void ScriptFunction::Iterate(const NodeTraverser &cb) const
{
    if (id_ != nullptr) {
        cb(id_);
    }
    ir_signature_.Iterate(cb);
    if (body_ != nullptr) {
        cb(body_);
    }
}

void ScriptFunction::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ScriptFunction"},
                 {"id", AstDumper::Nullish(id_)},
                 {"generator", IsGenerator()},
                 {"async", IsAsyncFunc()},
                 {"expression", ((func_flags_ & ir::ScriptFunctionFlags::EXPRESSION) != 0)},
                 {"params", ir_signature_.Params()},
                 {"returnType", AstDumper::Optional(ir_signature_.ReturnType())},
                 {"typeParameters", AstDumper::Optional(ir_signature_.TypeParams())},
                 {"declare", AstDumper::Optional(declare_)},
                 {"body", AstDumper::Optional(body_)}});

    if (IsThrowing()) {
        dumper->Add({"throwMarker", "throws"});
    } else if (IsRethrowing()) {
        dumper->Add({"throwMarker", "rethrows"});
    }
}

void ScriptFunction::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void ScriptFunction::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ScriptFunction::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ScriptFunction::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
