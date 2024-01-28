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
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {

std::size_t ScriptFunction::FormalParamsLength() const noexcept
{
    std::size_t length = 0U;

    for (const auto *param : irSignature_.Params()) {
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
    irSignature_.TransformChildren(cb);
    if (body_ != nullptr) {
        body_ = cb(body_);
    }
}

void ScriptFunction::Iterate(const NodeTraverser &cb) const
{
    if (id_ != nullptr) {
        cb(id_);
    }
    irSignature_.Iterate(cb);
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
                 {"expression", ((funcFlags_ & ir::ScriptFunctionFlags::EXPRESSION) != 0)},
                 {"params", irSignature_.Params()},
                 {"returnType", AstDumper::Optional(irSignature_.ReturnType())},
                 {"typeParameters", AstDumper::Optional(irSignature_.TypeParams())},
                 {"declare", AstDumper::Optional(declare_)},
                 {"body", AstDumper::Optional(body_)}});

    if (IsThrowing()) {
        dumper->Add({"throwMarker", "throws"});
    } else if (IsRethrowing()) {
        dumper->Add({"throwMarker", "rethrows"});
    }
}

void ScriptFunction::Dump(ir::SrcDumper *dumper) const
{
    if (TypeParams() != nullptr) {
        TypeParams()->Dump(dumper);
    }
    dumper->Add("(");
    for (auto param : Params()) {
        param->Dump(dumper);
        if (param != Params().back()) {
            dumper->Add(", ");
        }
    }
    dumper->Add(")");
    if (ReturnTypeAnnotation() != nullptr) {
        dumper->Add(": ");
        ReturnTypeAnnotation()->Dump(dumper);
    }

    if (IsThrowing()) {
        dumper->Add(" throws");
    }

    if (HasBody()) {
        if (body_->IsBlockStatement()) {
            dumper->Add(" {");
            if (!body_->AsBlockStatement()->Statements().empty()) {
                dumper->IncrIndent();
                dumper->Endl();
                body_->Dump(dumper);
                dumper->DecrIndent();
                dumper->Endl();
            }
            dumper->Add("}");
        } else {
            dumper->Add(" ");
            body_->Dump(dumper);
        }
    }
    if (!IsArrow()) {
        dumper->Endl();
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
}  // namespace ark::es2panda::ir
