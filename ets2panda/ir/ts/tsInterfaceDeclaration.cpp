/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "tsInterfaceDeclaration.h"

#include "util/es2pandaMacros.h"
#include "varbinder/declaration.h"
#include "varbinder/variable.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/base/decorator.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace ark::es2panda::ir {
void TSInterfaceDeclaration::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    for (auto *&it : VectorIterationGuard(decorators_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsDecorator();
        }
    }

    for (auto *&it : Annotations()) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsAnnotationUsage();
        }
    }

    if (auto *transformedNode = cb(id_); id_ != transformedNode) {
        id_->SetTransformedNode(transformationName, transformedNode);
        id_ = transformedNode->AsIdentifier();
    }

    if (typeParams_ != nullptr) {
        if (auto *transformedNode = cb(typeParams_); typeParams_ != transformedNode) {
            typeParams_->SetTransformedNode(transformationName, transformedNode);
            typeParams_ = transformedNode->AsTSTypeParameterDeclaration();
        }
    }

    for (auto *&it : VectorIterationGuard(extends_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsTSInterfaceHeritage();
        }
    }

    if (auto *transformedNode = cb(body_); body_ != transformedNode) {
        body_->SetTransformedNode(transformationName, transformedNode);
        body_ = transformedNode->AsTSInterfaceBody();
    }
}

void TSInterfaceDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : VectorIterationGuard(decorators_)) {
        cb(it);
    }

    for (auto *it : Annotations()) {
        cb(it);
    }

    cb(id_);

    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    for (auto *it : VectorIterationGuard(extends_)) {
        cb(it);
    }

    cb(body_);
}

void TSInterfaceDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSInterfaceDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"annotations", AstDumper::Optional(Annotations())},
                 {"body", body_},
                 {"id", id_},
                 {"extends", extends_},
                 {"typeParameters", AstDumper::Optional(typeParams_)}});
}

void TSInterfaceDeclaration::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(id_);

    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }

    if (IsDeclare()) {
        dumper->Add("declare ");
    }
    dumper->Add("interface ");
    id_->Dump(dumper);

    if (typeParams_ != nullptr) {
        dumper->Add("<");
        typeParams_->Dump(dumper);
        dumper->Add(">");
    }
    if (!extends_.empty()) {
        dumper->Add(" extends ");
        for (auto ext : extends_) {
            ext->Dump(dumper);
            if (ext != extends_.back()) {
                dumper->Add(", ");
            }
        }
    }

    dumper->Add(" {");
    if (body_ != nullptr) {
        dumper->IncrIndent();
        dumper->Endl();
        body_->Dump(dumper);
        dumper->DecrIndent();
        dumper->Endl();
    }
    dumper->Add("}");
    dumper->Endl();
}

void TSInterfaceDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSInterfaceDeclaration::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSInterfaceDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType TSInterfaceDeclaration::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}
}  // namespace ark::es2panda::ir
