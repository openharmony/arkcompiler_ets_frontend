/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "annotationDeclaration.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void AnnotationDeclaration::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    for (auto *&it : VectorIterationGuard(properties_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode;
        }
    }

    if (expr_ != nullptr) {
        if (auto *transformedNode = cb(expr_); expr_ != transformedNode) {
            expr_->SetTransformedNode(transformationName, transformedNode);
            expr_ = transformedNode->AsIdentifier();
        }
    }

    for (auto *&it : VectorIterationGuard(Annotations())) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsAnnotationUsage();
        }
    }
}
void AnnotationDeclaration::Iterate(const NodeTraverser &cb) const
{
    if (expr_ != nullptr) {
        cb(expr_);
    }

    for (auto *it : VectorIterationGuard(properties_)) {
        cb(it);
    }

    for (auto *it : VectorIterationGuard(Annotations())) {
        cb(it);
    }
}

void AnnotationDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"Expr", expr_}, {"properties", properties_}, {"annotations", AstDumper::Optional(Annotations())}});
}
void AnnotationDeclaration::Dump(ir::SrcDumper *dumper) const
{  // re-understand
    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }
    ES2PANDA_ASSERT(expr_ != nullptr);
    dumper->Add("@interface ");
    expr_->Dump(dumper);
    dumper->Add(" {");

    if (!properties_.empty()) {
        dumper->IncrIndent();
        dumper->Endl();
        for (auto elem : properties_) {
            elem->Dump(dumper);
            if (elem == properties_.back()) {
                dumper->DecrIndent();
            }
        }
    }
    dumper->Add("}");
    dumper->Endl();
}
void AnnotationDeclaration::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void AnnotationDeclaration::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *AnnotationDeclaration::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType AnnotationDeclaration::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

Identifier *AnnotationDeclaration::GetBaseName() const
{
    if (expr_->IsIdentifier()) {
        return expr_->AsIdentifier();
    }
    auto *part = expr_->AsETSTypeReference()->Part();
    return part->Name()->AsTSQualifiedName()->Right();
}
}  // namespace ark::es2panda::ir