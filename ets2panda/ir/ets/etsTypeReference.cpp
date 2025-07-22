/*
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

#include "etsTypeReference.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
void ETSTypeReference::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    if (auto *transformedNode = cb(part_); part_ != transformedNode) {
        part_->SetTransformedNode(transformationName, transformedNode);
        part_ = transformedNode->AsETSTypeReferencePart();
    }
    for (auto *&it : VectorIterationGuard(Annotations())) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsAnnotationUsage();
        }
    }
}

void ETSTypeReference::Iterate(const NodeTraverser &cb) const
{
    cb(part_);
    for (auto *it : VectorIterationGuard(Annotations())) {
        cb(it);
    }
}

ir::Identifier *ETSTypeReference::BaseName() const
{
    ir::ETSTypeReferencePart *partIter = part_;

    while (partIter->Previous() != nullptr) {
        partIter = partIter->Previous();
    }

    ir::Expression *baseName = partIter->Name();

    if (baseName->IsIdentifier()) {
        return baseName->AsIdentifier();
    }

    ir::TSQualifiedName *nameIter = baseName->AsTSQualifiedName();

    while (nameIter->Left()->IsTSQualifiedName()) {
        nameIter = nameIter->Left()->AsTSQualifiedName();
    }

    return nameIter->Left()->AsIdentifier();
}

void ETSTypeReference::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSTypeReference"}, {"part", part_}, {"annotations", AstDumper::Optional(Annotations())}});
}

void ETSTypeReference::Dump(ir::SrcDumper *dumper) const
{
    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }
    ES2PANDA_ASSERT(part_ != nullptr);
    part_->Dump(dumper);
}

void ETSTypeReference::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void ETSTypeReference::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSTypeReference::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType ETSTypeReference::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}
checker::Type *ETSTypeReference::GetType(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }
    auto *type = part_->GetType(checker);
    if (IsReadonlyType()) {
        type = checker->GetReadonlyType(type);
    }
    return SetTsType(type);
}

ETSTypeReference *ETSTypeReference::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    ETSTypeReferencePart *partClone = nullptr;
    if (part_ != nullptr) {
        auto *const clone = part_->Clone(allocator, nullptr);
        ES2PANDA_ASSERT(clone != nullptr);
        partClone = clone->AsETSTypeReferencePart();
    }
    auto *const clone = allocator->New<ETSTypeReference>(partClone, allocator);
    ES2PANDA_ASSERT(clone != nullptr);

    if (partClone != nullptr) {
        partClone->SetParent(clone);
    }

    clone->flags_ = flags_;

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    if (!Annotations().empty()) {
        ArenaVector<AnnotationUsage *> annotationUsages {allocator->Adapter()};
        for (auto *annotationUsage : Annotations()) {
            auto *annotationClone = annotationUsage->Clone(allocator, clone);
            ES2PANDA_ASSERT(annotationClone != nullptr);
            annotationUsages.push_back(annotationClone->AsAnnotationUsage());
        }
        clone->SetAnnotations(std::move(annotationUsages));
    }

    clone->SetRange(Range());
    return clone;
}

ETSTypeReference *ETSTypeReference::Construct(ArenaAllocator *allocator)
{
    return allocator->New<ETSTypeReference>(nullptr, allocator);
}

void ETSTypeReference::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsETSTypeReference();

    otherImpl->part_ = part_;

    TypeNode::CopyTo(other);
}

}  // namespace ark::es2panda::ir
