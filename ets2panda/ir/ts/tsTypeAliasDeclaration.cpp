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

#include "tsTypeAliasDeclaration.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/typeNode.h"
#include "ir/base/decorator.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"

namespace ark::es2panda::ir {
void TSTypeAliasDeclaration::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
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

    if (auto *typeAnnotation = TypeAnnotation(); typeAnnotation != nullptr) {
        if (auto *transformedNode = cb(typeAnnotation); typeAnnotation != transformedNode) {
            typeAnnotation->SetTransformedNode(transformationName, transformedNode);
            SetTsTypeAnnotation(static_cast<TypeNode *>(transformedNode));
        }
    }
}

void TSTypeAliasDeclaration::Iterate(const NodeTraverser &cb) const
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

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void TSTypeAliasDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSTypeAliasDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"annotations", AstDumper::Optional(Annotations())},
                 {"id", id_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())},
                 {"typeParameters", AstDumper::Optional(typeParams_)}});
}

bool TSTypeAliasDeclaration::RegisterUnexportedForDeclGen(ir::SrcDumper *dumper) const
{
    if (!dumper->IsDeclgen()) {
        return false;
    }

    if (dumper->IsIndirectDepPhase()) {
        return false;
    }

    if (id_->Parent()->IsExported() || id_->Parent()->IsDefaultExported()) {
        return false;
    }

    auto name = id_->Name().Mutf8();
    dumper->AddNode(name, this);
    return true;
}

void TSTypeAliasDeclaration::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(id_);
    if (RegisterUnexportedForDeclGen(dumper)) {
        return;
    }
    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }
    if (id_->Parent()->IsExported()) {
        dumper->Add("export ");
    }
    dumper->Add("type ");
    id_->Dump(dumper);
    if (typeParams_ != nullptr) {
        dumper->Add("<");
        typeParams_->Dump(dumper);
        dumper->Add(">");
    }
    dumper->Add(" = ");
    if (id_->IsAnnotatedExpression()) {
        auto type = TypeAnnotation();
        ES2PANDA_ASSERT(type);
        type->Dump(dumper);
    }
    dumper->Add(";");
    dumper->Endl();
}

void TSTypeAliasDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSTypeAliasDeclaration::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSTypeAliasDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType TSTypeAliasDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

TSTypeAliasDeclaration *TSTypeAliasDeclaration::Construct(ArenaAllocator *allocator)
{
    return allocator->New<TSTypeAliasDeclaration>(allocator, nullptr, nullptr, nullptr);
}

void TSTypeAliasDeclaration::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsTSTypeAliasDeclaration();

    otherImpl->decorators_ = decorators_;
    otherImpl->annotations_ = annotations_;
    otherImpl->id_ = id_;
    otherImpl->typeParams_ = typeParams_;
    otherImpl->typeParamTypes_ = typeParamTypes_;

    JsDocAllowed<AnnotatedStatement>::CopyTo(other);
}

}  // namespace ark::es2panda::ir
