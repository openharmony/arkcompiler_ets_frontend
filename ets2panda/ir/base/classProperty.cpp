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

#include "classProperty.h"
#include <string>

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::ir {
void ClassProperty::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    if (auto *transformedNode = cb(key_); key_ != transformedNode) {
        key_->SetTransformedNode(transformationName, transformedNode);
        key_ = transformedNode->AsExpression();
    }

    if (value_ != nullptr) {
        if (auto *transformedNode = cb(value_); value_ != transformedNode) {
            value_->SetTransformedNode(transformationName, transformedNode);
            value_ = transformedNode->AsExpression();
        }
    }

    if (typeAnnotation_ != nullptr) {
        if (auto *transformedNode = cb(typeAnnotation_); typeAnnotation_ != transformedNode) {
            typeAnnotation_->SetTransformedNode(transformationName, transformedNode);
            typeAnnotation_ = static_cast<TypeNode *>(transformedNode);
        }
    }

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
}

void ClassProperty::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (value_ != nullptr) {
        cb(value_);
    }

    if (typeAnnotation_ != nullptr) {
        cb(typeAnnotation_);
    }

    for (auto *it : VectorIterationGuard(decorators_)) {
        cb(it);
    }

    for (auto *it : Annotations()) {
        cb(it);
    }
}

void ClassProperty::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ClassProperty"},
                 {"key", key_},
                 {"value", AstDumper::Optional(value_)},
                 {"accessibility", AstDumper::Optional(AstDumper::ModifierToString(flags_))},
                 {"static", IsStatic()},
                 {"readonly", IsReadonly()},
                 {"declare", IsDeclare()},
                 {"optional", IsOptionalDeclaration()},
                 {"computed", isComputed_},
                 {"typeAnnotation", AstDumper::Optional(typeAnnotation_)},
                 {"definite", IsDefinite()},
                 {"decorators", decorators_},
                 {"annotations", AstDumper::Optional(Annotations())}});
}

void ClassProperty::DumpModifiers(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(key_);
    if (dumper->IsDeclgen()) {
        if (key_->Parent()->IsExported()) {
            dumper->Add("export declare ");
        } else if (key_->Parent()->IsDefaultExported()) {
            dumper->Add("export default declare ");
        }
    }

    if (compiler::HasGlobalClassParent(this)) {
        if (key_->Parent()->IsConst()) {
            dumper->Add("const ");
        } else {
            dumper->Add("let ");
        }
        return;
    }

    if (compiler::HasGlobalClassParent(this)) {
        dumper->Add("let ");
        return;
    }

    if (Parent() != nullptr && Parent()->IsClassDefinition() && !Parent()->AsClassDefinition()->IsLocal()) {
        if (IsPrivate()) {
            dumper->Add("private ");
        } else if (IsProtected()) {
            dumper->Add("protected ");
        } else if (IsInternal()) {
            dumper->Add("internal ");
        } else {
            dumper->Add("public ");
        }
    }

    if (IsStatic()) {
        dumper->Add("static ");
    }

    if (IsReadonly()) {
        dumper->Add("readonly ");
    }
}

bool ClassProperty::DumpNamespaceForDeclGen(ir::SrcDumper *dumper) const
{
    if (!dumper->IsDeclgen()) {
        return false;
    }

    if (Parent() == nullptr) {
        return false;
    }

    bool isNamespaceTransformed =
        Parent()->IsClassDefinition() && Parent()->AsClassDefinition()->IsNamespaceTransformed();
    if (isNamespaceTransformed) {
        dumper->Add("let ");
        return true;
    }
    return false;
}

void ClassProperty::DumpPrefix(ir::SrcDumper *dumper) const
{
    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }
    if (DumpNamespaceForDeclGen(dumper)) {
        return;
    }
    DumpModifiers(dumper);
}

void ClassProperty::DumpCheckerTypeForDeclGen(ir::SrcDumper *dumper) const
{
    if (!dumper->IsDeclgen()) {
        return;
    }

    if (TsType() == nullptr) {
        return;
    }

    auto typeStr = TsType()->ToString();
    if (TsType()->IsTypeError() && dumper->IsIsolatedDeclgen() && typeAnnotation_ != nullptr) {
        typeStr = typeAnnotation_->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Name().Mutf8();
    }

    dumper->Add(": ");
    dumper->Add(typeStr);

    dumper->PushTask([dumper, typeStr] { dumper->DumpNode(typeStr); });
}

bool ClassProperty::RegisterUnexportedForDeclGen(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(key_);
    if (!dumper->IsDeclgen()) {
        return false;
    }

    auto name = key_->AsIdentifier()->Name().Mutf8();
    if (name.rfind('#', 0) == 0) {
        return true;
    }

    if (!compiler::HasGlobalClassParent(this)) {
        return false;
    }

    if (dumper->IsIndirectDepPhase()) {
        return false;
    }

    if (key_->Parent()->IsExported() || key_->Parent()->IsDefaultExported()) {
        return false;
    }

    dumper->AddNode(name, this);
    return true;
}

void ClassProperty::Dump(ir::SrcDumper *dumper) const
{
    if (RegisterUnexportedForDeclGen(dumper)) {
        return;
    }
    DumpPrefix(dumper);

    if (key_ != nullptr) {
        key_->Dump(dumper);
    }

    if (IsOptionalDeclaration()) {
        dumper->Add("?");
    }

    if (IsDefinite()) {
        dumper->Add("!");
    }

    if (typeAnnotation_ != nullptr && !dumper->IsDeclgen()) {
        dumper->Add(": ");
        typeAnnotation_->Dump(dumper);
    }

    DumpCheckerTypeForDeclGen(dumper);

    if (value_ != nullptr && !dumper->IsDeclgen()) {
        dumper->Add(" = ");
        value_->Dump(dumper);
    }

    dumper->Add(";");
    dumper->Endl();
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

checker::VerifiedType ClassProperty::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

ClassProperty *ClassProperty::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const key = key_->Clone(allocator, nullptr)->AsExpression();
    auto *const value = value_ != nullptr ? value_->Clone(allocator, nullptr)->AsExpression() : nullptr;
    auto *const typeAnnotation = typeAnnotation_ != nullptr ? typeAnnotation_->Clone(allocator, nullptr) : nullptr;

    auto *const clone = allocator->New<ClassProperty>(key, value, typeAnnotation, flags_, allocator, isComputed_);

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    key->SetParent(clone);
    if (value != nullptr) {
        value->SetTsType(value_->TsType());
        value->SetParent(clone);
    }
    if (typeAnnotation != nullptr) {
        typeAnnotation->SetTsType(typeAnnotation->TsType());
        typeAnnotation->SetParent(clone);
    }

    for (auto *const decorator : decorators_) {
        clone->AddDecorator(decorator->Clone(allocator, clone));
    }

    if (!Annotations().empty()) {
        ArenaVector<AnnotationUsage *> annotationUsages {allocator->Adapter()};
        for (auto *annotationUsage : Annotations()) {
            annotationUsages.push_back(annotationUsage->Clone(allocator, clone)->AsAnnotationUsage());
        }
        clone->SetAnnotations(std::move(annotationUsages));
    }

    clone->SetRange(range_);

    return clone;
}

ClassProperty *ClassProperty::Construct(ArenaAllocator *allocator)
{
    return allocator->New<ClassProperty>(nullptr, nullptr, nullptr, ModifierFlags::NONE, allocator, false);
}

void ClassProperty::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsClassProperty();

    otherImpl->typeAnnotation_ = typeAnnotation_;
    otherImpl->isDefault_ = isDefault_;
    otherImpl->needInitInStaticBlock_ = needInitInStaticBlock_;

    JsDocAllowed<AnnotationAllowed<ClassElement>>::CopyTo(other);
}

}  // namespace ark::es2panda::ir
