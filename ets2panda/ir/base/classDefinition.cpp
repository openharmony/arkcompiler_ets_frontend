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

#include "classDefinition.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsClassImplements.h"

namespace ark::es2panda::ir {
const FunctionExpression *ClassDefinition::Ctor() const
{
    return ctor_ != nullptr ? ctor_->Value()->AsFunctionExpression() : nullptr;
}

bool ClassDefinition::HasPrivateMethod() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsMethodDefinition() && element->AsClassElement()->IsPrivateElement();
    });
}

bool ClassDefinition::HasNativeMethod() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsMethodDefinition() && element->AsMethodDefinition()->IsNative();
    });
}

bool ClassDefinition::HasComputedInstanceField() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsClassProperty() && element->AsClassElement()->IsComputed() &&
               !(element->AsClassElement()->Modifiers() & ir::ModifierFlags::STATIC);
    });
}

bool ClassDefinition::HasMatchingPrivateKey(const util::StringView &name) const
{
    return std::any_of(body_.cbegin(), body_.cend(), [&name](auto *element) {
        return element->AsClassElement()->IsPrivateElement() && element->AsClassElement()->Id()->Name() == name;
    });
}

void ClassDefinition::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (ident_ != nullptr) {
        if (auto *transformedNode = cb(ident_); ident_ != transformedNode) {
            ident_->SetTransformedNode(transformationName, transformedNode);
            ident_ = transformedNode->AsIdentifier();
        }
    }

    if (typeParams_ != nullptr) {
        if (auto *transformedNode = cb(typeParams_); typeParams_ != transformedNode) {
            typeParams_->SetTransformedNode(transformationName, transformedNode);
            typeParams_ = transformedNode->AsTSTypeParameterDeclaration();
        }
    }

    if (superClass_ != nullptr) {
        if (auto *transformedNode = cb(superClass_); superClass_ != transformedNode) {
            superClass_->SetTransformedNode(transformationName, transformedNode);
            superClass_ = transformedNode->AsExpression();
        }
    }

    if (superTypeParams_ != nullptr) {
        if (auto *transformedNode = cb(superTypeParams_); superTypeParams_ != transformedNode) {
            superTypeParams_->SetTransformedNode(transformationName, transformedNode);
            superTypeParams_ = transformedNode->AsTSTypeParameterInstantiation();
        }
    }

    for (auto *&it : VectorIterationGuard(implements_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsTSClassImplements();
        }
    }

    for (auto *&it : VectorIterationGuard(Annotations())) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsAnnotationUsage();
        }
    }

    if (ctor_ != nullptr) {
        if (auto *transformedNode = cb(ctor_); ctor_ != transformedNode) {
            ctor_->SetTransformedNode(transformationName, transformedNode);
            ctor_ = transformedNode->AsMethodDefinition();
        }
    }

    // Survives adding new elements to the end
    // NOLINTNEXTLINE(modernize-loop-convert)
    for (size_t ix = 0; ix < body_.size(); ix++) {
        if (auto *transformedNode = cb(body_[ix]); body_[ix] != transformedNode) {
            body_[ix]->SetTransformedNode(transformationName, transformedNode);
            body_[ix] = transformedNode;
        }
    }
}

void ClassDefinition::Iterate(const NodeTraverser &cb) const
{
    if (ident_ != nullptr) {
        cb(ident_);
    }

    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    if (superClass_ != nullptr) {
        cb(superClass_);
    }

    if (superTypeParams_ != nullptr) {
        cb(superTypeParams_);
    }

    // Survives adding new elements to the end
    // NOLINTNEXTLINE(modernize-loop-convert)
    for (size_t ix = 0; ix < implements_.size(); ix++) {
        cb(implements_[ix]);
    }

    for (auto *it : VectorIterationGuard(Annotations())) {
        cb(it);
    }

    if (ctor_ != nullptr) {
        cb(ctor_);
    }

    // NOLINTNEXTLINE(modernize-loop-convert)
    for (size_t ix = 0; ix < body_.size(); ix++) {
        cb(body_[ix]);
    }
}

void ClassDefinition::SetIdent(ir::Identifier *ident) noexcept
{
    ident_ = ident;
    if (ident_ != nullptr) {
        ident_->SetParent(this);
    }
}

void ClassDefinition::Dump(ir::AstDumper *dumper) const
{
    auto propFilter = [](AstNode *prop) -> bool {
        return !prop->IsClassStaticBlock() || !prop->AsClassStaticBlock()->Function()->IsHidden();
    };
    dumper->Add({{"id", AstDumper::Nullish(ident_)},
                 {"typeParameters", AstDumper::Optional(typeParams_)},
                 {"superClass", AstDumper::Nullish(superClass_)},
                 {"superTypeParameters", AstDumper::Optional(superTypeParams_)},
                 {"implements", implements_},
                 {"annotations", AstDumper::Optional(Annotations())},
                 {"constructor", AstDumper::Optional(ctor_)},
                 {"body", body_, propFilter}});
}

void ClassDefinition::DumpGlobalClass(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(IsGlobal());
    for (auto elem : body_) {
        if (elem->IsClassProperty()) {
            elem->Dump(dumper);
            dumper->Endl();
        }
    }
    for (auto elem : body_) {
        if (elem->IsMethodDefinition()) {
            elem->Dump(dumper);
            dumper->Endl();
        }
    }
}

// This method is needed by OHOS CI code checker
void ClassDefinition::DumpBody(ir::SrcDumper *dumper) const
{
    dumper->Add(" {");
    if (!body_.empty()) {
        dumper->IncrIndent();
        dumper->Endl();
        for (auto elem : body_) {
            elem->Dump(dumper);
            if (elem == body_.back()) {
                dumper->DecrIndent();
            }
            dumper->Endl();
        }
    }
    dumper->Add("}");
}

void ClassDefinition::DumpPrefix(ir::SrcDumper *dumper) const
{
    if (IsExported()) {
        dumper->Add("export ");
    } else if (IsDefaultExported()) {
        dumper->Add("export default ");
    }

    if (IsDeclare() || dumper->IsDeclgen()) {
        dumper->Add("declare ");
    }

    if (IsFinal()) {
        dumper->Add("final ");
    }

    if (IsAbstract() && !IsNamespaceTransformed()) {
        dumper->Add("abstract ");
    }

    if (parent_->IsETSStructDeclaration() || IsFromStruct()) {
        dumper->Add("struct ");
    } else if (IsNamespaceTransformed()) {
        dumper->Add("namespace ");
    } else {
        dumper->Add("class ");
    }
}

bool ClassDefinition::RegisterUnexportedForDeclGen(ir::SrcDumper *dumper) const
{
    if (!dumper->IsDeclgen()) {
        return false;
    }

    if (dumper->IsIndirectDepPhase()) {
        return false;
    }

    if (IsExported() || IsDefaultExported()) {
        return false;
    }

    const auto className = ident_->Name().Mutf8();
    dumper->AddNode(className, this);
    return true;
}

void ClassDefinition::Dump(ir::SrcDumper *dumper) const
{
    // NOTE: plugin API fails
    if ((ident_->Name().StartsWith("$dynmodule")) || (ident_->Name().StartsWith("$jscall"))) {
        return;
    }

    if (IsGlobal()) {
        DumpGlobalClass(dumper);
        return;
    }

    ES2PANDA_ASSERT(ident_ != nullptr);

    if (RegisterUnexportedForDeclGen(dumper)) {
        return;
    }

    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }

    DumpPrefix(dumper);
    ident_->Dump(dumper);

    if (typeParams_ != nullptr) {
        dumper->Add("<");
        typeParams_->Dump(dumper);
        dumper->Add("> ");
    }

    if (superClass_ != nullptr) {
        dumper->Add(" extends ");
        superClass_->Dump(dumper);
    }

    DumpItems(dumper, " implements ", implements_);
    if (!IsDeclare() || !body_.empty()) {
        DumpBody(dumper);
    }
    if (IsLocal()) {
        dumper->Add(";");
    }
    dumper->Endl();
}

void ClassDefinition::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ClassDefinition::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ClassDefinition::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType ClassDefinition::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

ClassDefinition *ClassDefinition::Construct(ArenaAllocator *allocator)
{
    ArenaVector<AstNode *> body {allocator->Adapter()};
    return allocator->New<ClassDefinition>(allocator, nullptr, std::move(body), ClassDefinitionModifiers::NONE,
                                           ModifierFlags::NONE, Language::Id::COUNT);
}

void ClassDefinition::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsClassDefinition();

    otherImpl->scope_ = scope_;
    otherImpl->internalName_ = internalName_;
    otherImpl->ident_ = ident_;
    otherImpl->typeParams_ = typeParams_;
    otherImpl->superTypeParams_ = superTypeParams_;
    otherImpl->implements_ = implements_;
    otherImpl->ctor_ = ctor_;
    otherImpl->superClass_ = superClass_;
    otherImpl->body_ = body_;
    otherImpl->modifiers_ = modifiers_;
    otherImpl->lang_ = lang_;
    otherImpl->capturedVars_ = capturedVars_;
    otherImpl->localVariableIsNeeded_ = localVariableIsNeeded_;
    otherImpl->origEnumDecl_ = origEnumDecl_;
    otherImpl->anonClass_ = anonClass_;
    otherImpl->localIndex_ = localIndex_;
    otherImpl->localPrefix_ = localPrefix_;
    otherImpl->functionalReferenceReferencedMethod_ = functionalReferenceReferencedMethod_;
    otherImpl->exportedClasses_ = exportedClasses_;

    JsDocAllowed<AnnotationAllowed<TypedAstNode>>::CopyTo(other);
}

int ClassDefinition::classCounter_ = 0;

}  // namespace ark::es2panda::ir
