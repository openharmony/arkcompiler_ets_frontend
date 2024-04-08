/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "identifier.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
Identifier::Identifier([[maybe_unused]] Tag const tag, Identifier const &other, ArenaAllocator *const allocator)
    : AnnotatedExpression(static_cast<AnnotatedExpression const &>(other), allocator), decorators_(allocator->Adapter())
{
    name_ = other.name_;
    flags_ = other.flags_;

    for (auto *decorator : other.decorators_) {
        decorators_.emplace_back(decorator->Clone(allocator, this));
    }
}

Identifier *Identifier::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<Identifier>(Tag {}, *this, allocator); clone != nullptr) {
        clone->SetTsType(TsType());
        if (parent != nullptr) {
            clone->SetParent(parent);
        }

        if (this->IsReference()) {
            clone->SetReference();
        }

        clone->SetRange(Range());

        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void Identifier::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    if (auto *typeAnnotation = TypeAnnotation(); typeAnnotation != nullptr) {
        if (auto *transformedNode = cb(typeAnnotation); typeAnnotation != transformedNode) {
            typeAnnotation->SetTransformedNode(transformationName, transformedNode);
            SetTsTypeAnnotation(static_cast<TypeNode *>(transformedNode));
        }
    }

    for (auto *&it : decorators_) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsDecorator();
        }
    }
}

void Identifier::Iterate(const NodeTraverser &cb) const
{
    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }

    for (auto *it : decorators_) {
        cb(it);
    }
}

ValidationInfo Identifier::ValidateExpression()
{
    if ((flags_ & IdentifierFlags::OPTIONAL) != 0U) {
        return {"Unexpected token '?'.", Start()};
    }

    if (TypeAnnotation() != nullptr) {
        return {"Unexpected token.", TypeAnnotation()->Start()};
    }

    ValidationInfo info;
    return info;
}

void Identifier::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", IsPrivateIdent() ? "PrivateIdentifier" : "Identifier"},
                 {"name", name_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())},
                 {"optional", AstDumper::Optional(IsOptional())},
                 {"decorators", decorators_}});
}

void Identifier::Dump(ir::SrcDumper *dumper) const
{
    if (IsPrivateIdent()) {
        dumper->Add("private ");
    }
    dumper->Add(std::string(name_));
    if (IsOptional()) {
        dumper->Add("?");
    }
}

void Identifier::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void Identifier::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *Identifier::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *Identifier::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir
