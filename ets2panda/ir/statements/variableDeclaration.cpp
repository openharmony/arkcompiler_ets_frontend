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

#include "variableDeclaration.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
void VariableDeclaration::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    for (auto *&it : VectorIterationGuard(decorators_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsDecorator();
        }
    }

    for (auto *&it : VectorIterationGuard(Annotations())) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsAnnotationUsage();
        }
    }

    for (auto *&it : VectorIterationGuard(declarators_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsVariableDeclarator();
        }
    }
}

void VariableDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : VectorIterationGuard(decorators_)) {
        cb(it);
    }

    for (auto *it : VectorIterationGuard(Annotations())) {
        cb(it);
    }

    for (auto *it : VectorIterationGuard(declarators_)) {
        cb(it);
    }
}

void VariableDeclaration::Dump(ir::AstDumper *dumper) const
{
    const char *kind = nullptr;

    switch (kind_) {
        case VariableDeclarationKind::CONST: {
            kind = "const";
            break;
        }
        case VariableDeclarationKind::LET: {
            kind = "let";
            break;
        }
        case VariableDeclarationKind::VAR: {
            kind = "var";
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }

    dumper->Add({{"type", "VariableDeclaration"},
                 {"declarations", declarators_},
                 {"kind", kind},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"annotations", AstDumper::Optional(Annotations())},
                 {"declare", AstDumper::Optional(IsDeclare())}});
}

void VariableDeclaration::Dump(ir::SrcDumper *dumper) const
{
    for (auto *anno : Annotations()) {
        anno->Dump(dumper);
    }

    if (IsDeclare()) {
        dumper->Add("declare ");
    }

    switch (kind_) {
        case VariableDeclarationKind::CONST:
            dumper->Add("const ");
            break;
        case VariableDeclarationKind::LET:
            dumper->Add("let ");
            break;
        case VariableDeclarationKind::VAR:
            dumper->Add("var ");
            break;
        default:
            ES2PANDA_UNREACHABLE();
    }

    for (auto declarator : declarators_) {
        declarator->Dump(dumper);
        if (declarator != declarators_.back()) {
            dumper->Add(", ");
        }
    }

    if ((parent_ != nullptr) &&
        (parent_->IsBlockStatement() || parent_->IsBlockExpression() || parent_->IsSwitchCaseStatement())) {
        dumper->Add(";");
    }
}

VariableDeclaration::VariableDeclaration([[maybe_unused]] Tag const tag, VariableDeclaration const &other,
                                         ArenaAllocator *const allocator)
    : AnnotationAllowed<Statement>(static_cast<AnnotationAllowed<Statement> const &>(other)),
      kind_(other.kind_),
      decorators_(allocator->Adapter()),
      declarators_(allocator->Adapter())
{
    for (auto const &d : other.decorators_) {
        decorators_.emplace_back(d->Clone(allocator, nullptr));
        decorators_.back()->SetParent(this);
    }

    for (auto const &d : other.declarators_) {
        declarators_.emplace_back(d->Clone(allocator, nullptr)->AsVariableDeclarator());
        declarators_.back()->SetParent(this);
    }
}

VariableDeclaration *VariableDeclaration::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<VariableDeclaration>(Tag {}, *this, allocator);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }
    clone->SetRange(range_);
    return clone;
}

void VariableDeclaration::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void VariableDeclaration::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *VariableDeclaration::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType VariableDeclaration::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}
}  // namespace ark::es2panda::ir
