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

#ifndef ES2PANDA_IR_MODULE_EXPORT_DECLARATION_H
#define ES2PANDA_IR_MODULE_EXPORT_DECLARATION_H

#include "plugins/ecmascript/es2panda/ir/statement.h"

namespace panda::es2panda::ir {
class StringLiteral;
class ExportSpecifier;

class ExportNamedDeclaration : public Statement {
public:
    explicit ExportNamedDeclaration(ArenaAllocator *allocator, StringLiteral *source,
                                    ArenaVector<ExportSpecifier *> &&specifiers)
        : Statement(AstNodeType::EXPORT_NAMED_DECLARATION),
          decorators_(allocator->Adapter()),
          source_(source),
          specifiers_(std::move(specifiers))
    {
    }

    explicit ExportNamedDeclaration(ArenaAllocator *allocator, AstNode *decl,
                                    ArenaVector<ExportSpecifier *> &&specifiers)
        : Statement(AstNodeType::EXPORT_NAMED_DECLARATION),
          decorators_(allocator->Adapter()),
          decl_(decl),
          specifiers_(std::move(specifiers))
    {
    }

    explicit ExportNamedDeclaration(ArenaAllocator *allocator, AstNode *decl)
        : Statement(AstNodeType::EXPORT_NAMED_DECLARATION),
          decorators_(allocator->Adapter()),
          decl_(decl),
          specifiers_(allocator->Adapter())
    {
    }

    const AstNode *Decl() const
    {
        return decl_;
    }

    const StringLiteral *Source() const
    {
        return source_;
    }

    const ArenaVector<ExportSpecifier *> &Specifiers() const
    {
        return specifiers_;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    bool CanHaveDecorator([[maybe_unused]] bool in_ts) const override
    {
        return !in_ts && (source_ == nullptr);
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    ArenaVector<Decorator *> decorators_;
    StringLiteral *source_ {};
    AstNode *decl_ {};
    ArenaVector<ExportSpecifier *> specifiers_;
};
}  // namespace panda::es2panda::ir

#endif
