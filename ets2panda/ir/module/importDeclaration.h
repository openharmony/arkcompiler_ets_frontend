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

#ifndef ES2PANDA_IR_MODULE_IMPORT_DECLARATION_H
#define ES2PANDA_IR_MODULE_IMPORT_DECLARATION_H

#include "ir/statement.h"

namespace ark::es2panda::ir {
class StringLiteral;

enum class ImportKinds { ALL, TYPES };

class ImportDeclaration : public Statement {
public:
    explicit ImportDeclaration(StringLiteral *source, ArenaVector<AstNode *> &&specifiers,
                               const ImportKinds importKinds = ImportKinds::ALL)
        : Statement(AstNodeType::IMPORT_DECLARATION),
          source_(source),
          specifiers_(std::move(specifiers)),
          importKinds_(importKinds)
    {
    }

    const StringLiteral *Source() const
    {
        return source_;
    }

    StringLiteral *Source()
    {
        return source_;
    }

    const ArenaVector<AstNode *> &Specifiers() const
    {
        return specifiers_;
    }

    ArenaVector<AstNode *> &Specifiers()
    {
        return specifiers_;
    }

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::VerifiedType Check(checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

    bool IsTypeKind() const
    {
        return importKinds_ == ImportKinds::TYPES;
    }

    ImportDeclaration *Construct(ArenaAllocator *allocator) override;
    void CopyTo(AstNode *other) const override;

private:
    friend class SizeOfNodeTest;
    StringLiteral *source_;
    ArenaVector<AstNode *> specifiers_;
    ImportKinds importKinds_;
};
}  // namespace ark::es2panda::ir

#endif
