/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_STATEMENT_DECLARE_NAMESPACE_DECLARATION_H
#define ES2PANDA_IR_STATEMENT_DECLARE_NAMESPACE_DECLARATION_H

#include "ir/statement.h"
#include "ir/visitor/AstVisitor.h"
#include "ir/base/namespaceDefinition.h"

namespace ark::es2panda::ir {
class NamespaceDeclaration : public Statement {
public:
    NamespaceDeclaration() = delete;
    ~NamespaceDeclaration() override = default;

    NO_COPY_SEMANTIC(NamespaceDeclaration);
    NO_MOVE_SEMANTIC(NamespaceDeclaration);

    explicit NamespaceDeclaration(NamespaceDefinition *def) : Statement(AstNodeType::NAMESPACE_DECLARATION), def_(def)
    {
    }

    NamespaceDefinition *Definition()
    {
        return def_;
    }

    const NamespaceDefinition *Definition() const
    {
        return def_;
    }

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;

    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    NamespaceDefinition *def_;
};
}  // namespace ark::es2panda::ir

#endif