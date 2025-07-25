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

#ifndef ES2PANDA_IR_MODULE_EXPORT_SPECIFIER_H
#define ES2PANDA_IR_MODULE_EXPORT_SPECIFIER_H

#include "ir/statement.h"

namespace ark::es2panda::ir {
class Identifier;

class ExportSpecifier : public Statement {
public:
    explicit ExportSpecifier(Identifier *local, Identifier *exported)
        : Statement(AstNodeType::EXPORT_SPECIFIER), local_(local), exported_(exported)
    {
    }

    const Identifier *Local() const
    {
        return local_;
    }

    const Identifier *Exported() const
    {
        return exported_;
    }

    void SetDefault()
    {
        isDefault_ = true;
    }

    bool IsDefault() const
    {
        return isDefault_;
    }

    void SetConstantExpression(ir::Expression *constantExpression)
    {
        constantExpression_ = constantExpression;
    }

    ir::Expression *GetConstantExpression() const
    {
        return constantExpression_;
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

private:
    Identifier *local_;
    Identifier *exported_;
    bool isDefault_ = false;
    ir::Expression *constantExpression_ = nullptr;
};
}  // namespace ark::es2panda::ir

#endif
