/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_EXPRESSION_ETS_PARAMETER_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_ETS_PARAMETER_EXPRESSION_H

#include "ir/expression.h"

namespace panda::es2panda::ir {
class ETSParameterExpression : public Expression {
public:
    explicit ETSParameterExpression(AnnotatedExpression *ident_or_spread, Expression *initializer);

    const Identifier *Ident() const;
    Identifier *Ident();
    const SpreadElement *Spread() const;
    SpreadElement *Spread();
    const Expression *Initializer() const;
    Expression *Initializer();

    void SetLexerSaved(util::StringView s);
    util::StringView LexerSaved() const;

    binder::Variable *Variable() const;
    void SetVariable(binder::Variable *variable);
    bool IsDefault() const;

    void Iterate(const NodeTraverser &cb) const override;
    void TransformChildren(const NodeTransformer &cb) override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;

private:
    Identifier *ident_;
    Expression *initializer_;
    SpreadElement *spread_;
    util::StringView saved_lexer_;
};
}  // namespace panda::es2panda::ir

#endif
