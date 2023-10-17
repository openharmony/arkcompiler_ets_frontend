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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_TS_INDEX_SIGNATURE_H
#define ES2PANDA_PARSER_INCLUDE_AST_TS_INDEX_SIGNATURE_H

#include "ir/statement.h"

namespace panda::es2panda::ir {
class TSIndexSignature : public TypedAstNode {
public:
    enum class TSIndexSignatureKind { NUMBER, STRING };

    explicit TSIndexSignature(Expression *param, TypeNode *type_annotation, bool readonly)
        : TypedAstNode(AstNodeType::TS_INDEX_SIGNATURE),
          param_(param),
          type_annotation_(type_annotation),
          readonly_(readonly)
    {
    }

    const Expression *Param() const
    {
        return param_;
    }

    const TypeNode *TypeAnnotation() const
    {
        return type_annotation_;
    }

    bool Readonly() const
    {
        return readonly_;
    }

    TSIndexSignatureKind Kind() const;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *param_;
    TypeNode *type_annotation_;
    bool readonly_;
};
}  // namespace panda::es2panda::ir

#endif /* TS_INDEX_SIGNATURE_H */
