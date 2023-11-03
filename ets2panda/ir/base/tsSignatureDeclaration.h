/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_TS_SIGNATURE_DECLARATION_H
#define ES2PANDA_PARSER_INCLUDE_AST_TS_SIGNATURE_DECLARATION_H

#include "ir/astNode.h"

namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;

class TSSignatureDeclaration : public TypedAstNode {
public:
    enum class TSSignatureDeclarationKind { CALL_SIGNATURE, CONSTRUCT_SIGNATURE };

    TSSignatureDeclaration() = delete;
    ~TSSignatureDeclaration() override = default;

    NO_COPY_SEMANTIC(TSSignatureDeclaration);
    NO_MOVE_SEMANTIC(TSSignatureDeclaration);

    explicit TSSignatureDeclaration(varbinder::Scope *const scope, TSSignatureDeclarationKind const kind,
                                    TSTypeParameterDeclaration *const type_params, ArenaVector<Expression *> &&params,
                                    TypeNode *const return_type_annotation)
        : TypedAstNode(AstNodeType::TS_SIGNATURE_DECLARATION),
          scope_(scope),
          kind_(kind),
          type_params_(type_params),
          params_(std::move(params)),
          return_type_annotation_(return_type_annotation)
    {
    }

    bool IsScopeBearer() const override
    {
        return true;
    }

    varbinder::Scope *Scope() const override
    {
        return scope_;
    }

    [[nodiscard]] const TSTypeParameterDeclaration *TypeParams() const noexcept
    {
        return type_params_;
    }

    [[nodiscard]] const ArenaVector<Expression *> &Params() const noexcept
    {
        return params_;
    }

    [[nodiscard]] const TypeNode *ReturnTypeAnnotation() const noexcept
    {
        return return_type_annotation_;
    }

    [[nodiscard]] TSSignatureDeclarationKind Kind() const noexcept
    {
        return kind_;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;

    void Dump(ir::AstDumper *dumper) const override;

    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    varbinder::Scope *scope_;
    TSSignatureDeclarationKind kind_;
    TSTypeParameterDeclaration *type_params_;
    ArenaVector<Expression *> params_;
    TypeNode *return_type_annotation_;
};
}  // namespace panda::es2panda::ir

#endif
