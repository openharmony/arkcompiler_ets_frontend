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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_TS_METHOD_SIGNATURE_H
#define ES2PANDA_PARSER_INCLUDE_AST_TS_METHOD_SIGNATURE_H

#include "plugins/ecmascript/es2panda/ir/statement.h"

namespace panda::es2panda::binder {
class Scope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;

class TSMethodSignature : public AstNode {
public:
    explicit TSMethodSignature(binder::Scope *scope, Expression *key, TSTypeParameterDeclaration *type_params,
                               ArenaVector<Expression *> &&params, TypeNode *return_type_annotation, bool computed,
                               bool optional)
        : AstNode(AstNodeType::TS_METHOD_SIGNATURE),
          scope_(scope),
          key_(key),
          type_params_(type_params),
          params_(std::move(params)),
          return_type_annotation_(return_type_annotation),
          computed_(computed),
          optional_(optional)
    {
    }

    binder::Scope *Scope() const
    {
        return scope_;
    }

    const Expression *Key() const
    {
        return key_;
    }

    Expression *Key()
    {
        return key_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    const ArenaVector<Expression *> &Params() const
    {
        return params_;
    }

    const TypeNode *ReturnTypeAnnotation() const
    {
        return return_type_annotation_;
    }

    bool Computed() const
    {
        return computed_;
    }

    bool Optional() const
    {
        return optional_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::Scope *scope_;
    Expression *key_;
    TSTypeParameterDeclaration *type_params_;
    ArenaVector<Expression *> params_;
    TypeNode *return_type_annotation_;
    bool computed_;
    bool optional_;
};
}  // namespace panda::es2panda::ir

#endif
