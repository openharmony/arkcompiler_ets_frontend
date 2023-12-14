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

#ifndef ES2PANDA_IR_TS_FUNCTION_TYPE_H
#define ES2PANDA_IR_TS_FUNCTION_TYPE_H

#include "ir/typeNode.h"
#include "ir/base/scriptFunctionSignature.h"

namespace panda::es2panda::checker {
class TSAnalyzer;
}  // namespace panda::es2panda::checker
namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;

class TSFunctionType : public TypeNode {
public:
    explicit TSFunctionType(FunctionSignature &&signature)
        : TypeNode(AstNodeType::TS_FUNCTION_TYPE), signature_(std::move(signature))
    {
    }
    // NOTE (vivienvoros): these friend relationships can be removed once there are getters for private fields
    friend class checker::TSAnalyzer;

    bool IsScopeBearer() const override
    {
        return true;
    }

    varbinder::Scope *Scope() const override
    {
        return scope_;
    }

    void SetScope(varbinder::Scope *scope)
    {
        scope_ = scope;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return signature_.TypeParams();
    }

    TSTypeParameterDeclaration *TypeParams()
    {
        return signature_.TypeParams();
    }

    const ArenaVector<Expression *> &Params() const
    {
        return signature_.Params();
    }

    const TypeNode *ReturnType() const
    {
        return signature_.ReturnType();
    }
    TypeNode *ReturnType()
    {
        return signature_.ReturnType();
    }

    void SetNullable(bool nullable)
    {
        nullable_ = nullable;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    varbinder::Scope *scope_ {nullptr};
    FunctionSignature signature_;
    bool nullable_ {};
};
}  // namespace panda::es2panda::ir

#endif
