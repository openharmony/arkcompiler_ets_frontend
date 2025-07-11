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

#ifndef ES2PANDA_IR_TS_CONSTRUCTOR_TYPE_H
#define ES2PANDA_IR_TS_CONSTRUCTOR_TYPE_H

#include "ir/typeNode.h"
#include "ir/base/scriptFunctionSignature.h"

namespace ark::es2panda::checker {
class TSAnalyzer;
}  // namespace ark::es2panda::checker
namespace ark::es2panda::ir {
class TSTypeParameterDeclaration;

class TSConstructorType : public TypeNode {
public:
    explicit TSConstructorType(FunctionSignature signature, bool abstract, ArenaAllocator *const allocator)
        : TypeNode(AstNodeType::TS_CONSTRUCTOR_TYPE, allocator), signature_(std::move(signature)), abstract_(abstract)
    {
    }
    // NOTE (vivienvoros): these friend relationships can be removed once there are getters for private fields
    friend class checker::TSAnalyzer;

    [[nodiscard]] bool IsScopeBearer() const noexcept override
    {
        return true;
    }

    [[nodiscard]] varbinder::Scope *Scope() const noexcept override
    {
        return scope_;
    }

    void SetScope(varbinder::Scope *scope)
    {
        ES2PANDA_ASSERT(scope_ == nullptr);
        scope_ = scope;
    }

    void ClearScope() noexcept override
    {
        scope_ = nullptr;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return signature_.TypeParams();
    }
    TSTypeParameterDeclaration *TypeParams()
    {
        return signature_.TypeParams();
    }

    const ArenaVector<ir::Expression *> &Params() const
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

    bool Abstract() const
    {
        return abstract_;
    }

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::VerifiedType Check([[maybe_unused]] checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    varbinder::Scope *scope_ {nullptr};
    FunctionSignature signature_;
    bool abstract_;
};
}  // namespace ark::es2panda::ir

#endif
