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

#ifndef ES2PANDA_IR_ETS_FUNCTION_TYPE_H
#define ES2PANDA_IR_ETS_FUNCTION_TYPE_H

#include "ir/typeNode.h"

namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;

class ETSFunctionType : public TypeNode {
public:
    explicit ETSFunctionType(binder::Scope *scope, ArenaVector<Expression *> &&params,
                             TSTypeParameterDeclaration *type_params, TypeNode *return_type,
                             ir::ScriptFunctionFlags func_flags)
        : TypeNode(AstNodeType::ETS_FUNCTION_TYPE),
          scope_(scope),
          params_(std::move(params)),
          type_params_(type_params),
          return_type_(return_type),
          func_flags_(func_flags)
    {
    }

    bool IsScopeBearer() const override
    {
        return true;
    }

    binder::Scope *Scope() const override
    {
        return scope_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    const ArenaVector<Expression *> &Params() const
    {
        return params_;
    }

    const TypeNode *ReturnType() const
    {
        return return_type_;
    }

    TypeNode *ReturnType()
    {
        return return_type_;
    }

    ir::TSInterfaceDeclaration *FunctionalInterface()
    {
        return functional_interface_;
    }

    const ir::TSInterfaceDeclaration *FunctionalInterface() const
    {
        return functional_interface_;
    }

    void SetFunctionalInterface(ir::TSInterfaceDeclaration *functional_interface)
    {
        functional_interface_ = functional_interface;
    }

    bool IsThrowing() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::THROWS) != 0;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::Scope *scope_;
    ArenaVector<Expression *> params_;
    TSTypeParameterDeclaration *type_params_;
    TypeNode *return_type_;
    ir::TSInterfaceDeclaration *functional_interface_ {};
    checker::Type *ts_type_ {};
    ir::ScriptFunctionFlags func_flags_;
};
}  // namespace panda::es2panda::ir

#endif
