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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H
#define ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H

#include "plugins/ecmascript/es2panda/ir/astNode.h"
#include "plugins/ecmascript/es2panda/util/enumbitops.h"

namespace panda::es2panda::binder {
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {
class TSTypeParameterDeclaration;
class TypeNode;

class ScriptFunction : public AstNode {
public:
    explicit ScriptFunction(binder::FunctionScope *scope, ArenaVector<Expression *> &&params,
                            TSTypeParameterDeclaration *type_params, AstNode *body, TypeNode *return_type_annotation,
                            ir::ScriptFunctionFlags func_flags, bool declare)
        : AstNode(AstNodeType::SCRIPT_FUNCTION),
          scope_(scope),
          params_(std::move(params)),
          type_params_(type_params),
          body_(body),
          return_type_annotation_(return_type_annotation),
          func_flags_(func_flags),
          declare_(declare)
    {
    }

    explicit ScriptFunction(binder::FunctionScope *scope, ArenaVector<Expression *> &&params,
                            TSTypeParameterDeclaration *type_params, AstNode *body, TypeNode *return_type_annotation,
                            ir::ScriptFunctionFlags func_flags, ir::ModifierFlags flags, bool declare)
        : AstNode(AstNodeType::SCRIPT_FUNCTION, flags),
          scope_(scope),
          params_(std::move(params)),
          type_params_(type_params),
          body_(body),
          return_type_annotation_(return_type_annotation),
          func_flags_(func_flags),
          declare_(declare)
    {
    }

    const Identifier *Id() const
    {
        return id_;
    }

    Identifier *Id()
    {
        return id_;
    }

    const checker::Signature *Signature() const
    {
        return signature_;
    }

    checker::Signature *Signature()
    {
        return signature_;
    }

    const ArenaVector<Expression *> &Params() const
    {
        return params_;
    }

    ArenaVector<Expression *> &Params()
    {
        return params_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    TSTypeParameterDeclaration *TypeParams()
    {
        return type_params_;
    }

    const AstNode *Body() const
    {
        return body_;
    }

    AstNode *Body()
    {
        return body_;
    }

    void SetBody(AstNode *body)
    {
        body_ = body;
    }

    const TypeNode *ReturnTypeAnnotation() const
    {
        return return_type_annotation_;
    }

    TypeNode *ReturnTypeAnnotation()
    {
        return return_type_annotation_;
    }

    void SetReturnTypeAnnotation(TypeNode *node)
    {
        return_type_annotation_ = node;
    }

    bool IsEntryPoint() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::ENTRY_POINT) != 0;
    }

    bool IsGenerator() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::GENERATOR) != 0;
    }

    bool IsAsyncFunc() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::ASYNC) != 0;
    }

    bool IsArrow() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::ARROW) != 0;
    }

    bool IsOverload() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::OVERLOAD) != 0;
    }

    bool IsConstructor() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::CONSTRUCTOR) != 0;
    }

    bool IsGetter() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::GETTER) != 0;
    }

    bool IsSetter() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::SETTER) != 0;
    }

    bool IsMethod() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::METHOD) != 0;
    }

    bool IsProxy() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::PROXY) != 0;
    }

    bool IsStaticBlock() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::STATIC_BLOCK) != 0;
    }

    bool IsEnum() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::ENUM) != 0;
    }

    bool IsHidden() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::HIDDEN) != 0;
    }

    bool IsExternal() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::EXTERNAL) != 0;
    }

    bool IsImplicitSuperCallNeeded() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED) != 0;
    }

    bool HasBody() const;

    bool IsThrowing() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::THROWS) != 0;
    }

    bool IsRethrowing() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::RETHROWS) != 0;
    }

    bool IsDefaultParamProxy() const
    {
        return (func_flags_ & ir::ScriptFunctionFlags::DEFAULT_PARAM_PROXY) != 0;
    }

    bool IsDefaultParamProxy()
    {
        return (func_flags_ & ir::ScriptFunctionFlags::DEFAULT_PARAM_PROXY) != 0;
    }

    void SetDefaultParamProxy()
    {
        AddFlag(ir::ScriptFunctionFlags::DEFAULT_PARAM_PROXY);
    }

    bool Declare() const
    {
        return declare_;
    }

    ir::ScriptFunctionFlags Flags() const;

    void SetIdent(Identifier *id)
    {
        id_ = id;
    }

    void SetSignature(checker::Signature *signature)
    {
        signature_ = signature;
    }

    void AddFlag(ir::ScriptFunctionFlags flags)
    {
        func_flags_ |= flags;
    }

    void AddModifier(ir::ModifierFlags flags)
    {
        flags_ |= flags;
    }

    size_t FormalParamsLength() const;

    binder::FunctionScope *Scope() const
    {
        return scope_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::FunctionScope *scope_;
    Identifier *id_ {};
    ArenaVector<Expression *> params_;
    TSTypeParameterDeclaration *type_params_;
    AstNode *body_;
    TypeNode *return_type_annotation_;
    ir::ScriptFunctionFlags func_flags_;
    checker::Signature *signature_ {};
    bool declare_;
};
}  // namespace panda::es2panda::ir

#endif
