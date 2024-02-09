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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H
#define ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H

#include "ir/astNode.h"
#include "varbinder/scope.h"
#include "util/enumbitops.h"
#include "util/language.h"
#include "scriptFunctionSignature.h"

namespace ark::es2panda::checker {
class Signature;

}  // namespace ark::es2panda::checker
namespace ark::es2panda::compiler {
class ScopesInitPhase;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::ir {
class TSTypeParameterDeclaration;
class TypeNode;

class ScriptFunction : public AstNode {
public:
    // Need to reduce the number of constructor parameters to pass OHOS CI code check
    struct ScriptFunctionData {
        ir::ScriptFunctionFlags funcFlags = ir::ScriptFunctionFlags::NONE;
        ir::ModifierFlags flags = ir::ModifierFlags::NONE;
        bool declare = false;
        ark::es2panda::Language lang {Language::Id::ETS};
    };

    ScriptFunction() = delete;
    ~ScriptFunction() override = default;

    NO_COPY_SEMANTIC(ScriptFunction);
    NO_MOVE_SEMANTIC(ScriptFunction);

    explicit ScriptFunction(FunctionSignature &&signature, AstNode *body, ScriptFunctionData &&data);

    explicit ScriptFunction(FunctionSignature &&signature, AstNode *body, ir::ScriptFunctionFlags funcFlags,
                            bool declare, Language lang)
        : ScriptFunction(std::move(signature), body, {funcFlags, {}, declare, lang})
    {
    }

    [[nodiscard]] const Identifier *Id() const noexcept
    {
        return id_;
    }

    [[nodiscard]] Identifier *Id() noexcept
    {
        return id_;
    }

    [[nodiscard]] const checker::Signature *Signature() const noexcept
    {
        return signature_;
    }

    [[nodiscard]] checker::Signature *Signature() noexcept
    {
        return signature_;
    }

    [[nodiscard]] const ArenaVector<Expression *> &Params() const noexcept
    {
        return irSignature_.Params();
    }

    [[nodiscard]] ArenaVector<Expression *> &Params() noexcept
    {
        return irSignature_.Params();
    }

    [[nodiscard]] const TSTypeParameterDeclaration *TypeParams() const noexcept
    {
        return irSignature_.TypeParams();
    }

    [[nodiscard]] TSTypeParameterDeclaration *TypeParams() noexcept
    {
        return irSignature_.TypeParams();
    }

    [[nodiscard]] const AstNode *Body() const noexcept
    {
        return body_;
    }

    [[nodiscard]] AstNode *Body() noexcept
    {
        return body_;
    }

    void SetBody(AstNode *body) noexcept
    {
        body_ = body;
    }

    [[nodiscard]] const TypeNode *ReturnTypeAnnotation() const noexcept
    {
        return irSignature_.ReturnType();
    }

    [[nodiscard]] TypeNode *ReturnTypeAnnotation() noexcept
    {
        return irSignature_.ReturnType();
    }

    void SetReturnTypeAnnotation(TypeNode *node) noexcept;

    [[nodiscard]] bool IsEntryPoint() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ENTRY_POINT) != 0;
    }

    [[nodiscard]] bool IsGenerator() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::GENERATOR) != 0;
    }

    [[nodiscard]] bool IsAsyncFunc() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ASYNC) != 0;
    }

    [[nodiscard]] bool IsArrow() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ARROW) != 0;
    }

    [[nodiscard]] bool IsOverload() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::OVERLOAD) != 0;
    }

    [[nodiscard]] bool IsConstructor() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::CONSTRUCTOR) != 0;
    }

    [[nodiscard]] bool IsGetter() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::GETTER) != 0;
    }

    [[nodiscard]] bool IsSetter() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::SETTER) != 0;
    }

    [[nodiscard]] bool IsMethod() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::METHOD) != 0;
    }

    [[nodiscard]] bool IsProxy() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::PROXY) != 0;
    }

    [[nodiscard]] bool IsStaticBlock() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::STATIC_BLOCK) != 0;
    }

    [[nodiscard]] bool IsEnum() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ENUM) != 0;
    }

    [[nodiscard]] bool IsHidden() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::HIDDEN) != 0;
    }

    [[nodiscard]] bool IsExternal() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::EXTERNAL) != 0;
    }

    [[nodiscard]] bool IsImplicitSuperCallNeeded() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED) != 0;
    }

    [[nodiscard]] bool HasBody() const noexcept
    {
        return body_ != nullptr;
    }

    [[nodiscard]] bool IsThrowing() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::THROWS) != 0;
    }

    [[nodiscard]] bool IsRethrowing() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::RETHROWS) != 0;
    }

    [[nodiscard]] bool IsDefaultParamProxy() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::DEFAULT_PARAM_PROXY) != 0;
    }

    void SetDefaultParamProxy() noexcept
    {
        AddFlag(ir::ScriptFunctionFlags::DEFAULT_PARAM_PROXY);
    }

    [[nodiscard]] bool IsDynamic() const noexcept
    {
        return lang_.IsDynamic();
    }

    [[nodiscard]] bool IsExtensionMethod() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD) != 0;
    }

    [[nodiscard]] bool Declare() const noexcept
    {
        return declare_;
    }

    [[nodiscard]] ir::ScriptFunctionFlags Flags() const noexcept
    {
        return funcFlags_;
    }

    void SetIdent(Identifier *id) noexcept;

    void SetSignature(checker::Signature *signature) noexcept
    {
        signature_ = signature;
    }

    void AddFlag(ir::ScriptFunctionFlags flags) noexcept
    {
        funcFlags_ |= flags;
    }

    void AddModifier(ir::ModifierFlags flags) noexcept
    {
        flags_ |= flags;
    }

    [[nodiscard]] std::size_t FormalParamsLength() const noexcept;

    bool IsScopeBearer() const override
    {
        return true;
    }

    varbinder::FunctionScope *Scope() const override
    {
        return scope_;
    }

    void SetScope(varbinder::FunctionScope *scope)
    {
        scope_ = scope;
    }

    [[nodiscard]] es2panda::Language Language() const
    {
        return lang_;
    }

    void TransformChildren(const NodeTransformer &cb) override;
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
    friend ark::es2panda::compiler::ScopesInitPhase;

private:
    Identifier *id_ {};
    FunctionSignature irSignature_;
    AstNode *body_;
    varbinder::FunctionScope *scope_ {nullptr};
    ir::ScriptFunctionFlags funcFlags_;
    checker::Signature *signature_ {};
    bool declare_;
    es2panda::Language lang_;
};
}  // namespace ark::es2panda::ir

#endif
