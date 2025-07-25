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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H
#define ES2PANDA_PARSER_INCLUDE_AST_SCRIPT_FUNCTION_H

#include "checker/types/signature.h"
#include "ir/annotationAllowed.h"
#include "ir/jsDocAllowed.h"
#include "ir/statements/returnStatement.h"
#include "ir/astNode.h"
#include "scriptFunctionSignature.h"
#include "util/enumbitops.h"
#include "util/language.h"
#include "varbinder/scope.h"

namespace ark::es2panda::checker {
class Signature;

}  // namespace ark::es2panda::checker

namespace ark::es2panda::ir {
class TSTypeParameterDeclaration;
class TypeNode;
class AnnotationUsage;
class FunctionSignature;

class ScriptFunction : public JsDocAllowed<AnnotationAllowed<AstNode>> {
public:
    // Need to reduce the number of constructor parameters to pass OHOS CI code check
    struct ScriptFunctionData {
        AstNode *body = nullptr;
        FunctionSignature &&signature;
        ir::ScriptFunctionFlags funcFlags = ir::ScriptFunctionFlags::NONE;
        ir::ModifierFlags flags = ir::ModifierFlags::NONE;
        ark::es2panda::Language lang {Language::Id::ETS};
    };

    ScriptFunction() = delete;
    ~ScriptFunction() override = default;

    NO_COPY_SEMANTIC(ScriptFunction);
    NO_MOVE_SEMANTIC(ScriptFunction);

    explicit ScriptFunction(ArenaAllocator *allocator, ScriptFunctionData &&data);

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

    [[nodiscard]] const ArenaVector<ir::Expression *> &Params() const noexcept
    {
        return irSignature_.Params();
    }

    [[nodiscard]] ArenaVector<ir::Expression *> &Params() noexcept
    {
        return irSignature_.Params();
    }

    const ArenaVector<ReturnStatement *> &ReturnStatements() const
    {
        return returnStatements_;
    }

    ArenaVector<ReturnStatement *> &ReturnStatements()
    {
        return returnStatements_;
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

    void AddReturnStatement(ReturnStatement *returnStatement)
    {
        returnStatements_.push_back(returnStatement);
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

    [[nodiscard]] bool IsAsyncImplFunc() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ASYNC_IMPL) != 0;
    }

    [[nodiscard]] bool IsArrow() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::ARROW) != 0;
    }

    [[nodiscard]] bool IsOverload() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::OVERLOAD) != 0;
    }

    [[nodiscard]] bool IsExternalOverload() const
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::EXTERNAL_OVERLOAD) != 0;
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

    [[nodiscard]] bool IsExtensionAccessor() const noexcept
    {
        return IsExtensionMethod() && (IsGetter() || IsSetter());
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

    [[nodiscard]] bool HasRestParameter() const noexcept
    {
        return signature_->RestVar() != nullptr;
    }

    [[nodiscard]] bool HasReturnStatement() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::HAS_RETURN) != 0;
    }

    [[nodiscard]] bool HasThrowStatement() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::HAS_THROW) != 0;
    }

    [[nodiscard]] bool IsThrowing() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::THROWS) != 0;
    }

    [[nodiscard]] bool IsRethrowing() const noexcept
    {
        return (funcFlags_ & ir::ScriptFunctionFlags::RETHROWS) != 0;
    }

    [[nodiscard]] bool IsDynamic() const noexcept
    {
        return lang_.IsDynamic();
    }

    // Note: This method has been written into CAPI, cannot remove it simply.
    [[nodiscard]] bool IsExtensionMethod() const noexcept
    {
        return HasReceiver();
    }

    [[nodiscard]] ir::ScriptFunctionFlags Flags() const noexcept
    {
        return funcFlags_;
    }

    [[nodiscard]] bool HasReceiver() const noexcept
    {
        return irSignature_.HasReceiver();
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

    void ClearFlag(ir::ScriptFunctionFlags flags) noexcept
    {
        funcFlags_ &= (~flags);
    }

    void AddModifier(ir::ModifierFlags flags) noexcept
    {
        flags_ |= flags;
    }

    [[nodiscard]] std::size_t FormalParamsLength() const noexcept;

    [[nodiscard]] bool IsScopeBearer() const noexcept override
    {
        return true;
    }

    [[nodiscard]] varbinder::FunctionScope *Scope() const noexcept override
    {
        return scope_;
    }

    void SetScope(varbinder::FunctionScope *scope) noexcept
    {
        scope_ = scope;
    }

    void ClearScope() noexcept override
    {
        scope_ = nullptr;
    }

    [[nodiscard]] es2panda::Language Language() const noexcept
    {
        return lang_;
    }

    void SetPreferredReturnType(checker::Type *preferredReturnType) noexcept
    {
        preferredReturnType_ = preferredReturnType;
    }

    [[nodiscard]] checker::Type *GetPreferredReturnType() noexcept
    {
        return preferredReturnType_;
    }

    [[nodiscard]] checker::Type const *GetPreferredReturnType() const noexcept
    {
        return preferredReturnType_;
    }

    [[nodiscard]] ScriptFunction *Clone(ArenaAllocator *allocator, AstNode *parent) override;

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;

    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::VerifiedType Check(checker::ETSChecker *checker) override;

    void SetIsolatedDeclgenReturnType(std::string type) noexcept
    {
        isolatedDeclGenInferType_ = std::move(type);
    }

    [[nodiscard]] std::string GetIsolatedDeclgenReturnType() const noexcept
    {
        return isolatedDeclGenInferType_;
    }

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

    void CleanUp() override
    {
        AstNode::CleanUp();
        signature_ = nullptr;
        preferredReturnType_ = nullptr;
    }

protected:
    ScriptFunction *Construct(ArenaAllocator *allocator) override;
    void CopyTo(AstNode *other) const override;

private:
    void DumpBody(ir::SrcDumper *dumper) const;
    void DumpCheckerTypeForDeclGen(ir::SrcDumper *dumper) const;
    friend class SizeOfNodeTest;
    Identifier *id_ {};
    FunctionSignature irSignature_;
    AstNode *body_;
    varbinder::FunctionScope *scope_ {nullptr};
    ir::ScriptFunctionFlags funcFlags_;
    checker::Signature *signature_ {};
    checker::Type *preferredReturnType_ {};
    es2panda::Language lang_;
    ArenaVector<ReturnStatement *> returnStatements_;
    std::string isolatedDeclGenInferType_;
};
}  // namespace ark::es2panda::ir

#endif
