/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_VARBINDER_VARBINDER_H
#define ES2PANDA_VARBINDER_VARBINDER_H

#include "varbinder/scope.h"
#include "varbinder/variableFlags.h"
#include "lexer/token/sourceLocation.h"
#include "macros.h"

namespace ark::es2panda::parser {
class Program;
enum class ScriptKind;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::ir {
class AstNode;
class BlockStatement;
class CatchClause;
class ClassDefinition;
class Expression;
class ForUpdateStatement;
class Identifier;
class ScriptFunction;
class Statement;
class VariableDeclarator;
class TSFunctionType;
class ThisExpression;
class MemberExpression;
class ClassStaticBlock;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::public_lib {
struct Context;
}  // namespace ark::es2panda::public_lib

namespace ark::es2panda::varbinder {
class ETSBinder;

class VarBinder {
public:
    explicit VarBinder(ArenaAllocator *allocator) : allocator_(allocator), functionScopes_(allocator_->Adapter()) {}

    NO_COPY_SEMANTIC(VarBinder);
    NO_MOVE_SEMANTIC(VarBinder);
    virtual ~VarBinder() = default;

    void InitTopScope();
    virtual void IdentifierAnalysis();

    template <typename T, typename... Args>
    T *AddDecl(const lexer::SourcePosition &pos, Args &&...args);

    template <typename T, typename... Args>
    T *AddTsDecl(const lexer::SourcePosition &pos, Args &&...args);

    template <typename T, typename... Args>
    std::tuple<T *, varbinder::Variable *> NewVarDecl(const lexer::SourcePosition &pos, Args &&...args);

    std::tuple<ParameterDecl *, Variable *> AddParamDecl(ir::AstNode *param);

    void SetProgram(parser::Program *program)
    {
        program_ = program;
    }

    parser::Program *Program()
    {
        return program_;
    }

    const parser::Program *Program() const
    {
        ASSERT(program_);
        return program_;
    }

    void SetContext(public_lib::Context *context)
    {
        ASSERT(!context_);
        context_ = context;
    }

    public_lib::Context *GetContext() const
    {
        ASSERT(context_);
        return context_;
    }

    void SetGenStdLib(bool genStdLib)
    {
        genStdLib_ = genStdLib;
    }

    bool IsGenStdLib()
    {
        return genStdLib_;
    }

    Scope *GetScope() const
    {
        return scope_;
    }

    void ResetAllScopes(GlobalScope *topScope, VariableScope *varScope, Scope *scope)
    {
        topScope_ = topScope;
        varScope_ = varScope;
        scope_ = scope;
    }

    void ResetTopScope(GlobalScope *topScope)
    {
        ASSERT(topScope_ == scope_);
        topScope_ = topScope;
        varScope_ = topScope_;
        scope_ = topScope_;
    }

    GlobalScope *TopScope() const
    {
        return topScope_;
    }

    VariableScope *VarScope() const
    {
        return varScope_;
    }

    bool IsETSBinder() const
    {
        return Extension() == ScriptExtension::ETS;
    }

    ETSBinder *AsETSBinder()
    {
        ASSERT(Extension() == ScriptExtension::ETS);
        return reinterpret_cast<ETSBinder *>(this);
    }

    [[noreturn]] void ThrowPrivateFieldMismatch(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowRedeclaration(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowUnresolvableVariable(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowUnresolvableType(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowTDZ(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowInvalidCapture(const lexer::SourcePosition &pos, const util::StringView &name) const;
    [[noreturn]] void ThrowError(const lexer::SourcePosition &pos, const std::string_view &msg) const;

    void PropagateDirectEval() const;

    template <typename T>
    friend class LexicalScope;

    inline ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

    const ArenaVector<FunctionScope *> &Functions() const
    {
        return functionScopes_;
    }

    ArenaVector<FunctionScope *> &Functions()
    {
        return functionScopes_;
    }

    virtual ScriptExtension Extension() const
    {
        return ScriptExtension::JS;
    }

    virtual ResolveBindingOptions BindingOptions() const
    {
        return ResolveBindingOptions::BINDINGS;
    }

    LocalVariable *AddMandatoryParam(const std::string_view &name);

    static constexpr std::string_view FUNCTION_ARGUMENTS = "arguments";
    static constexpr std::string_view MANDATORY_PARAM_FUNC = "=f";
    static constexpr std::string_view MANDATORY_PARAM_NEW_TARGET = "=nt";
    static constexpr std::string_view MANDATORY_PARAM_THIS = "=t";

    static constexpr uint32_t MANDATORY_PARAM_FUNC_REG = 0;
    static constexpr uint32_t MANDATORY_PARAMS_NUMBER = 3;

    static constexpr std::string_view LEXICAL_MANDATORY_PARAM_FUNC = "!f";
    static constexpr std::string_view LEXICAL_MANDATORY_PARAM_NEW_TARGET = "!nt";
    static constexpr std::string_view LEXICAL_MANDATORY_PARAM_THIS = "!t";

    static constexpr std::string_view LEXICAL_CONTEXT_PARAM = "=eval";
    static constexpr std::string_view MAIN = "main";
    static constexpr uint32_t LEXICAL_CONTEXT_PARAM_REG = MANDATORY_PARAMS_NUMBER;
    static constexpr std::string_view STAR_IMPORT = "*";

    void ResolveReference(ir::AstNode *childNode);

protected:
    template <size_t N>
    using MandatoryParams = std::array<std::string_view, N>;

    static constexpr MandatoryParams<MANDATORY_PARAMS_NUMBER> FUNCTION_MANDATORY_PARAMS = {
        MANDATORY_PARAM_FUNC, MANDATORY_PARAM_NEW_TARGET, MANDATORY_PARAM_THIS};

    static constexpr MandatoryParams<MANDATORY_PARAMS_NUMBER + 1> EVAL_SCRIPT_MANDATORY_PARAMS = {
        MANDATORY_PARAM_FUNC, MANDATORY_PARAM_NEW_TARGET, MANDATORY_PARAM_THIS, LEXICAL_CONTEXT_PARAM};

    static constexpr MandatoryParams<MANDATORY_PARAMS_NUMBER> ARROW_MANDATORY_PARAMS = {
        MANDATORY_PARAM_FUNC, LEXICAL_MANDATORY_PARAM_NEW_TARGET, LEXICAL_MANDATORY_PARAM_THIS};

    static constexpr MandatoryParams<MANDATORY_PARAMS_NUMBER> CTOR_ARROW_MANDATORY_PARAMS = {
        LEXICAL_MANDATORY_PARAM_FUNC, LEXICAL_MANDATORY_PARAM_NEW_TARGET, LEXICAL_MANDATORY_PARAM_THIS};

    void LookUpMandatoryReferences(const FunctionScope *funcScope, bool needLexicalFuncObj);
    template <size_t N>
    void AddMandatoryParams(const MandatoryParams<N> &params);
    void AddMandatoryParams();
    void LookupReference(const util::StringView &name);
    void InstantiateArguments();
    bool InstantiateArgumentsImpl(Scope **scope, Scope *iter, const ir::AstNode *node);
    void InstantiatePrivateContext(const ir::Identifier *ident) const;
    void BuildVarDeclarator(ir::VariableDeclarator *varDecl);
    void BuildVarDeclaratorId(ir::AstNode *childNode);
    void BuildForUpdateLoop(ir::ForUpdateStatement *forUpdateStmt);
    void BuildForInOfLoop(varbinder::LoopScope *loopScope, ir::AstNode *left, ir::Expression *right,
                          ir::Statement *body);
    void BuildCatchClause(ir::CatchClause *catchClauseStmt);
    void BuildTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAliasDecl);
    void ResolveReferences(const ir::AstNode *parent);
    void VisitScriptFunctionWithPotentialTypeParams(ir::ScriptFunction *func);
    void VisitScriptFunction(ir::ScriptFunction *func);
    util::StringView BuildFunctionName(util::StringView name, uint32_t idx);

    void AddCompilableFunctionScope(varbinder::FunctionScope *funcScope);

    void InitializeClassBinding(ir::ClassDefinition *classDef);
    void InitializeClassIdent(ir::ClassDefinition *classDef);

    virtual void LookupIdentReference(ir::Identifier *ident);
    virtual void HandleCustomNodes(ir::AstNode *childNode)
    {
        ResolveReferences(childNode);
    }
    virtual void BuildSignatureDeclarationBaseParams([[maybe_unused]] ir::AstNode *typeNode) {};
    virtual void BuildClassDefinition(ir::ClassDefinition *classDef);
    virtual void BuildClassProperty(const ir::ClassProperty *prop);
    virtual bool BuildInternalName(ir::ScriptFunction *scriptFunc);
    virtual void AddCompilableFunction(ir::ScriptFunction *func);

private:
    parser::Program *program_ {};
    ArenaAllocator *allocator_ {};
    public_lib::Context *context_ {};
    GlobalScope *topScope_ {};
    Scope *scope_ {};
    VariableScope *varScope_ {};
    ArenaVector<FunctionScope *> functionScopes_;
    ResolveBindingOptions bindingOptions_ {};
    bool genStdLib_ {false};
};

template <typename T>
class LexicalScope {
public:
    template <typename... Args>
    explicit LexicalScope(VarBinder *varbinder, Args &&...args)
        : LexicalScope(
              varbinder->Allocator()->New<T>(varbinder->Allocator(), varbinder->scope_, std::forward<Args>(args)...),
              varbinder)
    {
    }

    T *GetScope() const
    {
        return scope_;
    }

    ~LexicalScope()
    {
        ASSERT(varbinder_);
        varbinder_->scope_ = prevScope_;
        varbinder_->varScope_ = prevVarScope_;
    }

    [[nodiscard]] static LexicalScope<T> Enter(VarBinder *varbinder, T *scope, bool checkEval = true)
    {
        LexicalScope<T> lexScope(scope, varbinder);
        if (!checkEval || varbinder->Extension() == ScriptExtension::TS) {
            return lexScope;
        }

        // NOLINTNEXTLINE(readability-braces-around-statements)
        if constexpr (std::is_same_v<T, FunctionParamScope>) {
            varbinder->varScope_ = scope->GetFunctionScope();
            varbinder->varScope_->CheckDirectEval(varbinder->context_);
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, FunctionScope>) {
            varbinder->varScope_ = scope;
            varbinder->varScope_->CheckDirectEval(varbinder->context_);
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, LoopScope>) {
            if (scope->IsLoopScope()) {
                varbinder->varScope_ = scope;
                varbinder->varScope_->CheckDirectEval(varbinder->context_);
            }
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, LoopDeclarationScope>) {
            if (scope->IsLoopDeclarationScope()) {
                varbinder->varScope_ = scope;
                varbinder->varScope_->CheckDirectEval(varbinder->context_);
            }
        }

        return lexScope;
    }

    DEFAULT_MOVE_SEMANTIC(LexicalScope);

private:
    NO_COPY_SEMANTIC(LexicalScope);

    explicit LexicalScope(T *scope, VarBinder *varbinder)
        : varbinder_(varbinder), scope_(scope), prevScope_(varbinder->scope_), prevVarScope_(varbinder->varScope_)
    {
        varbinder_->scope_ = scope_;
    }

    VarBinder *varbinder_ {};
    T *scope_ {};
    Scope *prevScope_ {};
    VariableScope *prevVarScope_ {};
};

template <size_t N>
void VarBinder::AddMandatoryParams(const MandatoryParams<N> &params)
{
    ASSERT(scope_->IsFunctionVariableScope());

    auto scopeCtx = LexicalScope<FunctionParamScope>::Enter(this, scope_->AsFunctionVariableScope()->ParamScope());

    for (auto iter = params.rbegin(); iter != params.rend(); iter++) {
        AddMandatoryParam(*iter);
    }
}

template <typename T, typename... Args>
T *VarBinder::AddTsDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);

    if (scope_->AddTsDecl(Allocator(), decl, Extension()) != nullptr) {
        return decl;
    }

    ThrowRedeclaration(pos, decl->Name());
}

template <typename T, typename... Args>
T *VarBinder::AddDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);

    if (scope_->AddDecl(Allocator(), decl, Extension()) != nullptr) {
        return decl;
    }

    ThrowRedeclaration(pos, decl->Name());
}

template <typename T, typename... Args>
std::tuple<T *, varbinder::Variable *> VarBinder::NewVarDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);
    varbinder::Variable *var = scope_->AddDecl(Allocator(), decl, Extension());

    if (var != nullptr) {
        return {decl, var};
    }

    ThrowRedeclaration(pos, decl->Name());
}
}  // namespace ark::es2panda::varbinder

#endif
