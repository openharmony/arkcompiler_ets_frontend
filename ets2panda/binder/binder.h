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

#ifndef ES2PANDA_BINDER_BINDER_H
#define ES2PANDA_BINDER_BINDER_H

#include "binder/scope.h"
#include "binder/variableFlags.h"
#include "lexer/token/sourceLocation.h"
#include "macros.h"

namespace panda::es2panda::parser {
class Program;
enum class ScriptKind;
}  // namespace panda::es2panda::parser

namespace panda::es2panda::ir {
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
}  // namespace panda::es2panda::ir

namespace panda::es2panda::binder {
class ETSBinder;

class Binder {
public:
    explicit Binder(ArenaAllocator *allocator) : allocator_(allocator), function_scopes_(allocator_->Adapter()) {}

    NO_COPY_SEMANTIC(Binder);
    NO_MOVE_SEMANTIC(Binder);
    ~Binder() = default;

    void InitTopScope();
    virtual void IdentifierAnalysis();

    template <typename T, typename... Args>
    T *AddDecl(const lexer::SourcePosition &pos, Args &&...args);

    template <typename T, typename... Args>
    T *AddTsDecl(const lexer::SourcePosition &pos, Args &&...args);

    template <typename T, typename... Args>
    std::tuple<T *, binder::Variable *> NewVarDecl(const lexer::SourcePosition &pos, Args &&...args);

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

    void SetCompilerContext(compiler::CompilerContext *compiler_context)
    {
        ASSERT(!compiler_ctx_);
        compiler_ctx_ = compiler_context;
    }

    compiler::CompilerContext *GetCompilerContext() const
    {
        ASSERT(compiler_ctx_);
        return compiler_ctx_;
    }

    void SetGenStdLib(bool gen_std_lib)
    {
        gen_std_lib_ = gen_std_lib;
    }

    bool IsGenStdLib()
    {
        return gen_std_lib_;
    }

    Scope *GetScope() const
    {
        return scope_;
    }

    void ResetTopScope(GlobalScope *top_scope)
    {
        ASSERT(top_scope_ == scope_);
        top_scope_ = top_scope;
        var_scope_ = top_scope_;
        scope_ = top_scope_;
    }

    GlobalScope *TopScope() const
    {
        return top_scope_;
    }

    VariableScope *VarScope() const
    {
        return var_scope_;
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
        return function_scopes_;
    }

    ArenaVector<FunctionScope *> &Functions()
    {
        return function_scopes_;
    }

    virtual ScriptExtension Extension() const
    {
        return ScriptExtension::JS;
    }

    virtual ResolveBindingOptions BindingOptions() const
    {
        return ResolveBindingOptions::BINDINGS;
    }

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

    void LookUpMandatoryReferences(const FunctionScope *func_scope, bool need_lexical_func_obj);
    LocalVariable *AddMandatoryParam(const std::string_view &name);
    template <size_t N>
    void AddMandatoryParams(const MandatoryParams<N> &params);
    void AddMandatoryParams();
    void LookupReference(const util::StringView &name);
    void InstantiateArguments();
    void InstantiatePrivateContext(const ir::Identifier *ident) const;
    void BuildVarDeclarator(ir::VariableDeclarator *var_decl);
    void BuildVarDeclaratorId(ir::AstNode *child_node);
    void BuildForUpdateLoop(ir::ForUpdateStatement *for_update_stmt);
    void BuildForInOfLoop(binder::LoopScope *loop_scope, ir::AstNode *left, ir::Expression *right, ir::Statement *body);
    void BuildCatchClause(ir::CatchClause *catch_clause_stmt);
    void ResolveReference(ir::AstNode *child_node);
    void ResolveReferences(const ir::AstNode *parent);
    void VisitScriptFunctionWithPotentialTypeParams(ir::ScriptFunction *func);
    void VisitScriptFunction(ir::ScriptFunction *func);
    util::StringView BuildFunctionName(util::StringView name, uint32_t idx);

    void AddCompilableFunctionScope(binder::FunctionScope *func_scope);

    void InitializeClassBinding(ir::ClassDefinition *class_def);
    void InitializeClassIdent(ir::ClassDefinition *class_def);

    virtual void LookupIdentReference(ir::Identifier *ident);
    virtual void HandleCustomNodes(ir::AstNode *child_node)
    {
        ResolveReferences(child_node);
    }
    virtual void BuildSignatureDeclarationBaseParams([[maybe_unused]] ir::AstNode *type_node) {};
    virtual void BuildClassDefinition(ir::ClassDefinition *class_def);
    virtual void BuildClassProperty(const ir::ClassProperty *prop);
    virtual bool BuildInternalName(ir::ScriptFunction *script_func);
    virtual void AddCompilableFunction(ir::ScriptFunction *func);

private:
    parser::Program *program_ {};
    ArenaAllocator *allocator_ {};
    compiler::CompilerContext *compiler_ctx_ {};
    GlobalScope *top_scope_ {};
    Scope *scope_ {};
    VariableScope *var_scope_ {};
    ArenaVector<FunctionScope *> function_scopes_;
    ResolveBindingOptions binding_options_ {};
    bool gen_std_lib_ {false};
};

template <typename T>
class LexicalScope {
public:
    template <typename... Args>
    explicit LexicalScope(Binder *binder, Args &&...args)
        : LexicalScope(binder->Allocator()->New<T>(binder->Allocator(), binder->scope_, std::forward<Args>(args)...),
                       binder)
    {
    }

    T *GetScope() const
    {
        return scope_;
    }

    ~LexicalScope()
    {
        ASSERT(binder_);
        binder_->scope_ = prev_scope_;
        binder_->var_scope_ = prev_var_scope_;
    }

    [[nodiscard]] static LexicalScope<T> Enter(Binder *binder, T *scope, bool check_eval = true)
    {
        LexicalScope<T> lex_scope(scope, binder);
        if (!check_eval || binder->Extension() == ScriptExtension::TS) {
            return lex_scope;
        }

        // NOLINTNEXTLINE(readability-braces-around-statements)
        if constexpr (std::is_same_v<T, FunctionParamScope>) {
            binder->var_scope_ = scope->GetFunctionScope();
            binder->var_scope_->CheckDirectEval(binder->compiler_ctx_);
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, FunctionScope>) {
            binder->var_scope_ = scope;
            binder->var_scope_->CheckDirectEval(binder->compiler_ctx_);
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, LoopScope>) {
            if (scope->IsLoopScope()) {
                binder->var_scope_ = scope;
                binder->var_scope_->CheckDirectEval(binder->compiler_ctx_);
            }
            // NOLINTNEXTLINE(readability-braces-around-statements,readability-misleading-indentation)
        } else if constexpr (std::is_same_v<T, LoopDeclarationScope>) {
            if (scope->IsLoopDeclarationScope()) {
                binder->var_scope_ = scope;
                binder->var_scope_->CheckDirectEval(binder->compiler_ctx_);
            }
        }

        return lex_scope;
    }

    DEFAULT_MOVE_SEMANTIC(LexicalScope);

private:
    NO_COPY_SEMANTIC(LexicalScope);

    explicit LexicalScope(T *scope, Binder *binder)
        : binder_(binder), scope_(scope), prev_scope_(binder->scope_), prev_var_scope_(binder->var_scope_)
    {
        binder_->scope_ = scope_;
    }

    Binder *binder_ {};
    T *scope_ {};
    Scope *prev_scope_ {};
    VariableScope *prev_var_scope_ {};
};

template <size_t N>
void Binder::AddMandatoryParams(const MandatoryParams<N> &params)
{
    ASSERT(scope_->IsFunctionVariableScope());

    auto scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, scope_->AsFunctionVariableScope()->ParamScope());

    for (auto iter = params.rbegin(); iter != params.rend(); iter++) {
        AddMandatoryParam(*iter);
    }
}

template <typename T, typename... Args>
T *Binder::AddTsDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);

    if (scope_->AddTsDecl(Allocator(), decl, Extension()) != nullptr) {
        return decl;
    }

    ThrowRedeclaration(pos, decl->Name());
}

template <typename T, typename... Args>
T *Binder::AddDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);

    if (scope_->AddDecl(Allocator(), decl, Extension()) != nullptr) {
        return decl;
    }

    ThrowRedeclaration(pos, decl->Name());
}

template <typename T, typename... Args>
std::tuple<T *, binder::Variable *> Binder::NewVarDecl(const lexer::SourcePosition &pos, Args &&...args)
{
    T *decl = Allocator()->New<T>(std::forward<Args>(args)...);
    binder::Variable *var = scope_->AddDecl(Allocator(), decl, Extension());

    if (var != nullptr) {
        return {decl, var};
    }

    ThrowRedeclaration(pos, decl->Name());
}
}  // namespace panda::es2panda::binder

#endif
