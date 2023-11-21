/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_SCOPES_INIT_PHASE_H
#define ES2PANDA_COMPILER_CORE_SCOPES_INIT_PHASE_H

#include "util/helpers.h"
#include "parser/parserFlags.h"
#include "varbinder/tsBinding.h"
#include "varbinder/ETSBinder.h"
#include "compiler/lowering/phase.h"
#include "compiler/lowering/scopesInit/savedBindingsCtx.h"
#include "checker/checker.h"
#include "compiler/core/compilerContext.h"
#include "ir/visitor/IterateAstVisitor.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/blockExpression.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsTuple.h"

namespace panda::es2panda::compiler {

/**
 * Responsible for initialization of scopes. Should be called right after Parser stage.
 */
// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class ScopesInitPhase : public Phase, public ir::visitor::IterateAstVisitor {
public:
    using PhaseContext = public_lib::Context;

    std::string_view Name() override
    {
        return "scopes";
    }

    bool Perform(PhaseContext *ctx, parser::Program *program) override;

protected:
    void SetProgram(parser::Program *program) noexcept;

    void Prepare(PhaseContext *ctx, parser::Program *program);

    /**
     * Should be called at the end of each program perform
     */
    void Finalize();

    /**
     * Check if there's only one default export and no named export redeclaration,
     * throw error if so.
     * Side effect: fill local_exports_
     */
    void AnalyzeExports();

protected:
    template <typename T>
    void CallNode(T *node)
    {
        if (node) {
            node->Accept(this);
        }
    }

    template <typename T>
    void CallNode(const ArenaVector<T *> &nodes)
    {
        for (auto *node : nodes) {
            CallNode(node);
        }
    }

    void CallFuncParams(const ArenaVector<ir::Expression *> &params);
    void IterateNoTParams(ir::ClassDefinition *class_def);

protected:
    void ThrowSyntaxError(std::string_view error_message, const lexer::SourcePosition &pos) const;

    void VisitFunctionExpression(ir::FunctionExpression *func_expr) override;
    void VisitScriptFunction(ir::ScriptFunction *script_function) override;
    void VisitBlockStatement(ir::BlockStatement *block_stmt) override;
    void VisitImportDeclaration(ir::ImportDeclaration *import_declaration) override;
    void VisitClassStaticBlock(ir::ClassStaticBlock *static_block) override;
    void VisitClassDefinition(ir::ClassDefinition *class_def) override;
    void VisitMethodDefinition(ir::MethodDefinition *method_definition) override;
    void VisitForUpdateStatement(ir::ForUpdateStatement *for_update_stmt) override;
    void VisitForInStatement(ir::ForInStatement *for_in_stmt) override;
    void VisitForOfStatement(ir::ForOfStatement *for_of_stmt) override;
    void VisitCatchClause(ir::CatchClause *catch_clause) override;
    void VisitVariableDeclarator(ir::VariableDeclarator *var_decl) override;
    void VisitSwitchStatement(ir::SwitchStatement *switch_stmt) override;
    void VisitWhileStatement(ir::WhileStatement *while_stmt) override;
    void VisitETSStructDeclaration(ir::ETSStructDeclaration *struct_decl) override;
    void VisitClassDeclaration(ir::ClassDeclaration *class_decl) override;
    void VisitDoWhileStatement(ir::DoWhileStatement *do_while_stmt) override;
    void VisitFunctionDeclaration(ir::FunctionDeclaration *func_decl) override;
    void VisitExportAllDeclaration(ir::ExportAllDeclaration *export_all_decl) override;
    void VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *import_spec) override;
    void VisitImportSpecifier(ir::ImportSpecifier *import_spec) override;
    void VisitImportDefaultSpecifier(ir::ImportDefaultSpecifier *import_spec) override;
    void VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *export_decl) override;
    void VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl) override;
    void VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_expr) override;
    void VisitDirectEvalExpression(ir::DirectEvalExpression *direct_call_expr) override;
    void VisitTSFunctionType(ir::TSFunctionType *func_type) override;

protected:
    varbinder::Scope *GetScope()
    {
        return VarBinder()->GetScope();
    }

    ArenaAllocator *Allocator()
    {
        return program_->Allocator();
    }

    parser::Program *Program()
    {
        return program_;
    }

    PhaseContext *Context()
    {
        return ctx_;
    }

    [[nodiscard]] varbinder::VarBinder *VarBinder() const
    {
        return program_->VarBinder();
    }

protected:
    virtual void CreateFuncDecl(ir::ScriptFunction *func);
    virtual util::StringView FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id);
    void HandleFunction(ir::ScriptFunction *function);
    varbinder::FunctionParamScope *HandleFunctionSig(ir::TSTypeParameterDeclaration *type_params,
                                                     const ir::FunctionSignature::FunctionParams &params,
                                                     ir::TypeNode *return_type);

    /**
     * Handle block from existing scope
     */
    void HandleBlockStmt(ir::BlockStatement *block, varbinder::Scope *scope);

    template <typename ForT>
    void HandleFor(varbinder::LoopDeclarationScope *decl_scope, varbinder::LoopScope *loop_scope, ForT *for_stmt)
    {
        loop_scope->BindDecls(decl_scope);
        BindScopeNode(loop_scope, for_stmt);
        loop_scope->DeclScope()->BindNode(for_stmt);
    }

protected:
    virtual varbinder::Decl *BindClassName(ir::ClassDefinition *class_def);

    template <class Scope, class Node>
    static void BindScopeNode(Scope *scope, Node *node)
    {
        scope->BindNode(node);
        node->SetScope(scope);
    }

    static void BindFunctionScopes(varbinder::FunctionScope *scope, varbinder::FunctionParamScope *param_scope);

    void BindClassDefinition(ir::ClassDefinition *class_def);

    std::tuple<varbinder::Decl *, varbinder::Variable *> AddVarDecl(ir::VariableDeclaratorFlag flag,
                                                                    lexer::SourcePosition start_loc,
                                                                    const util::StringView &name);

    virtual void BindVarDecl([[maybe_unused]] ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                             [[maybe_unused]] varbinder::Variable *var);

private:
    PhaseContext *ctx_ {};
    parser::Program *program_ {};
};

/**
 * Specialization for typed script languages (typescript, ets)
 */
class ScopeInitTyped : public ScopesInitPhase {
protected:
public:
    void VisitTSModuleDeclaration(ir::TSModuleDeclaration *module_decl) override;

    void VisitTSModuleBlock(ir::TSModuleBlock *block) override;

    void VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *type_alias_decl) override;

    util::StringView FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id) override;

    virtual bool AllowInterfaceRedeclaration()
    {
        return false;
    }

    void VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interf_decl) override;

    void VisitTSEnumMember(ir::TSEnumMember *enum_member) override;

    void VisitTSEnumDeclaration(ir::TSEnumDeclaration *enum_decl) override;

    void VisitTSTypeParameter(ir::TSTypeParameter *type_param) override;

    void VisitTSTypeParameterDeclaration(ir::TSTypeParameterDeclaration *param_decl) override;

    void VisitClassDefinition(ir::ClassDefinition *class_def) override;
};

class ScopesInitPhaseJs : public ScopesInitPhase {
public:
    ScopesInitPhaseJs() = default;
    NO_COPY_SEMANTIC(ScopesInitPhaseJs);
    NO_MOVE_SEMANTIC(ScopesInitPhaseJs);

    ~ScopesInitPhaseJs() override = default;
};

class ScopesInitPhaseTs : public ScopeInitTyped {
protected:
    bool AllowInterfaceRedeclaration() override
    {
        return true;
    }

    void VisitTSMappedType([[maybe_unused]] ir::TSMappedType *mapped) override {}
    void VisitTSInferType([[maybe_unused]] ir::TSInferType *infer) override {}
    void VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *export_decl) override;
    void VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl) override;
    void VisitImportDeclaration(ir::ImportDeclaration *import_declaration) override;
    void VisitTSFunctionType(ir::TSFunctionType *constr_type) override;
    void VisitTSConstructorType(ir::TSConstructorType *constr_t) override;
    void VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_f_expr) override;
    void VisitTSSignatureDeclaration(ir::TSSignatureDeclaration *sign_decl) override;
    void VisitTSMethodSignature(ir::TSMethodSignature *method_sign) override;

    void CreateFuncDecl(ir::ScriptFunction *func) override;
};

class ScopesInitPhaseETS : public ScopeInitTyped {
public:
    ScopesInitPhaseETS() = default;
    NO_COPY_SEMANTIC(ScopesInitPhaseETS);
    NO_MOVE_SEMANTIC(ScopesInitPhaseETS);

    /**
     * Set scopes for ast-subtree
     * @param node ast-subtree, for this node and all children scopes will be initialized.
     * @param varbinder ref to VarBinder. All varbinder scopes should be set to current context.
     * Note: It's programmer responsibility to prepare VarBinder (remove previous names, set current scope, etc...)
     *
     * Example:
     * f<T>(x: Int) :  {
     *     let y = 0;
     * }
     * After ScopesInitPhase scope structure will look something like this:
     * global_scope:
     *     [f],
     *     local_scope:
     *        [T],
     *        function_param_scope:
     *            [x],
     *            function_scope:
     *                [y]
     * Suppose you want to rewrite function body in some lowering later to
     * {
     *     let z = 123;
     * }
     *
     * Then you should pass your new created node = ir::BlockStatement() to RunExternalNode,
     * set varbinder to previous `function_scope` and call RunExternalNode(node, varbinder).
     * It will update scopes to:
     * global_scope:
     *     [f],
     *     local_scope:
     *        [T],
     *        function_param_scope:
     *            [x],
     *            function_scope:
     *                [z]
     */
    static void RunExternalNode(ir::AstNode *node, varbinder::VarBinder *varbinder);
    /**
     * Same as previous, just uses varbinder from ctx->VarBinder()
     */
    static void RunExternalNode(ir::AstNode *node, parser::Program *ctx);

    /**
     * Run scope initialization on program.
     * It's not same as RunExternalNode(program->Ast()), because there's some specific handling for top scope.
     * @param ctx
     * @param program - program you want to set scopes on.
     * @return true if successful.
     */
    bool Perform(PhaseContext *ctx, parser::Program *program) override;

    ~ScopesInitPhaseETS() override = default;

private:
    void HandleProgram(parser::Program *program);

    void HandleETSScript(ir::BlockStatement *script);

    void ParseGlobalClass(ir::ClassDefinition *global);

    void AddGlobalDeclaration(ir::AstNode *node);

    varbinder::Decl *BindClassName([[maybe_unused]] ir::ClassDefinition *ident_node) override
    {
        return nullptr;
    }

    void BindVarDecl(ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                     varbinder::Variable *var) override;
    void DeclareClassMethod(ir::MethodDefinition *method);

    void VisitClassStaticBlock(ir::ClassStaticBlock *static_block) override;
    void VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *import_spec) override;
    void VisitImportSpecifier([[maybe_unused]] ir::ImportSpecifier *import_spec) override {};
    void VisitImportDefaultSpecifier([[maybe_unused]] ir::ImportDefaultSpecifier *import_spec) override {};
    void VisitETSParameterExpression(ir::ETSParameterExpression *param_expr) override;
    void VisitETSImportDeclaration(ir::ETSImportDeclaration *import_decl) override;
    void VisitTSEnumMember(ir::TSEnumMember *enum_member) override;
    void VisitMethodDefinition(ir::MethodDefinition *method) override;
    void VisitETSFunctionType(ir::ETSFunctionType *func_type) override;
    void VisitETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *new_class_expr) override;
    void VisitTSTypeParameter(ir::TSTypeParameter *type_param) override;
    void VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interface_decl) override;
    void VisitTSEnumDeclaration(ir::TSEnumDeclaration *enum_decl) override;
    void VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *type_alias) override;
    void VisitClassDefinition(ir::ClassDefinition *class_def) override;
    void VisitTSInterfaceBody(ir::TSInterfaceBody *interf_body) override;
    void VisitClassProperty(ir::ClassProperty *class_prop) override;
    void VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_expr) override
    {
        Iterate(arrow_expr);
    }

    util::StringView FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id) override
    {
        return id->Name();
    }

    static void AddGlobalToBinder(parser::Program *program);

    void FilterInterfaceOverloads(ArenaVector<ir::AstNode *> &props);

    void FilterOverloads(ArenaVector<ir::AstNode *> &props);
};

class ScopesInitPhaseAS : public ScopesInitPhase {
public:
    NO_COPY_SEMANTIC(ScopesInitPhaseAS);
    NO_MOVE_SEMANTIC(ScopesInitPhaseAS);
    ScopesInitPhaseAS() = default;
    ~ScopesInitPhaseAS() override = default;

private:
    void VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_expr) override;
    void VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl) override;
};
}  // namespace panda::es2panda::compiler

#endif
