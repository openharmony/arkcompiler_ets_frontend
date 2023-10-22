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

#ifndef ES2PANDA_PARSER_CORE_ETS_PARSER_H
#define ES2PANDA_PARSER_CORE_ETS_PARSER_H

#include "util/arktsconfig.h"
#include "TypedParser.h"
#include "ir/ets/etsParameterExpression.h"

namespace panda::es2panda::ir {
class ETSPackageDeclaration;
enum class ClassDefinitionModifiers : uint32_t;
enum class PrimitiveType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::parser {
class ETSParser final : public TypedParser {
public:
    ETSParser(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS)
        : TypedParser(program, options, status), global_program_(GetProgram()), parsed_sources_({})
    {
    }

    NO_COPY_SEMANTIC(ETSParser);
    NO_MOVE_SEMANTIC(ETSParser);

    ~ETSParser() = default;

private:
    struct ImportData {
        Language lang;
        std::string module;
        bool has_decl;
    };

    void ParseProgram(ScriptKind kind) override;
    [[nodiscard]] std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &source_file) override;
    void ParsePackageDeclaration(ArenaVector<ir::Statement *> &statements);
    ArenaVector<ir::AstNode *> ParseTopLevelStatements(ArenaVector<ir::Statement *> &statements);
#ifdef USE_FTW
    static int NFTWCallBack(const char *fpath, const struct stat * /*unused*/, int tflag, struct FTW * /*unused*/);
#endif
    void ParseTopLevelDeclaration(ArenaVector<ir::Statement *> &statements);
    void CollectDefaultSources();
    std::string ResolveImportPath(const std::string &path);
    ImportData GetImportData(const std::string &path);
    std::tuple<std::vector<std::string>, bool> CollectUserSources(const std::string &path);
    void ParseSources(const std::vector<std::string> &paths, bool is_external = true);
    std::tuple<ir::ImportSource *, std::vector<std::string>> ParseFromClause(bool require_from);
    void ParseNamedImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers);
    void ParseUserSources(std::vector<std::string> user_parths);
    std::vector<std::string> ParseImportDeclarations(ArenaVector<ir::Statement *> &statements);
    void ParseDefaultSources();
    void ParseSource(const SourceFile &source_file);
    void CreateGlobalClass();
    ArenaVector<ir::Statement *> PrepareGlobalClass();
    ArenaVector<ir::Statement *> PrepareExternalGlobalClass(const SourceFile &source_file);
    void ParseETSGlobalScript(lexer::SourcePosition start_loc, ArenaVector<ir::Statement *> &statements);
    void AddGlobalDeclaration(ir::AstNode *node);
    ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers) override;

    ir::MethodDefinition *ParseClassGetterSetterMethod(const ArenaVector<ir::AstNode *> &properties,
                                                       ir::ClassDefinitionModifiers modifiers,
                                                       ir::ModifierFlags member_modifiers);
    ir::Statement *ParseTypeDeclaration(bool allow_static = false);
    ir::ModifierFlags ParseClassModifiers();
    ir::ModifierFlags ParseInterfaceMethodModifiers();
    ir::ClassProperty *ParseInterfaceField(const lexer::SourcePosition &start_loc);
    ir::Expression *ParseInitializer();
    ir::ArrayExpression *ParseArrayLiteral();
    ir::MethodDefinition *ParseInterfaceMethod(ir::ModifierFlags flags);
    std::tuple<ir::ModifierFlags, bool> ParseClassMemberAccessModifiers();
    ir::ModifierFlags ParseClassFieldModifiers(bool seen_static);
    ir::ModifierFlags ParseClassMethodModifiers(bool seen_static);
    ir::MethodDefinition *ParseClassMethodDefinition(ir::Identifier *method_name, ir::ModifierFlags modifiers,
                                                     ir::Identifier *class_name = nullptr);
    ir::ScriptFunction *ParseFunction(ParserStatus new_status, ir::Identifier *class_name = nullptr);
    ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                           ir::Expression *prop_name, lexer::SourcePosition *prop_end) override;
    std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus new_status, ParserStatus context_status,
        binder::FunctionScope *func_scope) override;
    ir::TypeNode *ParseFunctionReturnType(ParserStatus status) override;
    ir::ScriptFunctionFlags ParseFunctionThrowMarker(bool is_rethrows_allowed) override;
    ir::Expression *CreateParameterThis(util::StringView class_name) override;

    // NOLINTNEXTLINE(google-default-arguments)
    void ParseClassFieldDefiniton(ir::Identifier *field_name, ir::ModifierFlags modifiers,
                                  ArenaVector<ir::AstNode *> *declarations,
                                  ir::ScriptFunction *init_function = nullptr);
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseTypeReferencePart(
        TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseBaseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type);
    ir::TSIntersectionType *ParseIntersectionType(ir::Expression *type);
    ir::TypeNode *ParseWildcardType(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseFunctionType();
    void CreateClassFunctionDeclaration(ir::MethodDefinition *method);
    void AddProxyOverloadToMethodWithDefaultParams(ir::MethodDefinition *method);
    std::string GetNameForTypeNode(const ir::TypeNode *type_annotation);
    ir::TSInterfaceDeclaration *ParseInterfaceBody(ir::Identifier *name, bool is_static);
    bool IsArrowFunctionExpressionStart();
    ir::ArrowFunctionExpression *ParseArrowFunctionExpression();

    void ThrowIfVarDeclaration(VariableParsingFlags flags) override;
    ir::TypeNode *ParseTypeAnnotation(TypeAnnotationParsingOptions *options) override;
    ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration() override;

    void ValidateForInStatement() override;

    ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList() override;
    void AddVariableDeclarationBindings(ir::Expression *init, lexer::SourcePosition start_loc,
                                        VariableParsingFlags flags) override;
    ir::Statement *ParseTryStatement() override;
    ir::DebuggerStatement *ParseDebuggerStatement() override;
    ir::Statement *ParseImportDeclaration(StatementParsingFlags flags) override;
    ir::Statement *ParseExportDeclaration(StatementParsingFlags flags) override;
    ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                    VariableParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                               const lexer::SourcePosition &start_loc) override;
    ir::AstNode *ParseTypeLiteralOrInterfaceMember() override;
    void ParseNameSpaceImport(ArenaVector<ir::AstNode *> *specifiers);
    bool CheckModuleAsModifier();
    ir::Expression *ParseFunctionParameter() override;
    ir::AnnotatedExpression *GetAnnotatedExpressionFromParam();
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseUnaryOrPrefixUpdateExpression(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Expression *ParsePostPrimaryExpression(ir::Expression *primary_expr, lexer::SourcePosition start_loc,
                                               bool ignore_call_expression, bool *is_chain_expression) override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *primary_expr) override;
    ir::Statement *ParseAssertStatement() override;
    void ValidateLabeledStatement(lexer::TokenType type) override;
    ir::Expression *ParseCatchParam() override;
    void ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param) override;
    ir::Expression *ParseSuperClassReference() override;
    ir::Identifier *ParseClassIdent(ir::ClassDefinitionModifiers modifiers) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDeclaration *ParseClassStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags mod_flags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ETSStructDeclaration *ParseStructStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                                   ir::ModifierFlags mod_flags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                   ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;
    ir::Expression *ParseNewExpression() override;
    ir::Expression *ParseAsyncExpression();
    ir::Expression *ParseAwaitExpression();
    ir::TSTypeParameter *ParseTypeParameter(TypeAnnotationParsingOptions *options) override;

    ir::TSEnumDeclaration *ParseEnumMembers(ir::Identifier *key, const lexer::SourcePosition &enum_start, bool is_const,
                                            bool is_static) override;
    void ParseNumberEnum(ArenaVector<ir::AstNode *> &members);
    void ParseStringEnum(ArenaVector<ir::AstNode *> &members);

    ir::Statement *ParseInterfaceDeclaration(bool is_static) override;
    ir::ThisExpression *ParseThisExpression() override;
    ir::Statement *ParseFunctionStatement(StatementParsingFlags flags) override;
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseClassImplementsElement() override;
    ir::TypeNode *ParseInterfaceExtendsElement() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseEnumDeclaration(bool is_const = false, bool is_static = false) override;
    ir::Expression *ParseLaunchExpression(ExpressionParseFlags flags);
    void ValidateRestParameter(ir::Expression *param) override;

    bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                           ArenaVector<ir::AstNode *> &properties) override;
    // NOLINTNEXTLINE(google-default-arguments)
    void CreateCCtor(binder::LocalScope *class_scope, ArenaVector<ir::AstNode *> &properties,
                     const lexer::SourcePosition &loc, bool in_global_class = false) override;
    void CreateImplicitConstructor(ir::MethodDefinition *&ctor, ArenaVector<ir::AstNode *> &properties,
                                   ir::ClassDefinitionModifiers modifiers,
                                   const lexer::SourcePosition &start_loc) override;
    bool ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                           const lexer::SourcePosition &start_loc,
                                           bool ignore_call_expression) override;
    bool ParsePotentialNonNullExpression(ir::Expression **expression, lexer::SourcePosition start_loc) override;
    binder::Decl *BindClassName([[maybe_unused]] ir::Identifier *ident_node) override
    {
        return nullptr;
    }

    std::shared_ptr<ArkTsConfig> ArkTSConfig() const
    {
        return GetOptions().arkts_config;
    }

    bool IsETSModule() const
    {
        return GetOptions().is_ets_module;
    }

    bool IsStructKeyword() const;

    util::StringView FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id) override;

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;

    ir::Expression *ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags) override;

    ir::ModifierFlags ParseTypeVarianceModifier(TypeAnnotationParsingOptions *options);

    ir::ScriptFunction *AddInitMethod(ArenaVector<ir::AstNode *> &global_properties);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseTopLevelStatement(StatementParsingFlags flags = StatementParsingFlags::NONE);

    void ParseTrailingBlock([[maybe_unused]] ir::CallExpression *call_expr) override;

    void CheckDeclare();

    //  Methods to create AST node(s) from the specified string (part of valid ETS-code!)
    //  NOTE: the correct initial scope should be entered BEFORE calling any of these methods,
    //  and correct parent and, probably, variable set to the node(s) after obtaining
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    inline static constexpr char const DEFAULT_SOURCE_FILE[] = "<auxiliary_tmp>.ets";
    // NOLINTBEGIN(google-default-arguments)
    ir::Statement *CreateStatement(std::string_view source_code, std::string_view file_name = DEFAULT_SOURCE_FILE);
    ArenaVector<ir::Statement *> CreateStatements(std::string_view source_code,
                                                  std::string_view file_name = DEFAULT_SOURCE_FILE);
    ir::MethodDefinition *CreateMethodDefinition(ir::ModifierFlags modifiers, std::string_view source_code,
                                                 std::string_view file_name = DEFAULT_SOURCE_FILE);
    ir::Expression *CreateExpression(ExpressionParseFlags flags, std::string_view source_code,
                                     std::string_view file_name = DEFAULT_SOURCE_FILE);
    ir::TypeNode *CreateTypeAnnotation(TypeAnnotationParsingOptions *options, std::string_view source_code,
                                       std::string_view file_name = DEFAULT_SOURCE_FILE);
    // NOLINTEND(google-default-arguments)

    friend class ExternalSourceParser;
    friend class InnerSourceParser;

private:
    parser::Program *global_program_;
    std::vector<std::string> parsed_sources_;
};

class ExternalSourceParser {
public:
    explicit ExternalSourceParser(ETSParser *parser, Program *new_program);
    NO_COPY_SEMANTIC(ExternalSourceParser);
    NO_MOVE_SEMANTIC(ExternalSourceParser);

    ~ExternalSourceParser();

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

private:
    ETSParser *parser_;
    Program *saved_program_;
    lexer::Lexer *saved_lexer_;
    binder::GlobalScope *saved_top_scope_;
};

class InnerSourceParser {
public:
    explicit InnerSourceParser(ETSParser *parser);
    NO_COPY_SEMANTIC(InnerSourceParser);
    NO_MOVE_SEMANTIC(InnerSourceParser);

    ~InnerSourceParser();

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

private:
    ETSParser *parser_;
    lexer::Lexer *saved_lexer_;
    util::StringView saved_source_code_ {};
    util::StringView saved_source_file_ {};
    util::StringView saved_source_file_path_ {};
};

}  // namespace panda::es2panda::parser
#endif
