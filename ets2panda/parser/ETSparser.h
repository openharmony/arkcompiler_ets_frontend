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

#ifndef ES2PANDA_PARSER_CORE_ETS_PARSER_H
#define ES2PANDA_PARSER_CORE_ETS_PARSER_H

#include <optional>
#include "parserFlags.h"
#include "util/arktsconfig.h"
#include "TypedParser.h"

namespace panda::es2panda::ir {
class ETSPackageDeclaration;
enum class ClassDefinitionModifiers : uint32_t;
enum class PrimitiveType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::parser {

// NOLINTBEGIN(modernize-avoid-c-arrays)
inline constexpr char const FORMAT_SIGNATURE = '@';
inline constexpr char const TYPE_FORMAT_NODE = 'T';
inline constexpr char const STATEMENT_FORMAT_NODE = 'S';
inline constexpr char const EXPRESSION_FORMAT_NODE = 'E';
inline constexpr char const IDENTIFIER_FORMAT_NODE = 'I';
inline constexpr char const DEFAULT_SOURCE_FILE[] = "<auxiliary_tmp>.ets";
// NOLINTEND(modernize-avoid-c-arrays)

class ETSParser final : public TypedParser {
public:
    ETSParser(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS)
        : TypedParser(program, options, status), globalProgram_(GetProgram())
    {
    }

    ETSParser() = delete;
    NO_COPY_SEMANTIC(ETSParser);
    NO_MOVE_SEMANTIC(ETSParser);

    ~ETSParser() final = default;

    [[nodiscard]] bool IsETSParser() const noexcept override
    {
        return true;
    }

    //  Methods to create AST node(s) from the specified string (part of valid ETS-code!)
    //  NOTE: the correct initial scope should be entered BEFORE calling any of these methods,
    //  and correct parent and, probably, variable set to the node(s) after obtaining

    ir::Expression *CreateExpression(std::string_view sourceCode,
                                     ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS,
                                     std::string_view fileName = DEFAULT_SOURCE_FILE);

    ir::Expression *CreateFormattedExpression(std::string_view sourceCode, std::vector<ir::AstNode *> &insertingNodes,
                                              std::string_view fileName = DEFAULT_SOURCE_FILE);

    template <typename... Args>
    ir::Expression *CreateFormattedExpression(std::string_view const sourceCode, std::string_view const fileName,
                                              Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (insertingNodes.emplace_back(std::forward<Args>(args)), ...);
        return CreateFormattedExpression(sourceCode, insertingNodes, fileName);
    }

    ArenaVector<ir::Statement *> CreateStatements(std::string_view sourceCode,
                                                  std::string_view fileName = DEFAULT_SOURCE_FILE);

    ArenaVector<ir::Statement *> CreateFormattedStatements(std::string_view sourceCode,
                                                           std::vector<ir::AstNode *> &insertingNodes,
                                                           std::string_view fileName = DEFAULT_SOURCE_FILE);

    template <typename... Args>
    ArenaVector<ir::Statement *> CreateFormattedStatements(std::string_view const sourceCode,
                                                           std::string_view const fileName, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        (insertingNodes.emplace(std::forward<Args>(args)), ...);
        return CreateFormattedStatements(sourceCode, insertingNodes, fileName);
    }

private:
    struct ImportData {
        Language lang;
        std::string module;
        bool hasDecl;
    };

    std::map<util::StringView, ir::AstNode *> fieldMap_;
    std::map<util::StringView, lexer::SourcePosition> exportNameMap_;
    void ParseProgram(ScriptKind kind) override;
    [[nodiscard]] std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &sourceFile) override;
    void ParsePackageDeclaration(ArenaVector<ir::Statement *> &statements);
    ArenaVector<ir::AstNode *> ParseTopLevelStatements(ArenaVector<ir::Statement *> &statements);
    void ParseTopLevelType(ArenaVector<ir::Statement *> &statements, bool &defaultExport, std::size_t currentPos,
                           std::function<ir::Statement *(ETSParser *)> const &parserFunction);
    void ParseTopLevelNextToken(ArenaVector<ir::Statement *> &statements, ArenaVector<ir::AstNode *> &globalProperties,
                                ir::ScriptFunction *initFunction);
    void ParseTopLevelNextTokenDefault(ArenaVector<ir::Statement *> &statements, ir::ScriptFunction *initFunction,
                                       size_t currentPos, lexer::TokenType tokenType, bool defaultExport);
    ir::ModifierFlags ResolveMemberModifiers();
    lexer::SourcePosition ParseTopLevelNextTokenResolution(ArenaVector<ir::Statement *> &statements,
                                                           ArenaVector<ir::AstNode *> &globalProperties,
                                                           ir::ScriptFunction *initFunction, size_t currentPos,
                                                           bool defaultExport);
    void ParseTokenOfNative(panda::es2panda::lexer::TokenType tokenType, ir::ModifierFlags &memberModifiers);
    void ParseTokenOfFunction(ir::ModifierFlags memberModifiers, lexer::SourcePosition startLoc,
                              ArenaVector<ir::AstNode *> &globalProperties);
#ifdef USE_FTW
    static int NFTWCallBack(const char *fpath, const struct stat * /*unused*/, int tflag, struct FTW * /*unused*/);
#endif
    void ParseTopLevelDeclaration(ArenaVector<ir::Statement *> &statements);
    void CollectDefaultSources();
    void CollectUserSourcesFromIndex(const std::string &path, const std::string &resolvedPath,
                                     std::vector<std::string> &userPaths);
    std::string ResolveImportPath(const std::string &path);
    std::string ResolveFullPathFromRelative(const std::string &path);
    ImportData GetImportData(const std::string &path);
    std::tuple<std::vector<std::string>, bool> CollectUserSources(const std::string &path);
    std::tuple<std::string, bool> GetSourceRegularPath(const std::string &path, const std::string &resolvedPath);
    void ParseSources(const std::vector<std::string> &paths, bool isExternal = true);
    std::tuple<ir::ImportSource *, std::vector<std::string>> ParseFromClause(bool requireFrom);
    void ParseNamedSpecifiers(ArenaVector<ir::AstNode *> *specifiers, bool isExport = false);
    void ParseNamedExportSpecifiers(ArenaVector<ir::AstNode *> *specifiers, bool defaultExport);
    void ParseUserSources(std::vector<std::string> userParths);
    std::vector<std::string> ParseImportDeclarations(ArenaVector<ir::Statement *> &statements);
    void ParseDefaultSources();
    void ParseSource(const SourceFile &sourceFile);
    void CreateGlobalClass();
    ArenaVector<ir::Statement *> PrepareGlobalClass();
    ArenaVector<ir::Statement *> PrepareExternalGlobalClass(const SourceFile &sourceFile);
    void ParseETSGlobalScript(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements);
    ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers) override;

    ir::MethodDefinition *ParseClassGetterSetterMethod(const ArenaVector<ir::AstNode *> &properties,
                                                       ir::ClassDefinitionModifiers modifiers,
                                                       ir::ModifierFlags memberModifiers);
    ir::MethodDefinition *ParseInterfaceGetterSetterMethod(ir::ModifierFlags modifiers);
    ir::Statement *ParseTypeDeclaration(bool allowStatic = false);
    ir::Statement *ParseTypeDeclarationAbstractFinal(bool allowStatic, ir::ClassDefinitionModifiers modifiers);
    ir::ModifierFlags ParseClassModifiers();
    ir::ModifierFlags ParseInterfaceMethodModifiers();
    ir::ClassProperty *ParseInterfaceField();
    ir::Expression *ParseInitializer();
    ir::ArrayExpression *ParseArrayLiteral();
    ir::Expression *ParseCoercedNumberLiteral();
    ir::MethodDefinition *ParseInterfaceMethod(ir::ModifierFlags flags, ir::MethodDefinitionKind methodKind);
    std::tuple<ir::ModifierFlags, bool> ParseClassMemberAccessModifiers();
    ir::ModifierFlags ParseClassFieldModifiers(bool seenStatic);
    ir::ModifierFlags ParseClassMethodModifiers(bool seenStatic);
    ir::MethodDefinition *ParseClassMethodDefinition(ir::Identifier *methodName, ir::ModifierFlags modifiers,
                                                     ir::Identifier *className = nullptr,
                                                     ir::Identifier *identNode = nullptr);
    ir::ScriptFunction *ParseFunction(ParserStatus newStatus, ir::Identifier *className = nullptr);
    ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                           ir::Expression *propName, lexer::SourcePosition *propEnd) override;
    std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus newStatus, ParserStatus contextStatus) override;
    ir::TypeNode *ParseFunctionReturnType(ParserStatus status) override;
    ir::ScriptFunctionFlags ParseFunctionThrowMarker(bool isRethrowsAllowed) override;
    ir::Expression *CreateParameterThis(util::StringView className) override;

    // NOLINTNEXTLINE(google-default-arguments)
    void ParseClassFieldDefinition(ir::Identifier *fieldName, ir::ModifierFlags modifiers,
                                   ArenaVector<ir::AstNode *> *declarations, ir::ScriptFunction *initFunction = nullptr,
                                   lexer::SourcePosition *letLoc = nullptr);
    lexer::SourcePosition InitializeGlobalVariable(ir::Identifier *fieldName, ir::Expression *&initializer,
                                                   ir::ScriptFunction *initFunction, lexer::SourcePosition &startLoc,
                                                   ir::TypeNode *typeAnnotation);
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseTypeReferencePart(
        TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseBaseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type);
    ir::TypeNode *ParseUnionType(ir::TypeNode *firstType);
    ir::TSIntersectionType *ParseIntersectionType(ir::Expression *type);
    ir::TypeNode *GetTypeAnnotationOfPrimitiveType(lexer::TokenType tokenType, TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseWildcardType(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseFunctionType();
    ir::TypeNode *ParseETSTupleType(TypeAnnotationParsingOptions *options);
    std::pair<bool, std::size_t> CheckDefaultParameters(const ir::ScriptFunction *function) const;
    ir::MethodDefinition *CreateProxyMethodDefinition(ir::MethodDefinition const *method,
                                                      ir::Identifier const *identNode);
    ir::MethodDefinition *CreateProxyConstructorDefinition(ir::MethodDefinition const *method);
    void AddProxyOverloadToMethodWithDefaultParams(ir::MethodDefinition *method, ir::Identifier *identNode = nullptr);
    static std::string PrimitiveTypeToName(ir::PrimitiveType type);
    std::string GetNameForTypeNode(const ir::TypeNode *typeAnnotation, bool adjust = true) const;
    std::string GetNameForETSUnionType(const ir::TypeNode *typeAnnotation) const;
    ir::TSInterfaceDeclaration *ParseInterfaceBody(ir::Identifier *name, bool isStatic);
    bool IsArrowFunctionExpressionStart();
    ir::ArrowFunctionExpression *ParseArrowFunctionExpression();

    void ThrowIfVarDeclaration(VariableParsingFlags flags) override;
    std::pair<ir::TypeNode *, bool> GetTypeAnnotationFromToken(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseLiteralIdent(TypeAnnotationParsingOptions *options);
    void ParseRightParenthesis(TypeAnnotationParsingOptions *options, ir::TypeNode *&typeAnnotation,
                               lexer::LexerPosition savedPos);
    ir::TypeNode *ParseTypeAnnotation(TypeAnnotationParsingOptions *options) override;
    ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration() override;

    void ValidateForInStatement() override;

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Statement *ParseTryStatement() override;
    ir::DebuggerStatement *ParseDebuggerStatement() override;
    void ParseExport(lexer::SourcePosition startLoc);
    ir::Statement *ParseImportDeclaration(StatementParsingFlags flags) override;
    ir::Statement *ParseExportDeclaration(StatementParsingFlags flags) override;
    ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition startLoc,
                                                    VariableParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                               const lexer::SourcePosition &startLoc) override;
    ir::AstNode *ParseTypeLiteralOrInterfaceMember() override;
    void ParseNameSpaceSpecifier(ArenaVector<ir::AstNode *> *specifiers, bool isReExport = false);
    bool CheckModuleAsModifier();
    ir::Expression *ParseFunctionParameter() override;
    ir::AnnotatedExpression *GetAnnotatedExpressionFromParam();
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseUnaryOrPrefixUpdateExpression(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseDefaultPrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Expression *ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                               bool ignoreCallExpression, bool *isChainExpression) override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *primaryExpr) override;
    ir::Statement *ParseAssertStatement() override;
    void ValidateLabeledStatement(lexer::TokenType type) override;
    ir::Expression *ParseCatchParam() override;
    void ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param) override;
    ir::Expression *ParseSuperClassReference() override;
    ir::Identifier *ParseClassIdent(ir::ClassDefinitionModifiers modifiers) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDeclaration *ParseClassStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags modFlags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ETSStructDeclaration *ParseStructStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                                   ir::ModifierFlags modFlags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                   ir::ModifierFlags flags = ir::ModifierFlags::NONE,
                                   ir::Identifier *identNode = nullptr) override;
    ir::AstNode *ParseInnerTypeDeclaration(ir::ModifierFlags memberModifiers, lexer::LexerPosition savedPos,
                                           bool isStepToken, bool seenStatic);
    ir::AstNode *ParseInnerConstructorDeclaration(ir::ModifierFlags memberModifiers,
                                                  const lexer::SourcePosition &startLoc);
    ir::AstNode *ParseInnerRest(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                ir::ModifierFlags memberModifiers, ir::Identifier *identNode,
                                const lexer::SourcePosition &startLoc);
    ir::Expression *ParseNewExpression() override;
    ir::Expression *ParseAsyncExpression();
    ir::Expression *ParseAwaitExpression();
    ir::TSTypeParameter *ParseTypeParameter(TypeAnnotationParsingOptions *options) override;

    NodeFormatType GetFormatPlaceholderIdent() const;
    ir::AstNode *ParseFormatPlaceholder();
    ir::Statement *ParseStatementFormatPlaceholder(std::optional<NodeFormatType> nodeFormat = std::nullopt);
    ir::Expression *ParseExpressionFormatPlaceholder(std::optional<NodeFormatType> nodeFormat = std::nullopt);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Identifier *ParseIdentifierFormatPlaceholder(std::optional<NodeFormatType> nodeFormat = std::nullopt) override;
    ir::TypeNode *ParseTypeFormatPlaceholder(std::optional<NodeFormatType> nodeFormat = std::nullopt);

    ir::TSEnumDeclaration *ParseEnumMembers(ir::Identifier *key, const lexer::SourcePosition &enumStart, bool isConst,
                                            bool isStatic) override;
    void ParseNumberEnum(ArenaVector<ir::AstNode *> &members);
    void ParseStringEnum(ArenaVector<ir::AstNode *> &members);

    ir::Statement *ParseInterfaceDeclaration(bool isStatic) override;
    ir::ThisExpression *ParseThisExpression() override;
    ir::TypeNode *ParseThisType(TypeAnnotationParsingOptions *options);
    ir::Statement *ParseFunctionStatement(StatementParsingFlags flags) override;
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseClassImplementsElement() override;
    ir::TypeNode *ParseInterfaceExtendsElement() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseEnumDeclaration(bool isConst = false, bool isStatic = false) override;
    ir::Expression *ParseLaunchExpression(ExpressionParseFlags flags);
    void ValidateInstanceOfExpression(ir::Expression *expr);
    void ValidateRestParameter(ir::Expression *param) override;
    void CheckIndexAccessMethod(ir::ScriptFunction const *function, const lexer::SourcePosition &position) const;

    bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                           ArenaVector<ir::AstNode *> &properties) override;
    // NOLINTNEXTLINE(google-default-arguments)
    void CreateCCtor(ArenaVector<ir::AstNode *> &properties, const lexer::SourcePosition &loc,
                     bool inGlobalClass = false) override;
    void CreateImplicitConstructor(ir::MethodDefinition *&ctor, ArenaVector<ir::AstNode *> &properties,
                                   ir::ClassDefinitionModifiers modifiers,
                                   const lexer::SourcePosition &startLoc) override;
    bool ParsePotentialGenericFunctionCall(ir::Expression *primaryExpr, ir::Expression **returnExpression,
                                           const lexer::SourcePosition &startLoc, bool ignoreCallExpression) override;
    bool ParsePotentialNonNullExpression(ir::Expression **expression, lexer::SourcePosition startLoc) override;
    void MarkNodeAsExported(ir::AstNode *node, lexer::SourcePosition startPos, bool defaultExport,
                            std::size_t numOfElements = 1);

    std::shared_ptr<ArkTsConfig> ArkTSConfig() const
    {
        return GetOptions().arktsConfig;
    }

    bool IsETSModule() const
    {
        return GetOptions().isEtsModule;
    }

    bool IsStructKeyword() const;

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;

    ir::Expression *ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags) override;

    ir::ModifierFlags ParseTypeVarianceModifier(TypeAnnotationParsingOptions *options);

    ir::ScriptFunction *AddInitMethod(ArenaVector<ir::AstNode *> &globalProperties);
    ir::Statement *ParseTopLevelStatement(StatementParsingFlags flags = StatementParsingFlags::NONE);

    void ParseTrailingBlock([[maybe_unused]] ir::CallExpression *callExpr) override;

    void CheckDeclare();

    // Methods to create AST node(s) from the specified string (part of valid ETS-code!)
    // NOTE: the correct initial scope should be entered BEFORE calling any of these methods,
    // and correct parent and, probably, variable set to the node(s) after obtaining
    // NOLINTBEGIN(modernize-avoid-c-arrays)
    inline static constexpr char const DEFAULT_SOURCE_FILE[] = "<auxiliary_tmp>.ets";
    inline static constexpr char const DEFAULT_PROXY_FILE[] = "<default_method>.ets";
    // NOLINTEND(modernize-avoid-c-arrays)

    // NOLINTBEGIN(google-default-arguments)
    ir::Statement *CreateStatement(std::string_view sourceCode, std::string_view fileName = DEFAULT_SOURCE_FILE);
    ir::Statement *CreateFormattedStatement(std::string_view sourceCode, std::vector<ir::AstNode *> &insertingNodes,
                                            std::string_view fileName = DEFAULT_SOURCE_FILE);
    // NOLINTEND(google-default-arguments)

    template <typename... Args>
    ir::Statement *CreateFormattedStatement(std::string_view const sourceCode, std::string_view const fileName,
                                            Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        (insertingNodes.emplace(std::forward<Args>(args)), ...);
        return CreateFormattedStatement(sourceCode, insertingNodes, fileName);
    }

    // NOLINTBEGIN(google-default-arguments)
    ir::MethodDefinition *CreateMethodDefinition(ir::ModifierFlags modifiers, std::string_view sourceCode,
                                                 std::string_view fileName = DEFAULT_SOURCE_FILE);
    ir::MethodDefinition *CreateConstructorDefinition(ir::ModifierFlags modifiers, std::string_view sourceCode,
                                                      std::string_view fileName = DEFAULT_SOURCE_FILE);
    ir::TypeNode *CreateTypeAnnotation(TypeAnnotationParsingOptions *options, std::string_view sourceCode,
                                       std::string_view fileName = DEFAULT_SOURCE_FILE);
    // NOLINTEND(google-default-arguments)

    friend class ExternalSourceParser;
    friend class InnerSourceParser;

public:
    const std::unordered_map<std::string, std::string> &ResolvedParsedSourcesMap() const
    {
        return resolvedParsedSources_;
    }

private:
    parser::Program *globalProgram_;
    std::vector<std::string> parsedSources_;
    std::vector<ir::AstNode *> insertingNodes_ {};
    std::unordered_map<std::string, std::string> resolvedParsedSources_;
};

class ExternalSourceParser {
public:
    explicit ExternalSourceParser(ETSParser *parser, Program *newProgram);
    NO_COPY_SEMANTIC(ExternalSourceParser);
    NO_MOVE_SEMANTIC(ExternalSourceParser);

    ~ExternalSourceParser();

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

private:
    ETSParser *parser_;
    Program *savedProgram_;
    lexer::Lexer *savedLexer_;
    varbinder::GlobalScope *savedTopScope_;
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
    lexer::Lexer *savedLexer_;
    util::StringView savedSourceCode_ {};
    util::StringView savedSourceFile_ {};
    util::StringView savedSourceFilePath_ {};
};

}  // namespace panda::es2panda::parser
#endif
