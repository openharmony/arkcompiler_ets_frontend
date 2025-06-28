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

#ifndef ES2PANDA_PARSER_CORE_ETS_PARSER_H
#define ES2PANDA_PARSER_CORE_ETS_PARSER_H

#include "util/arktsconfig.h"
#include "util/importPathManager.h"
#include "util/recursiveGuard.h"
#include "innerSourceParser.h"
#include "TypedParser.h"
#include "ir/base/classDefinition.h"
#include "ir/module/importDeclaration.h"
#include <utility>

namespace ark::es2panda::ir {
class ETSPackageDeclaration;
enum class ClassDefinitionModifiers : uint32_t;
enum class PrimitiveType;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {

class ETSParser final : public TypedParser {
public:
    ETSParser(Program *program, const util::Options &options, util::DiagnosticEngine &diagnosticEngine,
              ParserStatus status);
    ETSParser(Program *program, std::nullptr_t options, util::DiagnosticEngine &diagnosticEngine);

    ETSParser() = delete;
    NO_COPY_SEMANTIC(ETSParser);
    NO_MOVE_SEMANTIC(ETSParser);

    ~ETSParser() final = default;

    util::ImportPathManager *GetImportPathManager()
    {
        return importPathManager_.get();
    }

    util::StringView GetGlobalProgramAbsName()
    {
        return globalProgram_->AbsoluteName();
    }

    [[nodiscard]] bool IsETSParser() const noexcept override;

    void AddDirectImportsToDirectExternalSources(const ArenaVector<util::StringView> &directImportsFromMainSource,
                                                 parser::Program *newProg) const;
    ArenaVector<ir::ETSImportDeclaration *> ParseDefaultSources(std::string_view srcFile, std::string_view importSrc);

public:
    //============================================================================================//
    // Methods to create AST node(s) from the specified string (part of valid ETS-code!)
    // NOTE: ScopeInitPhase, SetParent should be called on created subtree after calling any of these methods,
    //============================================================================================//

    template <typename>
    static constexpr bool STATIC_FALSE = false;

    std::string_view FormattingFileName()
    {
        return GetContext().FormattingFileName();
    }

    template <typename T>
    void SetFormattingFileName(T &&fileName)
    {
        GetContext().SetFormattingFileName(std::forward<T>(fileName));
    }

    template <typename T>
    void ProcessFormattedArg(std::vector<ir::AstNode *> &nodes, T &&arg)
    {
        if constexpr (std::is_convertible_v<std::decay_t<T>, ir::AstNode *>) {
            nodes.emplace_back(std::forward<T>(arg));
        } else if constexpr (std::is_same_v<std::decay_t<T>, util::StringView>) {
            nodes.emplace_back(AllocNode<ir::Identifier>(std::forward<T>(arg), Allocator()));
        } else if constexpr (std::is_same_v<std::decay_t<T>, util::UString>) {
            nodes.emplace_back(AllocNode<ir::Identifier>(arg.View(), Allocator()));
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
            nodes.emplace_back(
                AllocNode<ir::Identifier>(util::UString(std::forward<T>(arg), Allocator()).View(), Allocator()));
        } else if constexpr (std::is_constructible_v<std::string, std::decay_t<T>>) {
            nodes.emplace_back(AllocNode<ir::Identifier>(
                util::UString(std::string {std::forward<T>(arg)}, Allocator()).View(), Allocator()));
        } else if constexpr (std::is_convertible_v<std::decay_t<T>, checker::Type *>) {
            nodes.emplace_back(AllocNode<ir::OpaqueTypeNode>(std::forward<T>(arg), Allocator()));
        } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::AstNode *>>) {
            nodes.emplace_back(AllocNode<ir::TSInterfaceBody>(std::forward<T>(arg)));
        } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::Expression *>>) {
            nodes.emplace_back(AllocNode<ir::SequenceExpression>(std::forward<T>(arg)));
        } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::Statement *>>) {
            nodes.emplace_back(AllocNode<ir::BlockExpression>(std::forward<T>(arg)));
        } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<checker::Type *>>) {
            for (auto *type : arg) {
                nodes.emplace_back(AllocNode<ir::OpaqueTypeNode>(type, Allocator()));
            }
        } else {
            static_assert(STATIC_FALSE<T>, "Format argument has invalid type.");
        }
    }

    ir::Expression *CreateExpression(std::string_view sourceCode,
                                     ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);

    ir::Expression *CreateFormattedExpression(std::string_view sourceCode, std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ir::Expression *CreateFormattedExpression(std::string_view const sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedExpression(sourceCode, insertingNodes);
    }

    ir::Expression *CreateFormattedExpression(std::string_view const sourceCode, ArenaVector<ir::Expression *> &args);

    ir::Statement *CreateFormattedStatement(std::string_view sourceCode, std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ir::Statement *CreateFormattedStatement(std::string_view const sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedStatement(sourceCode, insertingNodes);
    }

    ArenaVector<ir::Statement *> CreateStatements(std::string_view sourceCode);

    ArenaVector<ir::Statement *> CreateFormattedStatements(std::string_view sourceCode,
                                                           std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ArenaVector<ir::Statement *> CreateFormattedStatements(std::string_view const sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedStatements(sourceCode, insertingNodes);
    }
    ir::Statement *ParseTopLevelAnnotation(ir::ModifierFlags memberModifiers);
    ArenaVector<ir::AnnotationUsage *> ParseAnnotations(bool isTopLevelSt);
    ir::Statement *CreateFormattedClassDeclaration(std::string_view sourceCode,
                                                   std::vector<ir::AstNode *> &insertingNodes,
                                                   bool allowStatic = false);

    template <typename... Args>
    ir::Statement *CreateFormattedClassDeclaration(std::string_view sourceCode, bool allowStatic, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedClassDeclaration(sourceCode, insertingNodes, allowStatic);
    }

    ir::AstNode *CreateFormattedClassElement(std::string_view sourceCode, std::vector<ir::AstNode *> &insertingNodes,
                                             const ArenaVector<ir::AstNode *> &properties,
                                             ir::ClassDefinitionModifiers modifiers);

    template <typename... Args>
    ir::AstNode *CreateFormattedClassElement(std::string_view sourceCode, const ArenaVector<ir::AstNode *> &properties,
                                             ir::ClassDefinitionModifiers modifiers, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedClassElement(sourceCode, insertingNodes, properties, modifiers);
    }

    template <typename... Args>
    ir::AstNode *CreateFormattedClassElement(std::string_view sourceCode, ir::ClassDefinition *classDefinition,
                                             Args &&...args)
    {
        return CreateFormattedClassElement(sourceCode, classDefinition->Body(), classDefinition->Modifiers(),
                                           std::forward<Args...>(args...));
    }

    ir::AstNode *CreateFormattedClassFieldDefinition(std::string_view sourceCode,
                                                     std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ir::AstNode *CreateFormattedClassFieldDefinition(std::string_view const sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedClassFieldDefinition(sourceCode, insertingNodes);
    }

    ir::AstNode *CreateFormattedClassMethodDefinition(std::string_view sourceCode,
                                                      std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ir::AstNode *CreateFormattedClassMethodDefinition(std::string_view const sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedClassMethodDefinition(sourceCode, insertingNodes);
    }

    ir::Statement *CreateFormattedTopLevelStatement(std::string_view sourceCode,
                                                    std::vector<ir::AstNode *> &insertingNodes);

    template <typename... Args>
    ir::Statement *CreateFormattedTopLevelStatement(std::string_view sourceCode, Args &&...args)
    {
        std::vector<ir::AstNode *> insertingNodes {};
        insertingNodes.reserve(sizeof...(Args));
        (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
        return CreateFormattedTopLevelStatement(sourceCode, insertingNodes);
    }
    void ApplyAnnotationsToNode(ir::AstNode *node, ArenaVector<ir::AnnotationUsage *> &&annotations,
                                lexer::SourcePosition pos,
                                TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::NO_OPTS);
    [[nodiscard]] bool IsInitializerBlockStart() const;

    uint32_t GetNamespaceNestedRank()
    {
        return namespaceNestedRank_;
    }

    void IncrementNamespaceNestedRank()
    {
        namespaceNestedRank_++;
    }

    void DecrementNamespaceNestedRank()
    {
        namespaceNestedRank_--;
    }

    ir::ETSImportDeclaration *BuildImportDeclaration(ir::ImportKinds importKinds,
                                                     ArenaVector<ir::AstNode *> &&specifiers,
                                                     ir::StringLiteral *pathToResolve);

    void AddExternalSource(const std::vector<Program *> &programs);
    std::vector<Program *> ParseSources(bool firstSource = false);

private:
    NodeFormatType GetFormatPlaceholderType();

    ir::Statement *ParseStatementFormatPlaceholder() override;
    ir::Expression *ParseExpressionFormatPlaceholder();
    ir::Identifier *ParseIdentifierFormatPlaceholder(std::optional<NodeFormatType> nodeFormat) override;
    ir::TypeNode *ParseTypeFormatPlaceholder(std::optional<NodeFormatType> nodeFormat = std::nullopt);
    ir::AstNode *ParseTypeParametersFormatPlaceholder() override;
    void ApplyAnnotationsToArrayType(ir::AstNode *node, ArenaVector<ir::AnnotationUsage *> &&annotations,
                                     lexer::SourcePosition pos);
    void ApplyAnnotationsToSpecificNodeType(ir::AstNode *node, ArenaVector<ir::AnnotationUsage *> &&annotations,
                                            lexer::SourcePosition pos);
    ArenaVector<ir::AstNode *> &ParseAstNodesArrayFormatPlaceholder() override;
    ArenaVector<ir::Statement *> &ParseStatementsArrayFormatPlaceholder() override;
    ArenaVector<ir::Expression *> &ParseExpressionsArrayFormatPlaceholder() override;

    ir::Statement *CreateStatement(std::string_view sourceCode);

    ir::MethodDefinition *CreateConstructorDefinition(ir::ModifierFlags modifiers, std::string_view sourceCode);

    ir::Statement *CreateClassDeclaration(std::string_view sourceCode, bool allowStatic = false);
    ir::AstNode *CreateClassElement(std::string_view sourceCode, const ArenaVector<ir::AstNode *> &properties,
                                    ir::ClassDefinitionModifiers modifiers);

    ir::TypeNode *CreateTypeAnnotation(TypeAnnotationParsingOptions *options, std::string_view sourceCode);
    ir::Statement *CreateTopLevelStatement(std::string_view const sourceCode);

    //============================================================================================//
    //  END: Methods to create AST node(s)...
    //============================================================================================//

private:
    void ParseProgram(ScriptKind kind) override;
    [[nodiscard]] std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &sourceFile) override;
    ir::ETSPackageDeclaration *ParsePackageDeclaration();
    void AddPackageSourcesToParseList();
    ArenaVector<ir::Statement *> ParseTopLevelStatements();

    ir::AstNode *HandleAmbientDeclaration(ir::ModifierFlags &memberModifiers,
                                          const std::function<ir::AstNode *(ir::Identifier *)> &parseClassMethod);
    static bool IsClassMethodModifier(lexer::TokenType type) noexcept;

#ifdef USE_FTW
    static int NFTWCallBack(const char *fpath, const struct stat * /*unused*/, int tflag, struct FTW * /*unused*/);
#endif
    ir::ETSImportDeclaration *ParseImportPathBuildImport(ArenaVector<ir::AstNode *> &&specifiers, bool requireFrom,
                                                         lexer::SourcePosition startLoc, ir::ImportKinds importKind);
    void ParseNamedExportSpecifiers(ArenaVector<ir::AstNode *> *specifiers, bool defaultExport);
    void ParseUserSources(std::vector<std::string> userParths);
    ArenaVector<ir::Statement *> ParseTopLevelDeclaration();
    void ParseParseListElement(const util::ImportPathManager::ParseInfo &parseListElem, util::UString *extSrc,
                               const ArenaVector<util::StringView> &directImportsFromMainSource,
                               std::vector<Program *> *programs);
    bool IsDefaultImport();
    void ParseNamedSpecifiesDefaultImport(ArenaVector<ir::ImportDefaultSpecifier *> *resultDefault,
                                          const std::string &fileName);
    std::pair<ArenaVector<ir::ImportSpecifier *>, ArenaVector<ir::ImportDefaultSpecifier *>> ParseNamedSpecifiers();
    ir::ExportNamedDeclaration *ParseSingleExport(ir::ModifierFlags modifiers);
    ArenaVector<ir::ETSImportDeclaration *> ParseImportDeclarations();
    ir::Statement *ParseImportDeclarationHelper(lexer::SourcePosition startLoc, ArenaVector<ir::AstNode *> &specifiers,
                                                ir::ImportKinds importKind);
    parser::Program *ParseSource(const SourceFile &sourceFile);
    ir::ETSModule *ParseETSGlobalScript(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements);
    ir::ETSModule *ParseImportsOnly(lexer::SourcePosition startLoc, ArenaVector<ir::Statement *> &statements);
    ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers) override;

    void *ApplyAnnotationsToClassElement(ir::AstNode *property, ArenaVector<ir::AnnotationUsage *> &&annotations,
                                         lexer::SourcePosition pos);
    ir::MethodDefinition *ParseClassGetterSetterMethod(const ArenaVector<ir::AstNode *> &properties,
                                                       ir::ClassDefinitionModifiers modifiers,
                                                       ir::ModifierFlags memberModifiers, bool isDefault);
    ir::MethodDefinition *ParseInterfaceGetterSetterMethod(const ir::ModifierFlags modifiers);
    ir::Statement *ParseIdentKeyword();
    ir::Statement *ParseTypeDeclaration(bool allowStatic = false);
    ir::Statement *ParseTypeDeclarationAbstractFinal(bool allowStatic, ir::ClassDefinitionModifiers modifiers);
    ir::ModifierFlags ParseClassModifiers();
    ir::ModifierFlags ParseInterfaceMethodModifiers();
    ir::AstNode *ParseInterfaceField();
    ir::MethodDefinition *ParseInterfaceMethod(ir::ModifierFlags flags, ir::MethodDefinitionKind methodKind);
    void ReportAccessModifierError(const lexer::Token &token);
    std::tuple<ir::ModifierFlags, bool, bool> ParseClassMemberAccessModifiers();
    ir::ModifierFlags ParseClassFieldModifiers(bool seenStatic);
    ir::ModifierFlags ParseClassMethodModifierFlag();
    ir::ModifierFlags ParseClassMethodModifiers(bool seenStatic);
    ir::MethodDefinition *ParseClassMethodDefinition(ir::Identifier *methodName, ir::ModifierFlags modifiers,
                                                     bool isDefault);
    ir::ScriptFunction *ParseFunction(ParserStatus newStatus);
    ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                           ir::Expression *propName, lexer::SourcePosition *propEnd) override;
    std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus newStatus, ParserStatus contextStatus) override;
    ir::TypeNode *ParseFunctionReturnType(ParserStatus status) override;
    ir::ScriptFunctionFlags ParseFunctionThrowMarker(bool isRethrowsAllowed) override;
    ir::Expression *CreateParameterThis(ir::TypeNode *typeAnnotation) override;
    ir::TypeNode *ConvertToOptionalUnionType(ir::TypeNode *typeAnno);
    // NOLINTNEXTLINE(google-default-arguments)
    void ParseClassFieldDefinition(ir::Identifier *fieldName, ir::ModifierFlags modifiers,
                                   ArenaVector<ir::AstNode *> *declarations, bool isDefault);
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseTypeReferencePart(
        TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseBaseTypeReference(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type);
    ir::TypeNode *ParseUnionType(ir::TypeNode *firstType);
    ir::TypeNode *GetTypeAnnotationOfPrimitiveType(lexer::TokenType tokenType, TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseWildcardType(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseFunctionType(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseETSTupleType(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTsArrayType(ir::TypeNode *typeNode, TypeAnnotationParsingOptions *options);
    bool ParseTriplePeriod(bool spreadTypePresent);
    std::pair<bool, std::size_t> CheckDefaultParameters(const ir::ScriptFunction *function);
    std::string PrimitiveTypeToName(ir::PrimitiveType type) const;
    std::string GetNameForTypeNode(const ir::TypeNode *typeAnnotation) const;
    std::string GetNameForETSUnionType(const ir::TypeNode *typeAnnotation) const;
    ir::TSInterfaceDeclaration *ParseInterfaceBody(ir::Identifier *name, bool isStatic);
    bool IsArrowFunctionExpressionStart();
    ir::ArrowFunctionExpression *ParseArrowFunctionExpression();

    void ReportIfVarDeclaration(VariableParsingFlags flags) override;

    ir::TypeNode *ParsePotentialFunctionalType(TypeAnnotationParsingOptions *options);
    std::pair<ir::TypeNode *, bool> GetTypeAnnotationFromToken(TypeAnnotationParsingOptions *options);
    std::pair<ir::TypeNode *, bool> GetTypeAnnotationFromParentheses(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseLiteralIdent(TypeAnnotationParsingOptions *options);
    void ParseRightParenthesis(TypeAnnotationParsingOptions *options, ir::TypeNode *&typeAnnotation,
                               lexer::LexerPosition savedPos);
    ir::TypeNode *ParseTypeAnnotationNoPreferParam(TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTypeAnnotation(TypeAnnotationParsingOptions *options) override;
    bool ParseReadonlyInTypeAnnotation();
    ir::TypeNode *ParseMultilineString();
    ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration() override;

    bool ValidateForInStatement() override;
    bool ValidAnnotationValue(ir::Expression *initializer);

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Statement *ParseTryStatement() override;
    ir::Statement *ParseDebuggerStatement() override;
    ir::Statement *ParseExport(lexer::SourcePosition startLoc, ir::ModifierFlags modifiers);
    ir::Statement *ParseImportDeclaration(StatementParsingFlags flags) override;
    ir::Statement *ParseExportDeclaration(StatementParsingFlags flags) override;
    ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags) override;
    ir::Statement *ParseAnnotationsInStatement(StatementParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition startLoc,
                                                    VariableParsingFlags flags) override;
    ir::VariableDeclarator *ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                               const lexer::SourcePosition &startLoc) override;
    bool IsFieldStartToken(lexer::TokenType t);
    ir::AstNode *ParseTypeLiteralOrInterfaceMember() override;
    ir::AstNode *ParseAnnotationsInInterfaceBody();
    void ParseNameSpaceSpecifier(ArenaVector<ir::AstNode *> *specifiers, bool isReExport = false);
    bool CheckModuleAsModifier();
    bool IsFixedArrayTypeNode(ir::AstNode *node);
    ir::Expression *ParseFunctionParameterExpression(ir::AnnotatedExpression *paramIdent, bool isOptional);
    std::pair<ir::Expression *, std::string> TypeAnnotationValue(ir::TypeNode *typeAnnotation);
    ir::ETSParameterExpression *ParseFunctionParameterTail(ir::AnnotatedExpression *paramIdent, bool defaultUndefined);
    ir::Expression *ParseFunctionParameterAnnotations();
    ir::Expression *ParseFunctionParameter() override;
    ir::Expression *ParseFunctionReceiver();
    ir::AnnotatedExpression *GetAnnotatedExpressionFromParam();
    ir::Expression *ResolveArgumentUnaryExpr(ExpressionParseFlags flags);
    ir::Expression *CreateUnaryExpressionFromArgument(ir::Expression *argument, lexer::TokenType operatorType,
                                                      char32_t beginningChar);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseUnaryOrPrefixUpdateExpression(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePropertyDefinition(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseDefaultPrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Expression *ParsePrimaryExpressionWithLiterals(ExpressionParseFlags flags) override;
    ir::Expression *ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                               bool ignoreCallExpression, bool *isChainExpression) override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *primaryExpr) override;
    bool ValidateLabeledStatement(lexer::TokenType type) override;
    ir::Expression *ParseCatchParam() override;
    void ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param) override;
    ir::Expression *ParseSuperClassReference() override;
    ir::Identifier *ParseClassIdent(ir::ClassDefinitionModifiers modifiers) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseClassStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                       ir::ModifierFlags modFlags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseStructStatement(StatementParsingFlags flags, ir::ClassDefinitionModifiers modifiers,
                                        ir::ModifierFlags modFlags = ir::ModifierFlags::NONE) override;
    ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                   ir::ModifierFlags flags) override;
    std::tuple<bool, bool, bool> HandleClassElementModifiers(ir::ModifierFlags &memberModifiers);
    void UpdateMemberModifiers(ir::ModifierFlags &memberModifiers, bool &seenStatic);
    ir::ModifierFlags ParseMemberAccessModifiers();
    template <bool IS_USAGE>
    ir::Expression *ParseAnnotationName();
    ir::AnnotationDeclaration *ParseAnnotationDeclaration(
        [[maybe_unused]] ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    ir::AstNode *ParseAnnotationProperty(ir::Identifier *fieldName,
                                         ir::ModifierFlags memberModifiers = ir::ModifierFlags::NONE,
                                         bool needTypeAnnotation = true);
    ArenaVector<ir::AstNode *> ParseAnnotationProperties(ir::ModifierFlags memberModifiers = ir::ModifierFlags::NONE);
    ir::AnnotationUsage *ParseAnnotationUsage();
    bool TryParseAnnotations();
    void TryParseAnnotationsParams();
    bool IsAnnotationUsageStart(lexer::SourcePosition lastTokenEndIndex);
    ir::AstNode *ParseInnerTypeDeclaration(ir::ModifierFlags memberModifiers, lexer::LexerPosition savedPos,
                                           bool isStepToken, bool seenStatic);
    ir::AstNode *ParseInnerConstructorDeclaration(ir::ModifierFlags memberModifiers,
                                                  const lexer::SourcePosition &startLoc, bool isDefault);
    ir::AstNode *ParseInnerRest(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                ir::ModifierFlags memberModifiers, const lexer::SourcePosition &startLoc,
                                bool isDefault);
    bool CheckAccessorDeclaration(ir::ModifierFlags memberModifiers);

    ir::AstNode *ParseAmbientSignature(const lexer::SourcePosition &startPosAmbient);

    void ParseArgumentsNewExpression(ArenaVector<ir::Expression *> &arguments, ir::TypeNode *typeReference);
    ir::Identifier *CreateInvokeIdentifier();

    ir::Expression *ParseNewExpression() override;
    ir::Expression *ParseAsyncExpression();
    ir::Expression *ParseAwaitExpression();
    ir::ArrayExpression *ParseArrayExpression(ExpressionParseFlags flags) override;
    ir::TSTypeParameter *ParseTypeParameter(TypeAnnotationParsingOptions *options) override;

    bool IsStringEnum();
    ir::TSEnumDeclaration *ParseEnumMembers(ir::Identifier *key, const lexer::SourcePosition &enumStart, bool isConst,
                                            bool isStatic) override;

    ir::Expression *ParseEnumExpression();
    bool ParseNumberEnumHelper();
    lexer::SourcePosition ParseEnumMember(ArenaVector<ir::AstNode *> &members);

    ir::Statement *ParseInterfaceDeclaration(bool isStatic) override;
    ir::TypeNode *ParseThisType(TypeAnnotationParsingOptions *options);
    ir::Statement *ParseFunctionStatement(StatementParsingFlags flags) override;
    ir::FunctionDeclaration *ParseFunctionDeclaration(bool canBeAnonymous, ir::ModifierFlags modifiers);
    ir::FunctionDeclaration *ParseAccessorWithReceiver(ir::ModifierFlags modifiers);
    ir::TypeNode *ParseExtensionFunctionsTypeAnnotation();
    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseClassImplementsElement() override;
    ir::TypeNode *ParseInterfaceExtendsElement() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;
    bool CheckInNamespaceContextIsExported();
    ir::ETSModule *ParseNamespaceStatement(ir::ModifierFlags memberModifiers);
    ir::Statement *ParseNamespace(ir::ModifierFlags flags) override;
    ir::ETSModule *ParseNamespaceImp(ir::ModifierFlags flags);
    using NamespaceBody = std::tuple<ir::MethodDefinition *, ArenaVector<ir::AstNode *>, lexer::SourceRange>;
    NamespaceBody ParseNamespaceBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseEnumDeclaration(bool isConst = false, bool isStatic = false) override;
    ir::Statement *ParsePotentialConstEnum(VariableParsingFlags flags) override;
    ir::Expression *ParseLaunchExpression(ExpressionParseFlags flags);
    void ValidateInstanceOfExpression(ir::Expression *expr);
    void ValidateRestParameter(ir::Expression *param) override;
    bool ValidateBreakLabel(util::StringView label) override;
    bool ValidateContinueLabel(util::StringView label) override;
    void CheckPredefinedMethods(ir::ScriptFunction const *function, const lexer::SourcePosition &position);

    bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                           ArenaVector<ir::AstNode *> &properties) override;
    void CreateImplicitConstructor(ir::MethodDefinition *&ctor, ArenaVector<ir::AstNode *> &properties,
                                   ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags,
                                   const lexer::SourcePosition &startLoc) override;
    bool ParsePotentialGenericFunctionCall(ir::Expression *primaryExpr, ir::Expression **returnExpression,
                                           const lexer::SourcePosition &startLoc, bool ignoreCallExpression) override;
    bool ParsePotentialNonNullExpression(ir::Expression **expression, lexer::SourcePosition startLoc) override;

    std::pair<ir::ModifierFlags, lexer::SourcePosition> ParseMemberModifiers();

    void SkipInvalidType() const;

    bool IsStructKeyword() const;

    bool IsExternal() const override
    {
        return util::Helpers::IsStdLib(GetProgram());
    }

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;

    ir::Expression *ParseExpressionOrTypeAnnotation(lexer::TokenType type, ExpressionParseFlags flags) override;

    ir::Expression *ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags) override;

    ir::ModifierFlags ParseTypeVarianceModifier(TypeAnnotationParsingOptions *const options);

    bool IsExportedDeclaration(ir::ModifierFlags memberModifiers);
    ir::Statement *ParseTopLevelDeclStatement(StatementParsingFlags flags);
    ir::Statement *ParseTopLevelStatement();

    void ParseTrailingBlock([[maybe_unused]] ir::CallExpression *callExpr) override;

    void CheckDeclare();

    friend class ExternalSourceParser;
    friend class InnerSourceParser;
    friend ir::Expression *HandleLeftParanthesis(ETSParser *parser, ExpressionParseFlags flags);

private:
    uint32_t namespaceNestedRank_;
    std::optional<ir::Expression *> GetPostPrimaryExpression(ir::Expression *returnExpression,
                                                             lexer::SourcePosition startLoc, bool ignoreCallExpression,
                                                             [[maybe_unused]] bool *isChainExpression);
    parser::Program *globalProgram_;
    std::vector<ir::AstNode *> insertingNodes_ {};
    std::unique_ptr<util::ImportPathManager> importPathManager_ {nullptr};
    RecursiveContext recursiveCtx_;
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

class SavedFormattingFileName {
public:
    SavedFormattingFileName(ETSParser *parser, std::string_view fname)
        : parser_(parser), savedFname_(parser->FormattingFileName())
    {
        parser->SetFormattingFileName(fname);
    }

    NO_COPY_SEMANTIC(SavedFormattingFileName);
    NO_MOVE_SEMANTIC(SavedFormattingFileName);

    ~SavedFormattingFileName()
    {
        parser_->SetFormattingFileName(savedFname_);
    }

private:
    ETSParser *parser_;
    std::string_view savedFname_;
};

}  // namespace ark::es2panda::parser
#endif
