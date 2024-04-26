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

#ifndef ES2PANDA_PARSER_CORE_PARSER_IMPL_H
#define ES2PANDA_PARSER_CORE_PARSER_IMPL_H

#include "es2panda.h"
#include "ir/base/scriptFunctionSignature.h"
#include "lexer/token/sourceLocation.h"
#include "lexer/token/tokenType.h"
#include "parser/context/classPrivateContext.h"
#include "parser/context/parserContext.h"
#include "parser/parserFlags.h"
#include "parser/program/program.h"
#include "util/helpers.h"

namespace ark::es2panda::lexer {
enum class TokenFlags : uint32_t;
class LexerPosition;
class Token;
class Lexer;
}  // namespace ark::es2panda::lexer

namespace ark::es2panda::ir {
class ArrowFunctionExpression;
class AstNode;
class BlockStatement;
class BreakStatement;
class CallExpression;
class ClassDeclaration;
class ClassDefinition;
class ContinueStatement;
class DoWhileStatement;
class ExportAllDeclaration;
class ExportDefaultDeclaration;
class ExportNamedDeclaration;
class ExportNamedDeclaration;
class Expression;
class FunctionDeclaration;
class FunctionExpression;
class Identifier;
class IfStatement;
class ImportSource;
class ImportDeclaration;
class LabelledStatement;
class NewExpression;
class ObjectExpression;
class ReturnStatement;
class ScriptFunction;
class SequenceExpression;
class SpreadElement;
class Statement;
class StringLiteral;
class SwitchCaseStatement;
class SwitchStatement;
class TemplateLiteral;
class ThrowStatement;
class TryStatement;
class VariableDeclaration;
class WhileStatement;
class WithStatement;
class MemberExpression;
class MethodDefinition;
class Property;
class YieldExpression;
class MetaProperty;
class EmptyStatement;
class DebuggerStatement;
class CatchClause;
class VariableDeclarator;
class ClassElement;

enum class PropertyKind;
enum class MethodDefinitionKind;
enum class ModifierFlags : uint32_t;
enum class Primitives;
enum class ClassDefinitionModifiers : uint32_t;
enum class CatchClauseType;
enum class VariableDeclaratorFlag;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {

class ETSParser;

using FunctionSignature = std::tuple<ir::FunctionSignature, ark::es2panda::ir::ScriptFunctionFlags>;

// NOLINTBEGIN(modernize-avoid-c-arrays)
inline constexpr char const ARRAY_FORMAT_NODE = '[';
inline constexpr char const STATEMENT_FORMAT_NODE = 'S';
// NOLINTEND(modernize-avoid-c-arrays)

class ClassElementDescriptor {
public:
    explicit ClassElementDescriptor(ArenaAllocator *allocator) : decorators(allocator->Adapter()) {}

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<ir::Decorator *> decorators;
    ir::MethodDefinitionKind methodKind {};
    ParserStatus newStatus {};
    ir::ModifierFlags modifiers {};
    lexer::SourcePosition methodStart {};
    lexer::SourcePosition propStart {};
    bool isPrivateIdent {};
    bool hasSuperClass {};
    bool isGenerator {};
    bool invalidComputedProperty {};
    bool isComputed {};
    bool isIndexSignature {};
    bool classMethod {};
    bool classField {};
    varbinder::LocalScope *staticFieldScope {};
    varbinder::LocalScope *staticMethodScope {};
    varbinder::LocalScope *instanceFieldScope {};
    varbinder::LocalScope *instanceMethodScope {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class ArrowFunctionDescriptor {
public:
    explicit ArrowFunctionDescriptor(ArenaVector<ir::Expression *> &&p, lexer::SourcePosition sl, ParserStatus ns)
        : params(p), startLoc(sl), newStatus(ns)
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<ir::Expression *> params;
    lexer::SourcePosition startLoc;
    ParserStatus newStatus;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

enum class TypeAnnotationParsingOptions : uint32_t {
    NO_OPTS = 0U,
    IN_UNION = 1U << 0U,
    ALLOW_CONST = 1U << 1U,
    IN_INTERSECTION = 1U << 2U,
    RESTRICT_EXTENDS = 1U << 3U,
    THROW_ERROR = 1U << 4U,
    CAN_BE_TS_TYPE_PREDICATE = 1U << 5U,
    BREAK_AT_NEW_LINE = 1U << 6U,
    RETURN_TYPE = 1U << 7U,
    POTENTIAL_CLASS_LITERAL = 1U << 8U,
    ALLOW_INTERSECTION = 1U << 9U,
    ADD_TYPE_PARAMETER_BINDING = 1U << 10U,
    DISALLOW_PRIMARY_TYPE = 1U << 11U,
    ALLOW_WILDCARD = 1U << 12U,
    IGNORE_FUNCTION_TYPE = 1U << 13U,
    ALLOW_DECLARATION_SITE_VARIANCE = 1U << 14U,
    DISALLOW_UNION = 1U << 15U,
};

DEFINE_BITOPS(TypeAnnotationParsingOptions)

class ArrowFunctionContext;

class ParserImpl {
public:
    explicit ParserImpl(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS);
    NO_COPY_SEMANTIC(ParserImpl);
    NO_MOVE_SEMANTIC(ParserImpl);
    virtual ~ParserImpl() = default;

    void ParseScript(const SourceFile &sourceFile, bool genStdLib);

    ScriptExtension Extension() const;

    [[nodiscard]] virtual bool IsETSParser() const noexcept
    {
        return false;
    }

    ETSParser *AsETSParser()
    {
        ASSERT(IsETSParser());
        return reinterpret_cast<ETSParser *>(this);
    }

    const ETSParser *AsETSParser() const
    {
        ASSERT(IsETSParser());
        return reinterpret_cast<const ETSParser *>(this);
    }

    [[noreturn]] void ThrowSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const;

protected:
    virtual void ParseProgram(ScriptKind kind);
    static ExpressionParseFlags CarryExpressionParserFlag(ExpressionParseFlags origin, ExpressionParseFlags carry);
    static ExpressionParseFlags CarryPatternFlags(ExpressionParseFlags flags);

    void ThrowIfPrivateIdent(ClassElementDescriptor *desc, const char *msg);
    void ValidateClassKey(ClassElementDescriptor *desc);
    void ValidatePrivateIdentifier();

    static ir::VariableDeclaratorFlag GetFlag(VariableParsingFlags flags);
    ir::MethodDefinition *CheckClassMethodOverload(ir::Statement *property, ir::MethodDefinition **ctor,
                                                   lexer::SourcePosition errorInfo, ir::MethodDefinition *lastOverload,
                                                   bool implExists, bool isAbstract = false);

    void ThrowAllocationError(std::string_view message) const;

    void ValidateAccessor(ExpressionParseFlags flags, lexer::TokenFlags currentTokenFlags);
    void CheckPropertyKeyAsyncModifier(ParserStatus *methodStatus);
    ir::Property *ParseShorthandProperty(const lexer::LexerPosition *startPos);
    void ParseGeneratorPropertyModifier(ExpressionParseFlags flags, ParserStatus *methodStatus);
    bool ParsePropertyModifiers(ExpressionParseFlags flags, ir::PropertyKind *propertyKind, ParserStatus *methodStatus);
    ir::Expression *ParsePropertyValue(const ir::PropertyKind *propertyKind, const ParserStatus *methodStatus,
                                       ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    bool ParsePropertyEnd();

    // ExpressionParser.Cpp

    ir::Expression *ParseKeywordExpression();
    ir::Expression *ParseBinaryExpression(ir::Expression *left,
                                          ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    void ValidateUpdateExpression(ir::Expression *returnExpression, bool isChainExpression);
    ir::Expression *ParseMemberExpression(bool ignoreCallExpression = false,
                                          ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::Expression *SetupChainExpr(ir::Expression *const top, lexer::SourcePosition startLoc);
    ir::MetaProperty *ParsePotentialNewTarget();
    void CheckInvalidDestructuring(const ir::AstNode *object) const;
    void ValidateParenthesizedExpression(ir::Expression *lhsExpression);
    void ValidateGroupedExpression(ir::Expression *lhsExpression);
    ir::Expression *ParseImportExpression();
    ir::Expression *ParseOptionalChain(ir::Expression *leftSideExpr);
    ir::Expression *ParsePropertyKey(ExpressionParseFlags flags);
    void ValidateAssignmentTarget(ExpressionParseFlags flags, ir::Expression *node);
    void ValidateLvalueAssignmentTarget(ir::Expression *node);
    void ValidateArrowParameterBindings(const ir::Expression *node);
    ir::Identifier *ParseNamedExport(const lexer::Token &exportedToken);
    virtual void ParseTrailingBlock([[maybe_unused]] ir::CallExpression *callExpr) {}

    // StatementParser.Cpp

    void CheckFunctionDeclaration(StatementParsingFlags flags);
    void CheckLabelledFunction(const ir::Statement *node);
    bool ParseDirective(ArenaVector<ir::Statement *> *statements);
    void ParseDirectivePrologue(ArenaVector<ir::Statement *> *statements);
    ir::BlockStatement *ParseFunctionBody();
    std::tuple<ForStatementKind, ir::AstNode *, ir::Expression *, ir::Expression *> ParseForInOf(
        ir::Expression *leftNode, ExpressionParseFlags exprFlags, bool isAwait);
    std::tuple<ForStatementKind, ir::Expression *, ir::Expression *> ParseForInOf(ir::AstNode *initNode,
                                                                                  ExpressionParseFlags exprFlags,
                                                                                  bool isAwait);
    std::tuple<ir::Expression *, ir::Expression *> ParseForUpdate(bool isAwait);
    ir::SwitchCaseStatement *ParseSwitchCaseStatement(bool *seenDefault);
    virtual ir::Expression *ParseCatchParam();
    ir::CatchClause *ParseCatchClause();
    ir::VariableDeclaration *ParseContextualLet(VariableParsingFlags flags,
                                                StatementParsingFlags stmFlags = StatementParsingFlags::ALLOW_LEXICAL);

    friend class Lexer;
    friend class SavedParserContext;
    friend class SavedClassPrivateContext;
    friend class ArrowFunctionContext;
    friend class ETSNolintParser;

    [[noreturn]] void ThrowParameterModifierError(ir::ModifierFlags status) const;
    [[noreturn]] void ThrowUnexpectedToken(lexer::TokenType tokenType) const;
    [[noreturn]] void ThrowExpectedToken(lexer::TokenType tokenType) const;
    [[noreturn]] void ThrowSyntaxError(std::string_view errorMessage) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list,
                                       const lexer::SourcePosition &pos) const;

    template <typename T, typename... Args>
    T *AllocNode(Args &&...args)
    {
        auto *ret = util::NodeAllocator::ForceSetParent<T>(
            Allocator(), std::forward<Args>(args)...);  // Note: replace with AllocNode
        if (ret == nullptr) {
            ThrowAllocationError("Unsuccessful allocation during parsing");
        }
        return ret;
    }

    ArenaAllocator *Allocator() const
    {
        return program_->Allocator();
    }

    bool CheckModuleAsModifier();

    // ETS extension
    virtual bool IsExternal() const
    {
        return false;
    }

    ir::Identifier *ExpectIdentifier(bool isReference = false, bool isUserDefinedType = false);
    void ExpectToken(lexer::TokenType tokenType, bool consumeToken = true);

    // ExpressionParser.cpp

    ir::SpreadElement *ParseSpreadElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::YieldExpression *ParseYieldExpression();
    virtual ir::Expression *ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags);
    ir::ArrowFunctionExpression *ParseArrowFunctionExpressionBody(ArrowFunctionContext *arrowFunctionContext,
                                                                  ArrowFunctionDescriptor *desc,
                                                                  ir::TSTypeParameterDeclaration *typeParamDecl,
                                                                  ir::TypeNode *returnTypeAnnotation);
    ir::Expression *ParseAssignmentExpression(ir::Expression *lhsExpression,
                                              ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::SequenceExpression *ParseSequenceExpression(ir::Expression *startExpr, bool acceptRest = false);
    ir::FunctionExpression *ParseFunctionExpression(ParserStatus newStatus = ParserStatus::NO_OPTS);
    ir::ArrowFunctionExpression *ParseArrowFunctionExpression(ir::Expression *expr,
                                                              ir::TSTypeParameterDeclaration *typeParamDecl,
                                                              ir::TypeNode *returnTypeAnnotation, bool isAsync);
    ir::CallExpression *ParseCallExpression(ir::Expression *callee, bool isOptionalChain = false,
                                            bool handleEval = true);
    ArenaVector<ir::Expression *> ParseCallExpressionArguments(bool &trailingComma);

    ir::TemplateLiteral *ParseTemplateLiteral();
    ir::Expression *ParseLeftHandSideExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    void ParseNameSpaceImport(ArenaVector<ir::AstNode *> *specifiers);
    void ParseNamedImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers);
    ir::StringLiteral *ParseFromClause(bool requireFrom = true);

    ir::BooleanLiteral *ParseBooleanLiteral();
    ir::NullLiteral *ParseNullLiteral();
    ir::Literal *ParseNumberLiteral();
    ir::CharLiteral *ParseCharLiteral();
    ir::StringLiteral *ParseStringLiteral();
    ir::UndefinedLiteral *ParseUndefinedLiteral();
    virtual ir::ThisExpression *ParseThisExpression();
    ir::RegExpLiteral *ParseRegularExpression();
    ir::SuperExpression *ParseSuperExpression();
    ir::MemberExpression *ParseElementAccess(ir::Expression *primaryExpr, bool isOptional = false);
    ir::MemberExpression *ParsePrivatePropertyAccess(ir::Expression *primaryExpr);
    ir::MemberExpression *ParsePropertyAccess(ir::Expression *primaryExpr, bool isOptional = false);
    void CreateAmendedBinaryExpression(ir::Expression *left, ir::Expression *right, lexer::TokenType operatorType);

    // StatementParser
    ArenaVector<ir::Statement *> ParseStatementList(StatementParsingFlags flags = StatementParsingFlags::ALLOW_LEXICAL);
    virtual ir::Statement *ParseAssertStatement();
    virtual void ValidateLabeledStatement(lexer::TokenType type);
    ir::BlockStatement *ParseBlockStatement();
    ir::EmptyStatement *ParseEmptyStatement();
    ir::Statement *ParseForStatement();
    ir::IfStatement *ParseIfStatement();
    virtual ir::Statement *ParseFunctionStatement(StatementParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ClassDeclaration *ParseClassStatement(StatementParsingFlags flags,
                                                      ir::ClassDefinitionModifiers modifiers,
                                                      ir::ModifierFlags modFlags = ir::ModifierFlags::NONE);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ETSStructDeclaration *ParseStructStatement(StatementParsingFlags flags,
                                                           ir::ClassDefinitionModifiers modifiers,
                                                           ir::ModifierFlags modFlags = ir::ModifierFlags::NONE);
    ir::Statement *ParseVarStatement();
    ir::Statement *ParseLetStatement(StatementParsingFlags flags);
    ir::BreakStatement *ParseBreakStatement();
    ir::ContinueStatement *ParseContinueStatement();
    ir::DoWhileStatement *ParseDoWhileStatement();
    ir::WhileStatement *ParseWhileStatement();
    ir::SwitchStatement *ParseSwitchStatement();
    ir::ReturnStatement *ParseReturnStatement();
    ir::Statement *ParseExpressionStatement(StatementParsingFlags flags = StatementParsingFlags::NONE);
    ir::LabelledStatement *ParseLabelledStatement(const lexer::LexerPosition &pos);
    virtual void ValidateRestParameter(ir::Expression *param);
    bool InAmbientContext();

    ir::MethodDefinition *BuildImplicitConstructor(ir::ClassDefinitionModifiers modifiers,
                                                   const lexer::SourcePosition &startLoc);

    virtual void CreateImplicitConstructor(ir::MethodDefinition *&ctor, ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers,
                                           const lexer::SourcePosition &startLoc);
    void CheckClassGeneratorMethod(ClassElementDescriptor *desc, char32_t *nextCp);
    void ParseClassAccessor(ClassElementDescriptor *desc, char32_t *nextCp);
    ir::Expression *ParseClassKey(ClassElementDescriptor *desc);
    ir::ClassElement *ParseClassProperty(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                         ir::Expression *propName, ir::TypeNode *typeAnnotation);
    void AddPrivateElement(const ir::ClassElement *elem);
    ir::ScriptFunction *ParseFunction(ParserStatus newStatus = ParserStatus::NO_OPTS);
    ir::ModifierFlags GetAccessability(ir::ModifierFlags modifiers);
    void CheckAccessorPair(const ArenaVector<ir::AstNode *> &properties, const ir::Expression *propName,
                           ir::MethodDefinitionKind methodKind, ir::ModifierFlags access);
    ir::Identifier *ParseNamedImport(const lexer::Token &importedToken);
    void ConsumeSemicolon(ir::Statement *statement);
    ir::ExportAllDeclaration *ParseExportAllDeclaration(const lexer::SourcePosition &startLoc);
    ir::ExportNamedDeclaration *ParseExportNamedSpecifiers(const lexer::SourcePosition &startLoc);
    ir::Statement *ParseVariableDeclaration(VariableParsingFlags flags = VariableParsingFlags::NO_OPTS);
    void ValidateDeclaratorId();
    void CheckRestrictedBinding() const;
    void CheckRestrictedBinding(lexer::TokenType keywordType) const;
    void CheckRestrictedBinding(const util::StringView &ident, const lexer::SourcePosition &pos) const;

    ir::VariableDeclarator *ParseVariableDeclarator(VariableParsingFlags flags);
    ir::FunctionDeclaration *ParseFunctionDeclaration(bool canBeAnonymous = false,
                                                      ParserStatus newStatus = ParserStatus::NO_OPTS);
    ir::ETSStructDeclaration *ParseStructDeclaration(ir::ClassDefinitionModifiers modifiers,
                                                     ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    ir::ClassDeclaration *ParseClassDeclaration(ir::ClassDefinitionModifiers modifiers,
                                                ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    FunctionSignature ParseFunctionSignature(ParserStatus status, ir::Identifier *className = nullptr);

    [[nodiscard]] virtual std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &sourceFile);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseStatement(StatementParsingFlags flags = StatementParsingFlags::NONE);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseExpressionOrTypeAnnotation(lexer::TokenType type, ExpressionParseFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePatternElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS,
                                                bool allowDefault = true);
    virtual bool ParsePotentialNonNullExpression(ir::Expression **returnExpression, lexer::SourcePosition startLoc);
    virtual ir::AstNode *ParseImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers);
    virtual ir::Statement *ParseImportDeclaration(StatementParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePropertyDefinition(
        [[maybe_unused]] ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ObjectExpression *ParseObjectExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ArrayExpression *ParseArrayExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual ir::ArrowFunctionExpression *ParsePotentialArrowExpression(ir::Expression **returnExpression,
                                                                       const lexer::SourcePosition &startLoc);
    virtual bool ParsePotentialGenericFunctionCall(ir::Expression *primaryExpr, ir::Expression **returnExpression,
                                                   const lexer::SourcePosition &startLoc, bool ignoreCallExpression);
    virtual ir::Expression *ParsePotentialAsExpression(ir::Expression *primaryExpression);
    virtual bool IsNamedFunctionExpression();
    virtual ir::Identifier *ParsePrimaryExpressionIdent(ExpressionParseFlags flags);
    virtual void ValidateArrowFunctionRestParameter(ir::SpreadElement *restElement);
    virtual ir::Statement *ParsePotentialExpressionStatement(StatementParsingFlags flags);
    virtual ArenaVector<ir::Expression *> ParseFunctionParams();
    virtual ir::Expression *CreateParameterThis(util::StringView className);
    virtual ir::Expression *ParseFunctionParameter();
    virtual void ConvertThisKeywordToIdentIfNecessary() {}
    virtual void ParseCatchParamTypeAnnotation(ir::AnnotatedExpression *param);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                                      ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    virtual ir::Identifier *ParseClassIdent(ir::ClassDefinitionModifiers modifiers);
    virtual ir::Statement *ParsePotentialConstEnum(VariableParsingFlags flags);
    virtual ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags);
    virtual bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                                   ArenaVector<ir::AstNode *> &properties);
    virtual void ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *typeAnnotation);
    virtual ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc,
                                                   const ArenaVector<ir::AstNode *> &properties,
                                                   ir::Expression *propName, lexer::SourcePosition *propEnd);
    virtual void ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                     ir::Expression *propName, ir::ScriptFunction *func);
    virtual void ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                     ir::Expression *propName, ir::ScriptFunction *func);
    virtual ir::ModifierFlags ParseModifiers();
    virtual ir::Statement *ParseConstStatement(StatementParsingFlags flags);

    virtual ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags);
    virtual ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition startLoc,
                                                            VariableParsingFlags flags);
    virtual ir::VariableDeclarator *ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                                       const lexer::SourcePosition &startLoc);
    virtual bool IsModifierKind(const lexer::Token &token);
    virtual void ConsumeClassPrivateIdentifier(ClassElementDescriptor *desc, char32_t *nextCp);
    virtual void ThrowPossibleOutOfBoundaryJumpError(bool allowBreak);
    virtual void ThrowIllegalBreakError();
    virtual void ThrowIllegalContinueError();
    virtual void ThrowIfBodyEmptyError(ir::Statement *consequent);
    virtual void ThrowMultipleDefaultError();
    virtual void ThrowIllegalNewLineErrorAfterThrow();
    virtual void ThrowIfVarDeclaration(VariableParsingFlags flags);
    virtual ir::Expression *ParsePrefixAssertionExpression();
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual void ThrowErrorIfStaticConstructor(ir::ModifierFlags flags);
    virtual std::tuple<bool, bool, bool> ParseComputedClassFieldOrIndexSignature(ir::Expression **propName);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseUnaryOrPrefixUpdateExpression(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual ir::Expression *ParsePrimaryExpressionWithLiterals(ExpressionParseFlags flags);
    ir::Expression *ParseHashMaskOperator();
    ir::Expression *ParseClassExpression();
    ir::Expression *ParsePunctuators(ExpressionParseFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual ir::Expression *ParsePostPrimaryExpression(ir::Expression *primaryExpr, lexer::SourcePosition startLoc,
                                                       bool ignoreCallExpression, bool *isChainExpression);
    virtual ir::ClassElement *ParseClassStaticBlock();
    virtual ParserStatus ValidateArrowParameter(ir::Expression *expr, bool *seenOptional);
    virtual ArrowFunctionDescriptor ConvertToArrowParameter(ir::Expression *expr, bool isAsync);
    virtual ir::Expression *ParseNewExpression();

    virtual ir::TSTypeParameterDeclaration *ParseFunctionTypeParameters()
    {
        return nullptr;
    }

    virtual ir::TypeNode *ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
    {
        return nullptr;
    }

    virtual ir::ScriptFunctionFlags ParseFunctionThrowMarker([[maybe_unused]] const bool isRethrowsAllowed)
    {
        return ir::ScriptFunctionFlags::NONE;
    }

    using NodeFormatType = std::tuple<bool, char, std::size_t>;
    virtual ir::Identifier *ParseIdentifierFormatPlaceholder(std::optional<NodeFormatType> nodeFormat) const;
    virtual ir::Statement *ParseStatementFormatPlaceholder() const;
    virtual ArenaVector<ir::AstNode *> &ParseAstNodesArrayFormatPlaceholder() const;
    virtual ArenaVector<ir::Statement *> &ParseStatementsArrayFormatPlaceholder() const;
    virtual ArenaVector<ir::Expression *> &ParseExpressionsArrayFormatPlaceholder() const;

    virtual std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus newStatus, ParserStatus contextStatus);
    virtual ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers);
    virtual ir::Statement *ParseExportDeclaration(StatementParsingFlags flags);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ExportDefaultDeclaration *ParseExportDefaultDeclaration(const lexer::SourcePosition &startLoc,
                                                                        bool isExportEquals = false);
    virtual ir::ExportNamedDeclaration *ParseNamedExportDeclaration(const lexer::SourcePosition &startLoc);
    virtual void ValidateForInStatement() {};
    virtual ir::Statement *ParseTryStatement();
    virtual ir::ThrowStatement *ParseThrowStatement();
    virtual ir::DebuggerStatement *ParseDebuggerStatement();
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseModuleDeclaration(StatementParsingFlags flags = StatementParsingFlags::NONE)
    {
        return ParsePotentialExpressionStatement(flags);
    };

    virtual ir::Statement *ParseInterfaceDeclaration([[maybe_unused]] bool isStatic)
    {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_INTERFACE);
    }

    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseEnumDeclaration([[maybe_unused]] bool isConst = false,
                                                [[maybe_unused]] bool isStatic = false)
    {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_ENUM);
    }

    virtual std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseSuperClass();
    virtual ir::Expression *ParseSuperClassReference();

    using ClassBody = std::tuple<ir::MethodDefinition *, ArenaVector<ir::AstNode *>, lexer::SourceRange>;
    ClassBody ParseClassBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags = ir::ModifierFlags::NONE);

    Program *GetProgram() const
    {
        return program_;
    }

    void SetProgram(Program *program)
    {
        program_ = program;
    }

    lexer::Lexer *Lexer() const
    {
        return lexer_;
    }

    void SetLexer(lexer::Lexer *lexer)
    {
        lexer_ = lexer;
    }

    ParserContext &GetContext()
    {
        return context_;
    }

    const ParserContext &GetContext() const
    {
        return context_;
    }

    const CompilerOptions &GetOptions() const
    {
        return options_;
    }

    uint32_t &ClassId()
    {
        return classId_;
    }

private:
    Program *program_;
    ParserContext context_;
    ClassPrivateContext classPrivateContext_;
    uint32_t classId_ {};
    lexer::Lexer *lexer_ {};
    const CompilerOptions &options_;
};

template <ParserStatus STATUS>
class SavedStatusContext {
public:
    explicit SavedStatusContext(ParserContext *ctx)
        // NOLINTNEXTLINE(readability-magic-numbers)
        : ctx_(ctx), savedStatus_(static_cast<ParserStatus>(ctx->Status() & STATUS))
    {
        // NOLINTNEXTLINE(readability-magic-numbers)
        ctx->Status() |= STATUS;
    }

    NO_COPY_SEMANTIC(SavedStatusContext);
    NO_MOVE_SEMANTIC(SavedStatusContext);

    ~SavedStatusContext()
    {
        if (savedStatus_ == ParserStatus::NO_OPTS) {
            ctx_->Status() &= ~savedStatus_;
        }
    }

private:
    ParserContext *ctx_;
    ParserStatus savedStatus_;
};

class SwitchContext : public SavedStatusContext<ParserStatus::IN_SWITCH> {
public:
    explicit SwitchContext(ParserContext *ctx) : SavedStatusContext(ctx) {}
    NO_COPY_SEMANTIC(SwitchContext);
    NO_MOVE_SEMANTIC(SwitchContext);
    ~SwitchContext() = default;
};

class IterationContext : public SavedStatusContext<ParserStatus::IN_ITERATION> {
public:
    explicit IterationContext(ParserContext *ctx) : SavedStatusContext(ctx) {}

    NO_COPY_SEMANTIC(IterationContext);
    NO_MOVE_SEMANTIC(IterationContext);
    ~IterationContext() = default;
};

class FunctionParameterContext : public SavedStatusContext<ParserStatus::FUNCTION_PARAM> {
public:
    explicit FunctionParameterContext(ParserContext *ctx) : SavedStatusContext(ctx) {}

    NO_COPY_SEMANTIC(FunctionParameterContext);
    NO_MOVE_SEMANTIC(FunctionParameterContext);
    ~FunctionParameterContext() = default;
};

class SavedParserContext {
public:
    template <typename... Args>
    explicit SavedParserContext(ParserImpl *parser, Args &&...args) : parser_(parser), prev_(parser->context_)
    {
        parser_->context_ = ParserContext(&prev_, std::forward<Args>(args)...);
    }

    NO_COPY_SEMANTIC(SavedParserContext);
    DEFAULT_MOVE_SEMANTIC(SavedParserContext);

    ~SavedParserContext()
    {
        parser_->context_ = prev_;
    }

private:
    ParserImpl *parser_;
    ParserContext prev_;
};

class SavedClassPrivateContext {
public:
    explicit SavedClassPrivateContext(ParserImpl *parser) : parser_(parser), prev_(parser->classPrivateContext_)
    {
        parser_->classPrivateContext_ = ClassPrivateContext(&prev_);
    }

    NO_COPY_SEMANTIC(SavedClassPrivateContext);
    DEFAULT_MOVE_SEMANTIC(SavedClassPrivateContext);

    ~SavedClassPrivateContext()
    {
        parser_->classPrivateContext_ = prev_;
    }

private:
    ParserImpl *parser_;
    ClassPrivateContext prev_;
};

class FunctionContext : public SavedParserContext {
public:
    explicit FunctionContext(ParserImpl *parser, ParserStatus newStatus) : SavedParserContext(parser, newStatus)
    {
        if ((newStatus & ParserStatus::GENERATOR_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::GENERATOR;
        }

        if ((newStatus & ParserStatus::ASYNC_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::ASYNC;
        }

        if ((newStatus & ParserStatus::CONSTRUCTOR_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::CONSTRUCTOR;
        }
    }

    ir::ScriptFunctionFlags Flags() const
    {
        return flags_;
    }

    void AddFlag(ir::ScriptFunctionFlags flags)
    {
        flags_ |= flags;
    }

    NO_COPY_SEMANTIC(FunctionContext);
    NO_MOVE_SEMANTIC(FunctionContext);
    ~FunctionContext() = default;

private:
    ir::ScriptFunctionFlags flags_ {ir::ScriptFunctionFlags::NONE};
};

class ArrowFunctionContext : public FunctionContext {
public:
    explicit ArrowFunctionContext(ParserImpl *parser, bool isAsync)
        : FunctionContext(parser, InitialFlags(parser->context_.Status()))
    {
        if (isAsync) {
            AddFlag(ir::ScriptFunctionFlags::ASYNC);
        }

        AddFlag(ir::ScriptFunctionFlags::ARROW);
    }

    NO_COPY_SEMANTIC(ArrowFunctionContext);
    NO_MOVE_SEMANTIC(ArrowFunctionContext);
    ~ArrowFunctionContext() = default;

private:
    static ParserStatus InitialFlags(ParserStatus currentStatus)
    {
        return ParserStatus::FUNCTION | ParserStatus::ARROW_FUNCTION |
               static_cast<ParserStatus>(currentStatus & (ParserStatus::ALLOW_SUPER | ParserStatus::ALLOW_SUPER_CALL));
    }
};
}  // namespace ark::es2panda::parser
#endif
