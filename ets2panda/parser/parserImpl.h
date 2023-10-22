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

#ifndef ES2PANDA_PARSER_CORE_PARSER_IMPL_H
#define ES2PANDA_PARSER_CORE_PARSER_IMPL_H

#include "binder/binder.h"
#include "es2panda.h"
#include "ir/astNode.h"
#include "lexer/token/sourceLocation.h"
#include "lexer/token/tokenType.h"
#include "macros.h"
#include "mem/arena_allocator.h"
#include "parser/context/classPrivateContext.h"
#include "parser/context/parserContext.h"
#include "parser/parserFlags.h"
#include "parser/program/program.h"
#include "util/enumbitops.h"
#include "util/ustring.h"

#include <memory>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace panda::es2panda::lexer {
enum class TokenFlags : uint32_t;
class LexerPosition;
class Token;
class Lexer;
}  // namespace panda::es2panda::lexer

namespace panda::es2panda::ir {
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
}  // namespace panda::es2panda::ir

namespace panda::es2panda::parser {

using FunctionSignature = std::tuple<ir::TSTypeParameterDeclaration *, ArenaVector<ir::Expression *>, ir::TypeNode *,
                                     binder::FunctionParamScope *, panda::es2panda::ir::ScriptFunctionFlags>;

class ClassElementDescriptor {
public:
    explicit ClassElementDescriptor(ArenaAllocator *allocator) : decorators(allocator->Adapter()) {}

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<ir::Decorator *> decorators;
    ir::MethodDefinitionKind method_kind {};
    ParserStatus new_status {};
    ir::ModifierFlags modifiers {};
    lexer::SourcePosition method_start {};
    lexer::SourcePosition prop_start {};
    bool is_private_ident {};
    bool has_super_class {};
    bool is_generator {};
    bool invalid_computed_property {};
    bool is_computed {};
    bool is_index_signature {};
    bool class_method {};
    bool class_field {};
    binder::LocalScope *static_field_scope {};
    binder::LocalScope *static_method_scope {};
    binder::LocalScope *instance_field_scope {};
    binder::LocalScope *instance_method_scope {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class ArrowFunctionDescriptor {
public:
    explicit ArrowFunctionDescriptor(ArenaVector<ir::Expression *> &&p, binder::FunctionParamScope *ps,
                                     lexer::SourcePosition sl, ParserStatus ns)
        : params(p), param_scope(ps), start_loc(sl), new_status(ns)
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ArenaVector<ir::Expression *> params;
    binder::FunctionParamScope *param_scope;
    lexer::SourcePosition start_loc;
    ParserStatus new_status;
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
};

DEFINE_BITOPS(TypeAnnotationParsingOptions)

class ArrowFunctionContext;

class ParserImpl {
public:
    explicit ParserImpl(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS);
    NO_COPY_SEMANTIC(ParserImpl);
    NO_MOVE_SEMANTIC(ParserImpl);
    ~ParserImpl() = default;

    void ParseScript(const SourceFile &source_file, bool gen_std_lib);

    ScriptExtension Extension() const;

protected:
    virtual void ParseProgram(ScriptKind kind);
    static ExpressionParseFlags CarryExpressionParserFlag(ExpressionParseFlags origin, ExpressionParseFlags carry);
    static ExpressionParseFlags CarryPatternFlags(ExpressionParseFlags flags);

    void ThrowIfPrivateIdent(ClassElementDescriptor *desc, const char *msg);
    void ValidateClassKey(ClassElementDescriptor *desc);
    void ValidatePrivateIdentifier();
    ir::MethodDefinition *CheckClassMethodOverload(ir::Statement *property, ir::MethodDefinition **ctor,
                                                   lexer::SourcePosition error_info,
                                                   ir::MethodDefinition *last_overload, bool impl_exists,
                                                   bool is_abstract = false);

    void ValidateAccessor(ExpressionParseFlags flags, lexer::TokenFlags current_token_flags);
    void CheckPropertyKeyAsyncModifier(ParserStatus *method_status);
    ir::Property *ParseShorthandProperty(const lexer::LexerPosition *start_pos);
    void ParseGeneratorPropertyModifier(ExpressionParseFlags flags, ParserStatus *method_status);
    bool ParsePropertyModifiers(ExpressionParseFlags flags, ir::PropertyKind *property_kind,
                                ParserStatus *method_status);
    ir::Expression *ParsePropertyValue(const ir::PropertyKind *property_kind, const ParserStatus *method_status,
                                       ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    bool ParsePropertyEnd();

    // ExpressionParser.Cpp

    ir::Expression *ParseKeywordExpression();
    ir::Expression *ParseBinaryExpression(ir::Expression *left);
    void ValidateUpdateExpression(ir::Expression *return_expression, bool is_chain_expression);
    ir::Expression *ParseMemberExpression(bool ignore_call_expression = false,
                                          ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::MetaProperty *ParsePotentialNewTarget();
    void CheckInvalidDestructuring(const ir::AstNode *object) const;
    void ValidateParenthesizedExpression(ir::Expression *lhs_expression);
    ir::Expression *ParseImportExpression();
    ir::Expression *ParseOptionalChain(ir::Expression *left_side_expr);
    ir::Expression *ParsePropertyKey(ExpressionParseFlags flags);
    void ValidateAssignmentTarget(ExpressionParseFlags flags, ir::Expression *node);
    void ValidateLvalueAssignmentTarget(ir::Expression *node);
    void ValidateArrowParameterBindings(const ir::Expression *node);
    ir::Identifier *ParseNamedExport(const lexer::Token &exported_token);
    virtual void ParseTrailingBlock([[maybe_unused]] ir::CallExpression *call_expr) {}

    // StatementParser.Cpp

    void CheckFunctionDeclaration(StatementParsingFlags flags);
    void CheckLabelledFunction(const ir::Statement *node);
    bool ParseDirective(ArenaVector<ir::Statement *> *statements);
    void ParseDirectivePrologue(ArenaVector<ir::Statement *> *statements);
    ir::BlockStatement *ParseFunctionBody();
    std::tuple<ForStatementKind, ir::AstNode *, ir::Expression *, ir::Expression *> ParseForInOf(
        ir::Expression *left_node, ExpressionParseFlags expr_flags, bool is_await);
    std::tuple<ForStatementKind, ir::Expression *, ir::Expression *> ParseForInOf(ir::AstNode *init_node,
                                                                                  ExpressionParseFlags expr_flags,
                                                                                  bool is_await);
    std::tuple<ir::Expression *, ir::Expression *> ParseForUpdate(bool is_await);
    ir::SwitchCaseStatement *ParseSwitchCaseStatement(bool *seen_default);
    virtual ir::Expression *ParseCatchParam();
    ir::CatchClause *ParseCatchClause();
    ir::VariableDeclaration *ParseContextualLet(VariableParsingFlags flags,
                                                StatementParsingFlags stm_flags = StatementParsingFlags::ALLOW_LEXICAL);

    friend class Lexer;
    friend class SavedParserContext;
    friend class SavedClassPrivateContext;
    friend class ArrowFunctionContext;

    [[noreturn]] void ThrowParameterModifierError(ir::ModifierFlags status) const;
    [[noreturn]] void ThrowUnexpectedToken(lexer::TokenType token_type) const;
    [[noreturn]] void ThrowExpectedToken(lexer::TokenType token_type) const;
    [[noreturn]] void ThrowSyntaxError(std::string_view error_message) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list) const;
    [[noreturn]] void ThrowSyntaxError(std::initializer_list<std::string_view> list,
                                       const lexer::SourcePosition &pos) const;

    [[noreturn]] void ThrowSyntaxError(std::string_view error_message, const lexer::SourcePosition &pos) const;

    template <typename T, typename... Args>
    T *AllocNodeNoSetParent(Args &&...args)
    {
        auto *ret = program_->Allocator()->New<T>(std::forward<Args>(args)...);
        if (ret == nullptr) {
            throw Error(ErrorType::GENERIC, program_->SourceFile().Utf8(), "Unsuccessful allocation during parsing");
        }

        return ret;
    }

    template <typename T, typename... Args>
    T *AllocNode(Args &&...args)
    {
        auto *ret = AllocNodeNoSetParent<T>(std::forward<Args>(args)...);
        ret->Iterate([ret](auto *child) { child->SetParent(ret); });

        return ret;
    }

    ArenaAllocator *Allocator() const
    {
        return program_->Allocator();
    }

    binder::Binder *Binder()
    {
        return program_->Binder();
    }

    bool CheckModuleAsModifier();

    ir::Identifier *ExpectIdentifier(bool is_reference = false);
    void ExpectToken(lexer::TokenType token_type, bool consume_token = true);

    // ExpressionParser.cpp

    ir::SpreadElement *ParseSpreadElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::YieldExpression *ParseYieldExpression();
    virtual ir::Expression *ParsePotentialExpressionSequence(ir::Expression *expr, ExpressionParseFlags flags);
    ir::ArrowFunctionExpression *ParseArrowFunctionExpressionBody(ArrowFunctionContext *arrow_function_context,
                                                                  binder::FunctionScope *function_scope,
                                                                  ArrowFunctionDescriptor *desc,
                                                                  ir::TSTypeParameterDeclaration *type_param_decl,
                                                                  ir::TypeNode *return_type_annotation);
    ir::Expression *ParseAssignmentExpression(ir::Expression *expression,
                                              ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::SequenceExpression *ParseSequenceExpression(ir::Expression *start_expr, bool accept_rest = false);
    ir::FunctionExpression *ParseFunctionExpression(ParserStatus new_status = ParserStatus::NO_OPTS);
    ir::ArrowFunctionExpression *ParseArrowFunctionExpression(ir::Expression *expr,
                                                              ir::TSTypeParameterDeclaration *type_param_decl,
                                                              ir::TypeNode *return_type_annotation, bool is_async);
    ir::CallExpression *ParseCallExpression(ir::Expression *callee, bool is_optional_chain = false,
                                            bool handle_eval = true);
    ir::TemplateLiteral *ParseTemplateLiteral();
    ir::Expression *ParseLeftHandSideExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    void ParseNameSpaceImport(ArenaVector<ir::AstNode *> *specifiers);
    void ParseNamedImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers);
    ir::StringLiteral *ParseFromClause(bool require_from = true);

    ir::BooleanLiteral *ParseBooleanLiteral();
    ir::NullLiteral *ParseNullLiteral();
    ir::Literal *ParseNumberLiteral();
    ir::CharLiteral *ParseCharLiteral();
    ir::StringLiteral *ParseStringLiteral();
    virtual ir::ThisExpression *ParseThisExpression();
    ir::RegExpLiteral *ParseRegularExpression();
    ir::SuperExpression *ParseSuperExpression();
    ir::MemberExpression *ParseElementAccess(ir::Expression *primary_expr, bool is_optional = false);
    ir::MemberExpression *ParsePrivatePropertyAccess(ir::Expression *primary_expr);
    ir::MemberExpression *ParsePropertyAccess(ir::Expression *primary_expr, bool is_optional = false);
    void CreateAmendedBinaryExpression(ir::Expression *left, ir::Expression *right, lexer::TokenType operator_type);

    // StatementParser
    ArenaVector<ir::Statement *> ParseStatementList(StatementParsingFlags flags = StatementParsingFlags::ALLOW_LEXICAL);
    virtual ir::Statement *ParseAssertStatement();
    virtual void ValidateLabeledStatement(lexer::TokenType type);
    ir::BlockStatement *ParseBlockStatement();
    ir::BlockStatement *ParseBlockStatement(binder::Scope *scope);
    ir::EmptyStatement *ParseEmptyStatement();
    ir::Statement *ParseForStatement();
    ir::IfStatement *ParseIfStatement();
    virtual ir::Statement *ParseFunctionStatement(StatementParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ClassDeclaration *ParseClassStatement(StatementParsingFlags flags,
                                                      ir::ClassDefinitionModifiers modifiers,
                                                      ir::ModifierFlags mod_flags = ir::ModifierFlags::NONE);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ETSStructDeclaration *ParseStructStatement(StatementParsingFlags flags,
                                                           ir::ClassDefinitionModifiers modifiers,
                                                           ir::ModifierFlags mod_flags = ir::ModifierFlags::NONE);
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
                                                   const lexer::SourcePosition &start_loc);

    virtual void CreateImplicitConstructor(ir::MethodDefinition *&ctor, ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers,
                                           const lexer::SourcePosition &start_loc);
    void CheckClassGeneratorMethod(ClassElementDescriptor *desc, char32_t *next_cp);
    void ParseClassAccessor(ClassElementDescriptor *desc, char32_t *next_cp);
    ir::Expression *ParseClassKey(ClassElementDescriptor *desc);
    ir::ClassElement *ParseClassProperty(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                         ir::Expression *prop_name, ir::TypeNode *type_annotation);
    void AddPrivateElement(const ir::ClassElement *elem);
    ir::ScriptFunction *ParseFunction(ParserStatus new_status = ParserStatus::NO_OPTS);
    ir::ModifierFlags GetAccessability(ir::ModifierFlags modifiers);
    void CheckAccessorPair(const ArenaVector<ir::AstNode *> &properties, const ir::Expression *prop_name,
                           ir::MethodDefinitionKind method_kind, ir::ModifierFlags access);
    ir::Identifier *ParseNamedImport(const lexer::Token &imported_token);
    void ConsumeSemicolon(ir::Statement *statement);
    ir::ExportAllDeclaration *ParseExportAllDeclaration(const lexer::SourcePosition &start_loc);
    ir::ExportNamedDeclaration *ParseExportNamedSpecifiers(const lexer::SourcePosition &start_loc);
    ir::Statement *ParseVariableDeclaration(VariableParsingFlags flags = VariableParsingFlags::NO_OPTS);
    void ValidateDeclaratorId();
    void CheckRestrictedBinding();
    void CheckRestrictedBinding(lexer::TokenType keyword_type);
    void CheckRestrictedBinding(const util::StringView &ident, const lexer::SourcePosition &pos);

    ir::VariableDeclarator *ParseVariableDeclarator(VariableParsingFlags flags);
    ir::FunctionDeclaration *ParseFunctionDeclaration(bool can_be_anonymous = false,
                                                      ParserStatus new_status = ParserStatus::NO_OPTS);
    ir::ETSStructDeclaration *ParseStructDeclaration(ir::ClassDefinitionModifiers modifiers,
                                                     ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    ir::ClassDeclaration *ParseClassDeclaration(ir::ClassDefinitionModifiers modifiers,
                                                ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    FunctionSignature ParseFunctionSignature(ParserStatus status, ir::Identifier *class_name = nullptr);

    [[nodiscard]] virtual std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &source_file);
    virtual void AddVariableDeclarationBindings(ir::Expression *init, lexer::SourcePosition start_loc,
                                                VariableParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseStatement(StatementParsingFlags flags = StatementParsingFlags::NONE);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePatternElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS,
                                                bool allow_default = true);
    virtual bool ParsePotentialNonNullExpression(ir::Expression **return_expression, lexer::SourcePosition start_loc);
    virtual ir::AstNode *ParseImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers);
    virtual ir::Statement *ParseImportDeclaration(StatementParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePropertyDefinition(
        [[maybe_unused]] ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ObjectExpression *ParseObjectExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ArrayExpression *ParseArrayExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual ir::ArrowFunctionExpression *ParsePotentialArrowExpression(ir::Expression **return_expression,
                                                                       const lexer::SourcePosition &start_loc);
    virtual bool ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                                   const lexer::SourcePosition &start_loc, bool ignore_call_expression);
    virtual ir::Expression *ParsePotentialAsExpression(ir::Expression *primary_expr);
    virtual bool IsNamedFunctionExpression();
    virtual ir::Identifier *ParsePrimaryExpressionIdent(ExpressionParseFlags flags);
    virtual void ValidateArrowFunctionRestParameter(ir::SpreadElement *rest_element);
    virtual ir::Statement *ParsePotentialExpressionStatement(StatementParsingFlags flags);
    virtual ArenaVector<ir::Expression *> ParseFunctionParams();
    virtual ir::Expression *CreateParameterThis(util::StringView class_name);
    virtual ir::Expression *ParseFunctionParameter();
    virtual void ConvertThisKeywordToIdentIfNecessary() {}
    virtual void ParseCatchParamTypeAnnotation(ir::AnnotatedExpression *param);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                                      ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    virtual ir::Identifier *ParseClassIdent(ir::ClassDefinitionModifiers modifiers);
    virtual ir::Statement *ParsePotentialConstEnum(VariableParsingFlags flags);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers,
                                           ir::ModifierFlags flags = ir::ModifierFlags::NONE);
    virtual bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                                   ArenaVector<ir::AstNode *> &properties);
    virtual void ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *type_annotation);
    virtual ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc,
                                                   const ArenaVector<ir::AstNode *> &properties,
                                                   ir::Expression *prop_name, lexer::SourcePosition *prop_end);
    virtual void ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                     ir::Expression *prop_name, ir::ScriptFunction *func);
    virtual void ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                     ir::Expression *prop_name, ir::ScriptFunction *func);
    virtual ir::ModifierFlags ParseModifiers();
    virtual ir::Statement *ParseConstStatement(StatementParsingFlags flags);

    virtual ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags);
    virtual ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                            VariableParsingFlags flags);
    virtual ir::VariableDeclarator *ParseVariableDeclaratorInitializer(ir::Expression *init, VariableParsingFlags flags,
                                                                       const lexer::SourcePosition &start_loc);
    virtual void CreateFunctionDeclaration(ir::Identifier *ident_node, util::StringView &name, ir::ScriptFunction *func,
                                           const lexer::SourcePosition &start_loc);
    virtual bool IsModifierKind(const lexer::Token &token);
    virtual void ConsumeClassPrivateIdentifier(ClassElementDescriptor *desc, char32_t *next_cp);
    virtual void ThrowPossibleOutOfBoundaryJumpError(bool allow_break);
    virtual void ThrowIllegalBreakError();
    virtual void ThrowIllegalContinueError();
    virtual void ThrowIfBodyEmptyError(ir::Statement *consequent);
    virtual void ThrowMultipleDefaultError();
    virtual void ThrowIllegalNewLineErrorAfterThrow();
    virtual void ThrowIfVarDeclaration(VariableParsingFlags flags);
    virtual ir::Expression *ParsePrefixAssertionExpression();
    virtual ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList();
    virtual void ThrowErrorIfStaticConstructor(ir::ModifierFlags flags);
    virtual std::tuple<bool, bool, bool> ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParseUnaryOrPrefixUpdateExpression(
        ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Expression *ParsePrimaryExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    virtual ir::Expression *ParsePostPrimaryExpression(ir::Expression *primary_expr, lexer::SourcePosition start_loc,
                                                       bool ignore_call_expression, bool *is_chain_expression);
    virtual ir::ClassElement *ParseClassStaticBlock();
    virtual ParserStatus ValidateArrowParameter(ir::Expression *expr, bool *seen_optional);
    virtual ArrowFunctionDescriptor ConvertToArrowParameter(ir::Expression *expr, bool is_async,
                                                            binder::FunctionParamScope *param_scope);
    virtual ir::Expression *ParseNewExpression();

    virtual ir::TSTypeParameterDeclaration *ParseFunctionTypeParameters()
    {
        return nullptr;
    }

    virtual ir::TypeNode *ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
    {
        return nullptr;
    }

    virtual ir::ScriptFunctionFlags ParseFunctionThrowMarker([[maybe_unused]] const bool is_rethrows_allowed)
    {
        return ir::ScriptFunctionFlags::NONE;
    }

    virtual std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus new_status, ParserStatus context_status,
        binder::FunctionScope *func_scope);
    virtual ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers);
    virtual ir::Statement *ParseExportDeclaration(StatementParsingFlags flags);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::ExportDefaultDeclaration *ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                        bool is_export_equals = false);
    virtual ir::ExportNamedDeclaration *ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc);
    virtual void ValidateForInStatement() {};
    virtual ir::Statement *ParseTryStatement();
    virtual ir::ThrowStatement *ParseThrowStatement();
    virtual ir::DebuggerStatement *ParseDebuggerStatement();
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseModuleDeclaration(StatementParsingFlags flags = StatementParsingFlags::NONE)
    {
        return ParsePotentialExpressionStatement(flags);
    };

    virtual ir::Statement *ParseInterfaceDeclaration([[maybe_unused]] bool is_static)
    {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_INTERFACE);
    }

    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::Statement *ParseEnumDeclaration([[maybe_unused]] bool is_const = false,
                                                [[maybe_unused]] bool is_static = false)
    {
        ThrowUnexpectedToken(lexer::TokenType::KEYW_ENUM);
    }

    virtual std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseSuperClass();
    virtual ir::Expression *ParseSuperClassReference();

    using ClassBody = std::tuple<ir::MethodDefinition *, ArenaVector<ir::AstNode *>, lexer::SourceRange>;
    ClassBody ParseClassBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags = ir::ModifierFlags::NONE);

    virtual binder::Decl *BindClassName(ir::Identifier *ident_node);

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
        return class_id_;
    }

private:
    Program *program_;
    ParserContext context_;
    ClassPrivateContext class_private_context_;
    uint32_t class_id_ {};
    lexer::Lexer *lexer_ {};
    const CompilerOptions &options_;

    ir::ClassDefinition *GetAndBindClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                                   ir::ModifierFlags flags = ir::ModifierFlags::NONE);
};

template <ParserStatus STATUS>
class SavedStatusContext {
public:
    explicit SavedStatusContext(ParserContext *ctx)
        // NOLINTNEXTLINE(readability-magic-numbers)
        : ctx_(ctx), saved_status_(static_cast<ParserStatus>(ctx->Status() & STATUS))
    {
        // NOLINTNEXTLINE(readability-magic-numbers)
        ctx->Status() |= STATUS;
    }

    NO_COPY_SEMANTIC(SavedStatusContext);
    NO_MOVE_SEMANTIC(SavedStatusContext);

    ~SavedStatusContext()
    {
        if (saved_status_ == ParserStatus::NO_OPTS) {
            ctx_->Status() &= ~saved_status_;
        }
    }

private:
    ParserContext *ctx_;
    ParserStatus saved_status_;
};

class SwitchContext : public SavedStatusContext<ParserStatus::IN_SWITCH> {
public:
    explicit SwitchContext(ParserContext *ctx) : SavedStatusContext(ctx) {}
    NO_COPY_SEMANTIC(SwitchContext);
    NO_MOVE_SEMANTIC(SwitchContext);
    ~SwitchContext() = default;
};

template <typename T>
class IterationContext : public SavedStatusContext<ParserStatus::IN_ITERATION> {
public:
    explicit IterationContext(ParserContext *ctx, binder::Binder *binder)
        : SavedStatusContext(ctx), lexical_scope_(binder)
    {
    }

    NO_COPY_SEMANTIC(IterationContext);
    NO_MOVE_SEMANTIC(IterationContext);
    ~IterationContext() = default;

    const auto &LexicalScope() const
    {
        return lexical_scope_;
    }

private:
    binder::LexicalScope<T> lexical_scope_;
};

class FunctionParameterContext : public SavedStatusContext<ParserStatus::FUNCTION_PARAM> {
public:
    explicit FunctionParameterContext(ParserContext *ctx, binder::Binder *binder)
        : SavedStatusContext(ctx), lexical_scope_(binder)
    {
    }

    const auto &LexicalScope() const
    {
        return lexical_scope_;
    }

    NO_COPY_SEMANTIC(FunctionParameterContext);
    NO_MOVE_SEMANTIC(FunctionParameterContext);
    ~FunctionParameterContext() = default;

private:
    binder::LexicalScope<binder::FunctionParamScope> lexical_scope_;
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

protected:
    binder::Binder *Binder()
    {
        return parser_->Binder();
    }

private:
    ParserImpl *parser_;
    ParserContext prev_;
};

class SavedClassPrivateContext {
public:
    explicit SavedClassPrivateContext(ParserImpl *parser) : parser_(parser), prev_(parser->class_private_context_)
    {
        parser_->class_private_context_ = ClassPrivateContext(&prev_);
    }

    NO_COPY_SEMANTIC(SavedClassPrivateContext);
    DEFAULT_MOVE_SEMANTIC(SavedClassPrivateContext);

    ~SavedClassPrivateContext()
    {
        parser_->class_private_context_ = prev_;
    }

private:
    ParserImpl *parser_;
    ClassPrivateContext prev_;
};

class FunctionContext : public SavedParserContext {
public:
    explicit FunctionContext(ParserImpl *parser, ParserStatus new_status) : SavedParserContext(parser, new_status)
    {
        if ((new_status & ParserStatus::GENERATOR_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::GENERATOR;
        }

        if ((new_status & ParserStatus::ASYNC_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::ASYNC;
        }

        if ((new_status & ParserStatus::CONSTRUCTOR_FUNCTION) != 0) {
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
    explicit ArrowFunctionContext(ParserImpl *parser, bool is_async)
        : FunctionContext(parser, InitialFlags(parser->context_.Status()))
    {
        if (is_async) {
            AddFlag(ir::ScriptFunctionFlags::ASYNC);
        }

        AddFlag(ir::ScriptFunctionFlags::ARROW);
    }

    NO_COPY_SEMANTIC(ArrowFunctionContext);
    NO_MOVE_SEMANTIC(ArrowFunctionContext);
    ~ArrowFunctionContext() = default;

private:
    static ParserStatus InitialFlags(ParserStatus current_status)
    {
        return ParserStatus::FUNCTION | ParserStatus::ARROW_FUNCTION |
               static_cast<ParserStatus>(current_status & (ParserStatus::ALLOW_SUPER | ParserStatus::ALLOW_SUPER_CALL));
    }
};

class SavedBindingsContext {
public:
    explicit SavedBindingsContext(binder::Binder *binder)
        : binder_(binder), saved_bindings_(binder_->GetScope()->Bindings())
    {
    }
    NO_COPY_SEMANTIC(SavedBindingsContext);
    NO_MOVE_SEMANTIC(SavedBindingsContext);
    ~SavedBindingsContext() = default;

protected:
    ArenaAllocator *Allocator() const
    {
        return binder_->Allocator();
    }

    binder::Binder *Binder() const
    {
        return binder_;
    }

    binder::Scope::VariableMap SavedBindings() const
    {
        return saved_bindings_;
    }

private:
    binder::Binder *binder_;
    binder::Scope::VariableMap saved_bindings_;
};

class ExportDeclarationContext : public SavedBindingsContext {
public:
    explicit ExportDeclarationContext(binder::Binder *binder) : SavedBindingsContext(binder) {}
    NO_COPY_SEMANTIC(ExportDeclarationContext);
    NO_MOVE_SEMANTIC(ExportDeclarationContext);
    ~ExportDeclarationContext() = default;

    void BindExportDecl(ir::AstNode *export_decl);

protected:
    static constexpr std::string_view DEFAULT_EXPORT = "*default*";
};

class ImportDeclarationContext : public SavedBindingsContext {
public:
    explicit ImportDeclarationContext(binder::Binder *binder) : SavedBindingsContext(binder) {}

    NO_COPY_SEMANTIC(ImportDeclarationContext);
    NO_MOVE_SEMANTIC(ImportDeclarationContext);

    ~ImportDeclarationContext() = default;

    void BindImportDecl(ir::ImportDeclaration *import_decl);

private:
};
}  // namespace panda::es2panda::parser

#endif
