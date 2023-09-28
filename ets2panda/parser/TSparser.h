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

#ifndef ES2PANDA_PARSER_CORE_TS_PARSER_H
#define ES2PANDA_PARSER_CORE_TS_PARSER_H

#include "TypedParser.h"

namespace panda::es2panda::ir {
class Decorator;
enum class TSTupleKind;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::parser {
class TSParser : public TypedParser {
public:
    TSParser(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS)
        : TypedParser(program, options, status)
    {
    }

private:
    [[nodiscard]] std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &source_file) override;
    bool IsStartOfMappedType() const;
    bool IsStartOfTypePredicate() const;
    bool IsStartOfAbstractConstructorType() const;
    bool CurrentLiteralIsBasicType() const;
    ir::TypeNode *ParseTypeAnnotationElement(ir::TypeNode *type_annotation, TypeAnnotationParsingOptions *options);
    ir::TypeNode *ParseTypeOperatorOrTypeReference();
    ir::TypeNode *ParseIdentifierReference();
    ir::TypeNode *ParseBasicType();
    ir::TSTypeReference *ParseConstExpression();
    ir::TSIntersectionType *ParseIntersectionType(ir::Expression *type, bool in_union, bool restrict_extends);
    ir::TSUnionType *ParseUnionType(ir::TypeNode *type, bool restrict_extends);
    ir::TypeNode *ParseParenthesizedOrFunctionType(ir::TypeNode *type_annotation, bool throw_error);
    ir::TSArrayType *ParseArrayType(ir::TypeNode *element_type);
    ir::TypeNode *ParseFunctionType(lexer::SourcePosition start_loc, bool is_construction_type, bool throw_error,
                                    bool abstract_constructor = false);
    ir::TSTypeParameter *ParseMappedTypeParameter();
    ir::MappedOption ParseMappedOption(lexer::TokenType token_type);
    ir::TSMappedType *ParseMappedType();
    ir::TSTypePredicate *ParseTypePredicate();
    ir::TypeNode *ParseConditionalType(ir::Expression *check_type, bool restrict_extends);
    ir::TypeNode *ParseThisType(bool throw_error);
    ir::TypeNode *ParseIndexAccessType(ir::TypeNode *type_name);
    ir::TypeNode *ParseTypeReferenceOrQuery(bool parse_query = false);
    ir::TypeNode *ParseTupleElement(ir::TSTupleKind *kind, bool *seen_optional);
    ir::TSTupleType *ParseTupleType();
    ir::TSImportType *ParseImportType(const lexer::SourcePosition &start_loc, bool is_typeof = false);
    ir::TypeNode *ParseTypeLiteralOrMappedType(ir::TypeNode *type_annotation);
    ir::TypeNode *ParseTypeReferenceOrTypePredicate(ir::TypeNode *type_annotation, bool can_be_ts_type_predicate);
    ir::TypeNode *ParseThisTypeOrTypePredicate(ir::TypeNode *type_annotation, bool can_be_ts_type_predicate,
                                               bool throw_error);
    ir::TSSignatureDeclaration *ParseSignatureMember(bool is_call_signature);
    bool IsPotentiallyIndexSignature();
    void CreateTSVariableForProperty(ir::AstNode *node, const ir::Expression *key, binder::VariableFlags flags);
    void ValidateFunctionParam(const ArenaVector<ir::Expression *> &params, const ir::Expression *parameter,
                               bool *seen_optional);
    ir::TSParameterProperty *CreateParameterProperty(ir::Expression *parameter, ir::ModifierFlags modifiers);
    void ValidateFunctionOverloadParams(const ArenaVector<ir::Expression *> &params);
    ir::Expression *ParseModuleReference();
    ir::TSImportEqualsDeclaration *ParseTsImportEqualsDeclaration(const lexer::SourcePosition &start_loc,
                                                                  bool is_export = false);
    void ParseOptionalFunctionParameter(ir::AnnotatedExpression *return_node, bool is_rest = false);

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseStatement(StatementParsingFlags flags = StatementParsingFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePatternElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS,
                                        bool allow_default = true) override;
    bool CurrentIsBasicType() override;
    ir::TypeNode *ParseTypeAnnotation(TypeAnnotationParsingOptions *options) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ObjectExpression *ParseObjectExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ArrayExpression *ParseArrayExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::ArrowFunctionExpression *ParsePotentialArrowExpression(ir::Expression **return_expression,
                                                               const lexer::SourcePosition &start_loc) override;
    bool ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                           const lexer::SourcePosition &start_loc,
                                           bool ignore_call_expression) override;
    bool ParsePotentialNonNullExpression(ir::Expression **return_expression, lexer::SourcePosition start_loc) override;
    bool IsNamedFunctionExpression() override;
    ir::Identifier *ParsePrimaryExpressionIdent(ExpressionParseFlags flags) override;
    void ValidateArrowFunctionRestParameter(ir::SpreadElement *rest_element) override;
    ir::Decorator *ParseDecorator() override;
    void AddDecorators(ir::AstNode *node, ArenaVector<ir::Decorator *> &decorators) override;
    ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration() override;
    ir::AstNode *ParseTypeLiteralOrInterfaceMember() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::TSIndexSignature *ParseIndexSignature(const lexer::SourcePosition &start_loc,
                                              bool is_readonly = false) override;
    ir::AstNode *ParsePropertyOrMethodSignature(const lexer::SourcePosition &start_loc, bool is_readonly) override;
    std::tuple<ir::Expression *, bool> ParseInterfacePropertyKey() override;
    ArenaVector<ir::Expression *> ParseFunctionParams() override;
    ir::Expression *ParseFunctionParameter() override;
    ir::TypeNode *ParseClassKeyAnnotation() override;
    void ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *type_annotation) override;
    ir::MethodDefinition *ParseClassMethod(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                           ir::Expression *prop_name, lexer::SourcePosition *prop_end) override;
    void ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                             ir::Expression *prop_name, ir::ScriptFunction *func) override;
    void ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                             ir::Expression *prop_name, ir::ScriptFunction *func) override;
    bool IsModifierKind(const lexer::Token &token) override;
    void CheckIfTypeParameterNameIsReserved() override;
    void ThrowErrorIfStaticConstructor(ir::ModifierFlags flags) override;
    std::tuple<bool, bool, bool> ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name) override;
    ir::TypeNode *ParseFunctionReturnType(ParserStatus status) override;
    std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus new_status, ParserStatus context_status,
        binder::FunctionScope *func_scope) override;
    ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers) override;
    ir::Statement *ParseExportDeclaration(StatementParsingFlags flags) override;
    ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList() override;
    ir::Statement *ParseConstStatement(StatementParsingFlags flags) override;
    ir::Statement *ParsePotentialConstEnum(VariableParsingFlags flags) override;
    void ParseCatchParamTypeAnnotation(ir::AnnotatedExpression *param) override;
    ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags) override;
    void ThrowPossibleOutOfBoundaryJumpError(bool allow_break) override;
    void ThrowIllegalBreakError() override;
    void ThrowIllegalContinueError() override;
    void ThrowIfBodyEmptyError(ir::Statement *consequent) override;
    void ThrowMultipleDefaultError() override;
    void ThrowIllegalNewLineErrorAfterThrow() override;
    void CreateFunctionDeclaration(ir::Identifier *ident_node, util::StringView &name, ir::ScriptFunction *func,
                                   const lexer::SourcePosition &start_loc) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ExportDefaultDeclaration *ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                bool is_export_equals = false) override;
    ir::ExportNamedDeclaration *ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc) override;
    ir::Statement *ParseImportDeclaration(StatementParsingFlags flags) override;
    void ValidateIndexSignatureTypeAnnotation(ir::TypeNode *type_annotation) override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *expr) override;

    bool AllowInterfaceRedeclaration() override
    {
        return true;
    }
};
}  // namespace panda::es2panda::parser

#endif
