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

#ifndef ES2PANDA_PARSER_CORE_AS_PARSER_H
#define ES2PANDA_PARSER_CORE_AS_PARSER_H

#include "TypedParser.h"

namespace panda::es2panda::parser {
class ASParser : public TypedParser {
public:
    ASParser(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS)
        : TypedParser(program, options, status)
    {
    }

private:
    [[nodiscard]] std::unique_ptr<lexer::Lexer> InitLexer(const SourceFile &source_file) override;
    ir::TypeNode *ParseParenthesizedOrFunctionType(bool throw_error);
    ir::TypeNode *ParseFunctionType(lexer::SourcePosition start_loc);
    void ParseOptionalFunctionParameter(ir::AnnotatedExpression *return_node, bool in_rest = false);

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseStatement(StatementParsingFlags flags = StatementParsingFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePatternElement(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS,
                                        bool allow_default = true) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParsePropertyDefinition(
        [[maybe_unused]] ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    bool CurrentIsBasicType() override;
    ir::TypeNode *ParseTypeAnnotation(TypeAnnotationParsingOptions *options) override;
    ir::ArrowFunctionExpression *ParsePotentialArrowExpression(ir::Expression **return_expression,
                                                               const lexer::SourcePosition &start_loc) override;
    bool ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                           const lexer::SourcePosition &start_loc,
                                           bool ignore_call_expression) override;
    bool ParsePotentialNonNullExpression(ir::Expression **return_expression, lexer::SourcePosition start_loc) override;
    bool IsNamedFunctionExpression() override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *primary_expression) override;
    ir::Identifier *ParsePrimaryExpressionIdent(ExpressionParseFlags flags) override;
    void ValidateArrowFunctionRestParameter(ir::SpreadElement *rest_element) override;
    ir::Decorator *ParseDecorator() override;
    void AddDecorators(ir::AstNode *node, ArenaVector<ir::Decorator *> &decorators) override;
    ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration() override;
    ArenaVector<ir::TSInterfaceHeritage *> ParseInterfaceExtendsClause() override;
    ir::AstNode *ParseTypeLiteralOrInterfaceMember() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::TSIndexSignature *ParseIndexSignature(const lexer::SourcePosition &start_loc,
                                              bool is_readonly = false) override;
    ir::AstNode *ParsePropertyOrMethodSignature(const lexer::SourcePosition &start_loc, bool is_readonly) override;
    ir::TypeNode *ParseClassKeyAnnotation() override;
    void ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *type_annotation) override;
    void ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                             ir::Expression *prop_name, ir::ScriptFunction *func) override;
    void ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                             ir::Expression *prop_name, ir::ScriptFunction *func) override;
    bool IsModifierKind(const lexer::Token &token) override;
    void ConsumeClassPrivateIdentifier(ClassElementDescriptor *desc, char32_t *next_cp) override;
    std::tuple<bool, bool, bool> ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name) override;
    std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParseFunctionBody(
        const ArenaVector<ir::Expression *> &params, ParserStatus new_status, ParserStatus context_status,
        binder::FunctionScope *func_scope) override;
    ir::AstNode *ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers) override;
    std::tuple<ir::Expression *, bool> ParseInterfacePropertyKey() override;
    ir::Expression *ParseCoverParenthesizedExpressionAndArrowParameterList() override;
    ir::Expression *ParsePrefixAssertionExpression() override;
    ir::Statement *ParseConstStatement(StatementParsingFlags flags) override;
    ir::AnnotatedExpression *ParseVariableDeclaratorKey(VariableParsingFlags flags) override;
    ir::Statement *ParsePotentialConstEnum(VariableParsingFlags flags) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ExportDefaultDeclaration *ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                bool is_export_equals = false) override;
    ir::ExportNamedDeclaration *ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc) override;
    ir::AstNode *ParseImportSpecifiers(ArenaVector<ir::AstNode *> *specifiers) override;
    ir::Statement *ParseImportDeclaration(StatementParsingFlags flags) override;
    ArenaVector<ir::TSClassImplements *> ParseClassImplementClause() override;
    ir::ClassElement *ParseClassStaticBlock() override;
    void ParseOptionalClassElement(ClassElementDescriptor *desc) override;
    void ValidateIndexSignatureTypeAnnotation(ir::TypeNode *type_annotation) override;
    ArrowFunctionDescriptor ConvertToArrowParameter(ir::Expression *expr, bool is_async,
                                                    binder::FunctionParamScope *param_scope) override;
    ParserStatus ValidateArrowParameter(ir::Expression *expr, bool *seen_optional) override;
    void ThrowIllegalBreakError() override;
    void ThrowIllegalContinueError() override;
};
}  // namespace panda::es2panda::parser

#endif
