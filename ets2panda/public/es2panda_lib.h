/*
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

#ifndef ES2PANDA_LIB
#define ES2PANDA_LIB

// Switch off the linter for C header
// NOLINTBEGIN

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ES2PANDA_LIB_VERSION 1

typedef struct es2panda_Config es2panda_Config;
typedef struct es2panda_Context es2panda_Context;

typedef struct es2panda_Program es2panda_Program;
typedef struct es2panda_ExternalSource es2panda_ExternalSource;
typedef struct es2panda_AstNode es2panda_AstNode;
typedef struct es2panda_Type es2panda_Type;
typedef struct es2panda_Variable es2panda_Variable;
typedef struct es2panda_Scope es2panda_Scope;

enum es2panda_ContextState {
    ES2PANDA_STATE_NEW,
    ES2PANDA_STATE_PARSED,
    ES2PANDA_STATE_SCOPE_INITED,
    ES2PANDA_STATE_CHECKED,
    ES2PANDA_STATE_LOWERED,
    ES2PANDA_STATE_ASM_GENERATED,
    ES2PANDA_STATE_BIN_GENERATED,

    ES2PANDA_STATE_ERROR
};
typedef enum es2panda_ContextState es2panda_ContextState;

// NB: has to be synchronized with astNode.h
enum es2panda_ModifierFlags {
    ES2PANDA_MODIFIER_NONE = 0U,
    ES2PANDA_MODIFIER_STATIC = 1U << 0U,
    ES2PANDA_MODIFIER_ASYNC = 1U << 1U,
    ES2PANDA_MODIFIER_PUBLIC = 1U << 2U,
    ES2PANDA_MODIFIER_PROTECTED = 1U << 3U,
    ES2PANDA_MODIFIER_PRIVATE = 1U << 4U,
    ES2PANDA_MODIFIER_DECLARE = 1U << 5U,
    ES2PANDA_MODIFIER_READONLY = 1U << 6U,
    ES2PANDA_MODIFIER_OPTIONAL = 1U << 7U,
    ES2PANDA_MODIFIER_DEFINITE = 1U << 8U,
    ES2PANDA_MODIFIER_ABSTRACT = 1U << 9U,
    ES2PANDA_MODIFIER_CONST = 1U << 10U,
    ES2PANDA_MODIFIER_FINAL = 1U << 11U,
    ES2PANDA_MODIFIER_NATIVE = 1U << 12U,
    ES2PANDA_MODIFIER_OVERRIDE = 1U << 13U,
    ES2PANDA_MODIFIER_CONSTRUCTOR = 1U << 14U,
    ES2PANDA_MODIFIER_SYNCHRONIZED = 1U << 15U,
    ES2PANDA_MODIFIER_FUNCTIONAL = 1U << 16U,
    ES2PANDA_MODIFIER_IN = 1U << 17U,
    ES2PANDA_MODIFIER_OUT = 1U << 18U,
    ES2PANDA_MODIFIER_INTERNAL = 1U << 19U,
    ES2PANDA_MODIFIER_EXPORT = 1U << 22U,
    ES2PANDA_MODIFIER_SETTER = 1U << 23U,
    ES2PANDA_MODIFIER_DEFAULT_EXPORT = 1U << 24U,
};
typedef enum es2panda_ModifierFlags es2panda_ModifierFlags;

// Has to be synchronized with astNode.h
enum es2panda_ScriptFunctionFlags {
    ES2PANDA_SCRIPT_FUNCTION_NONE = 0,
    ES2PANDA_SCRIPT_FUNCTION_GENERATOR = 1U << 0U,
    ES2PANDA_SCRIPT_FUNCTION_ASYNC = 1U << 1U,
    ES2PANDA_SCRIPT_FUNCTION_ARROW = 1U << 2U,
    ES2PANDA_SCRIPT_FUNCTION_EXPRESSION = 1U << 3U,
    ES2PANDA_SCRIPT_FUNCTION_OVERLOAD = 1U << 4U,
    ES2PANDA_SCRIPT_FUNCTION_CONSTRUCTOR = 1U << 5U,
    ES2PANDA_SCRIPT_FUNCTION_METHOD = 1U << 6U,
    ES2PANDA_SCRIPT_FUNCTION_STATIC_BLOCK = 1U << 7U,
    ES2PANDA_SCRIPT_FUNCTION_HIDDEN = 1U << 8U,
    ES2PANDA_SCRIPT_FUNCTION_IMPLICIT_SUPER_CALL_NEEDED = 1U << 9U,
    ES2PANDA_SCRIPT_FUNCTION_ENUM = 1U << 10U,
    ES2PANDA_SCRIPT_FUNCTION_EXTERNAL = 1U << 11U,
    ES2PANDA_SCRIPT_FUNCTION_PROXY = 1U << 12U,
    ES2PANDA_SCRIPT_FUNCTION_THROWS = 1U << 13U,
    ES2PANDA_SCRIPT_FUNCTION_RETHROWS = 1U << 14U,
    ES2PANDA_SCRIPT_FUNCTION_GETTER = 1U << 15U,
    ES2PANDA_SCRIPT_FUNCTION_SETTER = 1U << 16U,
    ES2PANDA_SCRIPT_FUNCTION_ENTRY_POINT = 1U << 17U,
    ES2PANDA_SCRIPT_FUNCTION_INSTANCE_EXTENSION_METHOD = 1U << 18U,
    ES2PANDA_SCRIPT_FUNCTION_HAS_RETURN = 1U << 19U
};
typedef enum es2panda_ScriptFunctionFlags es2panda_ScriptFunctionFlags;

// Needs to be synchronized with memberExpression.h
enum es2panda_MemberExpressionKind {
    ES2PANDA_MEMBER_EXPRESSION_KIND_NONE = 0,
    ES2PANDA_MEMBER_EXPRESSION_KIND_ELEMENT_ACCESS = 1U << 0U,
    ES2PANDA_MEMBER_EXPRESSION_KIND_PROPERTY_ACCESS = 1U << 1U,
    ES2PANDA_MEMBER_EXPRESSION_KIND_GETTER = 1U << 2U,
    ES2PANDA_MEMBER_EXPRESSION_KIND_SETTER = 1U << 3U
};
typedef enum es2panda_MemberExpressionKind es2panda_MemberExpressionKind;

struct es2panda_Impl {
    int version;

    es2panda_Config *(*CreateConfig)(int argc, char const **argv);
    void (*DestroyConfig)(es2panda_Config *config);

    es2panda_Context *(*CreateContextFromFile)(es2panda_Config *config, char const *source_file_name);
    es2panda_Context *(*CreateContextFromString)(es2panda_Config *config, char const *source, char const *file_name);
    es2panda_Context *(*ProceedToState)(es2panda_Context *context, es2panda_ContextState state);  // context is consumed
    void (*DestroyContext)(es2panda_Context *context);

    es2panda_ContextState (*ContextState)(es2panda_Context *context);
    char const *(*ContextErrorMessage)(es2panda_Context *context);

    es2panda_Program *(*ContextProgram)(es2panda_Context *context);
    es2panda_AstNode *(*ProgramAst)(es2panda_Program *program);
    es2panda_ExternalSource **(*ProgramExternalSources)(es2panda_Program *program, size_t *len_p);
    char const *(*ExternalSourceName)(es2panda_ExternalSource *e_source);
    es2panda_Program **(*ExternalSourcePrograms)(es2panda_ExternalSource *e_source, size_t *len_p);

    es2panda_Type *(*AstNodeType)(es2panda_AstNode *ast);
    void (*AstNodeSetType)(es2panda_AstNode *ast, es2panda_Type *type);

    es2panda_AstNode *const *(*AstNodeDecorators)(es2panda_AstNode *ast, size_t *size_p);
    void (*AstNodeSetDecorators)(es2panda_Context *context, es2panda_AstNode *ast, es2panda_AstNode **decorators,
                                 size_t n_decorators);

    es2panda_ModifierFlags (*AstNodeModifierFlags)(es2panda_AstNode *ast);

    void (*AstNodeForEach)(es2panda_AstNode *ast, void (*func)(es2panda_AstNode *, void *), void *arg);

    bool (*IsArrowFunctionExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateArrowFunctionExpression)(es2panda_Context *context, es2panda_AstNode *script_function);
    es2panda_AstNode *(*ArrowFunctionExpressionScriptFunction)(es2panda_AstNode *ast);

    bool (*IsAsExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateAsExpression)(es2panda_Context *context, es2panda_AstNode *expr,
                                            es2panda_AstNode *type_annotation, bool is_const);
    es2panda_AstNode *(*AsExpressionExpr)(es2panda_AstNode *ast);
    es2panda_AstNode *(*AsExpressionTypeAnnotation)(es2panda_AstNode *ast);
    bool (*AsExpressionIsConst)(es2panda_AstNode *ast);
    void (*AsExpressionSetExpr)(es2panda_AstNode *ast, es2panda_AstNode *expr);
    void (*AsExpressionSetTypeAnnotation)(es2panda_AstNode *ast, es2panda_AstNode *type_annotation);

    bool (*IsAssignmentExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateAssignmentExpression)(es2panda_Context *context, es2panda_AstNode *left,
                                                    es2panda_AstNode *right, char const *operator_type);
    es2panda_AstNode *(*AssignmentExpressionLeft)(es2panda_AstNode *ast);
    es2panda_AstNode *(*AssignmentExpressionRight)(es2panda_AstNode *ast);
    char const *(*AssignmentExpressionOperatorType)(es2panda_AstNode *ast);
    void (*AssignmentExpressionSetOperatorType)(es2panda_AstNode *ast, char const *operator_type);

    bool (*IsBinaryExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreatebinaryExpression)(es2panda_Context *context, es2panda_AstNode *left,
                                                es2panda_AstNode *right, char const *operator_type);
    es2panda_AstNode *(*BinaryExpressionLeft)(es2panda_AstNode *ast);
    es2panda_AstNode *(*BinaryExpressionRight)(es2panda_AstNode *ast);
    char const *(*BinaryExpressionOperator)(es2panda_AstNode *ast);
    void (*BinaryExpressionSetOperator)(es2panda_AstNode *ast, char const *operator_type);

    bool (*IsBlockStatement)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateBlockStatement)(es2panda_Context *context);
    es2panda_AstNode **(*BlockStatementStatements)(es2panda_AstNode *ast, size_t *size_p);
    void (*BlockStatementAddStatement)(es2panda_AstNode *ast, es2panda_AstNode *statement);

    bool (*IsCallExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateCallExpression)(es2panda_Context *context, es2panda_AstNode *callee,
                                              es2panda_AstNode *type_arguments, es2panda_AstNode **arguments,
                                              size_t n_arguments, bool optional);
    es2panda_AstNode const *(*CallExpressionCallee)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*CallExpressionTypeArguments)(es2panda_AstNode *ast);
    es2panda_AstNode **(*CallExpressionArguments)(es2panda_AstNode *ast, size_t *size_p);
    bool (*CallExpressionIsOptional)(es2panda_AstNode *ast);
    void (*CallExpressionSetTypeArguments)(es2panda_AstNode *ast, es2panda_AstNode *type_arguments);

    bool (*IsChainExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateChainExpression)(es2panda_Context *context, es2panda_AstNode *child);
    es2panda_AstNode const *(*ChainExpressionChild)(es2panda_AstNode *ast);

    bool (*IsClassDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateClassDeclaration)(es2panda_Context *context, es2panda_AstNode *definition);
    es2panda_AstNode *(*ClassDeclarationDefinition)(es2panda_AstNode *ast);

    bool (*IsClassDefinition)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateClassDefinition)(es2panda_Context *context, es2panda_AstNode *identifier,
                                               es2panda_ModifierFlags flags);
    es2panda_AstNode *(*ClassDefinitionIdentifier)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ClassDefinitionTypeParameters)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ClassDefinitionSuperClass)(es2panda_AstNode *ast);
    es2panda_AstNode **(*ClassDefinitionImplements)(es2panda_AstNode *ast, size_t *size_p);
    es2panda_AstNode *(*ClassDefinitionConstructor)(es2panda_AstNode *ast);
    es2panda_AstNode **(*ClassDefinitionBody)(es2panda_AstNode *ast, size_t *size_p);
    void (*ClassDefinitionSetIdentifier)(es2panda_AstNode *ast, es2panda_AstNode *identifier);
    void (*ClassDefinitionSetTypeParameters)(es2panda_AstNode *ast, es2panda_AstNode *type_params);
    void (*ClassDefinitionSetSuperClass)(es2panda_AstNode *ast, es2panda_AstNode *super_class);
    void (*ClassDefinitionSetImplements)(es2panda_AstNode *ast, es2panda_AstNode **implements, size_t n_implements);
    void (*ClassDefinitionAddImplements)(es2panda_AstNode *ast, es2panda_AstNode *implements);
    void (*ClassDefinitionSetConstructor)(es2panda_AstNode *ast, es2panda_AstNode *constructor);
    void (*ClassDefinitonSetBody)(es2panda_AstNode *ast, es2panda_AstNode **body, size_t n_elems);
    void (*ClassDefinitonAddToBody)(es2panda_AstNode *ast, es2panda_AstNode *statement);

    es2panda_AstNode *(*ClassElementKey)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ClassElementValue)(es2panda_AstNode *ast);

    bool (*IsClassImplementsClause)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateClassImplementsClause)(es2panda_Context *context, es2panda_AstNode *expression,
                                                     es2panda_AstNode *type_arguments);
    es2panda_AstNode *(*ClassImplementsClauseExpression)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*ClassImplementsClauseTypeArguments)(es2panda_AstNode *ast);

    bool (*IsClassProperty)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateClassProperty)(es2panda_Context *context, es2panda_AstNode *key, es2panda_AstNode *value,
                                             es2panda_AstNode *type_annotation, es2panda_ModifierFlags modifier_flags,
                                             bool is_computed);
    es2panda_AstNode *(*ClassPropertyTypeAnnotation)(es2panda_AstNode *ast);

    bool (*IsExpressionStatement)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateExpressionStatement)(es2panda_Context *context, es2panda_AstNode *expression);
    es2panda_AstNode *(*ExpressionStatementExpression)(es2panda_AstNode *ast);

    bool (*IsFunctionDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateFunctionDeclaration)(es2panda_Context *context, es2panda_AstNode *function);
    es2panda_AstNode *(*FunctionDeclarationFunction)(es2panda_AstNode *ast);

    bool (*IsFunctionExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateFunctionExpression)(es2panda_Context *context, es2panda_AstNode *function);
    es2panda_AstNode *(*FunctionExpressionFunction)(es2panda_AstNode *ast);

    bool (*IsFunctionTypeNode)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateFunctionTypeNode)(es2panda_Context *context, es2panda_AstNode *type_params,
                                                es2panda_AstNode **params, size_t n_params,
                                                es2panda_AstNode *return_type, es2panda_ScriptFunctionFlags func_flags);
    es2panda_AstNode const *(*FunctionTypeNodeTypeParams)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*FunctionTypeNodeParams)(es2panda_AstNode *ast, size_t *size_p);
    es2panda_AstNode *(*FunctionTypeNodeReturnType)(es2panda_AstNode *ast);
    es2panda_ScriptFunctionFlags (*FunctionTypeNodeFlags)(es2panda_AstNode *ast);

    bool (*IsIdentifier)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateIdentifier)(es2panda_Context *context, char const *name,
                                          es2panda_AstNode *type_annotation);
    char const *(*IdentifierName)(es2panda_Context *context, es2panda_AstNode *identifier);
    es2panda_AstNode *(*IdentifierTypeAnnotation)(es2panda_AstNode *identifier);
    es2panda_Variable *(*IdentifierVariable)(es2panda_AstNode *identifier);
    void (*IdentifierSetVariable)(es2panda_AstNode *identifier, es2panda_Variable *variable);

    bool (*IsIfStatement)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateIfStatement)(es2panda_Context *context, es2panda_AstNode *test,
                                           es2panda_AstNode *consequent, es2panda_AstNode *alternate);
    es2panda_AstNode const *(*IfStatementTest)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*IfStatementConsequent)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*IfStatementAlternate)(es2panda_AstNode *ast);

    bool (*IsImportDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateImportDeclaration)(es2panda_Context *context, es2panda_AstNode *source,
                                                 es2panda_AstNode **specifiers, size_t n_specifiers);
    es2panda_AstNode const *(*ImportDeclarationSource)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*ImportDeclarationSpecifiers)(es2panda_AstNode *ast, size_t *size_p);

    bool (*IsImportExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateImportExpression)(es2panda_Context *context, es2panda_AstNode *source);
    es2panda_AstNode *(*ImportExpressionSource)(es2panda_AstNode *ast);

    bool (*IsImportSpecifier)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateImportSpecifier)(es2panda_Context *context, es2panda_AstNode *imported,
                                               es2panda_AstNode *local);
    es2panda_AstNode *(*ImportSpecifierImported)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ImportSpecifierLocal)(es2panda_AstNode *ast);

    bool (*IsMemberExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateMemberExpression)(es2panda_Context *context, es2panda_AstNode *object,
                                                es2panda_AstNode *property, es2panda_MemberExpressionKind kind,
                                                bool is_computed, bool is_optional);
    es2panda_AstNode *(*MemberExpressionObject)(es2panda_AstNode *ast);
    es2panda_AstNode *(*MemberExpressionProperty)(es2panda_AstNode *ast);
    es2panda_MemberExpressionKind (*MemberExpressionKind)(es2panda_AstNode *ast);
    bool (*MemberExpressionIsComputed)(es2panda_AstNode *ast);
    bool (*MemberExpressionIsOptional)(es2panda_AstNode *ast);

    bool (*IsMethodDefinition)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateMethodDefinition)(es2panda_Context *context, char const *kind, es2panda_AstNode *key,
                                                es2panda_AstNode *value, es2panda_ModifierFlags modifiers,
                                                bool is_computed);
    char const *(*MethodDefinitionKind)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*MethodDefinitionKey)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*MethodDefinitionValue)(es2panda_AstNode *ast);
    es2panda_ModifierFlags (*MethodDefinitionModifiers)(es2panda_AstNode *ast);
    bool (*MethodDefinitionIsComputed)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*MethodDefinitionOverloads)(es2panda_AstNode *ast, size_t *size_p);
    void (*MethodDefinitionSetOverloads)(es2panda_AstNode *ast, es2panda_AstNode **overloads, size_t n_overloads);
    void (*MethodDefinitionAddOverload)(es2panda_AstNode *ast, es2panda_AstNode *overload);

    bool (*IsNewClassInstanceExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateNewClassInstanceExpression)(es2panda_Context *context, es2panda_AstNode *type_reference,
                                                          es2panda_AstNode **arguments, size_t n_arguments,
                                                          es2panda_AstNode *class_definition);
    es2panda_AstNode *(*NewClassInstanceExpressionTypeReference)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*NewClassInstanceExpressionArguments)(es2panda_AstNode *ast, size_t *size_p);
    es2panda_AstNode *(*NewClassInstanceExpressionClassDefinition)(es2panda_AstNode *ast);

    bool (*IsNewArrayInstanceExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateNewArrayInstanceExpression)(es2panda_Context *context, es2panda_AstNode *type_reference,
                                                          es2panda_AstNode *dimension);
    es2panda_AstNode *(*NewArrayInstanceExpressionTypeReference)(es2panda_AstNode *ast);
    es2panda_AstNode *(*NewArrayInstanceExpressionDimension)(es2panda_AstNode *ast);

    bool (*IsNewMultiDimArrayInstanceExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateNewMultiDimArrayInstanceExpression)(es2panda_Context *context,
                                                                  es2panda_AstNode *type_reference,
                                                                  es2panda_AstNode **dimensions, size_t n_dimensions);
    es2panda_AstNode *(*NewMultiDimArrayInstanceExpressionTypeReference)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*NewMultiDimArrayInstanceExpressionDimensions)(es2panda_AstNode *ast, size_t *size_p);

    bool (*IsNonNullExpression)(es2panda_AstNode *ast);
    bool (*IsNumberLiteral)(es2panda_AstNode *ast);
    bool (*IsObjectExpression)(es2panda_AstNode *ast);

    bool (*IsParameterDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateParameterDeclaration)(es2panda_Context *context, es2panda_AstNode *identifier_or_spread,
                                                    es2panda_AstNode *initializer);
    es2panda_AstNode *(*ParameterDeclarationIdentifierOrSpread)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ParameterDeclarationInitializer)(es2panda_AstNode *ast);

    bool (*IsPrimitiveTypeNode)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreatePrimitiveTypeNode)(es2panda_Context *context, char const *type);
    char const *(*PrimitiveTypeNodeType)(es2panda_AstNode *ast);

    bool (*IsReturnStatement)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreatereturnStatement)(es2panda_Context *context, es2panda_AstNode *argument);
    es2panda_AstNode *(*ReturnStatementArgument)(es2panda_AstNode *ast);
    es2panda_Type *(*ReturnStatementReturnType)(es2panda_AstNode *ast);

    bool (*IsScriptFunction)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateScriptFunction)(es2panda_Context *context, es2panda_AstNode *type_params,
                                              es2panda_AstNode **params, size_t n_params,
                                              es2panda_AstNode *return_type_annotation,
                                              es2panda_ScriptFunctionFlags function_flags,
                                              es2panda_ModifierFlags modifier_flags, bool is_declare);
    es2panda_AstNode *(*ScriptFunctionTypeParams)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*ScriptFunctionParams)(es2panda_AstNode *ast, size_t *size_p);
    es2panda_AstNode *(*ScriptFunctionReturnTypeAnnotation)(es2panda_AstNode *ast);
    es2panda_ScriptFunctionFlags (*ScriptFunctionScriptFunctionFlags)(es2panda_AstNode *ast);
    bool (*ScriptFunctionIsDeclare)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ScriptFunctionIdentifier)(es2panda_AstNode *ast);
    es2panda_AstNode *(*ScriptFunctionBody)(es2panda_AstNode *ast);
    void (*ScriptFunctionSetIdentifier)(es2panda_AstNode *ast, es2panda_AstNode *ident);
    void (*ScriptFunctionSetBody)(es2panda_AstNode *ast, es2panda_AstNode *body);
    void (*ScriptFunctionSetParams)(es2panda_AstNode *ast, es2panda_AstNode **params, size_t n_params);
    void (*ScripFunctionAddParam)(es2panda_AstNode *ast, es2panda_AstNode *param);

    bool (*IsStringLiteral)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateStringLiteral)(es2panda_Context *context, char const *string);
    char const *(*StringLiteralString)(es2panda_Context *context, es2panda_AstNode *ast);

    bool (*IsThisExpression)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateThisExpression)(es2panda_Context *context);

    bool (*IsTypeParameter)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateTypeParameter)(es2panda_Context *context, es2panda_AstNode *name,
                                             es2panda_AstNode *constraint, es2panda_AstNode *defaultType);
    es2panda_AstNode const *(*TypeParameterName)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*TypeParameterConstraint)(es2panda_AstNode *ast);
    es2panda_AstNode const *(*TypeParameterDefaultType)(es2panda_AstNode *ast);

    bool (*IsTypeParameterDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateTypeParameterDeclaration)(es2panda_Context *context);
    void (*TypeParameterDeclarationAddTypeParameter)(es2panda_AstNode *ast, es2panda_AstNode *type_parameter);
    es2panda_AstNode *const *(*TypeParameterDeclarationTypeParameters)(es2panda_AstNode *ast, size_t *size_p);

    bool (*IsTypeParameterInstantiation)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateTypeParameterInstantiation)(es2panda_Context *context, es2panda_AstNode **params,
                                                          size_t n_params);
    es2panda_AstNode *const *(*TypeParameterInstantiationTypeParameters)(es2panda_AstNode *ast, size_t *size_p);

    bool (*IsTypeReferenceNode)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateTypeReferenceNode)(es2panda_Context *context, es2panda_AstNode *part);
    es2panda_AstNode *(*TypeRefrenceNodePart)(es2panda_AstNode *ast);

    bool (*IsTypeReferencePart)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateTypeReferencePart)(es2panda_Context *context, es2panda_AstNode *name,
                                                 es2panda_AstNode *type_arguments, es2panda_AstNode *previous);
    es2panda_AstNode *(*TypeReferencePartName)(es2panda_AstNode *ast);
    es2panda_AstNode *(*TypeReferencePartTypeArguments)(es2panda_AstNode *ast);
    es2panda_AstNode *(*TypeReferencePartPrevious)(es2panda_AstNode *ast);

    bool (*IsUnionTypeNode)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateUnionTypeNode)(es2panda_Context *context, es2panda_AstNode **types, size_t n_types);
    es2panda_AstNode *const *(*UnionTypeNodeTypes)(es2panda_AstNode *ast, size_t *size_p);

    bool (*IsVariableDeclaration)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateVariableDeclaration)(es2panda_Context *context, char const *kind,
                                                   es2panda_AstNode **declarators, size_t n_declarators,
                                                   bool is_declare);
    char const *(*VariableDeclarationKind)(es2panda_AstNode *ast);
    es2panda_AstNode *const *(*VariableDeclarationDeclarators)(es2panda_AstNode *ast, size_t *size_p);
    bool (*VariableDeclarationIsDeclare)(es2panda_AstNode *ast);

    bool (*IsVariableDeclarator)(es2panda_AstNode *ast);
    es2panda_AstNode *(*CreateVariableDeclarator)(es2panda_Context *context, es2panda_AstNode *identifier,
                                                  es2panda_AstNode *initializer);
    es2panda_AstNode *(*VariableDeclaratorIdentifier)(es2panda_AstNode *ast);
    es2panda_AstNode *(*VariableDeclaratorInitializer)(es2panda_AstNode *ast);
};

struct es2panda_Impl const *es2panda_GetImpl(int version);
// NOLINTEND

#ifdef __cplusplus
}
#endif

#endif  // ES2PANDA_LIB
