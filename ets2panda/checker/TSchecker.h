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

#ifndef ES2PANDA_CHECKER_TS_CHECKER_H
#define ES2PANDA_CHECKER_TS_CHECKER_H

#include "checker/checker.h"
#include "binder/enumMemberResult.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ts/types.h"
#include "util/enumbitops.h"
#include "util/ustring.h"
#include "macros.h"

#include <cstdint>
#include <initializer_list>
#include <unordered_map>
#include <unordered_set>

namespace panda::es2panda::binder {
class Binder;
class Decl;
class EnumVariable;
class FunctionDecl;
class LocalVariable;
class Scope;
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class AstNode;
class SpreadElement;
class AssignmentExpression;
class Property;
class Expression;
class ScriptFunction;
class UnaryExpression;
class BinaryExpression;
class Identifier;
class MemberExpression;
class TSEnumDeclaration;
class TSInterfaceDeclaration;
class ObjectExpression;
class TSArrayType;
class TSUnionType;
class TSFunctionType;
class TSConstructorType;
class TSTypeLiteral;
class TSTypeReference;
class TSQualifiedName;
class TSIndexedAccessType;
class TSInterfaceHeritage;
class TSTypeQuery;
class TSTupleType;
class ArrayExpression;
class Statement;
class TSTypeParameterDeclaration;
class TSTypeParameterInstantiation;
class BlockStatement;
class VariableDeclaration;
class IfStatement;
class DoWhileStatement;
class WhileStatement;
class ForUpdateStatement;
class ForInStatement;
class ForOfStatement;
class ReturnStatement;
class SwitchStatement;
class LabelledStatement;
class ThrowStatement;
class TryStatement;
class TSTypeAliasDeclaration;
class TSAsExpression;
class ThisExpression;
class NewExpression;
class FunctionExpression;
class AwaitExpression;
class UpdateExpression;
class ConditionalExpression;
class YieldExpression;
class ArrowFunctionExpression;
class TemplateLiteral;
class TaggedTemplateExpression;
class TSIndexSignature;
class TSSignatureDeclaration;
class TSPropertySignature;
class TSMethodSignature;
class ChainExpression;
class VariableDeclarator;

enum class AstNodeType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {

class TSChecker : public Checker {
public:
    // NOLINTNEXTLINE(readability-redundant-member-init)
    explicit TSChecker() : Checker() {}

    Type *GlobalNumberType()
    {
        return GetGlobalTypesHolder()->GlobalNumberType();
    }

    Type *GlobalAnyType()
    {
        return GetGlobalTypesHolder()->GlobalAnyType();
    }

    Type *GlobalStringType()
    {
        return GetGlobalTypesHolder()->GlobalStringType();
    }

    Type *GlobalBooleanType()
    {
        return GetGlobalTypesHolder()->GlobalBooleanType();
    }

    Type *GlobalVoidType()
    {
        return GetGlobalTypesHolder()->GlobalVoidType();
    }

    Type *GlobalNullType()
    {
        return GetGlobalTypesHolder()->GlobalNullType();
    }

    Type *GlobalUndefinedType()
    {
        return GetGlobalTypesHolder()->GlobalUndefinedType();
    }

    Type *GlobalUnknownType()
    {
        return GetGlobalTypesHolder()->GlobalUnknownType();
    }

    Type *GlobalNeverType()
    {
        return GetGlobalTypesHolder()->GlobalNeverType();
    }

    Type *GlobalNonPrimitiveType()
    {
        return GetGlobalTypesHolder()->GlobalNonPrimitiveType();
    }

    Type *GlobalBigintType()
    {
        return GetGlobalTypesHolder()->GlobalBigintType();
    }

    Type *GlobalFalseType()
    {
        return GetGlobalTypesHolder()->GlobalFalseType();
    }

    Type *GlobalTrueType()
    {
        return GetGlobalTypesHolder()->GlobalTrueType();
    }

    Type *GlobalNumberOrBigintType()
    {
        return GetGlobalTypesHolder()->GlobalNumberOrBigintType();
    }

    Type *GlobalStringOrNumberType()
    {
        return GetGlobalTypesHolder()->GlobalStringOrNumberType();
    }

    Type *GlobalZeroType()
    {
        return GetGlobalTypesHolder()->GlobalZeroType();
    }

    Type *GlobalEmptyStringType()
    {
        return GetGlobalTypesHolder()->GlobalEmptyStringType();
    }

    Type *GlobalZeroBigintType()
    {
        return GetGlobalTypesHolder()->GlobalZeroBigintType();
    }

    Type *GlobalPrimitiveType()
    {
        return GetGlobalTypesHolder()->GlobalPrimitiveType();
    }

    Type *GlobalEmptyTupleType()
    {
        return GetGlobalTypesHolder()->GlobalEmptyTupleType();
    }

    Type *GlobalEmptyObjectType()
    {
        return GetGlobalTypesHolder()->GlobalEmptyObjectType();
    }

    Type *GlobalResolvingReturnType()
    {
        return GetGlobalTypesHolder()->GlobalResolvingReturnType();
    }

    Type *GlobalErrorType()
    {
        return GetGlobalTypesHolder()->GlobalErrorType();
    }

    NumberLiteralPool &NumberLiteralMap()
    {
        return number_literal_map_;
    }

    StringLiteralPool &StringLiteralMap()
    {
        return string_literal_map_;
    }

    StringLiteralPool &BigintLiteralMap()
    {
        return bigint_literal_map_;
    }

    bool StartChecker([[maybe_unused]] binder::Binder *binder, const CompilerOptions &options) override;
    Type *CheckTypeCached(ir::Expression *expr) override;

    // Util
    static bool InAssignment(ir::AstNode *node);
    static bool IsAssignmentOperator(lexer::TokenType op);
    static bool IsLiteralType(const Type *type);
    static ir::AstNode *FindAncestorUntilGivenType(ir::AstNode *node, ir::AstNodeType stop);
    static bool MaybeTypeOfKind(const Type *type, TypeFlag flags);
    static bool MaybeTypeOfKind(const Type *type, ObjectType::ObjectTypeKind kind);
    static bool IsConstantMemberAccess(ir::Expression *expr);
    static bool IsStringLike(ir::Expression *expr);
    static ir::MemberExpression *ResolveLeftMostMemberExpression(ir::MemberExpression *expr);

    // Helpers
    void CheckTruthinessOfType(Type *type, lexer::SourcePosition line_info);
    Type *CheckNonNullType(Type *type, lexer::SourcePosition line_info);
    Type *GetBaseTypeOfLiteralType(Type *type);
    void CheckReferenceExpression(ir::Expression *expr, const char *invalid_reference_msg,
                                  const char *invalid_optional_chain_msg);
    void CheckTestingKnownTruthyCallableOrAwaitableType(ir::Expression *cond_expr, Type *type, ir::AstNode *body);
    Type *ExtractDefinitelyFalsyTypes(Type *type);
    Type *RemoveDefinitelyFalsyTypes(Type *type);
    TypeFlag GetFalsyFlags(Type *type);
    bool IsVariableUsedInConditionBody(ir::AstNode *parent, binder::Variable *search_var);
    bool FindVariableInBinaryExpressionChain(ir::AstNode *parent, binder::Variable *search_var);
    bool IsVariableUsedInBinaryExpressionChain(ir::AstNode *parent, binder::Variable *search_var);
    [[noreturn]] void ThrowBinaryLikeError(lexer::TokenType op, Type *left_type, Type *right_type,
                                           lexer::SourcePosition line_info);
    [[noreturn]] void ThrowAssignmentError(Type *source, Type *target, lexer::SourcePosition line_info,
                                           bool is_as_src_left_type = false);
    void ElaborateElementwise(Type *target_type, ir::Expression *source_node, const lexer::SourcePosition &pos);
    void InferSimpleVariableDeclaratorType(ir::VariableDeclarator *declarator);
    Type *GetTypeOfVariable(binder::Variable *var) override;
    Type *GetUnaryResultType(Type *operand_type);
    Type *GetTypeFromClassOrInterfaceReference(ir::TSTypeReference *node, binder::Variable *var);
    Type *GetTypeFromTypeAliasReference(ir::TSTypeReference *node, binder::Variable *var);
    Type *GetTypeReferenceType(ir::TSTypeReference *node, binder::Variable *var);

    // Type creation
    Type *CreateNumberLiteralType(double value);
    Type *CreateBigintLiteralType(const util::StringView &str, bool negative);
    Type *CreateStringLiteralType(const util::StringView &str);
    Type *CreateFunctionTypeWithSignature(Signature *call_signature);
    Type *CreateConstructorTypeWithSignature(Signature *construct_signature);
    Type *CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&element_flags,
                          ElementFlags combined_flags, uint32_t min_length, uint32_t fixed_length, bool readonly);
    Type *CreateTupleType(ObjectDescriptor *desc, ArenaVector<ElementFlags> &&element_flags,
                          ElementFlags combined_flags, uint32_t min_length, uint32_t fixed_length, bool readonly,
                          NamedTupleMemberPool &&named_members);
    Type *CreateUnionType(std::initializer_list<Type *> constituent_types);
    Type *CreateUnionType(ArenaVector<Type *> &&constituent_types);
    Type *CreateUnionType(ArenaVector<Type *> &constituent_types);
    Type *CreateObjectTypeWithCallSignature(Signature *call_signature);
    Type *CreateObjectTypeWithConstructSignature(Signature *construct_signature);

    // Object
    void ResolvePropertiesOfObjectType(ObjectType *type, ir::AstNode *member,
                                       ArenaVector<ir::TSSignatureDeclaration *> &signature_declarations,
                                       ArenaVector<ir::TSIndexSignature *> &index_declarations, bool is_interface);
    void ResolveSignaturesOfObjectType(ObjectType *type,
                                       ArenaVector<ir::TSSignatureDeclaration *> &signature_declarations);
    void ResolveIndexInfosOfObjectType(ObjectType *type, ArenaVector<ir::TSIndexSignature *> &index_declarations);
    void ResolveDeclaredMembers(InterfaceType *type);
    bool ValidateInterfaceMemberRedeclaration(ObjectType *type, binder::Variable *prop,
                                              const lexer::SourcePosition &loc_info);
    binder::Variable *GetPropertyOfType(Type *type, const util::StringView &name, bool get_partial = false,
                                        binder::VariableFlags propagate_flags = binder::VariableFlags::NONE);
    binder::Variable *GetPropertyOfUnionType(UnionType *type, const util::StringView &name, bool get_partial,
                                             binder::VariableFlags propagate_flags);
    void CheckIndexConstraints(Type *type);
    void ResolveUnionTypeMembers(UnionType *type);
    void ResolveObjectTypeMembers(ObjectType *type);
    void ResolveInterfaceOrClassTypeMembers(InterfaceType *type);
    Type *CheckComputedPropertyName(ir::Expression *key);
    Type *GetPropertyTypeForIndexType(Type *type, Type *index_type);
    IndexInfo *GetApplicableIndexInfo(Type *type, Type *index_type);
    ArenaVector<ObjectType *> GetBaseTypes(InterfaceType *type);
    void ResolveStructuredTypeMembers(Type *type) override;

    // Function
    Type *HandleFunctionReturn(ir::ScriptFunction *func);
    void CheckFunctionParameterDeclarations(const ArenaVector<ir::Expression *> &params, SignatureInfo *signature_info);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionParameter(
        ir::Expression *param, SignatureInfo *signature_info);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionIdentifierParameter(
        ir::Identifier *param);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionAssignmentPatternParameter(
        ir::AssignmentExpression *param);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionRestParameter(
        ir::SpreadElement *param, SignatureInfo *signature_info);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionArrayPatternParameter(
        ir::ArrayExpression *param);
    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> CheckFunctionObjectPatternParameter(
        ir::ObjectExpression *param);
    void InferFunctionDeclarationType(const binder::FunctionDecl *decl, binder::Variable *func_var);
    void CollectTypesFromReturnStatements(ir::AstNode *parent, ArenaVector<Type *> *return_types);
    void CheckAllCodePathsInNonVoidFunctionReturnOrThrow(ir::ScriptFunction *func, lexer::SourcePosition line_info,
                                                         const char *err_msg);
    void CreatePatternParameterName(ir::AstNode *node, std::stringstream &ss);
    void ThrowReturnTypeCircularityError(ir::ScriptFunction *func);
    ArgRange GetArgRange(const ArenaVector<Signature *> &signatures, ArenaVector<Signature *> *potential_signatures,
                         uint32_t call_args_size, bool *have_signature_with_rest);
    bool CallMatchesSignature(const ArenaVector<ir::Expression *> &args, Signature *signature, bool throw_error);
    Type *ResolveCallOrNewExpression(const ArenaVector<Signature *> &signatures,
                                     ArenaVector<ir::Expression *> arguments, const lexer::SourcePosition &err_pos);
    Type *CreateParameterTypeForArrayAssignmentPattern(ir::ArrayExpression *array_pattern, Type *inferred_type);
    Type *CreateParameterTypeForObjectAssignmentPattern(ir::ObjectExpression *object_pattern, Type *inferred_type);

    // Binary like expression
    Type *CheckBinaryOperator(Type *left_type, Type *right_type, ir::Expression *left_expr, ir::Expression *right_expr,
                              ir::AstNode *expr, lexer::TokenType op);
    Type *CheckPlusOperator(Type *left_type, Type *right_type, ir::Expression *left_expr, ir::Expression *right_expr,
                            ir::AstNode *expr, lexer::TokenType op);
    Type *CheckCompareOperator(Type *left_type, Type *right_type, ir::Expression *left_expr, ir::Expression *right_expr,
                               ir::AstNode *expr, lexer::TokenType op);
    Type *CheckAndOperator(Type *left_type, Type *right_type, ir::Expression *left_expr);
    Type *CheckOrOperator(Type *left_type, Type *right_type, ir::Expression *left_expr);
    Type *CheckInstanceofExpression(Type *left_type, Type *right_type, ir::Expression *right_expr, ir::AstNode *expr);
    Type *CheckInExpression(Type *left_type, Type *right_type, ir::Expression *left_expr, ir::Expression *right_expr,
                            ir::AstNode *expr);
    void CheckAssignmentOperator(lexer::TokenType op, ir::Expression *left_expr, Type *left_type, Type *value_type);

private:
    NumberLiteralPool number_literal_map_;
    StringLiteralPool string_literal_map_;
    StringLiteralPool bigint_literal_map_;
};

}  // namespace panda::es2panda::checker

#endif /* CHECKER_H */
