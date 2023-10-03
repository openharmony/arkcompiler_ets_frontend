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

#ifndef ES2PANDA_CHECKER_ETS_CHECKER_H
#define ES2PANDA_CHECKER_ETS_CHECKER_H

#include "checker/checkerContext.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/checker.h"
#include "binder/enumMemberResult.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "util/enumbitops.h"
#include "util/ustring.h"
#include "checker/types/ets/types.h"
#include "checker/ets/typeConverter.h"
#include "checker/ets/primitiveWrappers.h"
#include "checker/types/globalTypesHolder.h"
#include "binder/scope.h"

#include "macros.h"

#include <cstdint>
#include <initializer_list>
#include <tuple>
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
class ETSBinder;
class RecordTable;
class FunctionParamScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
enum class OperationType {
    BITWISE_AND,
    BITWISE_OR,
    BITWISE_XOR,
    LEFT_SHIFT,
    RIGHT_SHIFT,
    ADDITION,
    SUBTRACTION,
    MULTIPLICATION,
    DIVISION,
    MOD,
    LESS_THAN,
    LESS_THAN_EQUAL,
    GREATER_THAN,
    GREATER_THAN_EQUAL,
};

enum class OverrideErrorCode {
    NO_ERROR,
    OVERRIDING_STATIC,
    OVERRIDDEN_STATIC,
    OVERRIDDEN_FINAL,
    INCOMPATIBLE_RETURN,
    OVERRIDDEN_WEAKER,
};

enum class ResolvedKind {
    PROPERTY,
    INSTANCE_EXTENSION_FUNCTION,
};

class ResolveResult {
public:
    explicit ResolveResult(binder::Variable *v, ResolvedKind kind) : variable_(v), kind_(kind) {}

    binder::Variable *Variable()
    {
        return variable_;
    }

    ResolvedKind Kind()
    {
        return kind_;
    }

private:
    binder::Variable *variable_ {};
    ResolvedKind kind_ {};
};

using ComputedAbstracts =
    ArenaUnorderedMap<ETSObjectType *, std::pair<ArenaVector<ETSFunctionType *>, std::unordered_set<ETSObjectType *>>>;
using ArrayMap = ArenaUnorderedMap<Type *, ETSArrayType *>;
using GlobalArraySignatureMap = ArenaUnorderedMap<ETSArrayType *, Signature *>;
using DynamicCallIntrinsicsMap = ArenaUnorderedMap<Language, ArenaUnorderedMap<util::StringView, ir::ScriptFunction *>>;
using DynamicLambdaObjectSignatureMap = ArenaUnorderedMap<std::string, Signature *>;

class ETSChecker final : public Checker {
public:
    explicit ETSChecker()
        // NOLINTNEXTLINE(readability-redundant-member-init)
        : Checker(),
          array_types_(Allocator()->Adapter()),
          global_array_signatures_(Allocator()->Adapter()),
          primitive_wrappers_(Allocator()),
          cached_computed_abstracts_(Allocator()->Adapter()),
          dynamic_call_intrinsics_(Allocator()->Adapter()),
          dynamic_new_intrinsics_(Allocator()->Adapter()),
          dynamic_lambda_signature_cache_(Allocator()->Adapter())
    {
    }

    static inline TypeFlag ETSType(const Type *type)
    {
        return static_cast<TypeFlag>(type->TypeFlags() & TypeFlag::ETS_TYPE);
    }

    static inline TypeFlag TypeKind(const Type *type)
    {
        return static_cast<checker::TypeFlag>(type->TypeFlags() & checker::TypeFlag::ETS_TYPE);
    }

    Type *GlobalByteType() const;
    Type *GlobalShortType() const;
    Type *GlobalIntType() const;
    Type *GlobalLongType() const;
    Type *GlobalFloatType() const;
    Type *GlobalDoubleType() const;
    Type *GlobalCharType() const;
    Type *GlobalETSBooleanType() const;
    Type *GlobalVoidType() const;
    Type *GlobalETSNullType() const;
    Type *GlobalETSStringLiteralType() const;
    Type *GlobalWildcardType() const;

    ETSObjectType *GlobalETSObjectType() const;
    ETSObjectType *GlobalBuiltinETSStringType() const;
    ETSObjectType *GlobalBuiltinTypeType() const;
    ETSObjectType *GlobalBuiltinExceptionType() const;
    ETSObjectType *GlobalBuiltinErrorType() const;
    ETSObjectType *GlobalStringBuilderBuiltinType() const;
    ETSObjectType *GlobalBuiltinPromiseType() const;
    ETSObjectType *GlobalBuiltinJSRuntimeType() const;
    ETSObjectType *GlobalBuiltinJSValueType() const;
    ETSObjectType *GlobalBuiltinBoxType(const Type *contents) const;
    ETSObjectType *GlobalBuiltinVoidType() const;

    ETSObjectType *GlobalBuiltinDynamicType(Language lang) const;

    const checker::WrapperDesc &PrimitiveWrapper() const;

    GlobalArraySignatureMap &GlobalArrayTypes();
    const GlobalArraySignatureMap &GlobalArrayTypes() const;

    void InitializeBuiltins(binder::ETSBinder *binder);
    bool StartChecker([[maybe_unused]] binder::Binder *binder, const CompilerOptions &options) override;
    Type *CheckTypeCached(ir::Expression *expr) override;
    void ResolveStructuredTypeMembers([[maybe_unused]] Type *type) override {}
    Type *GetTypeOfVariable([[maybe_unused]] binder::Variable *var) override;

    // Object
    ETSObjectType *BuildClassProperties(ir::ClassDefinition *class_def);
    ETSObjectType *BuildAnonymousClassProperties(ir::ClassDefinition *class_def, ETSObjectType *super_type);
    ETSObjectType *BuildInterfaceProperties(ir::TSInterfaceDeclaration *interface_decl);
    ETSObjectType *GetSuperType(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfaces(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfacesOfClass(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfacesOfInterface(ETSObjectType *type);
    void ValidateImplementedInterface(ETSObjectType *type, Type *interface, std::unordered_set<Type *> *extends_set,
                                      const lexer::SourcePosition &pos);
    void ResolveDeclaredMembersOfObject(ETSObjectType *type);
    Type *ValidateArrayIndex(ir::Expression *expr);
    Type *CheckArrayElementAccess(ir::MemberExpression *expr);
    ETSObjectType *CheckThisOrSuperAccess(ir::Expression *node, ETSObjectType *class_type, std::string_view msg);
    void CreateTypeForClassOrInterfaceTypeParameters(ETSObjectType *type);
    void SetTypeParameterType(ir::TSTypeParameter *type_param, Type *type_param_type);
    void ValidateOverriding(ETSObjectType *class_type, const lexer::SourcePosition &pos);
    void AddImplementedSignature(std::vector<Signature *> *implemented_signatures, binder::LocalVariable *function,
                                 ETSFunctionType *it);
    void CheckInnerClassMembers(const ETSObjectType *class_type);
    void CheckClassDefinition(ir::ClassDefinition *class_def);
    void FindAssignment(const ir::AstNode *node, const binder::LocalVariable *class_var, bool &initialized);
    void FindAssignments(const ir::AstNode *node, const binder::LocalVariable *class_var, bool &initialized);
    void CheckConstFields(const ETSObjectType *class_type);
    void CheckConstFieldInitialized(const ETSObjectType *class_type, binder::LocalVariable *class_var);
    void CheckConstFieldInitialized(const Signature *signature, binder::LocalVariable *class_var);
    void ComputeAbstractsFromInterface(ETSObjectType *interface_type);
    ArenaVector<ETSFunctionType *> &GetAbstractsForClass(ETSObjectType *class_type);
    std::vector<Signature *> CollectAbstractSignaturesFromObject(const ETSObjectType *obj_type);
    void CreateFunctionTypesFromAbstracts(const std::vector<Signature *> &abstracts,
                                          ArenaVector<ETSFunctionType *> *target);
    void CheckCyclicConstructorCall(Signature *signature);
    std::vector<ResolveResult *> ResolveMemberReference(const ir::MemberExpression *member_expr,
                                                        const ETSObjectType *target);
    binder::Variable *ResolveInstanceExtension(const ir::MemberExpression *member_expr);
    void CheckImplicitSuper(ETSObjectType *class_type, Signature *ctor_sig);
    void CheckValidInheritance(ETSObjectType *class_type, ir::ClassDefinition *class_def);
    void CheckGetterSetterProperties(ETSObjectType *class_type);
    void AddElementsToModuleObject(ETSObjectType *module_obj, const util::StringView &str);
    Type *FindLeastUpperBound(Type *source, Type *target);
    Type *GetCommonClass(Type *source, Type *target);
    ETSObjectType *GetClosestCommonAncestor(ETSObjectType *source, ETSObjectType *target);
    ETSObjectType *GetTypeargumentedLUB(ETSObjectType *source, ETSObjectType *target);

    // Type creation
    ByteType *CreateByteType(int8_t value);
    ETSBooleanType *CreateETSBooleanType(bool value);
    DoubleType *CreateDoubleType(double value);
    FloatType *CreateFloatType(float value);
    IntType *CreateIntType(int32_t value);
    LongType *CreateLongType(int64_t value);
    ShortType *CreateShortType(int16_t value);
    CharType *CreateCharType(char16_t value);
    ETSStringType *CreateETSStringLiteralType(util::StringView value);
    ETSArrayType *CreateETSArrayType(Type *element_type);
    Type *CreateETSUnionType(ArenaVector<Type *> &&constituent_types);
    ETSFunctionType *CreateETSFunctionType(Signature *signature);
    ETSFunctionType *CreateETSFunctionType(Signature *signature, util::StringView name);
    ETSFunctionType *CreateETSFunctionType(ir::ScriptFunction *func, Signature *signature, util::StringView name);
    ETSFunctionType *CreateETSFunctionType(util::StringView name);
    ETSFunctionType *CreateETSFunctionType(ArenaVector<Signature *> &signatures);
    ETSExtensionFuncHelperType *CreateETSExtensionFuncHelperType(ETSFunctionType *class_method_type,
                                                                 ETSFunctionType *extension_function_type);
    ETSTypeParameter *CreateTypeParameter(Type *assembler_type);
    ETSObjectType *CreateETSObjectType(util::StringView name, ir::AstNode *decl_node, ETSObjectFlags flags);
    ETSEnumType *CreateETSEnumType(ir::TSEnumDeclaration const *enum_decl);
    ETSStringEnumType *CreateETSStringEnumType(ir::TSEnumDeclaration const *enum_decl);
    std::tuple<util::StringView, SignatureInfo *> CreateBuiltinArraySignatureInfo(ETSArrayType *array_type, size_t dim);
    Signature *CreateBuiltinArraySignature(ETSArrayType *array_type, size_t dim);
    IntType *CreateIntTypeFromType(Type *type);
    ETSObjectType *CreateNewETSObjectType(util::StringView name, ir::AstNode *decl_node, ETSObjectFlags flags);

    Signature *CreateSignature(SignatureInfo *info, Type *return_type, ir::ScriptFunction *func);
    Signature *CreateSignature(SignatureInfo *info, Type *return_type, util::StringView internal_name);
    SignatureInfo *CreateSignatureInfo();

    // Arithmetic
    Type *NegateNumericType(Type *type, ir::Expression *node);
    Type *BitwiseNegateIntegralType(Type *type, ir::Expression *node);
    std::tuple<Type *, Type *> CheckBinaryOperator(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                                   lexer::TokenType operation_type, lexer::SourcePosition pos,
                                                   bool force_promotion = false);
    Type *HandleArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type);
    void FlagExpressionWithUnboxing(Type *type, Type *unboxed_type, ir::Expression *type_expression);
    template <typename ValueType>
    Type *PerformArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type);

    Type *HandleRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type);
    template <typename TargetType>
    Type *PerformRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operation_type);

    // Function
    bool NeedTypeInference(const ir::ScriptFunction *lambda);
    std::vector<bool> FindTypeInferenceArguments(const ArenaVector<ir::Expression *> &arguments);
    void InferTypesForLambda(ir::ScriptFunction *lambda, ir::ETSFunctionType *callee_type);
    bool TypeInference(Signature *signature, const ArenaVector<ir::Expression *> &arguments,
                       TypeRelationFlag flags = TypeRelationFlag::NONE);
    bool CheckLambdaAssignable(ir::Expression *param, ir::ScriptFunction *lambda);
    bool IsCompatibleTypeArgument(Type *type_param, Type *type_argument);
    Substitution *NewSubstitution()
    {
        return Allocator()->New<Substitution>(Allocator()->Adapter());
    }
    Substitution *CopySubstitution(const Substitution *src)
    {
        return Allocator()->New<Substitution>(*src);
    }
    void EnhanceSubstitutionForType(const ArenaVector<Type *> &type_params, Type *param_type, Type *argument_type,
                                    Substitution *substitution);
    Signature *ValidateSignature(Signature *signature, const ir::TSTypeParameterInstantiation *type_arguments,
                                 const ArenaVector<ir::Expression *> &arguments, const lexer::SourcePosition &pos,
                                 TypeRelationFlag initial_flags, const std::vector<bool> &arg_type_inference_required);
    Signature *ValidateSignatures(ArenaVector<Signature *> &signatures,
                                  const ir::TSTypeParameterInstantiation *type_arguments,
                                  const ArenaVector<ir::Expression *> &arguments, const lexer::SourcePosition &pos,
                                  std::string_view signature_kind,
                                  TypeRelationFlag resolve_flags = TypeRelationFlag::NONE);
    bool ValidateProxySignature(Signature *signature, const ir::TSTypeParameterInstantiation *type_arguments,
                                const ArenaVector<ir::Expression *> &arguments,
                                const std::vector<bool> &arg_type_inference_required);
    Signature *ChooseMostSpecificSignature(ArenaVector<Signature *> &signatures,
                                           const ArenaVector<ir::Expression *> &arguments,
                                           const std::vector<bool> &arg_type_inference_required,
                                           const lexer::SourcePosition &pos, size_t arguments_size = ULONG_MAX);
    Signature *ChooseMostSpecificProxySignature(ArenaVector<Signature *> &signatures,
                                                const ArenaVector<ir::Expression *> &arguments,
                                                const std::vector<bool> &arg_type_inference_required,
                                                const lexer::SourcePosition &pos, size_t arguments_size);
    Signature *ResolveCallExpression(ArenaVector<Signature *> &signatures,
                                     const ir::TSTypeParameterInstantiation *type_arguments,
                                     const ArenaVector<ir::Expression *> &arguments, const lexer::SourcePosition &pos);
    Signature *ResolveCallExpressionAndTrailingLambda(ArenaVector<Signature *> &signatures,
                                                      ir::CallExpression *call_expr, const lexer::SourcePosition &pos,
                                                      TypeRelationFlag throw_flag = TypeRelationFlag::NONE);
    Signature *ResolveConstructExpression(ETSObjectType *type, const ArenaVector<ir::Expression *> &arguments,
                                          const lexer::SourcePosition &pos);
    void CheckObjectLiteralArguments(Signature *sig, ArenaVector<ir::Expression *> const &arguments);
    checker::ETSFunctionType *BuildFunctionSignature(ir::ScriptFunction *func, bool is_construct_sig = false);
    checker::ETSFunctionType *BuildMethodSignature(ir::MethodDefinition *method);
    Signature *CheckEveryAbstractSignatureIsOverridden(ETSFunctionType *target, ETSFunctionType *source);
    Signature *GetSignatureFromMethodDefinition(const ir::MethodDefinition *method_def);
    void CheckIdenticalOverloads(ETSFunctionType *func, ETSFunctionType *overload,
                                 const ir::MethodDefinition *current_func);
    Signature *AdjustForTypeParameters(Signature *source, Signature *target);
    void CheckOverride(Signature *signature);
    bool CheckOverride(Signature *signature, ETSObjectType *site);
    std::tuple<bool, OverrideErrorCode> CheckOverride(Signature *signature, Signature *other);
    bool IsMethodOverridesOther(Signature *target, Signature *source);
    bool IsOverridableIn(Signature *signature);
    [[nodiscard]] bool AreOverrideEquivalent(Signature *s1, Signature *s2);
    [[nodiscard]] bool IsReturnTypeSubstitutable(Signature *s1, Signature *s2);
    void CheckStaticHide(Signature *target, Signature *source);
    void CheckThrowMarkers(Signature *source, Signature *target);
    void ValidateSignatureAccessibility(ETSObjectType *callee, Signature *signature, const lexer::SourcePosition &pos);
    void CreateLambdaObjectForLambdaReference(ir::ArrowFunctionExpression *lambda, ETSObjectType *functional_interface);
    ir::ClassProperty *CreateLambdaCapturedField(const binder::Variable *captured_var, binder::ClassScope *scope,
                                                 size_t &idx, const lexer::SourcePosition &pos);
    ir::ClassProperty *CreateLambdaCapturedThis(binder::ClassScope *scope, size_t &idx,
                                                const lexer::SourcePosition &pos);
    void CreateLambdaObjectForFunctionReference(ir::AstNode *ref_node, Signature *signature,
                                                ETSObjectType *functional_interface);
    ir::AstNode *CreateLambdaImplicitField(binder::ClassScope *scope, const lexer::SourcePosition &pos);
    ir::MethodDefinition *CreateLambdaImplicitCtor(const lexer::SourceRange &pos, bool is_static_reference);
    ir::MethodDefinition *CreateLambdaImplicitCtor(ArenaVector<ir::AstNode *> &properties);
    ir::MethodDefinition *CreateProxyMethodForLambda(ir::ClassDefinition *klass, ir::ArrowFunctionExpression *lambda,
                                                     ArenaVector<ir::AstNode *> &captured, bool is_static);
    binder::FunctionParamScope *CreateProxyMethodParams(ir::ArrowFunctionExpression *lambda,
                                                        ArenaVector<ir::Expression *> &proxy_params,
                                                        ArenaVector<ir::AstNode *> &captured, bool is_static);
    void ReplaceIdentifierReferencesInProxyMethod(ir::AstNode *body, ArenaVector<ir::Expression *> &proxy_params,
                                                  ArenaVector<ir::Expression *> &lambda_params,
                                                  ArenaVector<binder::Variable *> &captured);
    void ReplaceIdentifierReferencesInProxyMethod(
        ir::AstNode *node, ArenaVector<ir::Expression *> &proxy_params,
        std::unordered_map<binder::Variable *, size_t> &merged_target_references);
    void ReplaceIdentifierReferenceInProxyMethod(
        ir::AstNode *node, ArenaVector<ir::Expression *> &proxy_params,
        std::unordered_map<binder::Variable *, size_t> &merged_target_references);
    ir::Statement *CreateLambdaCtorFieldInit(util::StringView name, binder::Variable *var);
    binder::FunctionParamScope *CreateLambdaCtorImplicitParams(ArenaVector<ir::Expression *> &params,
                                                               ArenaVector<ir::AstNode *> &properties);
    std::tuple<binder::FunctionParamScope *, binder::Variable *> CreateLambdaCtorImplicitParam(
        ArenaVector<ir::Expression *> &params, const lexer::SourceRange &pos, bool is_static_reference);
    ir::MethodDefinition *CreateLambdaInvokeProto();
    void CreateLambdaFuncDecl(ir::MethodDefinition *func, binder::LocalScope *scope);
    void ResolveProxyMethod(ir::MethodDefinition *proxy_method, ir::ArrowFunctionExpression *lambda);
    void ResolveLambdaObject(ir::ClassDefinition *lambda_object, Signature *signature,
                             ETSObjectType *functional_interface, ir::AstNode *ref_node);
    void ResolveLambdaObject(ir::ClassDefinition *lambda_object, ETSObjectType *functional_interface,
                             ir::ArrowFunctionExpression *lambda, ir::MethodDefinition *proxy_method, bool save_this);
    void ResolveLambdaObjectCtor(ir::ClassDefinition *lambda_object, bool is_static_reference);
    void ResolveLambdaObjectCtor(ir::ClassDefinition *lambda_object);
    void ResolveLambdaObjectInvoke(ir::ClassDefinition *lambda_object, Signature *signature_ref);
    void ResolveLambdaObjectInvoke(ir::ClassDefinition *lambda_object, ir::ArrowFunctionExpression *lambda,
                                   ir::MethodDefinition *proxy_method, bool is_static);
    ir::Statement *ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambda_object, Signature *signature_ref);
    ir::Statement *ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambda_object,
                                                     ir::MethodDefinition *proxy_method, bool is_static);
    void CreateFunctionalInterfaceForFunctionType(ir::ETSFunctionType *func_type);
    ir::MethodDefinition *CreateInvokeFunction(ir::ETSFunctionType *func_type);
    void CheckCapturedVariables();
    void CheckCapturedVariableInSubnodes(ir::AstNode *node, binder::Variable *var);
    void CheckCapturedVariable(ir::AstNode *node, binder::Variable *var);
    void BuildFunctionalInterfaceName(ir::ETSFunctionType *func_type);
    void CreateAsyncProxyMethods(ir::ClassDefinition *class_def);
    ir::MethodDefinition *CreateAsyncProxy(ir::MethodDefinition *async_method, ir::ClassDefinition *class_def,
                                           bool create_decl = true);
    ir::MethodDefinition *CreateMethod(const util::StringView &name, ir::ModifierFlags modifiers,
                                       ir::ScriptFunctionFlags flags, ArenaVector<ir::Expression *> &&params,
                                       binder::FunctionParamScope *param_scope, ir::TypeNode *return_type,
                                       ir::AstNode *body);
    binder::FunctionParamScope *CopyParams(const ArenaVector<ir::Expression *> &params,
                                           ArenaVector<ir::Expression *> &out_params);
    void ReplaceScope(ir::AstNode *root, ir::AstNode *old_node, binder::Scope *new_scope);

    // Helpers
    static std::string GetAsyncImplName(const util::StringView &name);
    std::vector<util::StringView> GetNameForSynteticObjectType(const util::StringView &source);
    void SetPropertiesForModuleObject(checker::ETSObjectType *module_obj_type, const util::StringView &import_path);
    void SetrModuleObjectTsType(ir::Identifier *local, checker::ETSObjectType *module_obj_type);
    Type *GetReferencedTypeFromBase(Type *base_type, ir::Expression *name);
    Type *GetReferencedTypeBase(ir::Expression *name);
    Type *GetTypeFromInterfaceReference(binder::Variable *var);
    Type *GetTypeFromTypeAliasReference(binder::Variable *var);
    Type *GetTypeFromClassReference(binder::Variable *var);
    Type *GetTypeFromEnumReference(binder::Variable *var);
    Type *GetTypeFromTypeParameterReference(binder::LocalVariable *var, const lexer::SourcePosition &pos);
    Type *GetNonConstantTypeFromPrimitiveType(Type *type);
    bool IsNullOrVoidExpression(const ir::Expression *expr) const;
    bool IsConstantExpression(ir::Expression *expr, Type *type);
    void ValidateUnaryOperatorOperand(binder::Variable *variable);
    std::tuple<Type *, bool> ApplyBinaryOperatorPromotion(Type *left, Type *right, TypeFlag test,
                                                          bool do_promotion = true);
    checker::Type *ApplyConditionalOperatorPromotion(checker::ETSChecker *checker, checker::Type *unboxed_l,
                                                     checker::Type *unboxed_r);
    Type *ApplyUnaryOperatorPromotion(Type *type, bool create_const = true, bool do_promotion = true,
                                      bool is_cond_expr = false);
    Type *HandleBooleanLogicalOperators(Type *left_type, Type *right_type, lexer::TokenType token_type);
    Type *HandleBooleanLogicalOperatorsExtended(Type *left_type, Type *right_type, ir::BinaryExpression *expr);
    checker::Type *CheckVariableDeclaration(ir::Identifier *ident, ir::TypeNode *type_annotation, ir::Expression *init,
                                            ir::ModifierFlags flags);
    void CheckTruthinessOfType(ir::Expression *expr);
    void ConcatConstantString(util::UString &target, Type *type);
    Type *HandleStringConcatenation(Type *left_type, Type *right_type);
    Type *ResolveIdentifier(ir::Identifier *ident);
    ETSFunctionType *FindFunctionInVectorGivenByName(util::StringView name, ArenaVector<ETSFunctionType *> &list);
    void MergeComputedAbstracts(ArenaVector<ETSFunctionType *> &merged, ArenaVector<ETSFunctionType *> &current);
    void MergeSignatures(ETSFunctionType *target, ETSFunctionType *source);
    ir::AstNode *FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type,
                                         const ir::AstNode *end_node = nullptr);
    util::StringView GetContainingObjectNameFromSignature(Signature *signature);
    bool IsFunctionContainsSignature(ETSFunctionType *func_type, Signature *signature);
    void CheckFunctionContainsClashingSignature(const ETSFunctionType *func_type, Signature *signature);
    bool IsTypeBuiltinType(Type *type);
    bool IsReferenceType(const Type *type);
    const ir::AstNode *FindJumpTarget(ir::AstNodeType node_type, const ir::AstNode *node, const ir::Identifier *target);
    void ValidatePropertyAccess(binder::Variable *var, ETSObjectType *obj, const lexer::SourcePosition &pos);
    binder::VariableFlags GetAccessFlagFromNode(const ir::AstNode *node);
    void CheckSwitchDiscriminant(ir::Expression *discriminant);
    Type *ETSBuiltinTypeAsPrimitiveType(Type *object_type);
    Type *ETSBuiltinTypeAsConditionalType(Type *object_type);
    Type *PrimitiveTypeAsETSBuiltinType(Type *object_type);
    void AddBoxingUnboxingFlagToNode(ir::AstNode *node, Type *boxing_unboxing_type);
    ir::BoxingUnboxingFlags GetBoxingFlag(Type *boxing_type);
    ir::BoxingUnboxingFlags GetUnboxingFlag(Type *unboxing_type);
    Type *MaybeBoxedType(const binder::Variable *var, ArenaAllocator *allocator) const;
    Type *MaybeBoxedType(const binder::Variable *var)
    {
        return MaybeBoxedType(var, Allocator());
    }
    void CheckForSameSwitchCases(ArenaVector<ir::SwitchCaseStatement *> *cases);
    std::string GetStringFromIdentifierValue(checker::Type *case_type) const;
    bool CompareIdentifiersValuesAreDifferent(ir::Expression *compare_value, const std::string &case_value);
    void CheckIdentifierSwitchCase(ir::Expression *current_case, ir::Expression *compare_case,
                                   const lexer::SourcePosition &pos);
    std::string GetStringFromLiteral(ir::Expression *case_test) const;
    binder::Variable *FindVariableInFunctionScope(util::StringView name);
    std::pair<const binder::Variable *, const ETSObjectType *> FindVariableInClassOrEnclosing(
        util::StringView name, const ETSObjectType *class_type);
    binder::Variable *FindVariableInGlobal(const ir::Identifier *identifier);
    void ValidateResolvedIdentifier(ir::Identifier *ident, binder::Variable *resolved);
    bool IsVariableStatic(const binder::Variable *var) const;
    bool IsVariableGetterSetter(const binder::Variable *var) const;
    bool IsSameDeclarationType(binder::LocalVariable *target, binder::LocalVariable *compare);
    void SaveCapturedVariable(binder::Variable *var, const lexer::SourcePosition &pos);
    void AddBoxingFlagToPrimitiveType(TypeRelation *relation, Type *target);
    void AddUnboxingFlagToPrimitiveType(TypeRelation *relation, Type *source, Type *self);
    void CheckUnboxedTypeWidenable(TypeRelation *relation, Type *target, Type *self);
    void CheckUnboxedTypesAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckBoxedSourceTypeAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckUnboxedSourceTypeWithWideningAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckValidGenericTypeParameter(Type *arg_type, const lexer::SourcePosition &pos);
    void ValidateResolvedProperty(const binder::LocalVariable *property, const ETSObjectType *target,
                                  const ir::Identifier *ident, PropertySearchFlags flags);
    bool IsValidSetterLeftSide(const ir::MemberExpression *member);
    bool CheckRethrowingParams(const ir::AstNode *ancestor_function, const ir::AstNode *node);
    void CheckThrowingStatements(ir::AstNode *node);
    bool CheckThrowingPlacement(ir::AstNode *node, const ir::AstNode *ancestor_function);
    ir::BlockStatement *FindFinalizerOfTryStatement(ir::AstNode *start_from, const ir::AstNode *p);
    void CheckRethrowingFunction(ir::ScriptFunction *func);
    ETSObjectType *GetRelevantArgumentedTypeFromChild(ETSObjectType *child, ETSObjectType *target);
    util::StringView GetHashFromTypeArguments(const ArenaVector<Type *> &type_arg_types);
    util::StringView GetHashFromSubstitution(const Substitution *substitution);
    ETSObjectType *GetOriginalBaseType(Type *object);
    Type *GetTypeFromTypeAnnotation(ir::TypeNode *type_annotation);
    void AddNullParamsForDefaultParams(const Signature *signature,
                                       ArenaVector<panda::es2panda::ir::Expression *> &arguments, ETSChecker *checker);
    void SetArrayPreferredTypeForNestedMemberExpressions(ir::MemberExpression *expr, Type *annotation_type);
    bool ExtensionETSFunctionType(checker::Type *type);

    // Exception
    ETSObjectType *CheckExceptionOrErrorType(checker::Type *type, lexer::SourcePosition pos);

    static Type *TryToInstantiate(Type *type, ArenaAllocator *allocator, TypeRelation *relation,
                                  GlobalTypesHolder *global_types);
    // Enum
    [[nodiscard]] ir::Identifier *CreateEnumNamesArray(ETSEnumInterface const *enum_type);
    [[nodiscard]] ir::Identifier *CreateEnumValuesArray(ETSEnumType *enum_type);
    [[nodiscard]] ir::Identifier *CreateEnumStringValuesArray(ETSEnumInterface *enum_type);
    [[nodiscard]] ir::Identifier *CreateEnumItemsArray(ETSEnumInterface *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumFromIntMethod(ir::Identifier *names_array_ident,
                                                              ETSEnumInterface *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumGetValueMethod(ir::Identifier *values_array_ident,
                                                               ETSEnumType *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumToStringMethod(ir::Identifier *string_values_array_ident,
                                                               ETSEnumInterface *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumGetNameMethod(ir::Identifier *names_array_ident,
                                                              ETSEnumInterface *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumValueOfMethod(ir::Identifier *names_array_ident,
                                                              ETSEnumInterface *enum_type);
    [[nodiscard]] ETSEnumType::Method CreateEnumValuesMethod(ir::Identifier *items_array_ident,
                                                             ETSEnumInterface *enum_type);

    // Dynamic interop
    template <typename T>
    Signature *ResolveDynamicCallExpression(ir::Expression *callee, const ArenaVector<T *> &arguments, Language lang,
                                            bool is_construct);
    void BuildDynamicCallClass(bool is_construct);
    void BuildDynamicNewClass(bool is_construct);
    void BuildDynamicImportClass();
    void BuildLambdaObjectClass(ETSObjectType *functional_interface, ir::TypeNode *ret_type_annotation);
    // Trailing lambda
    void EnsureValidCurlyBrace(ir::CallExpression *call_expr);

    // Extension function
    void HandleUpdatedCallExpressionNode(ir::CallExpression *call_expr);

    // Static invoke
    void CheckInvokeMethodsLegitimacy(ETSObjectType *class_type);

    std::recursive_mutex *Mutex()
    {
        return &mtx_;
    }

    template <typename T, typename... Args>
    T *AllocNode(Args &&...args)
    {
        auto *ret = Allocator()->New<T>(std::forward<Args>(args)...);
        ret->Iterate([ret](auto *child) { child->SetParent(ret); });
        return ret;
    }

private:
    using ClassBuilder = std::function<void(binder::ClassScope *, ArenaVector<ir::AstNode *> *)>;
    using ClassInitializerBuilder =
        std::function<void(binder::FunctionScope *, ArenaVector<ir::Statement *> *, ArenaVector<ir::Expression *> *)>;
    using MethodBuilder = std::function<void(binder::FunctionScope *, ArenaVector<ir::Statement *> *,
                                             ArenaVector<ir::Expression *> *, Type **)>;

    void BuildClass(util::StringView name, const ClassBuilder &builder);
    template <bool IS_STATIC>
    std::conditional_t<IS_STATIC, ir::ClassStaticBlock *, ir::MethodDefinition *> CreateClassInitializer(
        binder::ClassScope *class_scope, const ClassInitializerBuilder &builder, ETSObjectType *type = nullptr);

    ir::ETSParameterExpression *AddParam(binder::FunctionParamScope *param_scope, util::StringView name,
                                         checker::Type *type);

    template <bool IS_STATIC>
    ir::MethodDefinition *CreateClassMethod(binder::ClassScope *class_scope, std::string_view method_name,
                                            panda::es2panda::ir::ModifierFlags modifier_flags,
                                            const MethodBuilder &builder);

    template <typename T>
    ir::ScriptFunction *CreateDynamicCallIntrinsic(ir::Expression *callee, const ArenaVector<T *> &arguments,
                                                   Language lang);
    ir::ClassStaticBlock *CreateDynamicCallClassInitializer(binder::ClassScope *class_scope, Language lang,
                                                            bool is_construct);
    ir::ClassStaticBlock *CreateDynamicModuleClassInitializer(binder::ClassScope *class_scope,
                                                              const std::vector<ir::ETSImportDeclaration *> &imports);
    ir::MethodDefinition *CreateDynamicModuleClassInitMethod(binder::ClassScope *class_scope);

    ir::MethodDefinition *CreateLambdaObjectClassInitializer(binder::ClassScope *class_scope,
                                                             ETSObjectType *functional_interface);

    ir::MethodDefinition *CreateLambdaObjectClassInvokeMethod(binder::ClassScope *class_scope,
                                                              Signature *invoke_signature,
                                                              ir::TypeNode *ret_type_annotation);

    void EmitDynamicModuleClassInitCall();

    DynamicCallIntrinsicsMap *DynamicCallIntrinsics(bool is_construct)
    {
        return is_construct ? &dynamic_new_intrinsics_ : &dynamic_call_intrinsics_;
    }

    ArenaVector<Type *> CreateTypeForTypeParameters(ir::TSTypeParameterDeclaration *type_params);
    Type *CreateTypeParameterType(ir::TSTypeParameter *param);
    ETSObjectType *CreateETSObjectTypeCheckBuiltins(util::StringView name, ir::AstNode *decl_node,
                                                    ETSObjectFlags flags);
    void CheckProgram(parser::Program *program, bool run_analysis = false);

    template <typename UType>
    UType HandleModulo(UType left_value, UType right_value);

    template <typename UType>
    UType HandleBitWiseArithmetic(UType left_value, UType right_value, lexer::TokenType operation_type);

    template <typename TargetType>
    typename TargetType::UType GetOperand(Type *type);

    ETSObjectType *AsETSObjectType(Type *(GlobalTypesHolder::*type_functor)()) const;

    // Trailing lambda
    void MoveTrailingBlockToEnclosingBlockStatement(ir::CallExpression *call_expr);
    void TransformTraillingLambda(ir::CallExpression *call_expr);
    ArenaVector<ir::Expression *> ExtendArgumentsWithFakeLamda(ir::CallExpression *call_expr);

    // Static invoke
    bool TryTransformingToStaticInvoke(ir::Identifier *ident, const Type *resolved_type);

    ArrayMap array_types_;
    GlobalArraySignatureMap global_array_signatures_;
    PrimitiveWrappers primitive_wrappers_;
    ComputedAbstracts cached_computed_abstracts_;
    DynamicCallIntrinsicsMap dynamic_call_intrinsics_;
    DynamicCallIntrinsicsMap dynamic_new_intrinsics_;
    DynamicLambdaObjectSignatureMap dynamic_lambda_signature_cache_;
    std::recursive_mutex mtx_;
};

}  // namespace panda::es2panda::checker

#endif /* CHECKER_H */
