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

#ifndef ES2PANDA_CHECKER_ETS_CHECKER_H
#define ES2PANDA_CHECKER_ETS_CHECKER_H

#include <mutex>

#include "checker/checker.h"

#include "checker/types/ets/types.h"
#include "checker/ets/primitiveWrappers.h"
#include "checker/resolveResult.h"
#include "util/helpers.h"

namespace ark::es2panda::varbinder {
class VarBinder;
class Decl;
class EnumVariable;
class FunctionDecl;
class LocalVariable;
class Scope;
class Variable;
class ETSBinder;
class RecordTable;
class FunctionParamScope;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::evaluate {
class ScopedDebugInfoPlugin;
}  // namespace ark::es2panda::evaluate

namespace ark::es2panda::checker {

struct Accessor {
    bool isGetter {false};
    bool isSetter {false};
    bool isExternal {false};
};

using ComputedAbstracts =
    ArenaUnorderedMap<ETSObjectType *, std::pair<ArenaVector<ETSFunctionType *>, std::unordered_set<ETSObjectType *>>>;
using ArrayMap = ArenaUnorderedMap<Type *, ETSArrayType *>;
using GlobalArraySignatureMap = ArenaUnorderedMap<ETSArrayType *, Signature *>;
using DynamicCallIntrinsicsMap = ArenaUnorderedMap<Language, ArenaUnorderedMap<util::StringView, ir::ScriptFunction *>>;
using DynamicClassIntrinsicsMap = ArenaUnorderedMap<Language, ir::ClassDeclaration *>;
using DynamicLambdaObjectSignatureMap = ArenaUnorderedMap<std::string, Signature *>;
using FunctionalInterfaceMap = ArenaUnorderedMap<util::StringView, ETSObjectType *>;
using TypeMapping = ArenaUnorderedMap<Type const *, Type *>;
using DynamicCallNamesMap = ArenaMap<const ArenaVector<util::StringView>, uint32_t>;
using ConstraintCheckRecord = std::tuple<const ArenaVector<Type *> *, const Substitution *, lexer::SourcePosition>;

class ETSChecker final : public Checker {
public:
    explicit ETSChecker()
        // NOLINTNEXTLINE(readability-redundant-member-init)
        : Checker(),
          arrayTypes_(Allocator()->Adapter()),
          pendingConstraintCheckRecords_(Allocator()->Adapter()),
          globalArraySignatures_(Allocator()->Adapter()),
          primitiveWrappers_(Allocator()),
          cachedComputedAbstracts_(Allocator()->Adapter()),
          dynamicIntrinsics_ {DynamicCallIntrinsicsMap {Allocator()->Adapter()},
                              DynamicCallIntrinsicsMap {Allocator()->Adapter()}},
          dynamicClasses_ {DynamicClassIntrinsicsMap(Allocator()->Adapter()),
                           DynamicClassIntrinsicsMap(Allocator()->Adapter())},
          dynamicLambdaSignatureCache_(Allocator()->Adapter()),
          functionalInterfaceCache_(Allocator()->Adapter()),
          apparentTypes_(Allocator()->Adapter()),
          dynamicCallNames_ {{DynamicCallNamesMap(Allocator()->Adapter()), DynamicCallNamesMap(Allocator()->Adapter())}}
    {
    }

    ~ETSChecker() override = default;

    NO_COPY_SEMANTIC(ETSChecker);
    NO_MOVE_SEMANTIC(ETSChecker);

    [[nodiscard]] static inline TypeFlag ETSType(const Type *const type) noexcept
    {
        return static_cast<TypeFlag>(type->TypeFlags() & TypeFlag::ETS_TYPE);
    }

    [[nodiscard]] static inline TypeFlag TypeKind(const Type *const type) noexcept
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
    Type *GlobalETSUndefinedType() const;
    Type *GlobalETSStringLiteralType() const;
    Type *GlobalETSBigIntType() const;
    Type *GlobalWildcardType() const;

    ETSObjectType *GlobalETSObjectType() const;
    ETSUnionType *GlobalETSNullishType() const;
    ETSUnionType *GlobalETSNullishObjectType() const;
    ETSObjectType *GlobalBuiltinETSStringType() const;
    ETSObjectType *GlobalBuiltinETSBigIntType() const;
    ETSObjectType *GlobalBuiltinTypeType() const;
    ETSObjectType *GlobalBuiltinExceptionType() const;
    ETSObjectType *GlobalBuiltinErrorType() const;
    ETSObjectType *GlobalStringBuilderBuiltinType() const;
    ETSObjectType *GlobalBuiltinPromiseType() const;
    ETSObjectType *GlobalBuiltinJSRuntimeType() const;
    ETSObjectType *GlobalBuiltinJSValueType() const;
    ETSObjectType *GlobalBuiltinBoxType(Type *contents);

    ETSObjectType *GlobalBuiltinFunctionType(size_t nargs, ir::ScriptFunctionFlags flags) const;
    size_t GlobalBuiltinFunctionTypeVariadicThreshold() const;

    ETSObjectType *GlobalBuiltinDynamicType(Language lang) const;

    const checker::WrapperDesc &PrimitiveWrapper() const;

    GlobalArraySignatureMap &GlobalArrayTypes();
    const GlobalArraySignatureMap &GlobalArrayTypes() const;

    Type *GlobalTypeError() const;

    void InitializeBuiltins(varbinder::ETSBinder *varbinder);
    void InitializeBuiltin(varbinder::Variable *var, const util::StringView &name);
    bool StartChecker([[maybe_unused]] varbinder::VarBinder *varbinder, const CompilerOptions &options) override;
    Type *CheckTypeCached(ir::Expression *expr) override;
    void ResolveStructuredTypeMembers([[maybe_unused]] Type *type) override {}
    Type *GetTypeOfVariable([[maybe_unused]] varbinder::Variable *var) override;
    Type *GuaranteedTypeForUncheckedCast(Type *base, Type *substituted);
    Type *GuaranteedTypeForUncheckedCallReturn(Signature *sig);
    Type *GuaranteedTypeForUncheckedPropertyAccess(varbinder::Variable *prop);

    [[nodiscard]] bool IsETSChecker() const noexcept override
    {
        return true;
    }

    // Object
    ETSObjectType *BuildBasicClassProperties(ir::ClassDefinition *classDef);
    ETSObjectType *BuildAnonymousClassProperties(ir::ClassDefinition *classDef, ETSObjectType *superType);
    ETSObjectType *BuildBasicInterfaceProperties(ir::TSInterfaceDeclaration *interfaceDecl);
    ETSObjectType *GetSuperType(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfaces(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfacesOfClass(ETSObjectType *type);
    ArenaVector<ETSObjectType *> GetInterfacesOfInterface(ETSObjectType *type);
    void ValidateImplementedInterface(ETSObjectType *type, Type *interface, std::unordered_set<Type *> *extendsSet,
                                      const lexer::SourcePosition &pos);
    void ResolveDeclaredMembersOfObject(const ETSObjectType *type);
    std::optional<int32_t> GetTupleElementAccessValue(const Type *type, const lexer::SourcePosition &pos);
    bool ValidateArrayIndex(ir::Expression *expr, bool relaxed = false);
    bool ValidateTupleIndex(const ETSTupleType *tuple, ir::MemberExpression *expr);
    ETSObjectType *CheckThisOrSuperAccess(ir::Expression *node, ETSObjectType *classType, std::string_view msg);
    void CreateTypeForClassOrInterfaceTypeParameters(ETSObjectType *type);
    ETSTypeParameter *SetUpParameterType(ir::TSTypeParameter *param);
    void CheckIfOverrideIsValidInInterface(const ETSObjectType *classType, Signature *sig, ir::ScriptFunction *func);
    void CheckFunctionRedeclarationInInterface(const ETSObjectType *classType,
                                               ArenaVector<Signature *> &similarSignatures, ir::ScriptFunction *func);
    void ValidateAbstractMethodsToBeImplemented(ArenaVector<ETSFunctionType *> &abstractsToBeImplemented,
                                                ETSObjectType *classType,
                                                const std::vector<Signature *> &implementedSignatures);
    void ApplyModifiersAndRemoveImplementedAbstracts(ArenaVector<ETSFunctionType *>::iterator &it,
                                                     ArenaVector<ETSFunctionType *> &abstractsToBeImplemented,
                                                     ETSObjectType *classType, bool &functionOverridden,
                                                     const Accessor &isGetSetExternal);
    void ValidateAbstractSignature(ArenaVector<ETSFunctionType *>::iterator &it,
                                   ArenaVector<ETSFunctionType *> &abstractsToBeImplemented,
                                   const std::vector<Signature *> &implementedSignatures, bool &functionOverridden,
                                   Accessor &isGetSetExternal);
    void ValidateNonOverriddenFunction(ETSObjectType *classType, ArenaVector<ETSFunctionType *>::iterator &it,
                                       ArenaVector<ETSFunctionType *> &abstractsToBeImplemented,
                                       bool &functionOverridden, const Accessor &isGetSet);
    void MaybeReportErrorsForOverridingValidation(ArenaVector<ETSFunctionType *> &abstractsToBeImplemented,
                                                  ETSObjectType *classType, const lexer::SourcePosition &pos,
                                                  bool reportError);
    void ValidateOverriding(ETSObjectType *classType, const lexer::SourcePosition &pos);
    void CheckInterfaceFunctions(ETSObjectType *classType);
    void CollectImplementedMethodsFromInterfaces(ETSObjectType *classType,
                                                 std::vector<Signature *> *implementedSignatures,
                                                 const ArenaVector<ETSFunctionType *> &abstractsToBeImplemented);
    void AddImplementedSignature(std::vector<Signature *> *implementedSignatures, varbinder::LocalVariable *function,
                                 ETSFunctionType *it);
    void CheckInnerClassMembers(const ETSObjectType *classType);
    void CheckLocalClass(ir::ClassDefinition *classDef, CheckerStatus &checkerStatus);
    void CheckClassDefinition(ir::ClassDefinition *classDef);
    void CheckConstructors(ir::ClassDefinition *classDef, ETSObjectType *classType);
    void FindAssignment(const ir::AstNode *node, const varbinder::LocalVariable *classVar, bool &initialized);
    void FindAssignments(const ir::AstNode *node, const varbinder::LocalVariable *classVar, bool &initialized);
    void CheckConstFields(const ETSObjectType *classType);
    void CheckConstFieldInitialized(const ETSObjectType *classType, varbinder::LocalVariable *classVar);
    void CheckConstFieldInitialized(const Signature *signature, varbinder::LocalVariable *classVar);
    void ComputeAbstractsFromInterface(ETSObjectType *interfaceType);
    ArenaVector<ETSFunctionType *> &GetAbstractsForClass(ETSObjectType *classType);
    std::vector<Signature *> CollectAbstractSignaturesFromObject(const ETSObjectType *objType);
    void CreateFunctionTypesFromAbstracts(const std::vector<Signature *> &abstracts,
                                          ArenaVector<ETSFunctionType *> *target);
    void CheckCyclicConstructorCall(Signature *signature);
    std::vector<ResolveResult *> ResolveMemberReference(const ir::MemberExpression *memberExpr,
                                                        const ETSObjectType *target);
    varbinder::Variable *ResolveInstanceExtension(const ir::MemberExpression *memberExpr);
    void CheckImplicitSuper(ETSObjectType *classType, Signature *ctorSig);
    void CheckThisOrSuperCallInConstructor(ETSObjectType *classType, Signature *ctorSig);
    void CheckExpressionsInConstructor(const ArenaVector<const ir::Expression *> &arguments);
    ArenaVector<const ir::Expression *> CheckMemberOrCallOrObjectExpressionInConstructor(const ir::Expression *arg);
    void CheckValidInheritance(ETSObjectType *classType, ir::ClassDefinition *classDef);
    void CheckProperties(ETSObjectType *classType, ir::ClassDefinition *classDef, varbinder::LocalVariable *it,
                         varbinder::LocalVariable *found, ETSObjectType *interfaceFound);
    void TransformProperties(ETSObjectType *classType);
    void CheckGetterSetterProperties(ETSObjectType *classType);
    void AddElementsToModuleObject(ETSObjectType *moduleObj, const util::StringView &str);
    void ComputeApparentType(Type *type)
    {
        [[maybe_unused]] auto x = GetApparentType(type);
    }
    [[nodiscard]] Type *GetApparentType(Type *type);
    [[nodiscard]] Type const *GetApparentType(Type const *type) const;
    ETSObjectType *GetClosestCommonAncestor(ETSObjectType *source, ETSObjectType *target);
    bool HasETSFunctionType(ir::TypeNode *typeAnnotation);

    // Type creation
    ByteType *CreateByteType(int8_t value);
    ETSBooleanType *CreateETSBooleanType(bool value);
    DoubleType *CreateDoubleType(double value);
    FloatType *CreateFloatType(float value);
    IntType *CreateIntType(int32_t value);
    LongType *CreateLongType(int64_t value);
    ShortType *CreateShortType(int16_t value);
    CharType *CreateCharType(char16_t value);
    ETSBigIntType *CreateETSBigIntLiteralType(util::StringView value);
    ETSStringType *CreateETSStringLiteralType(util::StringView value);
    ETSArrayType *CreateETSArrayType(Type *elementType);
    ETSIntEnumType *CreateEnumIntTypeFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl);
    ETSStringEnumType *CreateEnumStringTypeFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl);

    Type *CreateETSUnionType(Span<Type *const> constituentTypes);
    template <size_t N>
    Type *CreateETSUnionType(Type *const (&arr)[N])  // NOLINT(modernize-avoid-c-arrays)
    {
        return CreateETSUnionType(Span(arr));
    }
    Type *CreateETSUnionType(ArenaVector<Type *> &&constituentTypes)
    {
        return CreateETSUnionType(Span<Type *const>(constituentTypes));
    }
    ETSFunctionType *CreateETSFunctionType(Signature *signature);
    ETSFunctionType *CreateETSFunctionType(Signature *signature, util::StringView name);
    ETSFunctionType *CreateETSFunctionType(ir::ScriptFunction *func, Signature *signature, util::StringView name);
    ETSFunctionType *CreateETSFunctionType(util::StringView name);
    ETSFunctionType *CreateETSFunctionType(ArenaVector<Signature *> &signatures);
    ETSFunctionType *CreateETSFunctionType(ir::ScriptFunction *func, ArenaVector<Signature *> &&signature,
                                           util::StringView name);
    ETSExtensionFuncHelperType *CreateETSExtensionFuncHelperType(ETSFunctionType *classMethodType,
                                                                 ETSFunctionType *extensionFunctionType);
    ETSObjectType *FunctionTypeToFunctionalInterfaceType(Signature *signature);
    Type *ResolveFunctionalInterfaces(ArenaVector<Signature *> &signatures);
    ETSTypeParameter *CreateTypeParameter();
    ETSObjectType *CreateETSObjectType(util::StringView name, ir::AstNode *declNode, ETSObjectFlags flags);
    std::tuple<util::StringView, SignatureInfo *> CreateBuiltinArraySignatureInfo(ETSArrayType *arrayType, size_t dim);
    Signature *CreateBuiltinArraySignature(ETSArrayType *arrayType, size_t dim);
    IntType *CreateIntTypeFromType(Type *type);
    std::tuple<Language, bool> CheckForDynamicLang(ir::AstNode *declNode, util::StringView assemblerName);
    ETSObjectType *CreateNewETSObjectType(util::StringView name, ir::AstNode *declNode, ETSObjectFlags flags);

    Signature *CreateSignature(SignatureInfo *info, Type *returnType, ir::ScriptFunction *func);
    Signature *CreateSignature(SignatureInfo *info, Type *returnType, util::StringView internalName);
    SignatureInfo *CreateSignatureInfo();

    // Arithmetic
    Type *NegateNumericType(Type *type, ir::Expression *node);
    Type *BitwiseNegateNumericType(Type *type, ir::Expression *node);
    bool CheckBinaryOperatorForBigInt(Type *left, Type *right, lexer::TokenType op);
    [[nodiscard]] bool CheckBinaryPlusMultDivOperandsForUnionType(const Type *leftType, const Type *rightType,
                                                                  const ir::Expression *left,
                                                                  const ir::Expression *right);
    std::tuple<Type *, Type *> CheckBinaryOperator(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                                   lexer::TokenType operationType, lexer::SourcePosition pos,
                                                   bool forcePromotion = false);
    checker::Type *CheckBinaryOperatorMulDivMod(
        std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
        std::tuple<checker::Type *, checker::Type *, Type *, Type *> types);
    checker::Type *CheckBinaryOperatorPlusForEnums(const checker::Type *const leftType,
                                                   const checker::Type *const rightType);
    checker::Type *CheckBinaryOperatorPlus(
        std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
        std::tuple<checker::Type *, checker::Type *, Type *, Type *> types);
    checker::Type *CheckBinaryOperatorShift(
        std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
        std::tuple<checker::Type *, checker::Type *, Type *, Type *> types);
    checker::Type *CheckBinaryOperatorBitwise(
        std::tuple<ir::Expression *, ir::Expression *, lexer::TokenType, lexer::SourcePosition> op, bool isEqualOp,
        std::tuple<checker::Type *, checker::Type *, Type *, Type *> types);
    checker::Type *CheckBinaryOperatorLogical(ir::Expression *left, ir::Expression *right, ir::Expression *expr,
                                              lexer::SourcePosition pos, checker::Type *leftType,
                                              checker::Type *rightType, Type *unboxedL, Type *unboxedR);
    std::tuple<Type *, Type *> CheckBinaryOperatorStrictEqual(ir::Expression *left, lexer::TokenType operationType,
                                                              lexer::SourcePosition pos, checker::Type *leftType,
                                                              checker::Type *rightType);
    std::optional<std::tuple<Type *, Type *>> CheckBinaryOperatorEqualError(checker::Type *const leftType,
                                                                            checker::Type *const rightType,
                                                                            checker::Type *tsType,
                                                                            lexer::SourcePosition pos);
    std::tuple<Type *, Type *> CheckBinaryOperatorEqual(ir::Expression *left, ir::Expression *right,
                                                        lexer::TokenType operationType, lexer::SourcePosition pos,
                                                        checker::Type *leftType, checker::Type *rightType,
                                                        Type *unboxedL, Type *unboxedR);
    std::tuple<Type *, Type *> CheckBinaryOperatorEqualDynamic(ir::Expression *left, ir::Expression *right,
                                                               lexer::SourcePosition pos);
    std::tuple<Type *, Type *> CheckBinaryOperatorLessGreater(ir::Expression *left, ir::Expression *right,
                                                              lexer::TokenType operationType, lexer::SourcePosition pos,
                                                              bool isEqualOp, checker::Type *leftType,
                                                              checker::Type *rightType, Type *unboxedL, Type *unboxedR);
    std::tuple<Type *, Type *> CheckBinaryOperatorInstanceOf(lexer::SourcePosition pos, checker::Type *leftType,
                                                             checker::Type *rightType);
    checker::Type *CheckBinaryOperatorNullishCoalescing(ir::Expression *left, ir::Expression *right,
                                                        lexer::SourcePosition pos);
    bool AdjustNumberLiteralType(ir::NumberLiteral *literal, Type *literalType, Type *otherType);

    Type *HandleArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType);
    Type *HandleBitwiseOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType);
    void FlagExpressionWithUnboxing(Type *type, Type *unboxedType, ir::Expression *typeExpression);
    template <typename ValueType>
    Type *PerformArithmeticOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType);

    Type *HandleRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType);
    template <typename TargetType>
    Type *PerformRelationOperationOnTypes(Type *left, Type *right, lexer::TokenType operationType);

    // Function
    bool NeedTypeInference(const ir::ScriptFunction *lambda);
    std::vector<bool> FindTypeInferenceArguments(const ArenaVector<ir::Expression *> &arguments);
    void InferTypesForLambda(ir::ScriptFunction *lambda, ir::ETSFunctionType *calleeType);
    bool TypeInference(Signature *signature, const ArenaVector<ir::Expression *> &arguments,
                       TypeRelationFlag flags = TypeRelationFlag::NONE);
    bool CheckLambdaTypeAnnotation(ir::AstNode *typeAnnotation, ir::ArrowFunctionExpression *arrowFuncExpr,
                                   Type *parameterType, TypeRelationFlag flags);
    bool CheckLambdaInvocable(ir::AstNode *typeAnnotation, ir::ArrowFunctionExpression *arrowFuncExpr,
                              Type *parameterType, TypeRelationFlag flags);
    bool CheckLambdaAssignable(ir::Expression *param, ir::ScriptFunction *lambda);
    bool CheckLambdaAssignableUnion(ir::AstNode *typeAnn, ir::ScriptFunction *lambda);
    bool IsCompatibleTypeArgument(ETSTypeParameter *typeParam, Type *typeArgument, const Substitution *substitution);
    Substitution *NewSubstitution()
    {
        return Allocator()->New<Substitution>(Allocator()->Adapter());
    }
    Substitution *CopySubstitution(const Substitution *src)
    {
        return Allocator()->New<Substitution>(*src);
    }
    static void EmplaceSubstituted(Substitution *substitution, ETSTypeParameter *tparam, Type *typeArg);
    [[nodiscard]] bool EnhanceSubstitutionForType(const ArenaVector<Type *> &typeParams, Type *paramType,
                                                  Type *argumentType, Substitution *substitution);
    [[nodiscard]] bool EnhanceSubstitutionForReadonly(const ArenaVector<Type *> &typeParams, ETSReadonlyType *paramType,
                                                      Type *argumentType, Substitution *substitution);
    [[nodiscard]] bool EnhanceSubstitutionForObject(const ArenaVector<Type *> &typeParams, ETSObjectType *paramType,
                                                    Type *argumentType, Substitution *substitution);
    [[nodiscard]] bool EnhanceSubstitutionForUnion(const ArenaVector<Type *> &typeParams, ETSUnionType *paramUn,
                                                   Type *argumentType, Substitution *substitution);
    [[nodiscard]] bool EnhanceSubstitutionForArray(const ArenaVector<Type *> &typeParams, ETSArrayType *paramType,
                                                   Type *argumentType, Substitution *substitution);
    [[nodiscard]] bool EnhanceSubstitutionForGenericType(const ArenaVector<Type *> &typeParams, const Type *argType,
                                                         const Type *paramType, Substitution *substitution);
    [[nodiscard]] static bool HasTypeArgsOfObject(Type *argType, Type *paramType);
    [[nodiscard]] bool InsertTypeIntoSubstitution(const ArenaVector<Type *> &typeParams, const Type *typeParam,
                                                  const size_t index, Substitution *substitution, Type *objectParam);
    std::pair<ArenaVector<Type *>, bool> CreateUnconstrainedTypeParameters(
        ir::TSTypeParameterDeclaration const *typeParams);
    void AssignTypeParameterConstraints(ir::TSTypeParameterDeclaration const *typeParams);
    Signature *ValidateParameterlessConstructor(Signature *signature, const lexer::SourcePosition &pos,
                                                TypeRelationFlag flags);
    Signature *CollectParameterlessConstructor(ArenaVector<Signature *> &signatures, const lexer::SourcePosition &pos,
                                               TypeRelationFlag resolveFlags = TypeRelationFlag::NONE);
    Signature *ValidateSignature(
        std::tuple<Signature *, const ir::TSTypeParameterInstantiation *, TypeRelationFlag> info,
        const ArenaVector<ir::Expression *> &arguments, const lexer::SourcePosition &pos,
        const std::vector<bool> &argTypeInferenceRequired);
    void MaybeSubstituteLambdaArgumentsInFunctionCall(ir::CallExpression *callExpr);
    void MaybeSubstituteLambdaArgumentsInFunctionCallHelper(ir::CallExpression *callExpr, ir::Identifier *ident);
    void MaybeSubstituteLambdaArguments(const ArenaVector<ir::Expression *> &params, ir::CallExpression *callExpr);
    bool ValidateSignatureRequiredParams(Signature *substitutedSig, const ArenaVector<ir::Expression *> &arguments,
                                         TypeRelationFlag flags, const std::vector<bool> &argTypeInferenceRequired,
                                         bool reportError);
    bool ValidateSignatureInvocationContext(Signature *substitutedSig, ir::Expression *argument, const Type *targetType,
                                            std::size_t index, TypeRelationFlag flags);
    bool CheckInvokable(Signature *substitutedSig, ir::Expression *argument, std::size_t index, TypeRelationFlag flags);
    bool CheckOptionalLambdaFunction(ir::Expression *argument, Signature *substitutedSig, std::size_t index);
    bool ValidateArgumentAsIdentifier(const ir::Identifier *identifier);
    bool ValidateSignatureRestParams(Signature *substitutedSig, const ArenaVector<ir::Expression *> &arguments,
                                     TypeRelationFlag flags, bool reportError);
    Signature *ValidateSignatures(ArenaVector<Signature *> &signatures,
                                  const ir::TSTypeParameterInstantiation *typeArguments,
                                  const ArenaVector<ir::Expression *> &arguments, const lexer::SourcePosition &pos,
                                  std::string_view signatureKind,
                                  TypeRelationFlag resolveFlags = TypeRelationFlag::NONE);
    Signature *FindMostSpecificSignature(const ArenaVector<Signature *> &signatures,
                                         const ArenaMultiMap<size_t, Signature *> &bestSignaturesForParameter,
                                         size_t paramCount);
    void SearchAmongMostSpecificTypes(
        Type *&mostSpecificType, Signature *&prevSig,
        std::tuple<const lexer::SourcePosition &, size_t, size_t, size_t, Signature *> info, bool lookForClassType);
    ArenaMultiMap<size_t, Signature *> GetSuitableSignaturesForParameter(
        const std::vector<bool> &argTypeInferenceRequired, size_t paramCount, ArenaVector<Signature *> &signatures,
        const lexer::SourcePosition &pos, size_t argumentsSize);
    Signature *ChooseMostSpecificSignature(ArenaVector<Signature *> &signatures,
                                           const std::vector<bool> &argTypeInferenceRequired,
                                           const lexer::SourcePosition &pos, size_t argumentsSize = ULONG_MAX);
    Signature *ResolveCallExpressionAndTrailingLambda(ArenaVector<Signature *> &signatures,
                                                      ir::CallExpression *callExpr, const lexer::SourcePosition &pos,
                                                      TypeRelationFlag reportFlag = TypeRelationFlag::NONE);
    Signature *ResolveConstructExpression(ETSObjectType *type, const ArenaVector<ir::Expression *> &arguments,
                                          const lexer::SourcePosition &pos);
    void CheckObjectLiteralArguments(Signature *sig, ArenaVector<ir::Expression *> const &arguments);
    Signature *ComposeSignature(ir::ScriptFunction *func, SignatureInfo *signatureInfo, Type *returnType,
                                varbinder::Variable *nameVar);
    Type *ComposeReturnType(ir::ScriptFunction *func);
    SignatureInfo *ComposeSignatureInfo(ir::ScriptFunction *func);
    ArenaVector<SignatureInfo *> ComposeSignatureInfosForArrowFunction(ir::ArrowFunctionExpression *arrowFuncExpr);
    void SetParamForSignatureInfoOfArrowFunction(SignatureInfo *signatureInfo, ir::ETSParameterExpression *param);
    void ValidateMainSignature(ir::ScriptFunction *func);
    void BuildFunctionSignature(ir::ScriptFunction *func, bool isConstructSig = false);
    checker::ETSFunctionType *BuildNamedFunctionType(ir::ScriptFunction *func);
    checker::ETSFunctionType *BuildMethodSignature(ir::MethodDefinition *method);
    Signature *CheckEveryAbstractSignatureIsOverridden(ETSFunctionType *target, ETSFunctionType *source);
    static Signature *GetSignatureFromMethodDefinition(const ir::MethodDefinition *methodDef);
    void CheckIdenticalOverloads(ETSFunctionType *func, ETSFunctionType *overload,
                                 const ir::MethodDefinition *currentFunc);
    Signature *AdjustForTypeParameters(Signature *source, Signature *target);
    void ReportOverrideError(Signature *signature, Signature *overriddenSignature, const OverrideErrorCode &errorCode);
    void CheckOverride(Signature *signature);
    bool CheckOverride(Signature *signature, ETSObjectType *site);
    OverrideErrorCode CheckOverride(Signature *signature, Signature *other);
    bool IsMethodOverridesOther(Signature *base, Signature *derived);
    bool IsOverridableIn(Signature *signature);
    [[nodiscard]] bool AreOverrideEquivalent(Signature *s1, Signature *s2);
    [[nodiscard]] bool IsReturnTypeSubstitutable(Signature *s1, Signature *s2);
    bool CheckThrowMarkers(Signature *source, Signature *target);
    void ValidateSignatureAccessibility(ETSObjectType *callee, const ir::CallExpression *callExpr, Signature *signature,
                                        const lexer::SourcePosition &pos, char const *errorMessage = nullptr);
    void CheckCapturedVariables();
    void CheckCapturedVariableInSubnodes(ir::AstNode *node, varbinder::Variable *var);
    void CheckCapturedVariable(ir::AstNode *node, varbinder::Variable *var);
    void CreateAsyncProxyMethods(ir::ClassDefinition *classDef);
    ir::MethodDefinition *CreateAsyncImplMethod(ir::MethodDefinition *asyncMethod, ir::ClassDefinition *classDef);
    ir::MethodDefinition *CreateAsyncProxy(ir::MethodDefinition *asyncMethod, ir::ClassDefinition *classDef,
                                           bool createDecl = true);
    ir::MethodDefinition *CreateMethod(const util::StringView &name, ir::ModifierFlags modifiers,
                                       ir::ScriptFunctionFlags flags, ArenaVector<ir::Expression *> &&params,
                                       varbinder::FunctionParamScope *paramScope, ir::TypeNode *returnType,
                                       ir::AstNode *body);
    varbinder::FunctionParamScope *CopyParams(const ArenaVector<ir::Expression *> &params,
                                              ArenaVector<ir::Expression *> &outParams);
    void ReplaceScope(ir::AstNode *root, ir::AstNode *oldNode, varbinder::Scope *newScope);

    // Helpers
    size_t ComputeProxyMethods(ir::ClassDefinition *klass);
    ir::ModifierFlags GetFlagsForProxyLambda(bool isStatic);
    ir::ScriptFunction *CreateProxyFunc(ir::ArrowFunctionExpression *lambda, ArenaVector<ir::AstNode *> &captured,
                                        bool isStatic);
    ir::AstNode *GetProxyMethodBody(ir::ArrowFunctionExpression *lambda, varbinder::FunctionScope *scope);
    static std::string GetAsyncImplName(const util::StringView &name);
    static std::string GetAsyncImplName(ir::MethodDefinition *asyncMethod);
    static bool IsAsyncImplMethod(ir::MethodDefinition const *method);
    std::vector<util::StringView> GetNameForSynteticObjectType(const util::StringView &source);
    template <checker::PropertyType TYPE>
    void BindingsModuleObjectAddProperty(checker::ETSObjectType *moduleObjType, ir::ETSImportDeclaration *importDecl,
                                         const varbinder::Scope::VariableMap &bindings);
    util::StringView FindPropNameForNamespaceImport(const util::StringView &originalName);
    void SetPropertiesForModuleObject(checker::ETSObjectType *moduleObjType, const util::StringView &importPath,
                                      ir::ETSImportDeclaration *importDecl = nullptr);
    void SetrModuleObjectTsType(ir::Identifier *local, checker::ETSObjectType *moduleObjType);
    Type *GetReferencedTypeFromBase(Type *baseType, ir::Expression *name);
    Type *GetReferencedTypeBase(ir::Expression *name);
    Type *GetTypeFromInterfaceReference(varbinder::Variable *var);
    Type *GetTypeFromTypeAliasReference(varbinder::Variable *var);
    Type *GetTypeFromClassReference(varbinder::Variable *var);
    void ValidateGenericTypeAliasForClonedNode(ir::TSTypeAliasDeclaration *typeAliasNode,
                                               const ir::TSTypeParameterInstantiation *exactTypeParams);
    Type *HandleTypeAlias(ir::Expression *name, const ir::TSTypeParameterInstantiation *typeParams);
    Type *GetTypeFromEnumReference(varbinder::Variable *var);
    Type *GetTypeFromTypeParameterReference(varbinder::LocalVariable *var, const lexer::SourcePosition &pos);
    Type *GetNonConstantTypeFromPrimitiveType(Type *type) const;
    bool IsNullLikeOrVoidExpression(const ir::Expression *expr) const;
    bool IsConstantExpression(ir::Expression *expr, Type *type);
    void ValidateUnaryOperatorOperand(varbinder::Variable *variable);
    void InferAliasLambdaType(ir::TypeNode *localTypeAnnotation, ir::ArrowFunctionExpression *init);
    bool TestUnionType(Type *type, TypeFlag test);
    std::tuple<Type *, bool> ApplyBinaryOperatorPromotion(Type *left, Type *right, TypeFlag test,
                                                          bool doPromotion = true);
    checker::Type *ApplyConditionalOperatorPromotion(checker::ETSChecker *checker, checker::Type *unboxedL,
                                                     checker::Type *unboxedR);
    Type *ApplyUnaryOperatorPromotion(Type *type, bool createConst = true, bool doPromotion = true,
                                      bool isCondExpr = false);
    Type *HandleBooleanLogicalOperators(Type *leftType, Type *rightType, lexer::TokenType tokenType);
    Type *HandleBooleanLogicalOperatorsExtended(Type *leftType, Type *rightType, ir::BinaryExpression *expr);

    checker::Type *FixOptionalVariableType(varbinder::Variable *const bindingVar, ir::ModifierFlags flags,
                                           ir::Expression *init);
    void CheckEnumType(ir::Expression *init, checker::Type *initType, const util::StringView &varName);
    checker::Type *CheckVariableDeclaration(ir::Identifier *ident, ir::TypeNode *typeAnnotation, ir::Expression *init,
                                            ir::ModifierFlags flags);
    void CheckAnnotationTypeForVariableDeclaration(checker::Type *annotationType, bool isUnionFunction,
                                                   ir::Expression *init, checker::Type *initType);
    void CheckTruthinessOfType(ir::Expression *expr);

    bool CheckNonNullish(ir::Expression const *expr);
    Type *GetNonNullishType(Type *type);
    Type *RemoveNullType(Type *type);
    Type *RemoveUndefinedType(Type *type);
    std::pair<Type *, Type *> RemoveNullishTypes(Type *type);

    void ConcatConstantString(util::UString &target, Type *type);
    Type *HandleStringConcatenation(Type *leftType, Type *rightType);
    Type *ResolveIdentifier(ir::Identifier *ident);
    ETSFunctionType *FindFunctionInVectorGivenByName(util::StringView name, ArenaVector<ETSFunctionType *> &list);
    void MergeComputedAbstracts(ArenaVector<ETSFunctionType *> &merged, ArenaVector<ETSFunctionType *> &current);
    void MergeSignatures(ETSFunctionType *target, ETSFunctionType *source);
    ir::AstNode *FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type, const ir::AstNode *endNode = nullptr);
    util::StringView GetContainingObjectNameFromSignature(Signature *signature);
    bool IsFunctionContainsSignature(ETSFunctionType *funcType, Signature *signature);
    bool CheckFunctionContainsClashingSignature(const ETSFunctionType *funcType, Signature *signature);
    bool IsTypeBuiltinType(const Type *type) const;
    static bool IsReferenceType(const Type *type)
    {
        return type->IsETSReferenceType();
    }
    std::optional<const ir::AstNode *> FindJumpTarget(ir::AstNode *node);
    void ValidatePropertyAccess(varbinder::Variable *var, ETSObjectType *obj, const lexer::SourcePosition &pos);
    varbinder::VariableFlags GetAccessFlagFromNode(const ir::AstNode *node);
    Type *CheckSwitchDiscriminant(ir::Expression *discriminant);
    Type *ETSBuiltinTypeAsPrimitiveType(Type *objectType);
    Type *ETSBuiltinTypeAsConditionalType(Type *objectType);
    Type *PrimitiveTypeAsETSBuiltinType(Type *objectType);
    void AddBoxingUnboxingFlagsToNode(ir::AstNode *node, Type *boxingUnboxingType);
    ir::BoxingUnboxingFlags GetBoxingFlag(Type *boxingType);
    ir::BoxingUnboxingFlags GetUnboxingFlag(Type const *unboxingType) const;
    Type *MaybeBoxExpression(ir::Expression *expr);
    Type *MaybeUnboxExpression(ir::Expression *expr);
    Type *MaybePromotedBuiltinType(Type *type) const;
    Type const *MaybePromotedBuiltinType(Type const *type) const;
    Type *MaybePrimitiveBuiltinType(Type *type) const;
    void CheckForSameSwitchCases(ArenaVector<ir::SwitchCaseStatement *> const &cases);
    std::string GetStringFromIdentifierValue(checker::Type *caseType) const;
    bool CompareIdentifiersValuesAreDifferent(ir::Expression *compareValue, const std::string &caseValue);
    void CheckIdentifierSwitchCase(ir::Expression *currentCase, ir::Expression *compareCase,
                                   const lexer::SourcePosition &pos);
    std::string GetStringFromLiteral(ir::Expression *caseTest) const;
    varbinder::Variable *FindVariableInFunctionScope(util::StringView name,
                                                     const varbinder::ResolveBindingOptions options);
    std::pair<varbinder::Variable *, const ETSObjectType *> FindVariableInClassOrEnclosing(
        util::StringView name, const ETSObjectType *classType);
    varbinder::Variable *FindVariableInGlobal(const ir::Identifier *identifier,
                                              const varbinder::ResolveBindingOptions options);
    varbinder::Variable *ExtraCheckForResolvedError(ir::Identifier *ident);
    void ValidateResolvedIdentifier(ir::Identifier *ident, varbinder::Variable *resolved);
    static bool IsVariableStatic(const varbinder::Variable *var);
    static bool IsVariableGetterSetter(const varbinder::Variable *var);
    bool IsSameDeclarationType(varbinder::LocalVariable *target, varbinder::LocalVariable *compare);
    void SaveCapturedVariable(varbinder::Variable *var, ir::Identifier *ident);
    bool SaveCapturedVariableInLocalClass(varbinder::Variable *var, ir::Identifier *ident);
    void AddBoxingFlagToPrimitiveType(TypeRelation *relation, Type *target);
    void AddUnboxingFlagToPrimitiveType(TypeRelation *relation, Type *source, Type *self);
    void CheckUnboxedTypeWidenable(TypeRelation *relation, Type *target, Type *self);
    void CheckUnboxedTypesAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckBoxedSourceTypeAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckUnboxedSourceTypeWithWideningAssignable(TypeRelation *relation, Type *source, Type *target);
    void CheckValidGenericTypeParameter(Type *argType, const lexer::SourcePosition &pos);
    void ValidateResolvedProperty(varbinder::LocalVariable **property, const ETSObjectType *target,
                                  const ir::Identifier *ident, PropertySearchFlags flags);
    bool IsValidSetterLeftSide(const ir::MemberExpression *member);
    bool CheckRethrowingParams(const ir::AstNode *ancestorFunction, const ir::AstNode *node);
    void CheckThrowingStatements(ir::AstNode *node);
    bool CheckThrowingPlacement(ir::AstNode *node, const ir::AstNode *ancestorFunction);
    bool CheckNumberOfTypeArguments(ETSObjectType *type, ir::TSTypeParameterInstantiation *typeArgs,
                                    const lexer::SourcePosition &pos);
    ir::BlockStatement *FindFinalizerOfTryStatement(ir::AstNode *startFrom, const ir::AstNode *p);
    void CheckExceptionClauseType(const std::vector<checker::ETSObjectType *> &exceptions, ir::CatchClause *catchClause,
                                  checker::Type *clauseType);
    void CheckRethrowingFunction(ir::ScriptFunction *func);
    ETSObjectType *GetRelevantArgumentedTypeFromChild(ETSObjectType *child, ETSObjectType *target);
    util::StringView GetHashFromTypeArguments(const ArenaVector<Type *> &typeArgTypes);
    util::StringView GetHashFromSubstitution(const Substitution *substitution);
    util::StringView GetHashFromFunctionType(ir::ETSFunctionType *type);
    static ETSObjectType *GetOriginalBaseType(Type *object);
    void SetArrayPreferredTypeForNestedMemberExpressions(ir::MemberExpression *expr, Type *annotationType);
    bool ExtensionETSFunctionType(checker::Type *type);
    bool ValidateTupleMinElementSize(ir::ArrayExpression *arrayExpr, ETSTupleType *tuple);
    void ModifyPreferredType(ir::ArrayExpression *arrayExpr, Type *newPreferredType);
    Type *SelectGlobalIntegerTypeForNumeric(Type *type);
    Type *TryGettingFunctionTypeFromInvokeFunction(Type *type);
    ir::ClassProperty *ClassPropToImplementationProp(ir::ClassProperty *classProp, varbinder::ClassScope *scope);
    ir::Expression *GenerateImplicitInstantiateArg(varbinder::LocalVariable *instantiateMethod,
                                                   const std::string &className);
    void GenerateGetterSetterBody(ArenaVector<ir::Statement *> &stmts, ArenaVector<ir::Expression *> &params,
                                  ir::ClassProperty *field, varbinder::FunctionParamScope *paramScope, bool isSetter);
    static ir::MethodDefinition *GenerateDefaultGetterSetter(ir::ClassProperty *property, ir::ClassProperty *field,
                                                             varbinder::ClassScope *scope, bool isSetter,
                                                             ETSChecker *checker);
    void GenerateGetterSetterPropertyAndMethod(ir::ClassProperty *originalProp, ETSObjectType *classType);
    ETSObjectType *GetImportSpecifierObjectType(ir::ETSImportDeclaration *importDecl, ir::Identifier *ident);
    void ImportNamespaceObjectTypeAddReExportType(ir::ETSImportDeclaration *importDecl,
                                                  checker::ETSObjectType *lastObjectType, ir::Identifier *ident);
    checker::ETSObjectType *CreateSyntheticType(util::StringView const &syntheticName,
                                                checker::ETSObjectType *lastObjectType, ir::Identifier *id);
    bool CheckValidUnionEqual(checker::Type *const leftType, checker::Type *const rightType);
    bool CheckValidEqualReferenceType(checker::Type *const leftType, checker::Type *const rightType);
    bool CheckVoidAnnotation(const ir::ETSPrimitiveType *typeAnnotation);

    // Utility type handler functions
    ir::TypeNode *GetUtilityTypeTypeParamNode(const ir::TSTypeParameterInstantiation *typeParams,
                                              const std::string_view &utilityTypeName);
    Type *HandleUtilityTypeParameterNode(const ir::TSTypeParameterInstantiation *typeParams,
                                         const std::string_view &utilityType);
    // Partial
    Type *HandlePartialType(Type *typeToBePartial);
    ir::ClassProperty *CreateNullishProperty(ir::ClassProperty *prop, ir::ClassDefinition *newClassDefinition);
    ir::ClassDefinition *CreatePartialClassDeclaration(ir::ClassDefinition *newClassDefinition,
                                                       const ir::ClassDefinition *classDef);
    void CreateConstructorForPartialType(ir::ClassDefinition *partialClassDef, checker::ETSObjectType *partialType,
                                         varbinder::RecordTable *recordTable);
    ir::ClassDefinition *CreateClassPrototype(util::StringView name, parser::Program *classDeclProgram);
    varbinder::Variable *SearchNamesInMultiplePrograms(const std::set<const parser::Program *> &programs,
                                                       const std::set<util::StringView> &classNamesToFind);
    util::StringView GetQualifiedClassName(const parser::Program *classDefProgram, util::StringView className);
    Type *HandleUnionForPartialType(ETSUnionType *typeToBePartial);
    Type *CreatePartialTypeClassDef(ir::ClassDefinition *partialClassDef, ir::ClassDefinition *classDef,
                                    const Type *typeToBePartial, varbinder::RecordTable *recordTableToUse);
    std::pair<ir::ScriptFunction *, ir::Identifier *> CreateScriptFunctionForConstructor(
        varbinder::FunctionScope *scope);
    ir::MethodDefinition *CreateNonStaticClassInitializer(varbinder::ClassScope *classScope,
                                                          varbinder::RecordTable *recordTable);
    // Readonly
    Type *HandleReadonlyType(const ir::TSTypeParameterInstantiation *typeParams);
    Type *GetReadonlyType(Type *type);
    void MakePropertiesReadonly(ETSObjectType *classType);
    // Required
    Type *HandleRequiredType(Type *typeToBeRequired);
    void MakePropertiesNonNullish(ETSObjectType *classType);
    template <PropertyType PROP_TYPE>
    void MakePropertyNonNullish(ETSObjectType *classType, varbinder::LocalVariable *prop);
    void ValidateObjectLiteralForRequiredType(const ETSObjectType *requiredType,
                                              const ir::ObjectExpression *initObjExpr);

    // Smart cast support
    [[nodiscard]] checker::Type *ResolveSmartType(checker::Type *sourceType, checker::Type *targetType);
    [[nodiscard]] std::pair<Type *, Type *> CheckTestNullishCondition(Type *testedType, Type *actualType, bool strict);
    [[nodiscard]] std::pair<Type *, Type *> CheckTestObjectCondition(ETSObjectType *testedType, Type *actualType,
                                                                     bool strict);
    [[nodiscard]] std::pair<Type *, Type *> CheckTestObjectCondition(ETSArrayType *testedType, Type *actualType);

    void ApplySmartCast(varbinder::Variable const *variable, checker::Type *smartType) noexcept;

    bool IsInLocalClass(const ir::AstNode *node) const;
    // Exception
    ETSObjectType *CheckExceptionOrErrorType(checker::Type *type, lexer::SourcePosition pos);

    static Type *TryToInstantiate(Type *type, ArenaAllocator *allocator, TypeRelation *relation,
                                  GlobalTypesHolder *globalTypes);

    // Dynamic interop
    template <typename T>
    Signature *ResolveDynamicCallExpression(ir::Expression *callee, const ArenaVector<T *> &arguments, Language lang,
                                            bool isConstruct);
    ir::ClassProperty *CreateStaticReadonlyField(const char *name);
    void BuildDynamicImportClass();
    void BuildLambdaObjectClass(ETSObjectType *functionalInterface, ir::TypeNode *retTypeAnnotation);
    // Trailing lambda
    void EnsureValidCurlyBrace(ir::CallExpression *callExpr);

    // Extension function
    void HandleUpdatedCallExpressionNode(ir::CallExpression *callExpr);

    // Static invoke
    void CheckInvokeMethodsLegitimacy(ETSObjectType *classType);
    checker::Type *CheckArrayElements(ir::ArrayExpression *init);
    void ResolveReturnStatement(checker::Type *funcReturnType, checker::Type *argumentType,
                                ir::ScriptFunction *containingFunc, ir::ReturnStatement *st);

    auto *DynamicCallNames(bool isConstruct)
    {
        return &dynamicCallNames_[static_cast<uint32_t>(isConstruct)];
    }

    const auto *DynamicCallNames(bool isConstruct) const
    {
        return &dynamicCallNames_[static_cast<uint32_t>(isConstruct)];
    }

    std::recursive_mutex *Mutex()
    {
        return &mtx_;
    }

    template <typename T, typename... Args>
    T *AllocNode(Args &&...args)
    {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        return util::NodeAllocator::ForceSetParent<T>(Allocator(), std::forward<Args>(args)...);
    }

    ArenaVector<ConstraintCheckRecord> &PendingConstraintCheckRecords();
    size_t &ConstraintCheckScopesCount();

    ETSObjectType *GetCachedFunctionalInterface(ir::ETSFunctionType *type);
    void CacheFunctionalInterface(ir::ETSFunctionType *type, ETSObjectType *ifaceType);
    void CollectReturnStatements(ir::AstNode *parent);
    ir::ETSParameterExpression *AddParam(util::StringView name, ir::TypeNode *type);

    [[nodiscard]] ir::ScriptFunction *FindFunction(ir::TSEnumDeclaration const *const enumDecl,
                                                   const std::string_view &name);

    evaluate::ScopedDebugInfoPlugin *GetDebugInfoPlugin();
    const evaluate::ScopedDebugInfoPlugin *GetDebugInfoPlugin() const;

    void SetDebugInfoPlugin(evaluate::ScopedDebugInfoPlugin *debugInfo);

    using ClassBuilder = std::function<void(ArenaVector<ir::AstNode *> *)>;
    using ClassInitializerBuilder =
        std::function<void(ArenaVector<ir::Statement *> *, ArenaVector<ir::Expression *> *)>;
    using MethodBuilder = std::function<void(ArenaVector<ir::Statement *> *, ArenaVector<ir::Expression *> *, Type **)>;

    ir::ClassStaticBlock *CreateClassStaticInitializer(const ClassInitializerBuilder &builder,
                                                       ETSObjectType *type = nullptr);
    ir::MethodDefinition *CreateClassInstanceInitializer(const ClassInitializerBuilder &builder,
                                                         ETSObjectType *type = nullptr);
    ir::MethodDefinition *CreateClassMethod(std::string_view name, ir::ScriptFunctionFlags funcFlags,
                                            ir::ModifierFlags modifierFlags, const MethodBuilder &builder);
    ir::ClassDeclaration *BuildClass(util::StringView name, const ClassBuilder &builder);

private:
    ETSEnumType::Method MakeMethod(ir::TSEnumDeclaration const *const enumDecl, const std::string_view &name,
                                   bool buildPorxyParam, Type *returnType, bool buildProxy = true);

    std::pair<const ir::Identifier *, ir::TypeNode *> GetTargetIdentifierAndType(ir::Identifier *ident);
    void LogUnResolvedError(ir::Identifier *ident);
    void LogOperatorCannotBeApplied(lexer::TokenType operationType, checker::Type *const leftType,
                                    checker::Type *const rightType, lexer::SourcePosition pos);
    void WrongContextErrorClassifyByType(ir::Identifier *ident, varbinder::Variable *resolved);
    void CheckEtsFunctionType(ir::Identifier *ident, ir::Identifier const *id);
    void NotResolvedError(ir::Identifier *const ident, const varbinder::Variable *classVar,
                          const ETSObjectType *classType);
    void ValidateCallExpressionIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                          Type *const type);
    void ValidateNewClassInstanceIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved);
    void ValidateMemberIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved, Type *const type);
    void ValidatePropertyOrDeclaratorIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved);
    void ValidateAssignmentIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                      Type *const type);
    bool ValidateBinaryExpressionIdentifier(ir::Identifier *const ident, Type *const type);
    void ValidateGetterSetter(const ir::MemberExpression *const memberExpr, const varbinder::LocalVariable *const prop,
                              PropertySearchFlags searchFlag);
    ir::ClassProperty *FindClassProperty(const ETSObjectType *objectType, const ETSFunctionType *propType);
    bool IsInitializedProperty(const ir::ClassDefinition *classDefinition, const ir::ClassProperty *prop);
    bool FindPropertyInAssignment(const ir::AstNode *it, const std::string &targetName);
    void ValidateReadonlyProperty(const ir::MemberExpression *memberExpr, const ETSFunctionType *propType,
                                  lexer::SourcePosition sourcePos);
    void ValidateVarDeclaratorOrClassProperty(const ir::MemberExpression *memberExpr, varbinder::LocalVariable *prop);
    void ResolveMemberReferenceValidate(varbinder::LocalVariable *prop, PropertySearchFlags searchFlag,
                                        const ir::MemberExpression *const memberExpr);
    std::tuple<bool, bool> IsResolvedAndValue(const ir::Expression *expr, Type *type) const;
    PropertySearchFlags GetSearchFlags(const ir::MemberExpression *memberExpr, const varbinder::Variable *targetRef);
    PropertySearchFlags GetInitialSearchFlags(const ir::MemberExpression *memberExpr);
    const varbinder::Variable *GetTargetRef(const ir::MemberExpression *memberExpr);
    Type *GetTypeOfSetterGetter([[maybe_unused]] varbinder::Variable *var);
    void IterateInVariableContext([[maybe_unused]] varbinder::Variable *const var);
    bool CheckInit(ir::Identifier *ident, ir::TypeNode *typeAnnotation, ir::Expression *init,
                   checker::Type *annotationType, varbinder::Variable *const bindingVar);
    void CheckItemCasesConstant(ArenaVector<ir::SwitchCaseStatement *> const &cases);
    void CheckItemCasesDuplicate(ArenaVector<ir::SwitchCaseStatement *> const &cases);

    template <typename EnumType>
    EnumType *CreateEnumTypeFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl);

    std::pair<ir::ScriptFunction *, ir::Identifier *> CreateStaticScriptFunction(
        ClassInitializerBuilder const &builder);
    std::pair<ir::ScriptFunction *, ir::Identifier *> CreateScriptFunction(ClassInitializerBuilder const &builder);

    template <typename T>
    ir::MethodDefinition *CreateDynamicCallIntrinsic(ir::Expression *callee, const ArenaVector<T *> &arguments,
                                                     Language lang);
    ir::ClassStaticBlock *CreateDynamicCallClassInitializer(Language lang, bool isConstruct);
    ir::ClassStaticBlock *CreateDynamicModuleClassInitializer(const std::vector<ir::ETSImportDeclaration *> &imports);
    ir::MethodDefinition *CreateDynamicModuleClassInitMethod();

    ir::MethodDefinition *CreateLambdaObjectClassInitializer(ETSObjectType *functionalInterface);

    ir::MethodDefinition *CreateLambdaObjectClassInvokeMethod(Signature *invokeSignature,
                                                              ir::TypeNode *retTypeAnnotation);

    void ClassInitializerFromImport(ir::ETSImportDeclaration *import, ArenaVector<ir::Statement *> *statements);
    void EmitDynamicModuleClassInitCall();
    DynamicCallIntrinsicsMap *DynamicCallIntrinsics(bool isConstruct)
    {
        return &dynamicIntrinsics_[static_cast<size_t>(isConstruct)];
    }

    ir::ClassDeclaration *GetDynamicClass(Language lang, bool isConstruct);

    using Type2TypeMap = std::unordered_map<varbinder::Variable *, varbinder::Variable *>;
    using TypeSet = std::unordered_set<varbinder::Variable *>;
    bool CheckTypeParameterConstraint(ir::TSTypeParameter *param, Type2TypeMap &extends);
    bool CheckDefaultTypeParameter(const ir::TSTypeParameter *param, TypeSet &typeParameterDecls);

    void SetUpTypeParameterConstraint(ir::TSTypeParameter *param);
    ETSObjectType *UpdateGlobalType(ETSObjectType *objType, util::StringView name);
    ETSObjectType *UpdateBoxedGlobalType(ETSObjectType *objType, util::StringView name);
    ETSObjectType *CreateETSObjectTypeCheckBuiltins(util::StringView name, ir::AstNode *declNode, ETSObjectFlags flags);
    void CheckProgram(parser::Program *program, bool runAnalysis = false);
    void CheckWarnings(parser::Program *program, const CompilerOptions &options);

    template <typename UType>
    UType HandleModulo(UType leftValue, UType rightValue);

    template <typename FloatOrIntegerType, typename IntegerType = FloatOrIntegerType>
    Type *HandleBitWiseArithmetic(Type *leftValue, Type *rightValue, lexer::TokenType operationType);

    template <typename TargetType>
    typename TargetType::UType GetOperand(Type *type);

    template <typename... Args>
    ETSObjectType *AsETSObjectType(Type *(GlobalTypesHolder::*typeFunctor)(Args...), Args... args) const;
    Signature *GetMostSpecificSignature(ArenaVector<Signature *> &compatibleSignatures,
                                        const ArenaVector<ir::Expression *> &arguments,
                                        const lexer::SourcePosition &pos, TypeRelationFlag resolveFlags);
    ArenaVector<Signature *> CollectSignatures(ArenaVector<Signature *> &signatures,
                                               const ir::TSTypeParameterInstantiation *typeArguments,
                                               const ArenaVector<ir::Expression *> &arguments,
                                               const lexer::SourcePosition &pos, TypeRelationFlag resolveFlags);
    // Trailing lambda
    void MoveTrailingBlockToEnclosingBlockStatement(ir::CallExpression *callExpr);
    void TransformTraillingLambda(ir::CallExpression *callExpr);
    ArenaVector<ir::Expression *> ExtendArgumentsWithFakeLamda(ir::CallExpression *callExpr);

    // Static invoke
    bool TryTransformingToStaticInvoke(ir::Identifier *ident, const Type *resolvedType);

    ArrayMap arrayTypes_;
    ArenaVector<ConstraintCheckRecord> pendingConstraintCheckRecords_;
    size_t constraintCheckScopesCount_ {0};
    GlobalArraySignatureMap globalArraySignatures_;
    PrimitiveWrappers primitiveWrappers_;
    ComputedAbstracts cachedComputedAbstracts_;
    // NOTE(aleksisch): Extract dynamic from checker to separate class
    std::array<DynamicCallIntrinsicsMap, 2U> dynamicIntrinsics_;
    std::array<DynamicClassIntrinsicsMap, 2U> dynamicClasses_;
    DynamicLambdaObjectSignatureMap dynamicLambdaSignatureCache_;
    FunctionalInterfaceMap functionalInterfaceCache_;
    TypeMapping apparentTypes_;
    std::array<DynamicCallNamesMap, 2U> dynamicCallNames_;
    std::recursive_mutex mtx_;
    evaluate::ScopedDebugInfoPlugin *debugInfoPlugin_ {nullptr};
};

}  // namespace ark::es2panda::checker

#endif /* CHECKER_H */
