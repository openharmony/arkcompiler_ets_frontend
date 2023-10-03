/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ETSGEN_H
#define ES2PANDA_COMPILER_CORE_ETSGEN_H

#include "ir/astNode.h"
#include "binder/ETSBinder.h"
#include "compiler/core/codeGen.h"
#include "compiler/core/ETSfunction.h"
#include "compiler/core/targetTypeContext.h"
#include "checker/ETSchecker.h"
#include "util/helpers.h"

namespace panda::es2panda::compiler {

class ETSGen final : public CodeGen {
public:
    explicit ETSGen(ArenaAllocator *allocator, RegSpiller *spiller, CompilerContext *context,
                    binder::FunctionScope *scope, ProgramElement *program_element) noexcept;

    [[nodiscard]] const checker::ETSChecker *Checker() const noexcept;
    [[nodiscard]] const binder::ETSBinder *Binder() const noexcept;
    [[nodiscard]] const checker::Type *ReturnType() const noexcept;
    [[nodiscard]] const checker::ETSObjectType *ContainingObjectType() const noexcept;

    [[nodiscard]] VReg &Acc() noexcept;
    [[nodiscard]] VReg Acc() const noexcept;

    void SetAccumulatorType(const checker::Type *type);
    [[nodiscard]] const checker::Type *GetAccumulatorType() const;

    [[nodiscard]] VReg StoreException(const ir::AstNode *node);
    void ApplyConversionAndStoreAccumulator(const ir::AstNode *node, VReg vreg, const checker::Type *target_type);
    void StoreAccumulator(const ir::AstNode *node, VReg vreg);
    void LoadAccumulator(const ir::AstNode *node, VReg vreg);
    [[nodiscard]] IRNode *AllocMov(const ir::AstNode *node, VReg vd, VReg vs) override;
    [[nodiscard]] IRNode *AllocMov(const ir::AstNode *node, OutVReg vd, VReg vs) override;
    void MoveVreg(const ir::AstNode *node, VReg vd, VReg vs);

    [[nodiscard]] checker::Type const *TypeForVar(binder::Variable const *var) const noexcept override;

    void LoadVar(const ir::AstNode *node, binder::Variable const *var);
    void LoadDynamicModuleVariable(const ir::AstNode *node, binder::Variable const *var);
    void LoadDynamicNamespaceVariable(const ir::AstNode *node, binder::Variable const *var);
    void StoreVar(const ir::AstNode *node, const binder::ConstScopeFindResult &result);

    void LoadStaticProperty(const ir::AstNode *node, const checker::Type *prop_type, const util::StringView &full_name);
    void StoreStaticProperty(const ir::AstNode *node, const checker::Type *prop_type,
                             const util::StringView &full_name);

    void StoreStaticOwnProperty(const ir::AstNode *node, const checker::Type *prop_type, const util::StringView &name);
    [[nodiscard]] util::StringView FormClassPropReference(const checker::ETSObjectType *class_type,
                                                          const util::StringView &name);

    void EmitGetter(const ir::AstNode *node, VReg vreg, ir::ScriptFunction *script_func);

    void StoreProperty(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                       const util::StringView &name);
    void LoadProperty(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                      const util::StringView &full_name);
    void StorePropertyDynamic(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                              const util::StringView &name, Language lang);
    void LoadPropertyDynamic(const ir::AstNode *node, const checker::Type *prop_type, VReg obj_reg,
                             const util::StringView &prop_name, Language lang);

    void StoreElementDynamic(const ir::AstNode *node, VReg object_reg, VReg index, Language lang);
    void LoadElementDynamic(const ir::AstNode *node, VReg object_reg, Language lang);

    void LoadUndefinedDynamic(const ir::AstNode *node, Language lang);

    void LoadThis(const ir::AstNode *node);
    [[nodiscard]] VReg GetThisReg() const;

    void LoadDefaultValue(const ir::AstNode *node, const checker::Type *type);
    void EmitReturnVoid(const ir::AstNode *node);
    void LoadBuiltinVoid(const ir::AstNode *node);
    void ReturnAcc(const ir::AstNode *node);
    void EmitSetter(const ir::MemberExpression *member, ir::Expression *right);

    void EmitIsInstance(const ir::AstNode *node, VReg lhs);

    void Binary(const ir::AstNode *node, lexer::TokenType op, VReg lhs);
    void Unary(const ir::AstNode *node, lexer::TokenType op);
    void Update(const ir::AstNode *node, lexer::TokenType op);

    bool TryLoadConstantExpression(const ir::Expression *node);
    void Condition(const ir::AstNode *node, lexer::TokenType op, VReg lhs, Label *if_false);

    void BranchIfFalse(const ir::AstNode *node, Label *if_false)
    {
        Sa().Emit<Jeqz>(node, if_false);
    }

    void BranchIfTrue(const ir::AstNode *node, Label *if_false)
    {
        Sa().Emit<Jnez>(node, if_false);
    }

    void BranchIfNull(const ir::AstNode *node, Label *if_null)
    {
        Sa().Emit<JeqzObj>(node, if_null);
    }

    void BranchIfNotNull(const ir::AstNode *node, Label *if_not_null)
    {
        Sa().Emit<JnezObj>(node, if_not_null);
    }

    void JumpTo(const ir::AstNode *node, Label *label_to)
    {
        Sa().Emit<Jmp>(node, label_to);
    }

    void EmitThrow(const ir::AstNode *node, VReg err)
    {
        Ra().Emit<Throw>(node, err);
    }

    void EmitNullPointerException(const ir::AstNode *node);

    void ThrowException(const ir::Expression *expr);
    bool ExtendWithFinalizer(ir::AstNode *node, const ir::AstNode *original_node, Label *prev_finnaly = nullptr);

    void Negate(const ir::AstNode *node);
    void LogicalNot(const ir::AstNode *node);

    void LoadAccumulatorByte(const ir::AstNode *node, int8_t number)
    {
        LoadAccumulatorNumber<int8_t>(node, number, checker::TypeFlag::BYTE);
    }

    void LoadAccumulatorShort(const ir::AstNode *node, int16_t number)
    {
        LoadAccumulatorNumber<int16_t>(node, number, checker::TypeFlag::SHORT);
    }

    void LoadAccumulatorInt(const ir::AstNode *node, int32_t number)
    {
        LoadAccumulatorNumber<int32_t>(node, number, checker::TypeFlag::INT);
    }

    void LoadAccumulatorWideInt(const ir::AstNode *node, int64_t number)
    {
        LoadAccumulatorNumber<int64_t>(node, number, checker::TypeFlag::LONG);
    }

    void LoadAccumulatorFloat(const ir::AstNode *node, float number)
    {
        LoadAccumulatorNumber<float>(node, number, checker::TypeFlag::FLOAT);
    }

    void LoadAccumulatorDouble(const ir::AstNode *node, double number)
    {
        LoadAccumulatorNumber<double>(node, number, checker::TypeFlag::DOUBLE);
    }

    void LoadAccumulatorBoolean(const ir::AstNode *node, bool value)
    {
        Sa().Emit<Ldai>(node, value ? 1 : 0);
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
        ApplyConversion(node, nullptr);
    }

    void LoadAccumulatorString(const ir::AstNode *node, util::StringView str)
    {
        Sa().Emit<LdaStr>(node, str);
        SetAccumulatorType(Checker()->GlobalETSStringLiteralType());
    }

    void LoadAccumulatorNull(const ir::AstNode *node, const checker::Type *type)
    {
        Sa().Emit<LdaNull>(node);
        SetAccumulatorType(type);
    }

    void LoadAccumulatorChar(const ir::AstNode *node, char16_t value)
    {
        Sa().Emit<Ldai>(node, value);
        SetAccumulatorType(Checker()->GlobalCharType());
        ApplyConversion(node);
    }

    void LoadAccumulatorDynamicModule(const ir::AstNode *node, const ir::ETSImportDeclaration *import);

    void ApplyConversion(const ir::AstNode *node)
    {
        if (target_type_ != nullptr) {
            ApplyConversion(node, target_type_);
        }
    }
    void ApplyConversion(const ir::AstNode *node, const checker::Type *target_type);
    void ApplyCast(const ir::AstNode *node, const checker::Type *target_type);
    void EmitUnboxingConversion(const ir::AstNode *node);
    void EmitBoxingConversion(const ir::AstNode *node);
    void SwapBinaryOpArgs(const ir::AstNode *node, VReg lhs);
    VReg MoveAccToReg(const ir::AstNode *node);

    void EmitLocalBoxCtor(ir::AstNode const *node);
    void EmitLocalBoxGet(ir::AstNode const *node, checker::Type const *content_type);
    void EmitLocalBoxSet(ir::AstNode const *node, binder::LocalVariable *lhs);

    void LoadArrayLength(const ir::AstNode *node, VReg array_reg);
    void LoadArrayElement(const ir::AstNode *node, VReg object_reg);
    void StoreArrayElement(const ir::AstNode *node, VReg object_reg, VReg index, const checker::Type *element_type);

    template <typename T>
    void MoveImmediateToRegister(const ir::AstNode *node, VReg reg, const checker::TypeFlag value_type, T const value)
    {
        switch (value_type) {
            case checker::TypeFlag::ETS_BOOLEAN:
                [[fallthrough]];
            case checker::TypeFlag::BYTE: {
                Ra().Emit<Movi>(node, reg, static_cast<checker::ByteType::UType>(value));
                SetVRegType(reg, Checker()->GlobalByteType());
                break;
            }
            case checker::TypeFlag::CHAR: {
                Ra().Emit<Movi>(node, reg, static_cast<checker::CharType::UType>(value));
                SetVRegType(reg, Checker()->GlobalCharType());
                break;
            }
            case checker::TypeFlag::SHORT: {
                Ra().Emit<Movi>(node, reg, static_cast<checker::ShortType::UType>(value));
                SetVRegType(reg, Checker()->GlobalShortType());
                break;
            }
            case checker::TypeFlag::INT: {
                Ra().Emit<Movi>(node, reg, static_cast<checker::IntType::UType>(value));
                SetVRegType(reg, Checker()->GlobalIntType());
                break;
            }
            case checker::TypeFlag::LONG: {
                Ra().Emit<MoviWide>(node, reg, static_cast<checker::LongType::UType>(value));
                SetVRegType(reg, Checker()->GlobalLongType());
                break;
            }
            case checker::TypeFlag::FLOAT: {
                Ra().Emit<Fmovi>(node, reg, static_cast<checker::FloatType::UType>(value));
                SetVRegType(reg, Checker()->GlobalFloatType());
                break;
            }
            case checker::TypeFlag::DOUBLE: {
                Ra().Emit<FmoviWide>(node, reg, static_cast<checker::DoubleType::UType>(value));
                SetVRegType(reg, Checker()->GlobalDoubleType());
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    template <typename T>
    void IncrementImmediateRegister(const ir::AstNode *node, VReg reg, const checker::TypeFlag value_type,
                                    T const value)
    {
        switch (value_type) {
            // NOTE: operand of increment instruction (INCI) is defined in spec as 32-bit integer,
            // but its current implementation actually can work with 64-bit integers as well.
            // Thus, leave this case just in case for possible use in the future.
            // case checker::TypeFlag::LONG: {
            //     Ra().Emit<Inci>(node, reg, static_cast<checker::LongType::UType>(value));
            //     break;
            // }
            case checker::TypeFlag::INT: {
                Ra().Emit<Inci>(node, reg, static_cast<checker::IntType::UType>(value));
                break;
            }
            case checker::TypeFlag::CHAR: {
                Ra().Emit<Inci>(node, reg, static_cast<checker::CharType::UType>(value));
                break;
            }
            case checker::TypeFlag::SHORT: {
                Ra().Emit<Inci>(node, reg, static_cast<checker::ShortType::UType>(value));
                break;
            }
            case checker::TypeFlag::ETS_BOOLEAN:
                [[fallthrough]];
            case checker::TypeFlag::BYTE: {
                Ra().Emit<Inci>(node, reg, static_cast<checker::ByteType::UType>(value));
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    template <typename IntCompare>
    void JumpCompareRegister(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        Ra().Emit<IntCompare>(node, lhs, if_false);
    }

    void LoadStringLength(const ir::AstNode *node);
    void LoadStringChar(const ir::AstNode *node, VReg string_obj, VReg char_index);

    void CompileStatements(const ArenaVector<ir::Statement *> &statements);

    // Cast
    void CastToBoolean(const ir::AstNode *node);
    void CastToByte(const ir::AstNode *node);
    void CastToChar(const ir::AstNode *node);
    void CastToShort(const ir::AstNode *node);
    void CastToDouble(const ir::AstNode *node);
    void CastToFloat(const ir::AstNode *node);
    void CastToLong(const ir::AstNode *node);
    void CastToInt(const ir::AstNode *node);
    void CastToString(const ir::AstNode *node);
    void CastToDynamic(const ir::AstNode *node, const checker::ETSDynamicType *type);
    void CastDynamicTo(const ir::AstNode *node, enum checker::TypeFlag type_flag);
    void CastToArrayOrObject(const ir::AstNode *node, const checker::Type *target_type, bool unchecked);
    void EmitCheckedNarrowingReferenceConversion(const ir::AstNode *node, const checker::Type *target_type);
    void CastDynamicToObject(const ir::AstNode *node, const checker::Type *target_type);

    // Call, Construct
    void NewArray(const ir::AstNode *node, VReg arr, VReg dim, const checker::Type *arr_type);
    void NewObject(const ir::AstNode *node, VReg ctor, util::StringView name);
    void BuildString(const ir::Expression *node);
    void BuildTemplateString(const ir::TemplateLiteral *node);
    void InitObject(const ir::AstNode *node, checker::Signature *signature,
                    const ArenaVector<ir::Expression *> &arguments)
    {
        CallImpl<InitobjShort, Initobj, InitobjRange>(node, signature, arguments);
    }

    void CallStatic(const ir::AstNode *node, checker::Signature *signature,
                    const ArenaVector<ir::Expression *> &arguments)
    {
        CallImpl<CallShort, Call, CallRange>(node, signature, arguments);
    }

    void CallThisStatic(const ir::AstNode *const node, const VReg ctor, checker::Signature *const signature,
                        const ArenaVector<ir::Expression *> &arguments)
    {
        CallThisImpl<CallShort, Call, CallRange>(node, ctor, signature, arguments);
    }

    void CallThisVirtual(const ir::AstNode *const node, const VReg ctor, checker::Signature *const signature,
                         const ArenaVector<ir::Expression *> &arguments)
    {
        CallThisImpl<CallVirtShort, CallVirt, CallVirtRange>(node, ctor, signature, arguments);
    }

    void CallThisVirtual0(const ir::AstNode *const node, const VReg ctor, const util::StringView name)
    {
        Ra().Emit<CallVirtShort, 1>(node, name, ctor, dummy_reg_);
    }

    void CallThisVirtual1(const ir::AstNode *const node, const VReg ctor, const util::StringView name, const VReg arg0)
    {
        Ra().Emit<CallVirtShort>(node, name, ctor, arg0);
    }

    void CallThisStatic0(const ir::AstNode *const node, const VReg ctor, const util::StringView name)
    {
        Ra().Emit<CallShort, 1>(node, name, ctor, dummy_reg_);
    }

    void CallThisStatic1(const ir::AstNode *const node, const VReg ctor, const util::StringView name, const VReg arg0)
    {
        Ra().Emit<CallShort>(node, name, ctor, arg0);
    }

    void CallThisStatic2(const ir::AstNode *const node, const VReg ctor, const util::StringView name, const VReg arg0,
                         const VReg arg1)
    {
        Ra().Emit<Call, 3>(node, name, ctor, arg0, arg1, dummy_reg_);
    }

    void CallDynamic(const ir::AstNode *node, VReg &obj, VReg &param2, checker::Signature *signature,
                     const ArenaVector<ir::Expression *> &arguments)
    {
        CallDynamicImpl<CallShort, Call, CallRange>(node, obj, param2, signature, arguments);
    }

#ifdef PANDA_WITH_ETS
    // The functions below use ETS specific instructions.
    // Compilation of es2panda fails if ETS plugin is disabled
    void LaunchStatic(const ir::AstNode *node, checker::Signature *signature,
                      const ArenaVector<ir::Expression *> &arguments)
    {
        CallImpl<EtsLaunchShort, EtsLaunch, EtsLaunchRange>(node, signature, arguments);
    }

    void LaunchThisStatic(const ir::AstNode *const node, const VReg ctor, checker::Signature *const signature,
                          const ArenaVector<ir::Expression *> &arguments)
    {
        CallThisImpl<EtsLaunchShort, EtsLaunch, EtsLaunchRange>(node, ctor, signature, arguments);
    }

    void LaunchThisVirtual(const ir::AstNode *const node, const VReg ctor, checker::Signature *const signature,
                           const ArenaVector<ir::Expression *> &arguments)
    {
        CallThisImpl<EtsLaunchVirtShort, EtsLaunchVirt, EtsLaunchVirtRange>(node, ctor, signature, arguments);
    }
#endif  // PANDA_WITH_ETS

    void CreateLambdaObjectFromIdentReference(const ir::AstNode *node, ir::ClassDefinition *lambda_obj);
    void CreateLambdaObjectFromMemberReference(const ir::AstNode *node, ir::Expression *obj,
                                               ir::ClassDefinition *lambda_obj);
    void InitLambdaObject(const ir::AstNode *node, checker::Signature *signature, std::vector<VReg> &arguments);

    void GetType(const ir::AstNode *node, bool is_ets_primitive)
    {
        if (is_ets_primitive) {
            // TODO(SzD) LoadStaticProperty if ETS stdlib has static TYPE constants otherwise fallback to LdaType
        } else {
            auto class_ref = GetAccumulatorType()->AsETSObjectType()->AssemblerName();
            Sa().Emit<LdaType>(node, class_ref);
        }
    }

    ~ETSGen() override = default;
    NO_COPY_SEMANTIC(ETSGen);
    NO_MOVE_SEMANTIC(ETSGen);

private:
    const VReg dummy_reg_ = VReg::RegStart();

    void StringBuilderAppend(const ir::AstNode *node, VReg builder);
    void AppendString(const ir::Expression *bin_expr, VReg builder);
    void StringBuilder(const ir::Expression *left, const ir::Expression *right, VReg builder);
    util::StringView FormClassPropReference(binder::Variable const *var);
    void UnaryMinus(const ir::AstNode *node);
    void UnaryTilde(const ir::AstNode *node);

    template <typename T>
    void StoreValueIntoArray(const ir::AstNode *const node, const VReg arr, const VReg index)
    {
        Ra().Emit<T>(node, arr, index);
    }

    template <typename LongOp, typename IntOp, typename DoubleOp, typename FloatOp>
    void UpdateOperator(const ir::AstNode *node)
    {
        switch (checker::ETSChecker::ETSType(GetAccumulatorType())) {
            case checker::TypeFlag::LONG: {
                RegScope scope(this);
                VReg reg = AllocReg();
                Ra().Emit<MoviWide>(node, reg, 1LL);
                Ra().Emit<LongOp>(node, reg);
                break;
            }
            case checker::TypeFlag::INT:
            case checker::TypeFlag::CHAR:
            case checker::TypeFlag::SHORT:
            case checker::TypeFlag::BYTE: {
                Sa().Emit<IntOp>(node, 1);
                break;
            }
            case checker::TypeFlag::DOUBLE: {
                RegScope scope(this);
                VReg reg = AllocReg();
                Ra().Emit<FmoviWide>(node, reg, 1.0);
                Ra().Emit<DoubleOp>(node, reg);
                break;
            }
            case checker::TypeFlag::FLOAT: {
                RegScope scope(this);
                VReg reg = AllocReg();
                Ra().Emit<Fmovi>(node, reg, 1.0F);
                Ra().Emit<FloatOp>(node, reg);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    template <typename CondCompare>
    void ConditionalBranching(const ir::AstNode *node, Label *if_false)
    {
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
        if constexpr (std::is_same_v<CondCompare, Jeqz>) {
            LogicalNot(node);
        }
        BranchIfFalse(node, if_false);
    }

    template <typename CondCompare>
    void BinaryEqualityObj(const ir::AstNode *node, VReg lhs, VReg arg0, Label *if_false)
    {
        Label *if_null = AllocLabel();
        Label *if_true = AllocLabel();
        LoadAccumulator(node, lhs);
        BranchIfNull(node, if_null);
        if (GetVRegType(lhs)->IsETSStringType() && GetVRegType(arg0)->IsETSObjectType()) {
            CallThisStatic1(node, lhs, Signatures::BUILTIN_STRING_EQUALS, arg0);
        } else {
            CallThisVirtual1(node, lhs, Signatures::BUILTIN_OBJECT_EQUALS, arg0);
        }
        ConditionalBranching<CondCompare>(node, if_false);
        JumpTo(node, if_true);

        SetLabel(node, if_null);
        LoadAccumulator(node, arg0);
        if constexpr (std::is_same_v<CondCompare, Jeqz>) {
            BranchIfNull(node, if_false);
        } else {
            BranchIfNotNull(node, if_false);
        }

        SetLabel(node, if_true);
    }

    template <typename Compare, typename Cond>
    void BinaryNumberComparison(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        Ra().Emit<Compare>(node, lhs);
        Sa().Emit<Cond>(node, if_false);
    }

    template <typename DynCompare>
    void BinaryDynamicStrictEquality(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        ASSERT(GetAccumulatorType()->IsETSDynamicType() && GetVRegType(lhs)->IsETSDynamicType());
        Ra().Emit<CallShort, 2>(node, Signatures::BUILTIN_JSRUNTIME_STRICT_EQUAL, lhs, MoveAccToReg(node));
        Ra().Emit<DynCompare>(node, if_false);
    }

    template <typename ObjCompare, typename IntCompare, typename CondCompare, typename DynCompare>
    void BinaryEquality(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        if (GetAccumulatorType()->IsETSDynamicType() || GetVRegType(lhs)->IsETSDynamicType()) {
            BinaryDynamicStrictEquality<DynCompare>(node, lhs, if_false);
        } else {
            BinaryEqualityCondition<ObjCompare, IntCompare, CondCompare>(node, lhs, if_false);
        }

        ToBinaryResult(node, if_false);
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    }

    template <typename ObjCompare, typename IntCompare, typename CondCompare>
    void BinaryEqualityCondition(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        auto type_kind = checker::ETSChecker::TypeKind(target_type_);

        switch (type_kind) {
            case checker::TypeFlag::ETS_OBJECT: {
                RegScope rs(this);
                VReg arg0 = AllocReg();
                StoreAccumulator(node, arg0);
                BinaryEqualityObj<CondCompare>(node, lhs, arg0, if_false);
                return;
            }
            case checker::TypeFlag::DOUBLE: {
                BinaryFloatingPointComparison<FcmpgWide, FcmplWide, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::FLOAT: {
                BinaryFloatingPointComparison<Fcmpg, Fcmpl, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::LONG: {
                BinaryNumberComparison<CmpWide, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::ETS_ENUM:
            case checker::TypeFlag::ETS_BOOLEAN:
            case checker::TypeFlag::BYTE:
            case checker::TypeFlag::CHAR:
            case checker::TypeFlag::SHORT:
            case checker::TypeFlag::INT: {
                Ra().Emit<IntCompare>(node, lhs, if_false);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    }

    template <typename ObjCompare, typename DynCompare>
    void BinaryStrictEquality(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        if (GetAccumulatorType()->IsETSDynamicType() || GetVRegType(lhs)->IsETSDynamicType()) {
            BinaryDynamicStrictEquality<DynCompare>(node, lhs, if_false);
        } else {
            Ra().Emit<ObjCompare>(node, lhs, if_false);
        }

        ToBinaryResult(node, if_false);
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    }

    template <typename IntCompare, typename CondCompare>
    void BinaryRelation(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        BinaryRelationCondition<IntCompare, CondCompare>(node, lhs, if_false);
        ToBinaryResult(node, if_false);
        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    }

    template <typename IntCompare, typename CondCompare>
    void BinaryRelationCondition(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        auto type_kind = checker::ETSChecker::TypeKind(target_type_);

        switch (type_kind) {
            case checker::TypeFlag::DOUBLE: {
                BinaryFloatingPointComparison<FcmpgWide, FcmplWide, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::FLOAT: {
                BinaryFloatingPointComparison<Fcmpg, Fcmpl, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::LONG: {
                BinaryNumberComparison<CmpWide, CondCompare>(node, lhs, if_false);
                break;
            }
            case checker::TypeFlag::ETS_BOOLEAN:
            case checker::TypeFlag::BYTE:
            case checker::TypeFlag::SHORT:
            case checker::TypeFlag::INT: {
                Ra().Emit<IntCompare>(node, lhs, if_false);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        SetAccumulatorType(Checker()->GlobalETSBooleanType());
    }

    template <typename CompareGreater, typename CompareLess, typename CondCompare>
    void BinaryFloatingPointComparison(const ir::AstNode *node, VReg lhs, Label *if_false)
    {
        if constexpr (std::is_same_v<CondCompare, Jgez> || std::is_same_v<CondCompare, Jgtz>) {
            BinaryNumberComparison<CompareGreater, CondCompare>(node, lhs, if_false);
        } else {
            BinaryNumberComparison<CompareLess, CondCompare>(node, lhs, if_false);
        }
    }

    template <typename IntOp, typename LongOp, typename FloatOp, typename DoubleOp>
    void BinaryArithmetic(const ir::AstNode *node, VReg lhs)
    {
        auto type_kind = checker::ETSChecker::TypeKind(target_type_);

        switch (type_kind) {
            case checker::TypeFlag::DOUBLE: {
                Ra().Emit<DoubleOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalDoubleType());
                break;
            }
            case checker::TypeFlag::FLOAT: {
                Ra().Emit<FloatOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalFloatType());
                break;
            }
            default: {
                BinaryBitwiseArithmetic<IntOp, LongOp>(node, lhs);
            }
        }
    }

    template <typename IntOp, typename LongOp>
    void BinaryBitwiseArithmetic(const ir::AstNode *node, VReg lhs)
    {
        auto type_kind = checker::ETSChecker::TypeKind(target_type_);

        switch (type_kind) {
            case checker::TypeFlag::LONG: {
                Ra().Emit<LongOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalLongType());
                break;
            }
            case checker::TypeFlag::BYTE:
            case checker::TypeFlag::SHORT:
            case checker::TypeFlag::INT: {
                Ra().Emit<IntOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalIntType());
                break;
            }
            case checker::TypeFlag::ETS_BOOLEAN: {
                Ra().Emit<IntOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalETSBooleanType());
                break;
            }
            case checker::TypeFlag::CHAR: {
                Ra().Emit<IntOp>(node, lhs);
                SetAccumulatorType(Checker()->GlobalCharType());
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }
// NOLINTBEGIN(cppcoreguidelines-macro-usage, readability-container-size-empty)
#define COMPILE_ARG(idx)                                                                     \
    ASSERT(idx < arguments.size());                                                          \
    auto *paramType##idx = Checker()->MaybeBoxedType(signature->Params()[idx], Allocator()); \
    auto ttctx##idx = TargetTypeContext(this, paramType##idx);                               \
    arguments[idx]->Compile(this);                                                           \
    VReg arg##idx = AllocReg();                                                              \
    ApplyConversion(arguments[idx], nullptr);                                                \
    ApplyConversionAndStoreAccumulator(arguments[idx], arg##idx, paramType##idx);

    template <typename Short, typename General, typename Range>
    void CallThisImpl(const ir::AstNode *const node, const VReg ctor, checker::Signature *const signature,
                      const ArenaVector<ir::Expression *> &arguments)
    {
        RegScope rs(this);
        const auto name = signature->InternalName();

        switch (arguments.size()) {
            case 0: {
                Ra().Emit<Short, 1>(node, name, ctor, dummy_reg_);
                break;
            }
            case 1: {
                COMPILE_ARG(0);
                Ra().Emit<Short>(node, name, ctor, arg0);
                break;
            }
            case 2: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                Ra().Emit<General, 3>(node, name, ctor, arg0, arg1, dummy_reg_);
                break;
            }
            case 3: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                COMPILE_ARG(2);
                Ra().Emit<General>(node, name, ctor, arg0, arg1, arg2);
                break;
            }
            default: {
                for (const auto *arg : arguments) {
                    auto ttctx = TargetTypeContext(this, arg->TsType());
                    VReg arg_reg = AllocReg();
                    arg->Compile(this);
                    StoreAccumulator(node, arg_reg);
                }

                Rra().Emit<Range>(node, ctor, arguments.size() + 1, name, ctor);
                break;
            }
        }
    }

    template <typename Short, typename General, typename Range>
    void CallImpl(const ir::AstNode *node, checker::Signature *signature,
                  const ArenaVector<ir::Expression *> &arguments)
    {
        RegScope rs(this);
        const auto name = signature->InternalName();

        switch (arguments.size()) {
            case 0: {
                Ra().Emit<Short, 0>(node, name, dummy_reg_, dummy_reg_);
                break;
            }
            case 1: {
                COMPILE_ARG(0);
                Ra().Emit<Short, 1>(node, name, arg0, dummy_reg_);
                break;
            }
            case 2: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                Ra().Emit<Short>(node, name, arg0, arg1);
                break;
            }
            case 3: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                COMPILE_ARG(2);
                Ra().Emit<General, 3>(node, name, arg0, arg1, arg2, dummy_reg_);
                break;
            }
            case 4: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                COMPILE_ARG(2);
                COMPILE_ARG(3);
                Ra().Emit<General>(node, name, arg0, arg1, arg2, arg3);
                break;
            }
            default: {
                VReg arg_start = NextReg();

                for (const auto *arg : arguments) {
                    auto ttctx = TargetTypeContext(this, arg->TsType());
                    VReg arg_reg = AllocReg();
                    arg->Compile(this);
                    StoreAccumulator(node, arg_reg);
                }

                Rra().Emit<Range>(node, arg_start, arguments.size(), name, arg_start);
                break;
            }
        }
    }
#undef COMPILE_ARG

#define COMPILE_ARG(idx)                                            \
    ASSERT(idx < arguments.size());                                 \
    auto *paramType##idx = signature->Params()[idx + 2U]->TsType(); \
    auto ttctx##idx = TargetTypeContext(this, paramType##idx);      \
    VReg arg##idx = AllocReg();                                     \
    arguments[idx]->Compile(this);                                  \
    ApplyConversionAndStoreAccumulator(arguments[idx], arg##idx, paramType##idx);

    template <typename Short, typename General, typename Range>
    void CallDynamicImpl(const ir::AstNode *node, VReg &obj, VReg &param2, checker::Signature *signature,
                         const ArenaVector<ir::Expression *> &arguments)
    {
        RegScope rs(this);
        const auto name = signature->InternalName();

        switch (arguments.size()) {
            case 0: {
                Ra().Emit<Short>(node, name, obj, param2);
                break;
            }
            case 1: {
                COMPILE_ARG(0);
                Ra().Emit<General, 3>(node, name, obj, param2, arg0, dummy_reg_);
                break;
            }
            case 2: {
                COMPILE_ARG(0);
                COMPILE_ARG(1);
                Ra().Emit<General>(node, name, obj, param2, arg0, arg1);
                break;
            }
            default: {
                size_t index = 0;
                for (const auto *arg : arguments) {
                    auto ttctx = TargetTypeContext(this, arg->TsType());
                    VReg arg_reg = AllocReg();
                    arg->Compile(this);
                    // + 2U since we need to skip first 2 args in signature; first args is obj,
                    // second arg is param2
                    auto *arg_type = signature->Params()[index + 2U]->TsType();
                    ApplyConversionAndStoreAccumulator(node, arg_reg, arg_type);
                    index++;
                }

                Rra().Emit<Range>(node, obj, arguments.size() + 2, name, obj);
                break;
            }
        }
    }

#undef COMPILE_ARG
    // NOLINTEND(cppcoreguidelines-macro-usage, readability-container-size-empty)

    void ToBinaryResult(const ir::AstNode *node, Label *if_false);

    template <typename T>
    void LoadAccumulatorNumber(const ir::AstNode *node, T number, checker::TypeFlag target_type);
    void InitializeContainingClass();

    util::StringView FormDynamicModulePropReference(const binder::Variable *var);
    util::StringView FormDynamicModulePropReference(const ir::ETSImportDeclaration *import);

    friend class TargetTypeContext;

    VReg acc_ {};
    const checker::Type *target_type_ {};
    const checker::ETSObjectType *containing_object_type_ {};
};

template <typename T>
void ETSGen::LoadAccumulatorNumber(const ir::AstNode *node, T number, checker::TypeFlag target_type)
{
    auto type_kind =
        target_type_ && !target_type_->IsETSObjectType() ? checker::ETSChecker::TypeKind(target_type_) : target_type;

    switch (type_kind) {
        case checker::TypeFlag::ETS_BOOLEAN:
        case checker::TypeFlag::BYTE: {
            Sa().Emit<Ldai>(node, static_cast<checker::ByteType::UType>(number));
            SetAccumulatorType(Checker()->GlobalByteType());
            break;
        }
        case checker::TypeFlag::CHAR: {
            Sa().Emit<Ldai>(node, static_cast<checker::CharType::UType>(number));
            SetAccumulatorType(Checker()->GlobalCharType());
            break;
        }
        case checker::TypeFlag::SHORT: {
            Sa().Emit<Ldai>(node, static_cast<checker::ShortType::UType>(number));
            SetAccumulatorType(Checker()->GlobalShortType());
            break;
        }
        case checker::TypeFlag::INT: {
            Sa().Emit<Ldai>(node, static_cast<checker::IntType::UType>(number));
            SetAccumulatorType(Checker()->GlobalIntType());
            break;
        }
        case checker::TypeFlag::LONG: {
            Sa().Emit<LdaiWide>(node, static_cast<checker::LongType::UType>(number));
            SetAccumulatorType(Checker()->GlobalLongType());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Sa().Emit<Fldai>(node, static_cast<checker::FloatType::UType>(number));
            SetAccumulatorType(Checker()->GlobalFloatType());
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Sa().Emit<FldaiWide>(node, static_cast<checker::DoubleType::UType>(number));
            SetAccumulatorType(Checker()->GlobalDoubleType());
            break;
        }
        case checker::TypeFlag::ETS_ENUM: {
            Sa().Emit<Ldai>(node, static_cast<checker::ETSEnumType::UType>(number));
            SetAccumulatorType(Checker()->GlobalIntType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    if (target_type_ && target_type_->IsETSObjectType()) {
        ApplyConversion(node, target_type_);
    }
}

}  // namespace panda::es2panda::compiler

#endif
