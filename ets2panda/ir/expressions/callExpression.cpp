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

#include "callExpression.h"

#include "util/helpers.h"
#include "compiler/core/function.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "checker/types/ts/objectType.h"
#include "checker/types/signature.h"
#include "ir/astDump.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/chainExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsEnumMember.h"

namespace panda::es2panda::ir {
void CallExpression::TransformChildren(const NodeTransformer &cb)
{
    callee_ = cb(callee_)->AsExpression();

    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterInstantiation();
    }

    for (auto *&it : arguments_) {
        it = cb(it)->AsExpression();
    }
}

void CallExpression::Iterate(const NodeTraverser &cb) const
{
    cb(callee_);

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : arguments_) {
        cb(it);
    }

    if (trailing_block_ != nullptr) {
        cb(trailing_block_);
    }
}

void CallExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "CallExpression"},
                 {"callee", callee_},
                 {"arguments", arguments_},
                 {"optional", optional_},
                 {"typeParameters", AstDumper::Optional(type_params_)}});
}

compiler::VReg CallExpression::CreateSpreadArguments(compiler::PandaGen *pg) const
{
    compiler::VReg args_obj = pg->AllocReg();
    pg->CreateArray(this, arguments_, args_obj);

    return args_obj;
}

void CallExpression::ConvertRestArguments(checker::ETSChecker *const checker) const
{
    if (signature_->RestVar() != nullptr) {
        std::size_t const argument_count = arguments_.size();
        std::size_t const parameter_count = signature_->MinArgCount();
        ASSERT(argument_count >= parameter_count);

        auto &arguments = const_cast<ArenaVector<Expression *> &>(arguments_);
        std::size_t i = parameter_count;

        if (i < argument_count && arguments_[i]->IsSpreadElement()) {
            arguments[i] = arguments_[i]->AsSpreadElement()->Argument();
        } else {
            ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
            for (; i < argument_count; ++i) {
                elements.emplace_back(arguments_[i]);
            }
            auto *array_expression = checker->AllocNode<ir::ArrayExpression>(std::move(elements), checker->Allocator());
            array_expression->SetParent(const_cast<CallExpression *>(this));
            array_expression->SetTsType(signature_->RestVar()->TsType());
            arguments.erase(arguments_.begin() + parameter_count, arguments_.end());
            arguments.emplace_back(array_expression);
        }
    }
}

void CallExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    bool contains_spread = util::Helpers::ContainSpreadElement(arguments_);

    if (callee_->IsSuperExpression()) {
        if (contains_spread) {
            compiler::RegScope param_scope(pg);
            compiler::VReg args_obj = CreateSpreadArguments(pg);

            pg->GetFunctionObject(this);
            pg->SuperCallSpread(this, args_obj);
        } else {
            compiler::RegScope param_scope(pg);
            compiler::VReg arg_start {};

            if (arguments_.empty()) {
                arg_start = pg->AllocReg();
                pg->StoreConst(this, arg_start, compiler::Constant::JS_UNDEFINED);
            } else {
                arg_start = pg->NextReg();
            }

            for (const auto *it : arguments_) {
                compiler::VReg arg = pg->AllocReg();
                it->Compile(pg);
                pg->StoreAccumulator(it, arg);
            }

            pg->GetFunctionObject(this);
            pg->SuperCall(this, arg_start, arguments_.size());
        }

        compiler::VReg new_this = pg->AllocReg();
        pg->StoreAccumulator(this, new_this);

        pg->GetThis(this);
        pg->ThrowIfSuperNotCorrectCall(this, 1);

        pg->LoadAccumulator(this, new_this);
        pg->SetThis(this);

        compiler::Function::CompileInstanceFields(pg, pg->RootNode()->AsScriptFunction());
        return;
    }

    compiler::VReg callee = pg->AllocReg();
    compiler::VReg this_reg = compiler::VReg::Invalid();

    if (callee_->IsMemberExpression()) {
        this_reg = pg->AllocReg();

        compiler::RegScope mrs(pg);
        callee_->AsMemberExpression()->CompileToReg(pg, this_reg);
    } else if (callee_->IsChainExpression()) {
        this_reg = pg->AllocReg();

        compiler::RegScope mrs(pg);
        callee_->AsChainExpression()->CompileToReg(pg, this_reg);
    } else {
        callee_->Compile(pg);
    }

    pg->StoreAccumulator(this, callee);
    pg->OptionalChainCheck(optional_, callee);

    if (contains_spread || arguments_.size() >= compiler::PandaGen::MAX_RANGE_CALL_ARG) {
        if (this_reg.IsInvalid()) {
            this_reg = pg->AllocReg();
            pg->StoreConst(this, this_reg, compiler::Constant::JS_UNDEFINED);
        }

        compiler::VReg args_obj = CreateSpreadArguments(pg);
        pg->CallSpread(this, callee, this_reg, args_obj);
    } else {
        pg->Call(this, callee, this_reg, arguments_);
    }
}

void CallExpression::Compile(compiler::ETSGen *etsg) const
{
    compiler::RegScope rs(etsg);
    compiler::VReg callee_reg = etsg->AllocReg();

    const auto is_proxy = signature_->HasSignatureFlag(checker::SignatureFlags::PROXY);

    if (is_proxy && callee_->IsMemberExpression()) {
        auto *const callee_object = callee_->AsMemberExpression()->Object();

        auto const *const enum_interface = [callee_type =
                                                callee_object->TsType()]() -> checker::ETSEnumInterface const * {
            if (callee_type->IsETSEnumType()) {
                return callee_type->AsETSEnumType();
            }
            if (callee_type->IsETSStringEnumType()) {
                return callee_type->AsETSStringEnumType();
            }
            return nullptr;
        }();

        if (enum_interface != nullptr) {
            ArenaVector<ir::Expression *> arguments(etsg->Allocator()->Adapter());

            checker::Signature *const signature = [this, callee_object, enum_interface, &arguments]() {
                const auto &member_proxy_method_name = signature_->InternalName();

                if (member_proxy_method_name == checker::ETSEnumType::TO_STRING_METHOD_NAME) {
                    arguments.push_back(callee_object);
                    return enum_interface->ToStringMethod().global_signature;
                }
                if (member_proxy_method_name == checker::ETSEnumType::GET_VALUE_METHOD_NAME) {
                    arguments.push_back(callee_object);
                    return enum_interface->GetValueMethod().global_signature;
                }
                if (member_proxy_method_name == checker::ETSEnumType::GET_NAME_METHOD_NAME) {
                    arguments.push_back(callee_object);
                    return enum_interface->GetNameMethod().global_signature;
                }
                if (member_proxy_method_name == checker::ETSEnumType::VALUES_METHOD_NAME) {
                    return enum_interface->ValuesMethod().global_signature;
                }
                if (member_proxy_method_name == checker::ETSEnumType::VALUE_OF_METHOD_NAME) {
                    arguments.push_back(arguments_.front());
                    return enum_interface->ValueOfMethod().global_signature;
                }
                UNREACHABLE();
            }();

            ASSERT(signature->ReturnType() == signature_->ReturnType());
            etsg->CallStatic(this, signature, arguments);
            etsg->SetAccumulatorType(TsType());
            return;
        }
    }

    bool is_static = signature_->HasSignatureFlag(checker::SignatureFlags::STATIC);
    bool is_reference = signature_->HasSignatureFlag(checker::SignatureFlags::TYPE);
    bool is_dynamic = callee_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG);

    ConvertRestArguments(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker()));

    compiler::VReg dyn_param2;

    // Helper function to avoid branching in non optional cases
    auto emit_arguments = [this, etsg, is_static, is_dynamic, &callee_reg, &dyn_param2]() {
        if (is_dynamic) {
            etsg->CallDynamic(this, callee_reg, dyn_param2, signature_, arguments_);
        } else if (is_static) {
            etsg->CallStatic(this, signature_, arguments_);
        } else if (signature_->HasSignatureFlag(checker::SignatureFlags::PRIVATE) || IsETSConstructorCall() ||
                   (callee_->IsMemberExpression() && callee_->AsMemberExpression()->Object()->IsSuperExpression())) {
            etsg->CallThisStatic(this, callee_reg, signature_, arguments_);
        } else {
            etsg->CallThisVirtual(this, callee_reg, signature_, arguments_);
        }

        if (GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
            etsg->ApplyConversion(this, nullptr);
        } else {
            etsg->SetAccumulatorType(signature_->ReturnType());
        }
    };

    if (is_dynamic) {
        dyn_param2 = etsg->AllocReg();

        ir::Expression *obj = callee_;
        std::vector<util::StringView> parts;

        while (obj->IsMemberExpression() && obj->AsMemberExpression()->ObjType()->IsETSDynamicType()) {
            auto *mem_expr = obj->AsMemberExpression();
            obj = mem_expr->Object();
            parts.push_back(mem_expr->Property()->AsIdentifier()->Name());
        }

        if (!obj->IsMemberExpression() && obj->IsIdentifier()) {
            auto *var = obj->AsIdentifier()->Variable();
            auto *data = etsg->Binder()->DynamicImportDataForVar(var);
            if (data != nullptr) {
                auto *import = data->import;
                auto *specifier = data->specifier;
                ASSERT(import->Language().IsDynamic());
                etsg->LoadAccumulatorDynamicModule(this, import);
                if (specifier->IsImportSpecifier()) {
                    parts.push_back(specifier->AsImportSpecifier()->Imported()->Name());
                }
            } else {
                obj->Compile(etsg);
            }
        } else {
            obj->Compile(etsg);
        }

        etsg->StoreAccumulator(this, callee_reg);

        if (!parts.empty()) {
            std::stringstream ss;
            for_each(parts.rbegin(), parts.rend(), [&ss](util::StringView sv) { ss << "." << sv; });

            etsg->LoadAccumulatorString(this, util::UString(ss.str(), etsg->Allocator()).View());
        } else {
            auto lang = callee_->TsType()->IsETSDynamicFunctionType()
                            ? callee_->TsType()->AsETSDynamicFunctionType()->Language()
                            : callee_->TsType()->AsETSDynamicType()->Language();

            etsg->LoadUndefinedDynamic(this, lang);
        }

        etsg->StoreAccumulator(this, dyn_param2);

        emit_arguments();

        if (signature_->ReturnType() != TsType()) {
            etsg->ApplyConversion(this, TsType());
        }
    } else if (!is_reference && callee_->IsIdentifier()) {
        if (!is_static) {
            etsg->LoadThis(this);
            etsg->StoreAccumulator(this, callee_reg);
        }
        emit_arguments();
    } else if (!is_reference && callee_->IsMemberExpression()) {
        if (!is_static) {
            callee_->AsMemberExpression()->Object()->Compile(etsg);
            etsg->StoreAccumulator(this, callee_reg);
        }
        emit_arguments();
    } else {
        callee_->Compile(etsg);
        etsg->StoreAccumulator(this, callee_reg);
        if (optional_) {
            compiler::Label *end_label = etsg->AllocLabel();
            etsg->BranchIfNull(this, end_label);
            emit_arguments();
            etsg->SetLabel(this, end_label);
        } else {
            emit_arguments();
        }
    }
}

checker::Type *CallExpression::Check(checker::TSChecker *checker)
{
    checker::Type *callee_type = callee_->Check(checker);

    // TODO(aszilagyi): handle optional chain
    if (callee_type->IsObjectType()) {
        checker::ObjectType *callee_obj = callee_type->AsObjectType();
        return checker->ResolveCallOrNewExpression(callee_obj->CallSignatures(), arguments_, Start());
    }

    checker->ThrowTypeError("This expression is not callable.", Start());
    return nullptr;
}

bool CallExpression::IsETSConstructorCall() const
{
    return callee_->IsThisExpression() || callee_->IsSuperExpression();
}

checker::Type *CallExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }
    checker::Type *callee_type = callee_->Check(checker);
    checker::Type *return_type;
    if (callee_type->IsETSDynamicType() && !callee_type->AsETSDynamicType()->HasDecl()) {
        // Trailing lambda for js function call is not supported, check the correctness of `foo() {}`
        checker->EnsureValidCurlyBrace(this);
        auto lang = callee_type->AsETSDynamicType()->Language();
        signature_ = checker->ResolveDynamicCallExpression(callee_, arguments_, lang, false);
        return_type = signature_->ReturnType();
    } else {
        bool constructor_call = IsETSConstructorCall();
        bool functional_interface =
            callee_type->IsETSObjectType() &&
            callee_type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);

        if (callee_->IsArrowFunctionExpression()) {
            callee_type = InitAnonymousLambdaCallee(checker, callee_, callee_type);
            functional_interface = true;
        }

        if (!functional_interface && !callee_type->IsETSFunctionType() && !constructor_call) {
            checker->ThrowTypeError("This expression is not callable.", Start());
        }

        auto &signatures = constructor_call ? callee_type->AsETSObjectType()->ConstructSignatures()
                           : functional_interface
                               ? callee_type->AsETSObjectType()
                                     ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke")
                                     ->TsType()
                                     ->AsETSFunctionType()
                                     ->CallSignatures()
                               : callee_type->AsETSFunctionType()->CallSignatures();

        auto *signature = checker->ResolveCallExpressionAndTrailingLambda(signatures, this, Start());

        checker->CheckObjectLiteralArguments(signature, arguments_);

        checker->AddNullParamsForDefaultParams(signature, arguments_, checker);

        if (!functional_interface) {
            checker::ETSObjectType *callee_obj {};
            if (constructor_call) {
                callee_obj = callee_type->AsETSObjectType();
            } else if (callee_->IsIdentifier()) {
                callee_obj = checker->Context().ContainingClass();
            } else {
                ASSERT(callee_->IsMemberExpression());
                callee_obj = callee_->AsMemberExpression()->ObjType();
            }

            checker->ValidateSignatureAccessibility(callee_obj, signature, Start());
        }

        ASSERT(signature->Function() != nullptr);

        if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
            checker->CheckThrowingStatements(this);
        }

        if (signature->Function()->IsDynamic()) {
            ASSERT(signature->Function()->IsDynamic());
            auto lang = signature->Function()->Language();
            signature_ = checker->ResolveDynamicCallExpression(callee_, signature->Params(), lang, false);
        } else {
            ASSERT(!signature->Function()->IsDynamic());
            signature_ = signature;
        }

        return_type = signature->ReturnType();
    }

    if (signature_->RestVar() != nullptr) {
        auto *const element_type = signature_->RestVar()->TsType()->AsETSArrayType()->ElementType();
        auto *const array_type = checker->CreateETSArrayType(element_type)->AsETSArrayType();
        checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
    }

    SetTsType(return_type);
    return TsType();
}

checker::Type *CallExpression::InitAnonymousLambdaCallee(checker::ETSChecker *checker, Expression *callee,
                                                         checker::Type *callee_type)
{
    auto *const arrow_func = callee->AsArrowFunctionExpression()->Function();
    auto orig_params = arrow_func->Params();
    auto *func_type = checker->Allocator()->New<ir::ETSFunctionType>(
        arrow_func->Scope()->AsFunctionScope()->ParamScope(), std::move(orig_params), nullptr,
        arrow_func->ReturnTypeAnnotation(), ir::ScriptFunctionFlags::NONE);
    auto *const func_iface = func_type->Check(checker);
    checker->Relation()->SetNode(callee);
    checker->Relation()->IsAssignableTo(callee_type, func_iface);
    return func_iface;
}
}  // namespace panda::es2panda::ir
