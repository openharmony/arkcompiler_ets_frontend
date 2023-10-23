/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "ETSCompiler.h"

#include "checker/types/ets/etsDynamicFunctionType.h"
#include "compiler/base/condition.h"
#include "compiler/base/lreference.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/switchBuilder.h"
#include "compiler/function/functionBuilder.h"

namespace panda::es2panda::compiler {

ETSGen *ETSCompiler::GetETSGen() const
{
    return static_cast<ETSGen *>(GetCodeGen());
}

// from as folder
void ETSCompiler::Compile([[maybe_unused]] const ir::NamedType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}
// from base folder
void ETSCompiler::Compile(const ir::CatchClause *st) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope lrs(etsg, st->Scope()->ParamScope());
    etsg->SetAccumulatorType(etsg->Checker()->GlobalETSObjectType());
    auto lref = compiler::ETSLReference::Create(etsg, st->Param(), true);
    lref.SetValue();
    st->Body()->Compile(etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ClassDefinition *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ClassProperty *st) const
{
    ETSGen *etsg = GetETSGen();
    if (st->Value() == nullptr || (st->IsStatic() && st->TsType()->HasTypeFlag(checker::TypeFlag::CONSTANT))) {
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, st->TsType());
    compiler::RegScope rs(etsg);

    if (!etsg->TryLoadConstantExpression(st->Value())) {
        st->Value()->Compile(etsg);
        etsg->ApplyConversion(st->Value(), nullptr);
    }

    if (st->IsStatic()) {
        etsg->StoreStaticOwnProperty(st, st->TsType(), st->Key()->AsIdentifier()->Name());
    } else {
        etsg->StoreProperty(st, st->TsType(), etsg->GetThisReg(), st->Key()->AsIdentifier()->Name());
    }
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ClassStaticBlock *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::Decorator *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::MetaProperty *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::MethodDefinition *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::Property *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ScriptFunction *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::SpreadElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TemplateElement *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorString(expr, expr->Raw());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSIndexSignature *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSMethodSignature *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSPropertySignature *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSSignatureDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}
// from ets folder
void ETSCompiler::Compile(const ir::ETSClassLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSImportDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSLaunchExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSNewArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSNewClassInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSPackageDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSParameterExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    expr->Ident()->Identifier::Compile(etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSPrimitiveType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSStructDeclaration *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSTypeReference *node) const
{
    ETSGen *etsg = GetETSGen();
    node->Part()->Compile(etsg);
}

void ETSCompiler::Compile(const ir::ETSTypeReferencePart *node) const
{
    ETSGen *etsg = GetETSGen();
    node->Name()->Compile(etsg);
}

void ETSCompiler::Compile(const ir::ETSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSWildcardType *node) const
{
    ETSGen *etsg = GetETSGen();
    etsg->Unimplemented();
}
// compile methods for EXPRESSIONS in alphabetical order
void ETSCompiler::Compile(const ir::ArrayExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ArrowFunctionExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    ASSERT(expr->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL_INTERFACE));
    ASSERT(expr->ResolvedLambda() != nullptr);
    auto *ctor = expr->ResolvedLambda()->TsType()->AsETSObjectType()->ConstructSignatures()[0];
    std::vector<compiler::VReg> arguments;

    for (auto *it : expr->CapturedVars()) {
        if (it->HasFlag(varbinder::VariableFlags::LOCAL)) {
            arguments.push_back(it->AsLocalVariable()->Vreg());
        }
    }

    if (expr->propagate_this_) {
        arguments.push_back(etsg->GetThisReg());
    }

    etsg->InitLambdaObject(expr, ctor, arguments);
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::AssignmentExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::AwaitExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    static constexpr bool IS_UNCHECKED_CAST = false;
    compiler::RegScope rs(etsg);
    compiler::VReg argument_reg = etsg->AllocReg();
    expr->Argument()->Compile(etsg);
    etsg->StoreAccumulator(expr, argument_reg);
    etsg->CallThisVirtual0(expr->Argument(), argument_reg, compiler::Signatures::BUILTIN_PROMISE_AWAIT_RESOLUTION);
    etsg->CastToArrayOrObject(expr->Argument(), expr->TsType(), IS_UNCHECKED_CAST);
    etsg->SetAccumulatorType(expr->TsType());
}

static void CompileNullishCoalescing(compiler::ETSGen *etsg, ir::BinaryExpression const *const node)
{
    auto const compile_operand = [etsg, optype = node->OperationType()](ir::Expression const *expr) {
        etsg->CompileAndCheck(expr);
        etsg->ApplyConversion(expr, optype);
    };

    compile_operand(node->Left());

    if (!node->Left()->TsType()->IsNullishOrNullLike()) {
        // fallthrough
    } else if (node->Left()->TsType()->IsETSNullLike()) {
        compile_operand(node->Right());
    } else {
        auto *if_left_nullish = etsg->AllocLabel();
        auto *end_label = etsg->AllocLabel();

        etsg->BranchIfNullish(node, if_left_nullish);

        etsg->ConvertToNonNullish(node);
        etsg->ApplyConversion(node->Left(), node->OperationType());
        etsg->JumpTo(node, end_label);

        etsg->SetLabel(node, if_left_nullish);
        compile_operand(node->Right());

        etsg->SetLabel(node, end_label);
    }
    etsg->SetAccumulatorType(node->TsType());
}

static void CompileLogical(compiler::ETSGen *etsg, const ir::BinaryExpression *expr)
{
    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING) {
        CompileNullishCoalescing(etsg, expr);
        return;
    }

    ASSERT(expr->IsLogicalExtended());
    auto ttctx = compiler::TargetTypeContext(etsg, expr->OperationType());
    compiler::RegScope rs(etsg);
    auto lhs = etsg->AllocReg();
    auto rhs = etsg->AllocReg();
    expr->Left()->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(expr->Left(), lhs, expr->OperationType());

    auto *end_label = etsg->AllocLabel();

    auto left_false_label = etsg->AllocLabel();
    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        etsg->ResolveConditionalResultIfFalse(expr->Left(), left_false_label);
        etsg->BranchIfFalse(expr, left_false_label);

        expr->Right()->Compile(etsg);
        etsg->ApplyConversionAndStoreAccumulator(expr->Right(), rhs, expr->OperationType());
        etsg->Branch(expr, end_label);

        etsg->SetLabel(expr, left_false_label);
        etsg->LoadAccumulator(expr, lhs);
    } else {
        etsg->ResolveConditionalResultIfFalse(expr->Left(), left_false_label);
        etsg->BranchIfFalse(expr, left_false_label);

        etsg->LoadAccumulator(expr, lhs);
        etsg->Branch(expr, end_label);

        etsg->SetLabel(expr, left_false_label);
        expr->Right()->Compile(etsg);
        etsg->ApplyConversionAndStoreAccumulator(expr->Right(), rhs, expr->OperationType());
    }

    etsg->SetLabel(expr, end_label);
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::BinaryExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    if (etsg->TryLoadConstantExpression(expr)) {
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, expr->OperationType());

    if (expr->IsLogical()) {
        CompileLogical(etsg, expr);
        etsg->ApplyConversion(expr, expr->OperationType());
        return;
    }

    compiler::RegScope rs(etsg);
    compiler::VReg lhs = etsg->AllocReg();

    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS &&
        (expr->Left()->TsType()->IsETSStringType() || expr->Right()->TsType()->IsETSStringType())) {
        etsg->BuildString(expr);
        return;
    }

    expr->Left()->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(expr->Left(), lhs, expr->OperationType());
    expr->Right()->Compile(etsg);
    etsg->ApplyConversion(expr->Right(), expr->OperationType());
    if (expr->OperatorType() >= lexer::TokenType::PUNCTUATOR_LEFT_SHIFT &&
        expr->OperatorType() <= lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT) {
        etsg->ApplyCast(expr->Right(), expr->OperationType());
    }

    etsg->Binary(expr, expr->OperatorType(), lhs);
}

static void ConvertRestArguments(checker::ETSChecker *const checker, const ir::CallExpression *expr)
{
    if (expr->Signature()->RestVar() != nullptr) {
        std::size_t const argument_count = expr->Arguments().size();
        std::size_t const parameter_count = expr->Signature()->MinArgCount();
        ASSERT(argument_count >= parameter_count);

        auto &arguments = const_cast<ArenaVector<ir::Expression *> &>(expr->Arguments());
        std::size_t i = parameter_count;

        if (i < argument_count && expr->Arguments()[i]->IsSpreadElement()) {
            arguments[i] = expr->Arguments()[i]->AsSpreadElement()->Argument();
        } else {
            ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
            for (; i < argument_count; ++i) {
                elements.emplace_back(expr->Arguments()[i]);
            }
            auto *array_expression = checker->AllocNode<ir::ArrayExpression>(std::move(elements), checker->Allocator());
            array_expression->SetParent(const_cast<ir::CallExpression *>(expr));
            array_expression->SetTsType(expr->Signature()->RestVar()->TsType());
            arguments.erase(expr->Arguments().begin() + parameter_count, expr->Arguments().end());
            arguments.emplace_back(array_expression);
        }
    }
}

void ETSCompiler::Compile(const ir::BlockExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

bool ETSCompiler::IsSucceedCompilationProxyMemberExpr(const ir::CallExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto *const callee_object = expr->callee_->AsMemberExpression()->Object();
    auto const *const enum_interface = [callee_type = callee_object->TsType()]() -> checker::ETSEnumInterface const * {
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

        checker::Signature *const signature = [expr, callee_object, enum_interface, &arguments]() {
            const auto &member_proxy_method_name = expr->Signature()->InternalName();

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
                arguments.push_back(expr->Arguments().front());
                return enum_interface->ValueOfMethod().global_signature;
            }
            UNREACHABLE();
        }();

        ASSERT(signature->ReturnType() == expr->Signature()->ReturnType());
        etsg->CallStatic(expr, signature, arguments);
        etsg->SetAccumulatorType(expr->TsType());
    }

    return enum_interface != nullptr;
}

void ETSCompiler::CompileDynamic(const ir::CallExpression *expr, compiler::VReg &callee_reg) const
{
    ETSGen *etsg = GetETSGen();
    compiler::VReg dyn_param2 = etsg->AllocReg();
    ir::Expression *obj = expr->callee_;
    std::vector<util::StringView> parts;

    while (obj->IsMemberExpression() && obj->AsMemberExpression()->ObjType()->IsETSDynamicType()) {
        auto *mem_expr = obj->AsMemberExpression();
        obj = mem_expr->Object();
        parts.push_back(mem_expr->Property()->AsIdentifier()->Name());
    }

    if (!obj->IsMemberExpression() && obj->IsIdentifier()) {
        auto *var = obj->AsIdentifier()->Variable();
        auto *data = etsg->VarBinder()->DynamicImportDataForVar(var);
        if (data != nullptr) {
            auto *import = data->import;
            auto *specifier = data->specifier;
            ASSERT(import->Language().IsDynamic());
            etsg->LoadAccumulatorDynamicModule(expr, import);
            if (specifier->IsImportSpecifier()) {
                parts.push_back(specifier->AsImportSpecifier()->Imported()->Name());
            }
        } else {
            obj->Compile(etsg);
        }
    } else {
        obj->Compile(etsg);
    }

    etsg->StoreAccumulator(expr, callee_reg);

    if (!parts.empty()) {
        std::stringstream ss;
        for_each(parts.rbegin(), parts.rend(), [&ss](util::StringView sv) { ss << "." << sv; });
        etsg->LoadAccumulatorString(expr, util::UString(ss.str(), etsg->Allocator()).View());
    } else {
        auto lang = expr->Callee()->TsType()->IsETSDynamicFunctionType()
                        ? expr->Callee()->TsType()->AsETSDynamicFunctionType()->Language()
                        : expr->Callee()->TsType()->AsETSDynamicType()->Language();
        etsg->LoadUndefinedDynamic(expr, lang);
    }
    etsg->StoreAccumulator(expr, dyn_param2);
    etsg->CallDynamic(expr, callee_reg, dyn_param2, expr->Signature(), expr->Arguments());
    etsg->SetAccumulatorType(expr->TsType());

    if (expr->Signature()->ReturnType() != expr->TsType()) {
        etsg->ApplyConversion(expr, expr->TsType());
    }
}

// Helper function to avoid branching in non optional cases
void ETSCompiler::EmitCall(const ir::CallExpression *expr, compiler::VReg &callee_reg, bool is_static) const
{
    ETSGen *etsg = GetETSGen();
    if (expr->Callee()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
        etsg->ApplyConversionAndStoreAccumulator(expr->Callee(), callee_reg, nullptr);
    }
    if (is_static) {
        etsg->CallStatic(expr, expr->Signature(), expr->Arguments());
    } else if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::PRIVATE) || expr->IsETSConstructorCall() ||
               (expr->Callee()->IsMemberExpression() &&
                expr->Callee()->AsMemberExpression()->Object()->IsSuperExpression())) {
        etsg->CallThisStatic(expr, callee_reg, expr->Signature(), expr->Arguments());
    } else {
        etsg->CallThisVirtual(expr, callee_reg, expr->Signature(), expr->Arguments());
    }
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::CallExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs(etsg);
    compiler::VReg callee_reg = etsg->AllocReg();

    const auto is_proxy = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::PROXY);
    if (is_proxy && expr->Callee()->IsMemberExpression()) {
        if (IsSucceedCompilationProxyMemberExpr(expr)) {
            return;
        }
    }

    bool is_static = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::STATIC);
    bool is_reference = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::TYPE);
    bool is_dynamic = expr->Callee()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG);

    ConvertRestArguments(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker()), expr);

    if (is_dynamic) {
        CompileDynamic(expr, callee_reg);
    } else if (!is_reference && expr->Callee()->IsIdentifier()) {
        if (!is_static) {
            etsg->LoadThis(expr);
            etsg->StoreAccumulator(expr, callee_reg);
        }
        EmitCall(expr, callee_reg, is_static);
    } else if (!is_reference && expr->Callee()->IsMemberExpression()) {
        if (!is_static) {
            expr->Callee()->AsMemberExpression()->Object()->Compile(etsg);
            etsg->StoreAccumulator(expr, callee_reg);
        }
        EmitCall(expr, callee_reg, is_static);
    } else if (expr->Callee()->IsSuperExpression() || expr->Callee()->IsThisExpression()) {
        ASSERT(!is_reference && expr->IsETSConstructorCall());
        expr->Callee()->Compile(etsg);  // ctor is not a value!
        etsg->SetVRegType(callee_reg, etsg->GetAccumulatorType());
        EmitCall(expr, callee_reg, is_static);
    } else {
        ASSERT(is_reference);
        etsg->CompileAndCheck(expr->Callee());
        etsg->StoreAccumulator(expr, callee_reg);
        etsg->EmitMaybeOptional(
            expr, [this, expr, is_static, &callee_reg]() { this->EmitCall(expr, callee_reg, is_static); },
            expr->IsOptional());
    }
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ChainExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ConditionalExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    auto *false_label = etsg->AllocLabel();
    auto *end_label = etsg->AllocLabel();

    compiler::Condition::Compile(etsg, expr->Test(), false_label);

    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());

    expr->Consequent()->Compile(etsg);
    etsg->ApplyConversion(expr->Consequent());
    etsg->Branch(expr, end_label);
    etsg->SetLabel(expr, false_label);
    expr->Alternate()->Compile(etsg);
    etsg->ApplyConversion(expr->Alternate());
    etsg->SetLabel(expr, end_label);
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::DirectEvalExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::FunctionExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::Identifier *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ImportExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::MemberExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::NewExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ObjectExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::OmittedExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::OpaqueTypeNode *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::SequenceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::SuperExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TaggedTemplateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TemplateLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ThisExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::UnaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::UpdateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::YieldExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
void ETSCompiler::Compile(const ir::BigIntLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::BooleanLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::CharLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::NullLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorNull(expr, expr->TsType());
}

void ETSCompiler::Compile(const ir::NumberLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
    if (expr->Number().IsInt()) {
        if (util::Helpers::IsTargetFitInSourceRange<checker::ByteType::UType, checker::IntType::UType>(
                expr->Number().GetInt())) {
            etsg->LoadAccumulatorByte(expr, static_cast<int8_t>(expr->Number().GetInt()));
            return;
        }

        if (util::Helpers::IsTargetFitInSourceRange<checker::ShortType::UType, checker::IntType::UType>(
                expr->Number().GetInt())) {
            etsg->LoadAccumulatorShort(expr, static_cast<int16_t>(expr->Number().GetInt()));
            return;
        }

        etsg->LoadAccumulatorInt(expr, static_cast<int32_t>(expr->Number().GetInt()));
        return;
    }

    if (expr->Number().IsLong()) {
        etsg->LoadAccumulatorWideInt(expr, expr->Number().GetLong());
        return;
    }

    if (expr->Number().IsFloat()) {
        etsg->LoadAccumulatorFloat(expr, expr->Number().GetFloat());
        return;
    }

    etsg->LoadAccumulatorDouble(expr, expr->Number().GetDouble());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::RegExpLiteral *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::StringLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorString(expr, expr->Str());
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::UndefinedLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
void ETSCompiler::Compile([[maybe_unused]] const ir::ExportAllDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ExportDefaultDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ExportNamedDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ExportSpecifier *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ImportDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ImportNamespaceSpecifier *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}
// compile methods for STATEMENTS in alphabetical order
void ETSCompiler::Compile(const ir::AssertStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::BlockStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::BreakStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ClassDeclaration *st) const
{
    UNREACHABLE();
}

static void CompileImpl(const ir::ContinueStatement *self, ETSGen *etsg)
{
    compiler::Label *target = etsg->ControlFlowChangeContinue(self->Ident());
    etsg->Branch(self, target);
}

void ETSCompiler::Compile(const ir::ContinueStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    if (etsg->ExtendWithFinalizer(st->parent_, st)) {
        return;
    }
    CompileImpl(st, etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::DebuggerStatement *st) const
{
    UNREACHABLE();
}

void CompileImpl(const ir::DoWhileStatement *self, ETSGen *etsg)
{
    auto *start_label = etsg->AllocLabel();
    compiler::LabelTarget label_target(etsg);

    etsg->SetLabel(self, start_label);

    {
        compiler::LocalRegScope reg_scope(etsg, self->Scope());
        compiler::LabelContext label_ctx(etsg, label_target);
        self->Body()->Compile(etsg);
    }

    etsg->SetLabel(self, label_target.ContinueTarget());
    compiler::Condition::Compile(etsg, self->Test(), label_target.BreakTarget());

    etsg->Branch(self, start_label);
    etsg->SetLabel(self, label_target.BreakTarget());
}

void ETSCompiler::Compile(const ir::DoWhileStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    CompileImpl(st, etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::EmptyStatement *st) const {}

void ETSCompiler::Compile(const ir::ExpressionStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    st->GetExpression()->Compile(etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ForInStatement *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ForOfStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope decl_reg_scope(etsg, st->Scope()->DeclScope()->InitScope());

    checker::Type const *const expr_type = st->Right()->TsType();
    ASSERT(expr_type->IsETSArrayType() || expr_type->IsETSStringType());

    st->Right()->Compile(etsg);
    compiler::VReg obj_reg = etsg->AllocReg();
    etsg->StoreAccumulator(st, obj_reg);

    if (expr_type->IsETSArrayType()) {
        etsg->LoadArrayLength(st, obj_reg);
    } else {
        etsg->LoadStringLength(st);
    }

    compiler::VReg size_reg = etsg->AllocReg();
    etsg->StoreAccumulator(st, size_reg);

    compiler::LabelTarget label_target(etsg);
    auto label_ctx = compiler::LabelContext(etsg, label_target);

    etsg->BranchIfFalse(st, label_target.BreakTarget());

    compiler::VReg count_reg = etsg->AllocReg();
    etsg->MoveImmediateToRegister(st, count_reg, checker::TypeFlag::INT, static_cast<std::int32_t>(0));
    etsg->LoadAccumulatorInt(st, static_cast<std::int32_t>(0));

    auto *const start_label = etsg->AllocLabel();
    etsg->SetLabel(st, start_label);

    auto lref = compiler::ETSLReference::Create(etsg, st->Left(), false);

    if (st->Right()->TsType()->IsETSArrayType()) {
        etsg->LoadArrayElement(st, obj_reg);
    } else {
        etsg->LoadStringChar(st, obj_reg, count_reg);
    }

    lref.SetValue();
    st->Body()->Compile(etsg);

    etsg->SetLabel(st, label_target.ContinueTarget());

    etsg->IncrementImmediateRegister(st, count_reg, checker::TypeFlag::INT, static_cast<std::int32_t>(1));
    etsg->LoadAccumulator(st, count_reg);

    etsg->JumpCompareRegister<compiler::Jlt>(st, size_reg, start_label);
    etsg->SetLabel(st, label_target.BreakTarget());
}

void ETSCompiler::Compile(const ir::ForUpdateStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope decl_reg_scope(etsg, st->Scope()->DeclScope()->InitScope());

    if (st->Init() != nullptr) {
        ASSERT(st->Init()->IsVariableDeclaration() || st->Init()->IsExpression());
        st->Init()->Compile(etsg);
    }

    auto *start_label = etsg->AllocLabel();
    compiler::LabelTarget label_target(etsg);
    auto label_ctx = compiler::LabelContext(etsg, label_target);
    etsg->SetLabel(st, start_label);

    {
        compiler::LocalRegScope reg_scope(etsg, st->Scope());

        if (st->Test() != nullptr) {
            compiler::Condition::Compile(etsg, st->Test(), label_target.BreakTarget());
        }

        st->Body()->Compile(etsg);
        etsg->SetLabel(st, label_target.ContinueTarget());
    }

    if (st->Update() != nullptr) {
        st->Update()->Compile(etsg);
    }

    etsg->Branch(st, start_label);
    etsg->SetLabel(st, label_target.BreakTarget());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::FunctionDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::IfStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    auto res = compiler::Condition::CheckConstantExpr(etsg, st->Test());
    if (res == compiler::Condition::Result::CONST_TRUE) {
        st->Consequent()->Compile(etsg);
        return;
    }

    if (res == compiler::Condition::Result::CONST_FALSE) {
        if (st->Alternate() != nullptr) {
            st->Alternate()->Compile(etsg);
        }
        return;
    }

    auto *consequent_end = etsg->AllocLabel();
    compiler::Label *statement_end = consequent_end;

    compiler::Condition::Compile(etsg, st->Test(), consequent_end);

    st->Consequent()->Compile(etsg);

    if (st->Alternate() != nullptr) {
        statement_end = etsg->AllocLabel();
        etsg->Branch(etsg->Insns().back()->Node(), statement_end);

        etsg->SetLabel(st, consequent_end);
        st->Alternate()->Compile(etsg);
    }

    etsg->SetLabel(st, statement_end);
}

void CompileImpl(const ir::LabelledStatement *self, ETSGen *cg)
{
    compiler::LabelContext label_ctx(cg, self);
    self->Body()->Compile(cg);
}

void ETSCompiler::Compile(const ir::LabelledStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    CompileImpl(st, etsg);
}

void ETSCompiler::Compile(const ir::ReturnStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    if (st->Argument() == nullptr) {
        if (st->ReturnType() == nullptr || st->ReturnType()->IsETSVoidType()) {
            if (etsg->ExtendWithFinalizer(st->parent_, st)) {
                return;
            }

            if (etsg->CheckControlFlowChange()) {
                etsg->ControlFlowChangeBreak();
            }
            etsg->EmitReturnVoid(st);
            return;
        }

        etsg->LoadBuiltinVoid(st);
    } else {
        auto ttctx = compiler::TargetTypeContext(etsg, etsg->ReturnType());

        if (!etsg->TryLoadConstantExpression(st->Argument())) {
            st->Argument()->Compile(etsg);
        }
        etsg->ApplyConversion(st->Argument(), nullptr);
        etsg->ApplyConversion(st->Argument(), st->ReturnType());
    }

    if (etsg->ExtendWithFinalizer(st->parent_, st)) {
        return;
    }

    if (etsg->CheckControlFlowChange()) {
        compiler::RegScope rs(etsg);
        compiler::VReg res = etsg->AllocReg();

        etsg->StoreAccumulator(st, res);
        etsg->ControlFlowChangeBreak();
        etsg->LoadAccumulator(st, res);
    }

    etsg->ReturnAcc(st);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

static void CompileImpl(const ir::SwitchStatement *self, ETSGen *etsg)
{
    compiler::LocalRegScope lrs(etsg, self->Scope());
    compiler::SwitchBuilder builder(etsg, self);
    compiler::VReg tag = etsg->AllocReg();

    builder.CompileTagOfSwitch(tag);
    uint32_t default_index = 0;

    for (size_t i = 0; i < self->Cases().size(); i++) {
        const auto *clause = self->Cases()[i];

        if (clause->Test() == nullptr) {
            default_index = i;
            continue;
        }

        builder.JumpIfCase(tag, i);
    }

    if (default_index > 0) {
        builder.JumpToDefault(default_index);
    } else {
        builder.Break();
    }

    for (size_t i = 0; i < self->Cases().size(); i++) {
        builder.SetCaseTarget(i);
        builder.CompileCaseStatements(i);
    }
}

void ETSCompiler::Compile(const ir::SwitchStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    CompileImpl(st, etsg);
}

void ETSCompiler::Compile(const ir::ThrowStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TryStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::VariableDeclarator *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::VariableDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::WhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}
// from ts folder
void ETSCompiler::Compile([[maybe_unused]] const ir::TSAnyKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSArrayType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSAsExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSBigintKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSBooleanKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSClassImplements *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSConditionalType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSConstructorType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSEnumDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSImportEqualsDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSImportType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSIndexedAccessType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSInferType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSInterfaceBody *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSInterfaceDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSInterfaceHeritage *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSIntersectionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSLiteralType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSMappedType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSModuleBlock *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSModuleDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSNamedTupleMember *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSNeverKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSNonNullExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSNullKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSNumberKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSParameterProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSParenthesizedType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSQualifiedName *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSStringKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSThisType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTupleType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeAliasDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeAssertion *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeLiteral *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeOperator *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeParameter *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeParameterDeclaration *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeParameterInstantiation *expr) const
{
    (void)expr;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypePredicate *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeQuery *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSTypeReference *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSUndefinedKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSUnknownKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSVoidKeyword *node) const
{
    UNREACHABLE();
}

}  // namespace panda::es2panda::compiler
