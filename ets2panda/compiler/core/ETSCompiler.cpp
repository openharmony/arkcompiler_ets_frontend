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

#include "ETSCompiler.h"

#include "compiler/base/catchTable.h"
#include "checker/ets/dynamic/dynamicCall.h"
#include "compiler/base/condition.h"
#include "compiler/base/lreference.h"
#include "compiler/core/switchBuilder.h"
#include "compiler/function/functionBuilder.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "parser/ETSparser.h"
#include "programElement.h"

namespace ark::es2panda::compiler {

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
    if (st->Value() == nullptr && st->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, st->TsType());
    compiler::RegScope rs(etsg);

    if (st->Value() == nullptr) {
        etsg->LoadDefaultValue(st, st->TsType());
    } else if (!etsg->TryLoadConstantExpression(st->Value())) {
        st->Value()->Compile(etsg);
        etsg->ApplyConversion(st->Value(), st->TsType());
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

void ETSCompiler::Compile([[maybe_unused]] const ir::SpreadElement *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TemplateElement *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorString(expr, expr->Cooked());
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

void ETSCompiler::Compile([[maybe_unused]] const ir::TSSignatureDeclaration *node) const
{
    UNREACHABLE();
}
// from ets folder
void ETSCompiler::Compile([[maybe_unused]] const ir::ETSScript *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSClassLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    if (expr->expr_->TsType()->IsETSReferenceType()) {
        expr->expr_->Compile(etsg);
        etsg->GetType(expr, false);
    } else {
        ASSERT(expr->expr_->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE));
        etsg->SetAccumulatorType(expr->expr_->TsType());
        etsg->GetType(expr, true);
    }
}

void ETSCompiler::Compile(const ir::ETSFunctionType *node) const
{
    ETSGen *etsg = GetETSGen();

    etsg->LoadAccumulatorNull(node, node->TsType());
}

void ETSCompiler::Compile(const ir::ETSTuple *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSLaunchExpression *expr) const
{
#ifdef PANDA_WITH_ETS
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs(etsg);
    compiler::VReg calleeReg = etsg->AllocReg();
    checker::Signature *signature = expr->expr_->Signature();
    bool isStatic = signature->HasSignatureFlag(checker::SignatureFlags::STATIC);
    bool isReference = signature->HasSignatureFlag(checker::SignatureFlags::TYPE);
    if (!isReference && expr->expr_->Callee()->IsIdentifier()) {
        if (!isStatic) {
            etsg->LoadThis(expr->expr_);
            etsg->StoreAccumulator(expr, calleeReg);
        }
    } else if (!isReference && expr->expr_->Callee()->IsMemberExpression()) {
        if (!isStatic) {
            expr->expr_->Callee()->AsMemberExpression()->Object()->Compile(etsg);
            etsg->StoreAccumulator(expr, calleeReg);
        }
    } else {
        expr->expr_->Callee()->Compile(etsg);
        etsg->StoreAccumulator(expr, calleeReg);
    }

    if (isStatic) {
        etsg->LaunchStatic(expr, signature, expr->expr_->Arguments());
    } else if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE)) {
        etsg->LaunchThisStatic(expr, calleeReg, signature, expr->expr_->Arguments());
    } else {
        etsg->LaunchThisVirtual(expr, calleeReg, signature, expr->expr_->Arguments());
    }

    etsg->SetAccumulatorType(expr->TsType());
#endif  // PANDA_WITH_ETS
}

void ETSCompiler::Compile(const ir::ETSNewArrayInstanceExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs(etsg);
    compiler::TargetTypeContext ttctx(etsg, etsg->Checker()->GlobalIntType());

    expr->Dimension()->Compile(etsg);

    compiler::VReg arr = etsg->AllocReg();
    compiler::VReg dim = etsg->AllocReg();
    etsg->ApplyConversionAndStoreAccumulator(expr, dim, expr->Dimension()->TsType());
    etsg->NewArray(expr, arr, dim, expr->TsType());

    if (expr->Signature() != nullptr) {
        compiler::VReg countReg = etsg->AllocReg();
        auto *startLabel = etsg->AllocLabel();
        auto *endLabel = etsg->AllocLabel();
        etsg->MoveImmediateToRegister(expr, countReg, checker::TypeFlag::INT, static_cast<std::int32_t>(0));
        const auto indexReg = etsg->AllocReg();

        etsg->SetLabel(expr, startLabel);
        etsg->LoadAccumulator(expr, dim);
        etsg->JumpCompareRegister<compiler::Jle>(expr, countReg, endLabel);

        etsg->LoadAccumulator(expr, countReg);
        etsg->StoreAccumulator(expr, indexReg);
        const compiler::TargetTypeContext ttctx2(etsg, expr->TypeReference()->TsType());
        ArenaVector<ir::Expression *> arguments(GetCodeGen()->Allocator()->Adapter());
        etsg->InitObject(expr, expr->Signature(), arguments);
        etsg->StoreArrayElement(expr, arr, indexReg, expr->TypeReference()->TsType());

        etsg->IncrementImmediateRegister(expr, countReg, checker::TypeFlag::INT, static_cast<std::int32_t>(1));
        etsg->JumpTo(expr, startLabel);

        etsg->SetLabel(expr, endLabel);
    }

    etsg->SetVRegType(arr, expr->TsType());
    etsg->LoadAccumulator(expr, arr);
}

static std::pair<VReg, VReg> LoadDynamicName(compiler::ETSGen *etsg, const ir::AstNode *node,
                                             const ArenaVector<util::StringView> &dynName, bool isConstructor)
{
    auto *checker = const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker());
    auto *callNames = checker->DynamicCallNames(isConstructor);

    auto qnameStart = etsg->AllocReg();
    auto qnameLen = etsg->AllocReg();

    TargetTypeContext ttctx(etsg, nullptr);  // without this ints will be cast to JSValue
    etsg->LoadAccumulatorInt(node, callNames->at(dynName));
    etsg->StoreAccumulator(node, qnameStart);
    etsg->LoadAccumulatorInt(node, dynName.size());
    etsg->StoreAccumulator(node, qnameLen);
    return {qnameStart, qnameLen};
}

static void CreateDynamicObject(const ir::AstNode *node, compiler::ETSGen *etsg, const ir::Expression *typeRef,
                                checker::Signature *signature, const ArenaVector<ir::Expression *> &arguments)
{
    auto objReg = etsg->AllocReg();

    auto callInfo = checker::DynamicCall::ResolveCall(etsg->VarBinder(), typeRef);
    if (callInfo.obj->IsETSImportDeclaration()) {
        etsg->LoadAccumulatorDynamicModule(node, callInfo.obj->AsETSImportDeclaration());
    } else {
        callInfo.obj->Compile(etsg);
    }

    etsg->StoreAccumulator(node, objReg);

    auto [qnameStart, qnameLen] = LoadDynamicName(etsg, node, callInfo.name, true);
    etsg->CallDynamic(node, objReg, qnameStart, qnameLen, signature, arguments);
}

static void ConvertRestArguments(checker::ETSChecker *const checker, const ir::ETSNewClassInstanceExpression *expr)
{
    if (expr->GetSignature()->RestVar() != nullptr) {
        std::size_t const argumentCount = expr->GetArguments().size();
        std::size_t const parameterCount = expr->GetSignature()->MinArgCount();
        ASSERT(argumentCount >= parameterCount);

        auto &arguments = const_cast<ArenaVector<ir::Expression *> &>(expr->GetArguments());
        std::size_t i = parameterCount;

        if (i < argumentCount && expr->GetArguments()[i]->IsSpreadElement()) {
            arguments[i] = expr->GetArguments()[i]->AsSpreadElement()->Argument();
        } else {
            ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
            for (; i < argumentCount; ++i) {
                elements.emplace_back(expr->GetArguments()[i]);
            }
            auto *arrayExpression = checker->AllocNode<ir::ArrayExpression>(std::move(elements), checker->Allocator());
            arrayExpression->SetParent(const_cast<ir::ETSNewClassInstanceExpression *>(expr));
            arrayExpression->SetTsType(expr->GetSignature()->RestVar()->TsType());
            arguments.erase(expr->GetArguments().begin() + parameterCount, expr->GetArguments().end());
            arguments.emplace_back(arrayExpression);
        }
    }
}

void ETSCompiler::Compile(const ir::ETSNewClassInstanceExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    if (expr->TsType()->IsETSDynamicType()) {
        compiler::RegScope rs(etsg);
        auto *name = expr->GetTypeRef();
        CreateDynamicObject(expr, etsg, name, expr->signature_, expr->GetArguments());
    } else {
        ConvertRestArguments(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker()), expr);
        etsg->InitObject(expr, expr->signature_, expr->GetArguments());
    }

    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->InitObject(expr, expr->Signature(), expr->Dimensions());
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSPackageDeclaration *st) const
{
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

void ETSCompiler::Compile(const ir::ETSNullType *node) const
{
    (void)node;
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ETSUndefinedType *node) const
{
    (void)node;
    UNREACHABLE();
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
    ETSGen *etsg = GetETSGen();
    const compiler::RegScope rs(etsg);

    const auto arr = etsg->AllocReg();
    const auto dim = etsg->AllocReg();

    const compiler::TargetTypeContext ttctx(etsg, etsg->Checker()->GlobalIntType());
    etsg->LoadAccumulatorInt(expr, static_cast<std::int32_t>(expr->Elements().size()));
    etsg->StoreAccumulator(expr, dim);
    etsg->NewArray(expr, arr, dim, expr->TsType());

    const auto indexReg = etsg->AllocReg();
    for (std::uint32_t i = 0; i < expr->Elements().size(); ++i) {
        const auto *const expression = expr->Elements()[i];
        etsg->LoadAccumulatorInt(expr, i);
        etsg->StoreAccumulator(expr, indexReg);

        const compiler::TargetTypeContext ttctx2(etsg, expr->preferredType_);
        if (!etsg->TryLoadConstantExpression(expression)) {
            expression->Compile(etsg);
        }

        etsg->ApplyConversion(expression, nullptr);
        etsg->ApplyConversion(expression);

        if (expression->TsType()->IsETSArrayType()) {
            etsg->StoreArrayElement(expr, arr, indexReg, expression->TsType());
        } else {
            etsg->StoreArrayElement(expr, arr, indexReg, expr->TsType()->AsETSArrayType()->ElementType());
        }
    }

    etsg->LoadAccumulator(expr, arr);
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

    if (expr->propagateThis_) {
        arguments.push_back(etsg->GetThisReg());
    }

    etsg->InitLambdaObject(expr, ctor, arguments);
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::AssignmentExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    // All other operations are handled in OpAssignmentLowering
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    compiler::RegScope rs(etsg);
    auto lref = compiler::ETSLReference::Create(etsg, expr->Left(), false);
    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());

    if (expr->Right()->IsNullLiteral()) {
        etsg->LoadAccumulatorNull(expr, expr->Left()->TsType());
    } else {
        expr->Right()->Compile(etsg);
        etsg->ApplyConversion(expr->Right(), expr->TsType());
    }

    if (expr->Right()->TsType()->IsETSBigIntType()) {
        // For bigints we have to copy the bigint object when performing an assignment operation
        const VReg value = etsg->AllocReg();
        etsg->StoreAccumulator(expr, value);
        etsg->CreateBigIntObject(expr, value, Signatures::BUILTIN_BIGINT_CTOR_BIGINT);
    }

    lref.SetValue();
}

void ETSCompiler::Compile(const ir::AwaitExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    static constexpr bool IS_UNCHECKED_CAST = false;
    compiler::RegScope rs(etsg);
    compiler::VReg argumentReg = etsg->AllocReg();
    expr->Argument()->Compile(etsg);
    etsg->StoreAccumulator(expr, argumentReg);
    etsg->CallThisVirtual0(expr->Argument(), argumentReg, compiler::Signatures::BUILTIN_PROMISE_AWAIT_RESOLUTION);
    etsg->CastToReftype(expr->Argument(), expr->TsType(), IS_UNCHECKED_CAST);
    etsg->SetAccumulatorType(expr->TsType());
}

static void CompileNullishCoalescing(compiler::ETSGen *etsg, ir::BinaryExpression const *const node)
{
    auto const compileOperand = [etsg, optype = node->OperationType()](ir::Expression const *expr) {
        etsg->CompileAndCheck(expr);
        etsg->ApplyConversion(expr, nullptr);
    };

    compileOperand(node->Left());

    if (node->Left()->TsType()->DefinitelyNotETSNullish()) {
        // fallthrough
    } else if (node->Left()->TsType()->DefinitelyETSNullish()) {
        compileOperand(node->Right());
    } else {
        auto *ifLeftNullish = etsg->AllocLabel();
        auto *endLabel = etsg->AllocLabel();

        etsg->BranchIfNullish(node, ifLeftNullish);

        etsg->AssumeNonNullish(node, node->OperationType());
        etsg->ApplyConversion(node->Left(), node->OperationType());
        etsg->JumpTo(node, endLabel);

        etsg->SetLabel(node, ifLeftNullish);
        compileOperand(node->Right());

        etsg->SetLabel(node, endLabel);
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

    expr->Left()->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(expr->Left(), lhs, expr->OperationType());

    auto *endLabel = etsg->AllocLabel();

    auto returnLeftLabel = etsg->AllocLabel();
    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        etsg->ResolveConditionalResultIfFalse(expr->Left(), returnLeftLabel);
        etsg->BranchIfFalse(expr, returnLeftLabel);

        expr->Right()->Compile(etsg);
        etsg->ApplyConversion(expr->Right(), expr->OperationType());
        etsg->Branch(expr, endLabel);

        etsg->SetLabel(expr, returnLeftLabel);
        etsg->LoadAccumulator(expr, lhs);
    } else {
        etsg->ResolveConditionalResultIfTrue(expr->Left(), returnLeftLabel);
        etsg->BranchIfTrue(expr, returnLeftLabel);

        expr->Right()->Compile(etsg);
        etsg->ApplyConversion(expr->Right(), expr->OperationType());
        etsg->Branch(expr, endLabel);

        etsg->SetLabel(expr, returnLeftLabel);
        etsg->LoadAccumulator(expr, lhs);
    }

    etsg->SetLabel(expr, endLabel);
    etsg->SetAccumulatorType(expr->TsType());
    etsg->ApplyConversion(expr, expr->OperationType());
}

static void CompileInstanceof(compiler::ETSGen *etsg, const ir::BinaryExpression *expr)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF);
    auto ttctx = compiler::TargetTypeContext(etsg, expr->OperationType());
    compiler::RegScope rs(etsg);
    auto lhs = etsg->AllocReg();

    expr->Left()->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(expr->Left(), lhs, expr->OperationType());

    if (expr->Right()->TsType()->IsETSDynamicType()) {
        auto rhs = etsg->AllocReg();
        expr->Right()->Compile(etsg);
        etsg->StoreAccumulator(expr, rhs);
        etsg->IsInstanceDynamic(expr, lhs, rhs);
    } else {
        etsg->IsInstance(expr, lhs, expr->Right()->TsType());
    }
    ASSERT(etsg->GetAccumulatorType() == expr->TsType());
}

std::map<lexer::TokenType, std::string_view> &GetBigintSignatures()
{
    static std::map<lexer::TokenType, std::string_view> bigintSignatures = {
        {lexer::TokenType::PUNCTUATOR_PLUS, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_ADD},
        {lexer::TokenType::PUNCTUATOR_MINUS, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_SUBTRACT},
        {lexer::TokenType::PUNCTUATOR_MULTIPLY, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_MULTIPLY},
        {lexer::TokenType::PUNCTUATOR_DIVIDE, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_DIVIDE},
        {lexer::TokenType::PUNCTUATOR_MOD, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_MODULE},
        {lexer::TokenType::PUNCTUATOR_BITWISE_OR, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_BITWISE_OR},
        {lexer::TokenType::PUNCTUATOR_BITWISE_AND, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_BITWISE_AND},
        {lexer::TokenType::PUNCTUATOR_BITWISE_XOR, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_BITWISE_XOR},
        {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_LEFT_SHIFT},
        {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_RIGHT_SHIFT},
        {lexer::TokenType::PUNCTUATOR_GREATER_THAN, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_GREATER_THAN},
        {lexer::TokenType::PUNCTUATOR_LESS_THAN, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_LESS_THAN},
        {lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL,
         compiler::Signatures::BUILTIN_BIGINT_OPERATOR_GREATER_THAN_EQUAL},
        {lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL, compiler::Signatures::BUILTIN_BIGINT_OPERATOR_LESS_THAN_EQUAL},
    };

    return bigintSignatures;
}

static bool CompileBigInt(compiler::ETSGen *etsg, const ir::BinaryExpression *expr)
{
    if ((expr->Left()->TsType() == nullptr) || (expr->Right()->TsType() == nullptr)) {
        return false;
    }

    if (!expr->Left()->TsType()->IsETSBigIntType()) {
        return false;
    }

    if (!expr->Right()->TsType()->IsETSBigIntType()) {
        return false;
    }

    auto map = GetBigintSignatures();
    if (map.find(expr->OperatorType()) == map.end()) {
        return false;
    }

    const checker::Type *operationType = expr->OperationType();
    auto ttctx = compiler::TargetTypeContext(etsg, operationType);
    compiler::RegScope rs(etsg);
    compiler::VReg lhs = etsg->AllocReg();
    expr->Left()->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(expr->Left(), lhs, operationType);
    expr->Right()->Compile(etsg);
    etsg->ApplyConversion(expr->Right(), operationType);
    compiler::VReg rhs = etsg->AllocReg();
    etsg->StoreAccumulator(expr, rhs);

    std::string_view signature = map.at(expr->OperatorType());
    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL:
            etsg->CallBigIntBinaryComparison(expr, lhs, rhs, signature);
            break;
        default:
            etsg->CallBigIntBinaryOperator(expr, lhs, rhs, signature);
            break;
    }

    return true;
}

void ETSCompiler::Compile(const ir::BinaryExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    if (CompileBigInt(etsg, expr)) {
        return;
    }

    if (etsg->TryLoadConstantExpression(expr)) {
        return;
    }

    if (expr->IsLogical()) {
        CompileLogical(etsg, expr);
        return;
    }
    if (expr->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF) {
        CompileInstanceof(etsg, expr);
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, expr->OperationType());
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
    if (expr->OperationType()->IsIntType()) {
        etsg->ApplyCast(expr->Right(), expr->OperationType());
    }

    etsg->Binary(expr, expr->OperatorType(), lhs);
}

static void ConvertRestArguments(checker::ETSChecker *const checker, const ir::CallExpression *expr,
                                 checker::Signature *signature)
{
    if (signature->RestVar() != nullptr) {
        std::size_t const argumentCount = expr->Arguments().size();
        std::size_t const parameterCount = signature->MinArgCount();
        ASSERT(argumentCount >= parameterCount);

        auto &arguments = const_cast<ArenaVector<ir::Expression *> &>(expr->Arguments());
        std::size_t i = parameterCount;

        if (i < argumentCount && expr->Arguments()[i]->IsSpreadElement()) {
            arguments[i] = expr->Arguments()[i]->AsSpreadElement()->Argument();
        } else {
            ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
            for (; i < argumentCount; ++i) {
                elements.emplace_back(expr->Arguments()[i]);
            }
            auto *arrayExpression = checker->AllocNode<ir::ArrayExpression>(std::move(elements), checker->Allocator());
            arrayExpression->SetParent(const_cast<ir::CallExpression *>(expr));
            arrayExpression->SetTsType(signature->RestVar()->TsType());
            arguments.erase(expr->Arguments().begin() + parameterCount, expr->Arguments().end());
            arguments.emplace_back(arrayExpression);
        }
    }
}

void ConvertArgumentsForFunctionalCall(checker::ETSChecker *const checker, const ir::CallExpression *expr)
{
    std::size_t const argumentCount = expr->Arguments().size();
    auto &arguments = const_cast<ArenaVector<ir::Expression *> &>(expr->Arguments());
    auto *signature = expr->Signature();

    for (size_t i = 0; i < argumentCount; i++) {
        checker::Type *paramType;
        if (i < signature->Params().size()) {
            paramType = checker->MaybeBoxedType(signature->Params()[i], checker->Allocator());
        } else {
            ASSERT(signature->RestVar() != nullptr);
            auto *restType = signature->RestVar()->TsType();
            ASSERT(restType->IsETSArrayType());
            paramType = restType->AsETSArrayType()->ElementType();
        }

        auto *arg = arguments[i];
        auto *cast = checker->Allocator()->New<ir::TSAsExpression>(arg, nullptr, false);
        arguments[i]->SetParent(cast);
        cast->SetParent(const_cast<ir::CallExpression *>(expr));
        cast->SetTsType(paramType);

        if (paramType->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            cast->AddBoxingUnboxingFlags(checker->GetBoxingFlag(paramType));
        }

        arguments[i] = cast;
    }
}

void ETSCompiler::Compile(const ir::BlockExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope lrs(etsg, expr->Scope());

    etsg->CompileStatements(expr->Statements());
}

bool ETSCompiler::IsSucceedCompilationProxyMemberExpr(const ir::CallExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto *const calleeObject = expr->callee_->AsMemberExpression()->Object();
    auto const *const enumInterface = [calleeType = calleeObject->TsType()]() -> checker::ETSEnumInterface const * {
        if (calleeType->IsETSEnumType()) {
            return calleeType->AsETSEnumType();
        }
        if (calleeType->IsETSStringEnumType()) {
            return calleeType->AsETSStringEnumType();
        }
        return nullptr;
    }();

    if (enumInterface != nullptr) {
        ArenaVector<ir::Expression *> arguments(etsg->Allocator()->Adapter());

        checker::Signature *const signature = [expr, calleeObject, enumInterface, &arguments]() {
            const auto &memberProxyMethodName = expr->Signature()->InternalName();

            if (memberProxyMethodName == checker::ETSEnumType::TO_STRING_METHOD_NAME) {
                arguments.push_back(calleeObject);
                return enumInterface->ToStringMethod().globalSignature;
            }
            if (memberProxyMethodName == checker::ETSEnumType::GET_VALUE_METHOD_NAME) {
                arguments.push_back(calleeObject);
                return enumInterface->GetValueMethod().globalSignature;
            }
            if (memberProxyMethodName == checker::ETSEnumType::GET_NAME_METHOD_NAME) {
                arguments.push_back(calleeObject);
                return enumInterface->GetNameMethod().globalSignature;
            }
            if (memberProxyMethodName == checker::ETSEnumType::VALUES_METHOD_NAME) {
                return enumInterface->ValuesMethod().globalSignature;
            }
            if (memberProxyMethodName == checker::ETSEnumType::VALUE_OF_METHOD_NAME) {
                arguments.push_back(expr->Arguments().front());
                return enumInterface->ValueOfMethod().globalSignature;
            }
            UNREACHABLE();
        }();

        ASSERT(signature->ReturnType() == expr->Signature()->ReturnType());
        etsg->CallStatic(expr, signature, arguments);
        etsg->SetAccumulatorType(expr->TsType());
    }

    return enumInterface != nullptr;
}

void ETSCompiler::CompileDynamic(const ir::CallExpression *expr, compiler::VReg &calleeReg) const
{
    ETSGen *etsg = GetETSGen();
    auto callInfo = checker::DynamicCall::ResolveCall(etsg->VarBinder(), expr->Callee());
    if (callInfo.obj->IsETSImportDeclaration()) {
        etsg->LoadAccumulatorDynamicModule(expr, callInfo.obj->AsETSImportDeclaration());
    } else {
        callInfo.obj->Compile(etsg);
    }
    etsg->StoreAccumulator(expr, calleeReg);

    if (!callInfo.name.empty()) {
        auto [qnameStart, qnameLen] = LoadDynamicName(etsg, expr, callInfo.name, false);
        etsg->CallDynamic(expr, calleeReg, qnameStart, qnameLen, expr->Signature(), expr->Arguments());
    } else {
        compiler::VReg dynParam2 = etsg->AllocReg();

        auto lang = expr->Callee()->TsType()->IsETSDynamicFunctionType()
                        ? expr->Callee()->TsType()->AsETSDynamicFunctionType()->Language()
                        : expr->Callee()->TsType()->AsETSDynamicType()->Language();
        etsg->LoadUndefinedDynamic(expr, lang);
        etsg->StoreAccumulator(expr, dynParam2);
        etsg->CallDynamic(expr, calleeReg, dynParam2, expr->Signature(), expr->Arguments());
    }
    etsg->SetAccumulatorType(expr->Signature()->ReturnType());

    if (etsg->GetAccumulatorType() != expr->TsType()) {
        etsg->ApplyConversion(expr, expr->TsType());
    }
}

// Helper function to avoid branching in non optional cases
void ETSCompiler::EmitCall(const ir::CallExpression *expr, compiler::VReg &calleeReg, bool isStatic,
                           checker::Signature *signature, bool isReference) const
{
    ETSGen *etsg = GetETSGen();
    if (expr->Callee()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
        etsg->ApplyConversionAndStoreAccumulator(expr->Callee(), calleeReg, nullptr);
    }
    if (isStatic) {
        etsg->CallStatic(expr, expr->Signature(), expr->Arguments());
    } else if (expr->Signature()->HasSignatureFlag(checker::SignatureFlags::PRIVATE) || expr->IsETSConstructorCall() ||
               (expr->Callee()->IsMemberExpression() &&
                expr->Callee()->AsMemberExpression()->Object()->IsSuperExpression())) {
        etsg->CallThisStatic(expr, calleeReg, signature, expr->Arguments());
    } else {
        etsg->CallThisVirtual(expr, calleeReg, signature, expr->Arguments());
    }

    if (isReference) {
        etsg->CheckedReferenceNarrowing(expr, signature->ReturnType());
    } else {
        etsg->SetAccumulatorType(signature->ReturnType());
    }

    etsg->GuardUncheckedType(expr, expr->UncheckedType(), expr->TsType());
}

static checker::Signature *ConvertArgumentsForFunctionReference(ETSGen *etsg, const ir::CallExpression *expr)
{
    checker::Signature *origSignature = expr->Signature();

    auto *funcType =
        origSignature->Owner()
            ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(checker::FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME)
            ->TsType()
            ->AsETSFunctionType();
    ASSERT(funcType->CallSignatures().size() == 1);
    checker::Signature *signature = funcType->CallSignatures()[0];

    if (signature->ReturnType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        expr->AddBoxingUnboxingFlags(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker())
                                         ->GetUnboxingFlag(signature->ReturnType()));
    }

    ConvertArgumentsForFunctionalCall(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker()), expr);

    return signature;
}

void ETSCompiler::Compile(const ir::CallExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs(etsg);
    compiler::VReg calleeReg = etsg->AllocReg();

    const auto isProxy = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::PROXY);
    if (isProxy && expr->Callee()->IsMemberExpression()) {
        if (IsSucceedCompilationProxyMemberExpr(expr)) {
            return;
        }
    }

    bool isStatic = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::STATIC);
    bool isReference = expr->Signature()->HasSignatureFlag(checker::SignatureFlags::TYPE);
    bool isDynamic = expr->Callee()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG);

    checker::Signature *signature = expr->Signature();
    if (isReference) {
        signature = ConvertArgumentsForFunctionReference(etsg, expr);
    }

    ConvertRestArguments(const_cast<checker::ETSChecker *>(etsg->Checker()->AsETSChecker()), expr, signature);

    if (isDynamic) {
        CompileDynamic(expr, calleeReg);
    } else if (!isReference && expr->Callee()->IsIdentifier()) {
        if (!isStatic) {
            etsg->LoadThis(expr);
            etsg->StoreAccumulator(expr, calleeReg);
        }
        EmitCall(expr, calleeReg, isStatic, signature, isReference);
    } else if (!isReference && expr->Callee()->IsMemberExpression()) {
        if (!isStatic) {
            expr->Callee()->AsMemberExpression()->Object()->Compile(etsg);
            etsg->StoreAccumulator(expr, calleeReg);
        }
        EmitCall(expr, calleeReg, isStatic, signature, isReference);
    } else if (expr->Callee()->IsSuperExpression() || expr->Callee()->IsThisExpression()) {
        ASSERT(!isReference && expr->IsETSConstructorCall());
        expr->Callee()->Compile(etsg);  // ctor is not a value!
        etsg->StoreAccumulator(expr, calleeReg);
        EmitCall(expr, calleeReg, isStatic, signature, isReference);
    } else {
        ASSERT(isReference);
        etsg->CompileAndCheck(expr->Callee());
        etsg->StoreAccumulator(expr, calleeReg);
        EmitCall(expr, calleeReg, isStatic, signature, isReference);
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

void ETSCompiler::Compile([[maybe_unused]] const ir::ETSReExportDeclaration *stmt) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ConditionalExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    auto *falseLabel = etsg->AllocLabel();
    auto *endLabel = etsg->AllocLabel();

    compiler::Condition::Compile(etsg, expr->Test(), falseLabel);

    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());

    expr->Consequent()->Compile(etsg);
    etsg->ApplyConversion(expr->Consequent());
    etsg->Branch(expr, endLabel);
    etsg->SetLabel(expr, falseLabel);
    expr->Alternate()->Compile(etsg);
    etsg->ApplyConversion(expr->Alternate());
    etsg->SetLabel(expr, endLabel);
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
    ETSGen *etsg = GetETSGen();
    auto lambda = etsg->VarBinder()->LambdaObjects().find(expr);
    if (lambda != etsg->VarBinder()->LambdaObjects().end()) {
        etsg->CreateLambdaObjectFromIdentReference(expr, lambda->second.first);
        return;
    }

    auto *const smartType = expr->TsType();
    auto ttctx = compiler::TargetTypeContext(etsg, smartType);

    ASSERT(expr->Variable() != nullptr);
    if (!expr->Variable()->HasFlag(varbinder::VariableFlags::TYPE_ALIAS)) {
        etsg->LoadVar(expr, expr->Variable());
    } else {
        etsg->SetAccumulatorType(smartType);
    }

    //  In case when smart cast type of identifier differs from common variable type
    //  set the accumulator type to the correct actual value and perform cast if required
    if (!etsg->Checker()->AsETSChecker()->Relation()->IsIdenticalTo(const_cast<checker::Type *>(smartType),
                                                                    expr->Variable()->TsType())) {
        etsg->SetAccumulatorType(smartType);
        if (smartType->IsETSReferenceType() &&  //! smartType->DefinitelyNotETSNullish() &&
            (expr->Parent() == nullptr || !expr->Parent()->IsTSAsExpression())) {
            etsg->CastToReftype(expr, smartType, false);
        }
    }
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ImportExpression *expr) const
{
    UNREACHABLE();
}

bool ETSCompiler::CompileComputed(compiler::ETSGen *etsg, const ir::MemberExpression *expr)
{
    if (!expr->IsComputed()) {
        return false;
    }
    auto *const objectType = expr->Object()->TsType();

    auto ottctx = compiler::TargetTypeContext(etsg, expr->Object()->TsType());
    etsg->CompileAndCheck(expr->Object());

    compiler::VReg objReg = etsg->AllocReg();
    etsg->StoreAccumulator(expr, objReg);

    etsg->CompileAndCheck(expr->Property());
    etsg->ApplyConversion(expr->Property(), expr->Property()->TsType());

    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());

    if (objectType->IsETSDynamicType()) {
        etsg->LoadElementDynamic(expr, objReg);
    } else {
        etsg->LoadArrayElement(expr, objReg);
    }

    etsg->GuardUncheckedType(expr, expr->UncheckedType(), expr->TsType());
    etsg->ApplyConversion(expr);
    return true;
}

void ETSCompiler::Compile(const ir::MemberExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    if (HandleLambdaObject(expr, etsg)) {
        return;
    }

    compiler::RegScope rs(etsg);

    if (CompileComputed(etsg, expr)) {
        return;
    }

    if (HandleArrayTypeLengthProperty(expr, etsg)) {
        return;
    }

    if (HandleEnumTypes(expr, etsg)) {
        return;
    }

    if (HandleStaticProperties(expr, etsg)) {
        return;
    }

    auto *const objectType = etsg->Checker()->GetApparentType(expr->Object()->TsType());
    auto &propName = expr->Property()->AsIdentifier()->Name();

    auto ottctx = compiler::TargetTypeContext(etsg, expr->Object()->TsType());
    etsg->CompileAndCheck(expr->Object());

    etsg->ApplyConversion(expr->Object());
    compiler::VReg objReg = etsg->AllocReg();
    etsg->StoreAccumulator(expr, objReg);

    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
    auto const *const variable = expr->PropVar();
    if (auto const *const variableType = variable->TsType();
        variableType->HasTypeFlag(checker::TypeFlag::GETTER_SETTER)) {
        checker::Signature *sig = variableType->AsETSFunctionType()->FindGetter();
        etsg->CallThisVirtual0(expr, objReg, sig->InternalName());
    } else if (objectType->IsETSDynamicType()) {
        etsg->LoadPropertyDynamic(expr, expr->TsType(), objReg, propName);
    } else if (objectType->IsETSUnionType()) {
        etsg->LoadUnionProperty(expr, expr->TsType(), objReg, propName);
    } else {
        const auto fullName = etsg->FormClassPropReference(objectType->AsETSObjectType(), propName);
        etsg->LoadProperty(expr, expr->TsType(), objReg, fullName);
    }
    etsg->GuardUncheckedType(expr, expr->UncheckedType(), expr->TsType());
}

bool ETSCompiler::HandleLambdaObject(const ir::MemberExpression *expr, ETSGen *etsg) const
{
    auto lambda = etsg->VarBinder()->LambdaObjects().find(expr);
    if (lambda != etsg->VarBinder()->LambdaObjects().end()) {
        etsg->CreateLambdaObjectFromMemberReference(expr, expr->object_, lambda->second.first);
        etsg->SetAccumulatorType(expr->TsType());
        return true;
    }
    return false;
}

bool ETSCompiler::HandleArrayTypeLengthProperty(const ir::MemberExpression *expr, ETSGen *etsg) const
{
    auto *const objectType = etsg->Checker()->GetApparentType(expr->Object()->TsType());
    auto &propName = expr->Property()->AsIdentifier()->Name();
    if (objectType->IsETSArrayType() && propName.Is("length")) {
        auto ottctx = compiler::TargetTypeContext(etsg, objectType);
        etsg->CompileAndCheck(expr->Object());

        compiler::VReg objReg = etsg->AllocReg();
        etsg->StoreAccumulator(expr, objReg);

        auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
        etsg->LoadArrayLength(expr, objReg);
        etsg->ApplyConversion(expr, expr->TsType());
        return true;
    }
    return false;
}

bool ETSCompiler::HandleEnumTypes(const ir::MemberExpression *expr, ETSGen *etsg) const
{
    auto *const objectType = etsg->Checker()->GetApparentType(expr->Object()->TsType());
    if (objectType->IsETSEnumType() || objectType->IsETSStringEnumType()) {
        auto const *const enumInterface = [objectType, expr]() -> checker::ETSEnumInterface const * {
            if (objectType->IsETSEnumType()) {
                return expr->TsType()->AsETSEnumType();
            }
            return expr->TsType()->AsETSStringEnumType();
        }();

        auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
        etsg->LoadAccumulatorInt(expr, enumInterface->GetOrdinal());
        return true;
    }
    return false;
}

bool ETSCompiler::HandleStaticProperties(const ir::MemberExpression *expr, ETSGen *etsg) const
{
    auto &propName = expr->Property()->AsIdentifier()->Name();
    auto const *const variable = expr->PropVar();
    if (etsg->Checker()->IsVariableStatic(variable)) {
        auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());

        if (expr->PropVar()->TsType()->HasTypeFlag(checker::TypeFlag::GETTER_SETTER)) {
            checker::Signature *sig = variable->TsType()->AsETSFunctionType()->FindGetter();
            etsg->CallStatic0(expr, sig->InternalName());
            etsg->SetAccumulatorType(expr->TsType());
            return true;
        }

        util::StringView fullName = etsg->FormClassPropReference(expr->Object()->TsType()->AsETSObjectType(), propName);
        etsg->LoadStaticProperty(expr, expr->TsType(), fullName);
        return true;
    }
    return false;
}

void ETSCompiler::Compile([[maybe_unused]] const ir::NewExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::ObjectExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs {etsg};
    compiler::VReg objReg = etsg->AllocReg();

    // NOTE: object expressions of dynamic type are not handled in objectLiteralLowering phase
    ASSERT(expr->TsType()->IsETSDynamicType());

    auto *signatureInfo = etsg->Allocator()->New<checker::SignatureInfo>(etsg->Allocator());
    auto *createObjSig = etsg->Allocator()->New<checker::Signature>(
        signatureInfo, nullptr, compiler::Signatures::BUILTIN_JSRUNTIME_CREATE_OBJECT);
    compiler::VReg dummyReg = compiler::VReg::RegStart();
    etsg->CallDynamic(expr, dummyReg, dummyReg, createObjSig,
                      ArenaVector<ir::Expression *>(etsg->Allocator()->Adapter()));

    etsg->SetAccumulatorType(expr->TsType());
    etsg->StoreAccumulator(expr, objReg);

    for (ir::Expression *propExpr : expr->Properties()) {
        ASSERT(propExpr->IsProperty());
        ir::Property *prop = propExpr->AsProperty();
        ir::Expression *key = prop->Key();
        ir::Expression *value = prop->Value();

        util::StringView pname;
        if (key->IsStringLiteral()) {
            pname = key->AsStringLiteral()->Str();
        } else if (key->IsIdentifier()) {
            pname = key->AsIdentifier()->Name();
        } else {
            UNREACHABLE();
        }

        value->Compile(etsg);
        etsg->ApplyConversion(value, key->TsType());
        if (expr->TsType()->IsETSDynamicType()) {
            etsg->StorePropertyDynamic(expr, value->TsType(), objReg, pname);
        } else {
            etsg->StoreProperty(expr, key->TsType(), objReg, pname);
        }
    }

    etsg->LoadAccumulator(expr, objReg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::OmittedExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::OpaqueTypeNode *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::SequenceExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    for (const auto *it : expr->Sequence()) {
        it->Compile(etsg);
    }
}

void ETSCompiler::Compile(const ir::SuperExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadThis(expr);
    etsg->SetAccumulatorType(etsg->GetAccumulatorType()->AsETSObjectType()->SuperType());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TaggedTemplateExpression *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TemplateLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->BuildTemplateString(expr);
}

void ETSCompiler::Compile(const ir::ThisExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadThis(expr);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TypeofExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    checker::ETSChecker const *checker = etsg->Checker();
    ir::Expression *arg = expr->Argument();

    arg->Compile(etsg);
    // NOTE(vpukhov): infer result type in analyzer
    auto argType = arg->TsType();
    if (auto unboxed = checker->MaybePrimitiveBuiltinType(argType);
        unboxed->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        etsg->LoadAccumulatorString(expr, checker->TypeToName(unboxed));
        return;
    }
    if (argType->IsETSUndefinedType()) {
        etsg->LoadAccumulatorString(expr, "undefined");
        return;
    }
    if (argType->IsETSArrayType() || argType->IsETSNullType()) {
        etsg->LoadAccumulatorString(expr, "object");
        return;
    }
    if (argType->IsETSEnumType()) {
        etsg->LoadAccumulatorString(expr, "number");
        return;
    }
    if (argType->IsETSStringType()) {
        etsg->LoadAccumulatorString(expr, "string");
        return;
    }
    auto argReg = etsg->AllocReg();
    etsg->StoreAccumulator(expr, argReg);
    etsg->CallThisStatic0(expr, argReg, Signatures::BUILTIN_RUNTIME_TYPEOF);
    etsg->SetAccumulatorType(expr->TsType());
}

void ETSCompiler::Compile(const ir::UnaryExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
    if (!etsg->TryLoadConstantExpression(expr->Argument())) {
        expr->Argument()->Compile(etsg);
    }

    etsg->ApplyConversion(expr->Argument(), nullptr);

    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_TILDE) {
        etsg->ApplyCast(expr->Argument(), expr->TsType());
    }

    etsg->Unary(expr, expr->OperatorType());
}

void ETSCompiler::Compile(const ir::UpdateExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    auto lref = compiler::ETSLReference::Create(etsg, expr->Argument(), false);

    const auto argumentBoxingFlags = static_cast<ir::BoxingUnboxingFlags>(expr->Argument()->GetBoxingUnboxingFlags() &
                                                                          ir::BoxingUnboxingFlags::BOXING_FLAG);
    const auto argumentUnboxingFlags = static_cast<ir::BoxingUnboxingFlags>(expr->Argument()->GetBoxingUnboxingFlags() &
                                                                            ir::BoxingUnboxingFlags::UNBOXING_FLAG);

    // workaround so argument_ does not get auto unboxed by lref.GetValue()
    expr->Argument()->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
    lref.GetValue();

    if (expr->IsPrefix()) {
        expr->Argument()->SetBoxingUnboxingFlags(argumentUnboxingFlags);
        etsg->ApplyConversion(expr->Argument(), nullptr);

        if (expr->Argument()->TsType()->IsETSBigIntType()) {
            compiler::RegScope rs(etsg);
            compiler::VReg valueReg = etsg->AllocReg();
            etsg->StoreAccumulator(expr->Argument(), valueReg);
            etsg->UpdateBigInt(expr, valueReg, expr->OperatorType());
        } else {
            etsg->Update(expr, expr->OperatorType());
        }

        expr->Argument()->SetBoxingUnboxingFlags(argumentBoxingFlags);
        etsg->ApplyConversion(expr->Argument(), expr->Argument()->TsType());
        lref.SetValue();
        return;
    }

    compiler::RegScope rs(etsg);
    compiler::VReg originalValueReg = etsg->AllocReg();
    etsg->StoreAccumulator(expr->Argument(), originalValueReg);

    expr->Argument()->SetBoxingUnboxingFlags(argumentUnboxingFlags);
    etsg->ApplyConversion(expr->Argument(), nullptr);

    if (expr->Argument()->TsType()->IsETSBigIntType()) {
        // For postfix operations copy the bigint object before running an update operation
        compiler::VReg updatedValue = etsg->AllocReg();
        etsg->CreateBigIntObject(expr->Argument(), originalValueReg, Signatures::BUILTIN_BIGINT_CTOR_BIGINT);
        etsg->StoreAccumulator(expr->Argument(), updatedValue);
        etsg->UpdateBigInt(expr, updatedValue, expr->OperatorType());
    } else {
        etsg->Update(expr, expr->OperatorType());
    }

    expr->Argument()->SetBoxingUnboxingFlags(argumentBoxingFlags);
    etsg->ApplyConversion(expr->Argument(), expr->Argument()->TsType());
    lref.SetValue();

    etsg->LoadAccumulator(expr->Argument(), originalValueReg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::YieldExpression *expr) const
{
    UNREACHABLE();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
void ETSCompiler::Compile([[maybe_unused]] const ir::BigIntLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::TargetTypeContext ttctx = compiler::TargetTypeContext(etsg, expr->TsType());
    compiler::RegScope rs {etsg};
    etsg->LoadAccumulatorBigInt(expr, expr->Str());
    const compiler::VReg value = etsg->AllocReg();
    etsg->StoreAccumulator(expr, value);
    etsg->CreateBigIntObject(expr, value);
}

void ETSCompiler::Compile(const ir::BooleanLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorBoolean(expr, expr->Value());
}

void ETSCompiler::Compile(const ir::CharLiteral *expr) const
{
    ETSGen *etsg = GetETSGen();
    etsg->LoadAccumulatorChar(expr, expr->Char());
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

static void ThrowError(compiler::ETSGen *const etsg, const ir::AssertStatement *st)
{
    const compiler::RegScope rs(etsg);

    if (st->Second() != nullptr) {
        st->Second()->Compile(etsg);
    } else {
        etsg->LoadAccumulatorString(st, "Assertion failed.");
    }

    const auto message = etsg->AllocReg();
    etsg->StoreAccumulator(st, message);

    const auto assertionError = etsg->AllocReg();
    etsg->NewObject(st, assertionError, compiler::Signatures::BUILTIN_ASSERTION_ERROR);
    etsg->CallThisStatic1(st, assertionError, compiler::Signatures::BUILTIN_ASSERTION_ERROR_CTOR, message);
    etsg->EmitThrow(st, assertionError);
}
// compile methods for STATEMENTS in alphabetical order
void ETSCompiler::Compile(const ir::AssertStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    auto res = compiler::Condition::CheckConstantExpr(etsg, st->Test());
    if (res == compiler::Condition::Result::CONST_TRUE) {
        return;
    }

    if (res == compiler::Condition::Result::CONST_FALSE) {
        ThrowError(etsg, st);
        return;
    }

    compiler::Label *trueLabel = etsg->AllocLabel();
    compiler::Label *falseLabel = etsg->AllocLabel();

    compiler::Condition::Compile(etsg, st->Test(), falseLabel);
    etsg->JumpTo(st, trueLabel);

    etsg->SetLabel(st, falseLabel);
    ThrowError(etsg, st);

    etsg->SetLabel(st, trueLabel);
}

void ETSCompiler::Compile(const ir::BlockStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope lrs(etsg, st->Scope());

    etsg->CompileStatements(st->Statements());
}

template <typename CodeGen>
static void CompileImpl(const ir::BreakStatement *self, [[maybe_unused]] CodeGen *cg)
{
    compiler::Label *target = cg->ControlFlowChangeBreak(self->Ident());
    cg->Branch(self, target);
}

void ETSCompiler::Compile(const ir::BreakStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    if (etsg->ExtendWithFinalizer(st->Parent(), st)) {
        return;
    }
    CompileImpl(st, etsg);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::ClassDeclaration *st) const {}

static void CompileImpl(const ir::ContinueStatement *self, ETSGen *etsg)
{
    compiler::Label *target = etsg->ControlFlowChangeContinue(self->Ident());
    etsg->Branch(self, target);
}

void ETSCompiler::Compile(const ir::ContinueStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    if (etsg->ExtendWithFinalizer(st->Parent(), st)) {
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
    auto *startLabel = etsg->AllocLabel();
    compiler::LabelTarget labelTarget(etsg);

    etsg->SetLabel(self, startLabel);

    {
        compiler::LocalRegScope regScope(etsg, self->Scope());
        compiler::LabelContext labelCtx(etsg, labelTarget);
        self->Body()->Compile(etsg);
    }

    etsg->SetLabel(self, labelTarget.ContinueTarget());
    compiler::Condition::Compile(etsg, self->Test(), labelTarget.BreakTarget());

    etsg->Branch(self, startLabel);
    etsg->SetLabel(self, labelTarget.BreakTarget());
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
    compiler::LocalRegScope declRegScope(etsg, st->Scope()->DeclScope()->InitScope());

    checker::Type const *const exprType = st->Right()->TsType();
    ASSERT(exprType->IsETSArrayType() || exprType->IsETSStringType());

    st->Right()->Compile(etsg);
    compiler::VReg objReg = etsg->AllocReg();
    etsg->StoreAccumulator(st, objReg);

    if (exprType->IsETSArrayType()) {
        etsg->LoadArrayLength(st, objReg);
    } else {
        etsg->LoadStringLength(st);
    }

    compiler::VReg sizeReg = etsg->AllocReg();
    etsg->StoreAccumulator(st, sizeReg);

    compiler::LabelTarget labelTarget(etsg);
    auto labelCtx = compiler::LabelContext(etsg, labelTarget);

    etsg->BranchIfFalse(st, labelTarget.BreakTarget());

    compiler::VReg countReg = etsg->AllocReg();
    etsg->MoveImmediateToRegister(st, countReg, checker::TypeFlag::INT, static_cast<std::int32_t>(0));
    etsg->LoadAccumulatorInt(st, static_cast<std::int32_t>(0));

    auto *const startLabel = etsg->AllocLabel();
    etsg->SetLabel(st, startLabel);

    auto lref = compiler::ETSLReference::Create(etsg, st->Left(), false);

    if (st->Right()->TsType()->IsETSArrayType()) {
        etsg->LoadArrayElement(st, objReg);
    } else {
        etsg->LoadStringChar(st, objReg, countReg);
    }

    lref.SetValue();
    st->Body()->Compile(etsg);

    etsg->SetLabel(st, labelTarget.ContinueTarget());

    etsg->IncrementImmediateRegister(st, countReg, checker::TypeFlag::INT, static_cast<std::int32_t>(1));
    etsg->LoadAccumulator(st, countReg);

    etsg->JumpCompareRegister<compiler::Jlt>(st, sizeReg, startLabel);
    etsg->SetLabel(st, labelTarget.BreakTarget());
}

void ETSCompiler::Compile(const ir::ForUpdateStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    compiler::LocalRegScope declRegScope(etsg, st->Scope()->DeclScope()->InitScope());

    if (st->Init() != nullptr) {
        ASSERT(st->Init()->IsVariableDeclaration() || st->Init()->IsExpression());
        st->Init()->Compile(etsg);
    }

    auto *startLabel = etsg->AllocLabel();
    compiler::LabelTarget labelTarget(etsg);
    auto labelCtx = compiler::LabelContext(etsg, labelTarget);
    etsg->SetLabel(st, startLabel);

    {
        compiler::LocalRegScope regScope(etsg, st->Scope());

        if (st->Test() != nullptr) {
            compiler::Condition::Compile(etsg, st->Test(), labelTarget.BreakTarget());
        }

        st->Body()->Compile(etsg);
        etsg->SetLabel(st, labelTarget.ContinueTarget());
    }

    if (st->Update() != nullptr) {
        st->Update()->Compile(etsg);
    }

    etsg->Branch(st, startLabel);
    etsg->SetLabel(st, labelTarget.BreakTarget());
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
        st->Test()->Compile(etsg);
        st->Consequent()->Compile(etsg);
        return;
    }

    if (res == compiler::Condition::Result::CONST_FALSE) {
        st->Test()->Compile(etsg);
        if (st->Alternate() != nullptr) {
            st->Alternate()->Compile(etsg);
        }
        return;
    }

    auto *consequentEnd = etsg->AllocLabel();
    compiler::Label *statementEnd = consequentEnd;

    compiler::Condition::Compile(etsg, st->Test(), consequentEnd);

    st->Consequent()->Compile(etsg);

    if (st->Alternate() != nullptr) {
        statementEnd = etsg->AllocLabel();
        etsg->Branch(etsg->Insns().back()->Node(), statementEnd);

        etsg->SetLabel(st, consequentEnd);
        st->Alternate()->Compile(etsg);
    }

    etsg->SetLabel(st, statementEnd);
}

void CompileImpl(const ir::LabelledStatement *self, ETSGen *cg)
{
    compiler::LabelContext labelCtx(cg, self);
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
        if (etsg->ExtendWithFinalizer(st->Parent(), st)) {
            return;
        }

        if (etsg->CheckControlFlowChange()) {
            etsg->ControlFlowChangeBreak();
        }

        etsg->EmitReturnVoid(st);

        return;
    }

    if (st->Argument()->IsCallExpression() &&
        st->Argument()->AsCallExpression()->Signature()->ReturnType()->IsETSVoidType()) {
        st->Argument()->Compile(etsg);
        etsg->EmitReturnVoid(st);
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, etsg->ReturnType());

    if (!etsg->TryLoadConstantExpression(st->Argument())) {
        st->Argument()->Compile(etsg);
    }

    etsg->ApplyConversion(st->Argument(), nullptr);
    etsg->ApplyConversion(st->Argument(), st->ReturnType());

    if (etsg->ExtendWithFinalizer(st->Parent(), st)) {
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
    uint32_t defaultIndex = 0;

    for (size_t i = 0; i < self->Cases().size(); i++) {
        const auto *clause = self->Cases()[i];

        if (clause->Test() == nullptr) {
            defaultIndex = i;
            continue;
        }

        builder.JumpIfCase(tag, i);
    }

    if (defaultIndex > 0) {
        builder.JumpToDefault(defaultIndex);
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
    ETSGen *etsg = GetETSGen();
    etsg->ThrowException(st->Argument());
}

void ETSCompiler::Compile(const ir::TryStatement *st) const
{
    ETSGen *etsg = GetETSGen();

    compiler::ETSTryContext tryCtx(etsg, etsg->Allocator(), st, st->FinallyBlock() != nullptr);

    compiler::LabelPair tryLabelPair(etsg->AllocLabel(), etsg->AllocLabel());

    for (ir::CatchClause *clause : st->CatchClauses()) {
        tryCtx.AddNewCathTable(clause->TsType()->AsETSObjectType()->AssemblerName(), tryLabelPair);
    }

    compiler::Label *statementEnd = etsg->AllocLabel();
    auto catchTables = tryCtx.GetETSCatchTable();

    etsg->SetLabel(st, tryLabelPair.Begin());
    st->Block()->Compile(etsg);
    etsg->Branch(st, statementEnd);
    etsg->SetLabel(st, tryLabelPair.End());

    ASSERT(st->CatchClauses().size() == catchTables.size());

    for (uint32_t i = 0; i < st->CatchClauses().size(); i++) {
        etsg->SetLabel(st, catchTables.at(i)->LabelSet().CatchBegin());

        st->CatchClauses().at(i)->Compile(etsg);

        etsg->Branch(st, statementEnd);
    }

    etsg->SetLabel(st, statementEnd);

    auto trycatchLabelPair = compiler::LabelPair(tryLabelPair.Begin(), statementEnd);

    tryCtx.EmitFinalizer(trycatchLabelPair, st->finalizerInsertions_);
}

void ETSCompiler::Compile(const ir::VariableDeclarator *st) const
{
    ETSGen *etsg = GetETSGen();
    auto lref = compiler::ETSLReference::Create(etsg, st->Id(), true);
    auto ttctx = compiler::TargetTypeContext(etsg, st->TsType());

    if (st->Id()->AsIdentifier()->Variable()->HasFlag(varbinder::VariableFlags::BOXED)) {
        etsg->EmitLocalBoxCtor(st->Id());
        etsg->StoreAccumulator(st, lref.Variable()->AsLocalVariable()->Vreg());
        etsg->SetAccumulatorType(lref.Variable()->TsType());
    }

    if (st->Init() != nullptr) {
        if (!etsg->TryLoadConstantExpression(st->Init())) {
            st->Init()->Compile(etsg);
            etsg->ApplyConversion(st->Init(), nullptr);
        }
    } else {
        etsg->LoadDefaultValue(st, st->Id()->AsIdentifier()->Variable()->TsType());
    }

    etsg->ApplyConversion(st, st->TsType());
    lref.SetValue();
}

void ETSCompiler::Compile(const ir::VariableDeclaration *st) const
{
    ETSGen *etsg = GetETSGen();
    for (const auto *it : st->Declarators()) {
        it->Compile(etsg);
    }
}

template <typename CodeGen>
void CompileImpl(const ir::WhileStatement *whileStmt, [[maybe_unused]] CodeGen *cg)
{
    compiler::LabelTarget labelTarget(cg);

    cg->SetLabel(whileStmt, labelTarget.ContinueTarget());
    compiler::Condition::Compile(cg, whileStmt->Test(), labelTarget.BreakTarget());

    {
        compiler::LocalRegScope regScope(cg, whileStmt->Scope());
        compiler::LabelContext labelCtx(cg, labelTarget);
        whileStmt->Body()->Compile(cg);
    }

    cg->Branch(whileStmt, labelTarget.ContinueTarget());
    cg->SetLabel(whileStmt, labelTarget.BreakTarget());
}

void ETSCompiler::Compile(const ir::WhileStatement *st) const
{
    ETSGen *etsg = GetETSGen();
    CompileImpl(st, etsg);
}
// from ts folder
void ETSCompiler::Compile([[maybe_unused]] const ir::TSAnyKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSArrayType *node) const
{
    ETSGen *etsg = GetETSGen();

    etsg->LoadAccumulatorNull(node, node->TsType());
}

void ETSCompiler::CompileCastUnboxable(const ir::TSAsExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto *targetType = etsg->Checker()->GetApparentType(expr->TsType());
    ASSERT(targetType->IsETSObjectType());

    switch (targetType->AsETSObjectType()->BuiltInKind()) {
        case checker::ETSObjectFlags::BUILTIN_BOOLEAN: {
            etsg->CastToBoolean(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_BYTE: {
            etsg->CastToByte(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_CHAR: {
            etsg->CastToChar(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_SHORT: {
            etsg->CastToShort(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_INT: {
            etsg->CastToInt(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_LONG: {
            etsg->CastToLong(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_FLOAT: {
            etsg->CastToFloat(expr);
            break;
        }
        case checker::ETSObjectFlags::BUILTIN_DOUBLE: {
            etsg->CastToDouble(expr);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSCompiler::CompileCast(const ir::TSAsExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    auto *targetType = etsg->Checker()->GetApparentType(expr->TsType());

    switch (checker::ETSChecker::TypeKind(targetType)) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            etsg->CastToBoolean(expr);
            break;
        }
        case checker::TypeFlag::CHAR: {
            etsg->CastToChar(expr);
            break;
        }
        case checker::TypeFlag::BYTE: {
            etsg->CastToByte(expr);
            break;
        }
        case checker::TypeFlag::SHORT: {
            etsg->CastToShort(expr);
            break;
        }
        case checker::TypeFlag::INT: {
            etsg->CastToInt(expr);
            break;
        }
        case checker::TypeFlag::LONG: {
            etsg->CastToLong(expr);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            etsg->CastToFloat(expr);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            etsg->CastToDouble(expr);
            break;
        }
        case checker::TypeFlag::ETS_ARRAY:
        case checker::TypeFlag::ETS_OBJECT:
        case checker::TypeFlag::ETS_TYPE_PARAMETER:
        case checker::TypeFlag::ETS_NONNULLISH:
        case checker::TypeFlag::ETS_UNION:
        case checker::TypeFlag::ETS_NULL:
        case checker::TypeFlag::ETS_UNDEFINED: {
            etsg->CastToReftype(expr, targetType, expr->isUncheckedCast_);
            break;
        }
        case checker::TypeFlag::ETS_DYNAMIC_TYPE: {
            etsg->CastToDynamic(expr, targetType->AsETSDynamicType());
            break;
        }
        case checker::TypeFlag::ETS_STRING_ENUM:
            [[fallthrough]];
        case checker::TypeFlag::ETS_ENUM: {
            auto *const signature = expr->TsType()->IsETSEnumType()
                                        ? expr->TsType()->AsETSEnumType()->FromIntMethod().globalSignature
                                        : expr->TsType()->AsETSStringEnumType()->FromIntMethod().globalSignature;
            ArenaVector<ir::Expression *> arguments(etsg->Allocator()->Adapter());
            arguments.push_back(expr->expression_);
            etsg->CallStatic(expr, signature, arguments);
            etsg->SetAccumulatorType(signature->ReturnType());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSCompiler::Compile(const ir::TSAsExpression *expr) const
{
    ETSGen *etsg = GetETSGen();

    auto ttctx = compiler::TargetTypeContext(etsg, nullptr);
    if (!etsg->TryLoadConstantExpression(expr->Expr())) {
        expr->Expr()->Compile(etsg);
    }

    auto *targetType = etsg->Checker()->GetApparentType(expr->TsType());

    if ((expr->Expr()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U) {
        etsg->ApplyUnboxingConversion(expr->Expr());
    }

    if (targetType->IsETSObjectType() &&
        ((expr->Expr()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U ||
         (expr->Expr()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG) != 0U) &&
        checker::ETSChecker::TypeKind(etsg->GetAccumulatorType()) != checker::TypeFlag::ETS_OBJECT) {
        if (targetType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE)) {
            CompileCastUnboxable(expr);
        }
    }

    if ((expr->Expr()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG) != 0U) {
        etsg->ApplyBoxingConversion(expr->Expr());
    }

    CompileCast(expr);
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSBigintKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSBooleanKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSClassImplements *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSConditionalType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSConstructorType *node) const
{
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

void ETSCompiler::Compile([[maybe_unused]] const ir::TSFunctionType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSImportEqualsDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSImportType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSIndexedAccessType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSInferType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSInterfaceBody *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSInterfaceDeclaration *st) const {}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSInterfaceHeritage *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSIntersectionType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSLiteralType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSMappedType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSModuleBlock *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSModuleDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSNamedTupleMember *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSNeverKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile(const ir::TSNonNullExpression *expr) const
{
    ETSGen *etsg = GetETSGen();
    compiler::RegScope rs(etsg);

    expr->Expr()->Compile(etsg);

    if (etsg->GetAccumulatorType()->DefinitelyNotETSNullish()) {
        return;
    }

    if (etsg->GetAccumulatorType()->DefinitelyETSNullish()) {
        etsg->EmitNullishException(expr);
        return;
    }

    auto arg = etsg->AllocReg();
    etsg->StoreAccumulator(expr, arg);
    etsg->LoadAccumulator(expr, arg);

    auto endLabel = etsg->AllocLabel();

    etsg->BranchIfNotNullish(expr, endLabel);
    etsg->EmitNullishException(expr);

    etsg->SetLabel(expr, endLabel);
    etsg->LoadAccumulator(expr, arg);
    etsg->AssumeNonNullish(expr, expr->OriginalType());
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSNullKeyword *node) const
{
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

void ETSCompiler::Compile([[maybe_unused]] const ir::TSParameterProperty *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSParenthesizedType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSQualifiedName *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSStringKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSThisType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTupleType *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeAliasDeclaration *st) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeAssertion *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeLiteral *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeOperator *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeParameter *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeParameterDeclaration *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeParameterInstantiation *expr) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypePredicate *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeQuery *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSTypeReference *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSUndefinedKeyword *node) const
{
    UNREACHABLE();
}

void ETSCompiler::Compile([[maybe_unused]] const ir::TSUnionType *node) const
{
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

}  // namespace ark::es2panda::compiler
