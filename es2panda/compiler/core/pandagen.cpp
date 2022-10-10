/*
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

#include "pandagen.h"

#include <binder/binder.h>
#include <util/helpers.h>
#include <util/hotfix.h>
#include <binder/scope.h>
#include <binder/variable.h>
#include <compiler/base/catchTable.h>
#include <compiler/base/lexenv.h>
#include <compiler/base/literals.h>
#include <compiler/core/compilerContext.h>
#include <compiler/core/labelTarget.h>
#include <compiler/core/regAllocator.h>
#include <compiler/function/asyncFunctionBuilder.h>
#include <compiler/function/asyncGeneratorFunctionBuilder.h>
#include <compiler/function/functionBuilder.h>
#include <compiler/function/generatorFunctionBuilder.h>
#include <es2panda.h>
#include <gen/isa.h>
#include <ir/base/classDefinition.h>
#include <ir/base/scriptFunction.h>
#include <ir/base/spreadElement.h>
#include <ir/expressions/callExpression.h>
#include <ir/expressions/functionExpression.h>
#include <ir/expressions/identifier.h>
#include <ir/expressions/literals/numberLiteral.h>
#include <ir/expressions/literals/stringLiteral.h>
#include <ir/expressions/newExpression.h>
#include <ir/statement.h>

namespace panda::es2panda::compiler {

// PandaGen

Label *PandaGen::AllocLabel()
{
    std::string id = std::string {Label::PREFIX} + std::to_string(labelId_++);
    return sa_.AllocLabel(std::move(id));
}

bool PandaGen::IsDebug() const
{
    return context_->IsDebug();
}

bool PandaGen::isDebuggerEvaluateExpressionMode() const
{
    return context_->isDebuggerEvaluateExpressionMode();
}

std::string PandaGen::SourceFile() const
{
    return context_->SourceFile();
}

uint32_t PandaGen::ParamCount() const
{
    if (rootNode_->IsProgram()) {
        return 0;
    }

    return rootNode_->AsScriptFunction()->Params().size();
}

uint32_t PandaGen::FormalParametersCount() const
{
    if (rootNode_->IsProgram()) {
        return 0;
    }

    ASSERT(rootNode_->IsScriptFunction());

    return rootNode_->AsScriptFunction()->FormalParamsLength();
}

uint32_t PandaGen::InternalParamCount() const
{
    static const uint32_t HIDDEN_PARAMS = 3;
    return ParamCount() + HIDDEN_PARAMS;
}

const util::StringView &PandaGen::InternalName() const
{
    return topScope_->InternalName();
}

const util::StringView &PandaGen::FunctionName() const
{
    return topScope_->Name();
}

binder::Binder *PandaGen::Binder() const
{
    return context_->Binder();
}

void PandaGen::FunctionInit(CatchTable *catchTable)
{
    if (rootNode_->IsProgram()) {
        builder_ = allocator_->New<FunctionBuilder>(this, catchTable);
        return;
    }

    const ir::ScriptFunction *func = rootNode_->AsScriptFunction();

    if (func->IsAsync()) {
        if (func->IsGenerator()) {
            builder_ = allocator_->New<AsyncGeneratorFunctionBuilder>(this, catchTable);
            return;
        }

        builder_ = allocator_->New<AsyncFunctionBuilder>(this, catchTable);
        return;
    }

    if (func->IsGenerator()) {
        builder_ = allocator_->New<GeneratorFunctionBuilder>(this, catchTable);
        return;
    }

    builder_ = allocator_->New<FunctionBuilder>(this, catchTable);
}

bool PandaGen::FunctionHasFinalizer() const
{
    if (rootNode_->IsProgram()) {
        return false;
    }

    const ir::ScriptFunction *func = rootNode_->AsScriptFunction();

    return func->IsAsync() || func->IsGenerator();
}

void PandaGen::FunctionEnter()
{
    builder_->Prepare(rootNode_->AsScriptFunction());
}

void PandaGen::FunctionExit()
{
    builder_->CleanUp(rootNode_->AsScriptFunction());
}

void PandaGen::InitializeLexEnv(const ir::AstNode *node, VReg lexEnv)
{
    FrontAllocator fa(this);

    if (topScope_->NeedLexEnv()) {
        NewLexicalEnv(node, topScope_->LexicalSlots(), topScope_);
    } else {
        LdLexEnv(node);
    }

    StoreAccumulator(node, lexEnv);
}

void PandaGen::CopyFunctionArguments(const ir::AstNode *node)
{
    FrontAllocator fa(this);
    VReg targetReg = totalRegs_;

    for (const auto *param : topScope_->ParamScope()->Params()) {
        if (param->LexicalBound()) {
            StoreLexicalVar(node, 0, param->LexIdx(), targetReg++);
        } else {
            ra_.Emit<MovDyn>(node, param->Vreg(), targetReg++);
        }
    }
}

LiteralBuffer *PandaGen::NewLiteralBuffer()
{
    return allocator_->New<LiteralBuffer>(allocator_);
}

int32_t PandaGen::AddLiteralBuffer(LiteralBuffer *buf)
{
    buffStorage_.push_back(buf);
    buf->SetIndex(context_->NewLiteralIndex());
    return buf->Index();
}

int32_t PandaGen::AddLexicalVarNamesForDebugInfo(ArenaMap<uint32_t, std::pair<util::StringView, int>> &lexicalVars)
{
    auto *buf = NewLiteralBuffer();
    buf->Add(Allocator()->New<ir::NumberLiteral>(lexicalVars.size()));
    for (auto &iter : lexicalVars) {
        buf->Add(Allocator()->New<ir::StringLiteral>(iter.second.first));
        buf->Add(Allocator()->New<ir::NumberLiteral>(iter.first));
    }
    return AddLiteralBuffer(buf);
}

void PandaGen::GetFunctionObject(const ir::AstNode *node)
{
    LoadAccFromLexEnv(node, scope_->Find(binder::Binder::MANDATORY_PARAM_FUNC));
}

void PandaGen::GetNewTarget(const ir::AstNode *node)
{
    LoadAccFromLexEnv(node, scope_->Find(binder::Binder::MANDATORY_PARAM_NEW_TARGET));
}

void PandaGen::GetThis(const ir::AstNode *node)
{
    LoadAccFromLexEnv(node, scope_->Find(binder::Binder::MANDATORY_PARAM_THIS));
}

void PandaGen::SetThis(const ir::AstNode *node)
{
    StoreAccToLexEnv(node, scope_->Find(binder::Binder::MANDATORY_PARAM_THIS), true);
}

void PandaGen::LoadVar(const ir::Identifier *node, const binder::ScopeFindResult &result)
{
    auto *var = result.variable;

    if (!var) {
        TryLoadGlobalByName(node, result.name);
        return;
    }

    if (var->IsGlobalVariable()) {
        LoadGlobalVar(node, var->Name());
        return;
    }

    if (var->IsModuleVariable()) {
        LoadModuleVariable(node, var->Name(), var->HasFlag(binder::VariableFlags::LOCAL_EXPORT));
        if (var->Declaration()->IsLetOrConstOrClassDecl()) {
            ThrowUndefinedIfHole(node, var->Name());
        }
        return;
    }

    ASSERT(var->IsLocalVariable());

    if (var->Declaration()->IsLetOrConstOrClassDecl() && result.scope->IsGlobalScope()) {
        TryLoadGlobalByName(node, result.name);
        return;
    }

    LoadAccFromLexEnv(node, result);
}

void PandaGen::StoreVar(const ir::AstNode *node, const binder::ScopeFindResult &result, bool isDeclaration)
{
    binder::Variable *var = result.variable;

    if (!var) {
        TryStoreGlobalByName(node, result.name);
        return;
    }

    if (var->IsGlobalVariable()) {
        StoreGlobalVar(node, var->Name());
        return;
    }

    if (var->IsModuleVariable()) {
        if (!isDeclaration && var->Declaration()->IsConstDecl()) {
            ThrowConstAssignment(node, var->Name());
            return;
        }

        if (!isDeclaration &&
            (var->Declaration()->IsLetDecl() || var->Declaration()->IsClassDecl())) {
            RegScope rs(this);
            VReg valueReg = AllocReg();
            StoreAccumulator(node, valueReg);
            LoadModuleVariable(node, var->Name(), true);
            ThrowUndefinedIfHole(node, var->Name());
            LoadAccumulator(node, valueReg);
        }

        StoreModuleVariable(node, var->Name());
        return;
    }

    ASSERT(var->IsLocalVariable());

    if (var->Declaration()->IsLetOrConstOrClassDecl() && result.scope->IsGlobalScope()) {
        if (!isDeclaration) {
            TryStoreGlobalByName(node, var->Name());
        } else if (var->Declaration()->IsLetDecl()) {
            StLetToGlobalRecord(node, var->Name());
        } else if (var->Declaration()->IsConstDecl()) {
            StConstToGlobalRecord(node, var->Name());
        } else if (var->Declaration()->IsClassDecl()) {
            StClassToGlobalRecord(node, var->Name());
        }
        return;
    }

    StoreAccToLexEnv(node, result, isDeclaration);
}

void PandaGen::StoreAccumulator(const ir::AstNode *node, VReg vreg)
{
    ra_.Emit<StaDyn>(node, vreg);
}

void PandaGen::LoadAccFromArgs(const ir::AstNode *node)
{
    const auto *varScope = scope_->AsVariableScope();

    if (!varScope->HasFlag(binder::VariableScopeFlags::USE_ARGS)) {
        return;
    }

    binder::ScopeFindResult res = scope_->Find(binder::Binder::FUNCTION_ARGUMENTS);
    ASSERT(res.scope);

    GetUnmappedArgs(node);
    StoreAccToLexEnv(node, res, true);
}

void PandaGen::LoadObjProperty(const ir::AstNode *node, VReg obj, const Operand &prop)
{
    if (std::holds_alternative<VReg>(prop)) {
        LoadObjByValue(node, obj, std::get<VReg>(prop));
        return;
    }

    if (std::holds_alternative<int64_t>(prop)) {
        LoadObjByIndex(node, obj, std::get<int64_t>(prop));
        return;
    }

    ASSERT(std::holds_alternative<util::StringView>(prop));
    LoadObjByName(node, obj, std::get<util::StringView>(prop));
}

void PandaGen::StoreObjProperty(const ir::AstNode *node, VReg obj, const Operand &prop)
{
    if (std::holds_alternative<VReg>(prop)) {
        StoreObjByValue(node, obj, std::get<VReg>(prop));
        return;
    }

    if (std::holds_alternative<int64_t>(prop)) {
        StoreObjByIndex(node, obj, std::get<int64_t>(prop));
        return;
    }

    ASSERT(std::holds_alternative<util::StringView>(prop));
    StoreObjByName(node, obj, std::get<util::StringView>(prop));
}

void PandaGen::StoreOwnProperty(const ir::AstNode *node, VReg obj, const Operand &prop, bool nameSetting)
{
    if (std::holds_alternative<VReg>(prop)) {
        StOwnByValue(node, obj, std::get<VReg>(prop), nameSetting);
        return;
    }

    if (std::holds_alternative<int64_t>(prop)) {
        StOwnByIndex(node, obj, std::get<int64_t>(prop));
        return;
    }

    ASSERT(std::holds_alternative<util::StringView>(prop));
    StOwnByName(node, obj, std::get<util::StringView>(prop), nameSetting);
}

constexpr size_t DEBUGGER_GET_SET_ARGS_NUM = 2;

void PandaGen::LoadObjByNameViaDebugger(const ir::AstNode *node, const util::StringView &name,
                                        bool throwUndefinedIfHole)
{
    RegScope rs(this);
    VReg global = AllocReg();
    LoadConst(node, compiler::Constant::JS_GLOBAL);
    StoreAccumulator(node, global);
    LoadObjByName(node, global, "debuggerGetValue");
    VReg debuggerGetValueReg = AllocReg();
    StoreAccumulator(node, debuggerGetValueReg);
    VReg variableReg = AllocReg();
    LoadAccumulatorString(node, name);
    StoreAccumulator(node, variableReg);
    VReg boolFlag = AllocReg();
    if (throwUndefinedIfHole) {
        LoadConst(node, compiler::Constant::JS_TRUE);
    } else {
        LoadConst(node, compiler::Constant::JS_FALSE);
    }
    StoreAccumulator(node, boolFlag);
    Call(node, debuggerGetValueReg, DEBUGGER_GET_SET_ARGS_NUM);
}

void PandaGen::TryLoadGlobalByName(const ir::AstNode *node, const util::StringView &name)
{
    if (isDebuggerEvaluateExpressionMode()) {
        LoadObjByNameViaDebugger(node, name, true);
    } else {
        sa_.Emit<EcmaTryldglobalbyname>(node, name);
    }
    strings_.insert(name);
}

void PandaGen::StoreObjByNameViaDebugger(const ir::AstNode *node, const util::StringView &name)
{
    RegScope rs(this);
    VReg valueReg = AllocReg();
    StoreAccumulator(node, valueReg);
    VReg global = AllocReg();
    LoadConst(node, compiler::Constant::JS_GLOBAL);
    StoreAccumulator(node, global);
    LoadObjByName(node, global, "debuggerSetValue");
    VReg debuggerSetValueReg = AllocReg();
    StoreAccumulator(node, debuggerSetValueReg);
    VReg variableReg = AllocReg();
    LoadAccumulatorString(node, name);
    StoreAccumulator(node, variableReg);
    MoveVreg(node, AllocReg(), valueReg);
    Call(node, debuggerSetValueReg, DEBUGGER_GET_SET_ARGS_NUM);
}

void PandaGen::TryStoreGlobalByName(const ir::AstNode *node, const util::StringView &name)
{
    if (isDebuggerEvaluateExpressionMode()) {
        StoreObjByNameViaDebugger(node, name);
    } else {
        sa_.Emit<EcmaTrystglobalbyname>(node, name);
    }
    strings_.insert(name);
}

void PandaGen::LoadObjByName(const ir::AstNode *node, VReg obj, const util::StringView &prop)
{
    ra_.Emit<EcmaLdobjbyname>(node, prop, obj);
    strings_.insert(prop);
}

void PandaGen::StoreObjByName(const ir::AstNode *node, VReg obj, const util::StringView &prop)
{
    ra_.Emit<EcmaStobjbyname>(node, prop, obj);
    strings_.insert(prop);
}

void PandaGen::LoadObjByIndex(const ir::AstNode *node, VReg obj, int64_t index)
{
    ra_.Emit<EcmaLdobjbyindex>(node, index, obj);
}

void PandaGen::LoadObjByValue(const ir::AstNode *node, VReg obj, VReg prop)
{
    ra_.Emit<EcmaLdobjbyvalue>(node, obj, prop);
}

void PandaGen::StoreObjByValue(const ir::AstNode *node, VReg obj, VReg prop)
{
    ra_.Emit<EcmaStobjbyvalue>(node, obj, prop);
}

void PandaGen::StoreObjByIndex(const ir::AstNode *node, VReg obj, int64_t index)
{
    ra_.Emit<EcmaStobjbyindex>(node, index, obj);
}

void PandaGen::StOwnByName(const ir::AstNode *node, VReg obj, const util::StringView &prop, bool nameSetting)
{
    nameSetting ? ra_.Emit<EcmaStownbynamewithnameset>(node, prop, obj) :
                  ra_.Emit<EcmaStownbyname>(node, prop, obj);
    strings_.insert(prop);
}

void PandaGen::StOwnByValue(const ir::AstNode *node, VReg obj, VReg prop, bool nameSetting)
{
    nameSetting ? ra_.Emit<EcmaStownbyvaluewithnameset>(node, obj, prop) :
                  ra_.Emit<EcmaStownbyvalue>(node, obj, prop);
}

void PandaGen::StOwnByIndex(const ir::AstNode *node, VReg obj, int64_t index)
{
    ra_.Emit<EcmaStownbyindex>(node, obj, index);
}

void PandaGen::DeleteObjProperty(const ir::AstNode *node, VReg obj, const Operand &prop)
{
    VReg property {};

    if (std::holds_alternative<VReg>(prop)) {
        property = std::get<VReg>(prop);
    } else if (std::holds_alternative<int64_t>(prop)) {
        LoadAccumulatorInt(node, static_cast<size_t>(std::get<int64_t>(prop)));
        property = AllocReg();
        StoreAccumulator(node, property);
    } else {
        ASSERT(std::holds_alternative<util::StringView>(prop));
        LoadAccumulatorString(node, std::get<util::StringView>(prop));
        property = AllocReg();
        StoreAccumulator(node, property);
    }

    ra_.Emit<EcmaDelobjprop>(node, obj, property);
}

void PandaGen::LoadAccumulator(const ir::AstNode *node, VReg reg)
{
    ra_.Emit<LdaDyn>(node, reg);
}

void PandaGen::LoadGlobalVar(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaLdglobalvar>(node, name);
    strings_.insert(name);
}

void PandaGen::StoreGlobalVar(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStglobalvar>(node, name);
    strings_.insert(name);
}

void PandaGen::StoreGlobalLet(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStglobalvar>(node, name);
    strings_.insert(name);
}

VReg PandaGen::LexEnv() const
{
    return envScope_->LexEnv();
}

void PandaGen::LoadAccFromLexEnv(const ir::AstNode *node, const binder::ScopeFindResult &result)
{
    VirtualLoadVar::Expand(this, node, result);
}

void PandaGen::StoreAccToLexEnv(const ir::AstNode *node, const binder::ScopeFindResult &result, bool isDeclaration)
{
    VirtualStoreVar::Expand(this, node, result, isDeclaration);
}

void PandaGen::LoadAccumulatorString(const ir::AstNode *node, const util::StringView &str)
{
    sa_.Emit<LdaStr>(node, str);
    strings_.insert(str);
}

void PandaGen::LoadAccumulatorFloat(const ir::AstNode *node, double num)
{
    sa_.Emit<FldaiDyn>(node, num);
}

void PandaGen::LoadAccumulatorInt(const ir::AstNode *node, int32_t num)
{
    sa_.Emit<LdaiDyn>(node, num);
}

void PandaGen::LoadAccumulatorInt(const ir::AstNode *node, size_t num)
{
    sa_.Emit<LdaiDyn>(node, static_cast<int64_t>(num));
}

void PandaGen::LoadAccumulatorBigInt(const ir::AstNode *node, const util::StringView &num)
{
    sa_.Emit<EcmaLdbigint>(node, num);
    strings_.insert(num);
}

void PandaGen::StoreConst(const ir::AstNode *node, VReg reg, Constant id)
{
    LoadConst(node, id);
    StoreAccumulator(node, reg);
}

void PandaGen::LoadConst(const ir::AstNode *node, Constant id)
{
    switch (id) {
        case Constant::JS_HOLE: {
            sa_.Emit<EcmaLdhole>(node);
            break;
        }
        case Constant::JS_NAN: {
            sa_.Emit<EcmaLdnan>(node);
            break;
        }
        case Constant::JS_INFINITY: {
            sa_.Emit<EcmaLdinfinity>(node);
            break;
        }
        case Constant::JS_GLOBAL: {
            sa_.Emit<EcmaLdglobal>(node);
            break;
        }
        case Constant::JS_UNDEFINED: {
            sa_.Emit<EcmaLdundefined>(node);
            break;
        }
        case Constant::JS_SYMBOL: {
            sa_.Emit<EcmaLdsymbol>(node);
            break;
        }
        case Constant::JS_NULL: {
            sa_.Emit<EcmaLdnull>(node);
            break;
        }
        case Constant::JS_TRUE: {
            sa_.Emit<EcmaLdtrue>(node);
            break;
        }
        case Constant::JS_FALSE: {
            sa_.Emit<EcmaLdfalse>(node);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void PandaGen::MoveVreg(const ir::AstNode *node, VReg vd, VReg vs)
{
    ra_.Emit<MovDyn>(node, vd, vs);
}

void PandaGen::SetLabel([[maybe_unused]] const ir::AstNode *node, Label *label)
{
    sa_.AddLabel(label);
}

void PandaGen::Branch(const ir::AstNode *node, Label *label)
{
    sa_.Emit<Jmp>(node, label);
}

bool PandaGen::CheckControlFlowChange()
{
    const auto *iter = dynamicContext_;

    while (iter) {
        if (iter->HasFinalizer()) {
            return true;
        }

        iter = iter->Prev();
    }

    return false;
}

Label *PandaGen::ControlFlowChangeBreak(const ir::Identifier *label)
{
    auto *iter = dynamicContext_;

    util::StringView labelName = label ? label->Name() : LabelTarget::BREAK_LABEL;
    Label *breakTarget = nullptr;

    while (iter) {
        iter->AbortContext(ControlFlowChange::BREAK, labelName);

        const auto &labelTargetName = iter->Target().BreakLabel();

        if (iter->Target().BreakTarget()) {
            breakTarget = iter->Target().BreakTarget();
        }

        if (labelTargetName == labelName) {
            break;
        }

        iter = iter->Prev();
    }

    return breakTarget;
}

Label *PandaGen::ControlFlowChangeContinue(const ir::Identifier *label)
{
    auto *iter = dynamicContext_;
    util::StringView labelName = label ? label->Name() : LabelTarget::CONTINUE_LABEL;
    Label *continueTarget = nullptr;

    while (iter) {
        iter->AbortContext(ControlFlowChange::CONTINUE, labelName);

        const auto &labelTargetName = iter->Target().ContinueLabel();

        if (iter->Target().ContinueTarget()) {
            continueTarget = iter->Target().ContinueTarget();
        }

        if (labelTargetName == labelName) {
            break;
        }

        iter = iter->Prev();
    }

    return continueTarget;
}

void PandaGen::ControlFlowChangeReturn()
{
    auto *iter = dynamicContext_;
    while (iter) {
        iter->AbortContext(ControlFlowChange::BREAK, LabelTarget::RETURN_LABEL);
        iter = iter->Prev();
    }
}

void PandaGen::Condition(const ir::AstNode *node, lexer::TokenType op, VReg lhs, Label *ifFalse)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            ra_.Emit<EcmaEqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            ra_.Emit<EcmaNoteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL: {
            ra_.Emit<EcmaStricteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            ra_.Emit<EcmaStrictnoteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            ra_.Emit<EcmaLessdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            ra_.Emit<EcmaLesseqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            ra_.Emit<EcmaGreaterdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            ra_.Emit<EcmaGreatereqdyn>(node, lhs);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    BranchIfFalse(node, ifFalse);
}

void PandaGen::Unary(const ir::AstNode *node, lexer::TokenType op, VReg operand)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            ra_.Emit<EcmaTonumber>(node, operand);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            ra_.Emit<EcmaNegdyn>(node, operand);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            ra_.Emit<EcmaNotdyn>(node, operand);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            Negate(node);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_PLUS_PLUS: {
            ra_.Emit<EcmaIncdyn>(node, operand);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS_MINUS: {
            ra_.Emit<EcmaDecdyn>(node, operand);
            break;
        }
        case lexer::TokenType::KEYW_VOID:
        case lexer::TokenType::KEYW_DELETE: {
            LoadConst(node, Constant::JS_UNDEFINED);
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void PandaGen::Binary(const ir::AstNode *node, lexer::TokenType op, VReg lhs)
{
    switch (op) {
        case lexer::TokenType::PUNCTUATOR_EQUAL: {
            ra_.Emit<EcmaEqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL: {
            ra_.Emit<EcmaNoteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL: {
            ra_.Emit<EcmaStricteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            ra_.Emit<EcmaStrictnoteqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            ra_.Emit<EcmaLessdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL: {
            ra_.Emit<EcmaLesseqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            ra_.Emit<EcmaGreaterdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL: {
            ra_.Emit<EcmaGreatereqdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            ra_.Emit<EcmaAdd2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL: {
            ra_.Emit<EcmaSub2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL: {
            ra_.Emit<EcmaMul2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL: {
            ra_.Emit<EcmaDiv2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL: {
            ra_.Emit<EcmaMod2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION: {
            ra_.Emit<EcmaExpdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL: {
            ra_.Emit<EcmaShl2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL: {
            ra_.Emit<EcmaShr2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL: {
            ra_.Emit<EcmaAshr2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL: {
            ra_.Emit<EcmaAnd2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL: {
            ra_.Emit<EcmaOr2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL: {
            ra_.Emit<EcmaXor2dyn>(node, lhs);
            break;
        }
        case lexer::TokenType::KEYW_IN: {
            ra_.Emit<EcmaIsindyn>(node, lhs);
            break;
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            ra_.Emit<EcmaInstanceofdyn>(node, lhs);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING:
        case lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL: {
            Unimplemented();
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

void PandaGen::BranchIfUndefined(const ir::AstNode *node, Label *target)
{
    RegScope rs(this);
    VReg tmp = AllocReg();
    StoreAccumulator(node, tmp);
    sa_.Emit<EcmaLdundefined>(node);
    ra_.Emit<EcmaEqdyn>(node, tmp);
    sa_.Emit<Jnez>(node, target);
}

void PandaGen::BranchIfNotUndefined(const ir::AstNode *node, Label *target)
{
    RegScope rs(this);
    VReg tmp = AllocReg();
    StoreAccumulator(node, tmp);
    sa_.Emit<EcmaLdundefined>(node);
    ra_.Emit<EcmaEqdyn>(node, tmp);
    sa_.Emit<Jeqz>(node, target);
}

void PandaGen::BranchIfStrictNotUndefined(const ir::AstNode *node, class Label *target)
{
    RegScope rs(this);
    VReg tmp = AllocReg();
    StoreAccumulator(node, tmp);
    LoadConst(node, Constant::JS_UNDEFINED);
    ra_.Emit<EcmaStricteqdyn>(node, tmp);
    sa_.Emit<Jeqz>(node, target);
}

void PandaGen::BranchIfTrue(const ir::AstNode *node, Label *target)
{
    sa_.Emit<EcmaIstrue>(node);
    sa_.Emit<Jnez>(node, target);
}

void PandaGen::BranchIfNotTrue(const ir::AstNode *node, Label *target)
{
    sa_.Emit<EcmaIstrue>(node);
    BranchIfFalse(node, target);
}

void PandaGen::BranchIfFalse(const ir::AstNode *node, Label *target)
{
    sa_.Emit<EcmaIsfalse>(node);
    sa_.Emit<Jnez>(node, target);
}

void PandaGen::EmitThrow(const ir::AstNode *node)
{
    sa_.Emit<EcmaThrowdyn>(node);
}

void PandaGen::EmitRethrow(const ir::AstNode *node)
{
    RegScope rs(this);
    auto *skipThrow = AllocLabel();
    auto *doThrow = AllocLabel();

    VReg exception = AllocReg();
    StoreAccumulator(node, exception);

    VReg hole = AllocReg();
    StoreConst(node, hole, Constant::JS_HOLE);

    LoadAccumulator(node, exception);
    ra_.Emit<EcmaNoteqdyn>(node, hole);
    sa_.Emit<Jeqz>(node, skipThrow);

    SetLabel(node, doThrow);
    LoadAccumulator(node, exception);
    sa_.Emit<EcmaThrowdyn>(node);

    SetLabel(node, skipThrow);
}

void PandaGen::EmitReturn(const ir::AstNode *node)
{
    sa_.Emit<ReturnDyn>(node);
}

void PandaGen::EmitReturnUndefined(const ir::AstNode *node)
{
    sa_.Emit<EcmaReturnundefined>(node);
}

void PandaGen::ImplicitReturn(const ir::AstNode *node)
{
    builder_->ImplicitReturn(node);
}

void PandaGen::DirectReturn(const ir::AstNode *node)
{
    builder_->DirectReturn(node);
}

void PandaGen::ValidateClassDirectReturn(const ir::AstNode *node)
{
    const ir::ScriptFunction *func = util::Helpers::GetContainingFunction(node);

    if (!func || !func->IsConstructor()) {
        return;
    }

    RegScope rs(this);
    VReg value = AllocReg();
    StoreAccumulator(node, value);

    auto *notUndefined = AllocLabel();
    auto *condEnd = AllocLabel();

    BranchIfStrictNotUndefined(node, notUndefined);
    GetThis(func);
    ThrowIfSuperNotCorrectCall(func, 0);
    Branch(node, condEnd);

    SetLabel(node, notUndefined);
    LoadAccumulator(node, value);

    SetLabel(node, condEnd);
}

void PandaGen::EmitAwait(const ir::AstNode *node)
{
    builder_->Await(node);
}

void PandaGen::CallThis(const ir::AstNode *node, VReg startReg, size_t argCount)
{
    rra_.Emit<EcmaCallithisrangedyn>(node, startReg, argCount + 2, static_cast<int64_t>(argCount), startReg);
}

void PandaGen::Call(const ir::AstNode *node, VReg startReg, size_t argCount)
{
    VReg callee = startReg;

    switch (argCount) {
        case 0: { // 0 args
            ra_.Emit<EcmaCallarg0dyn>(node, callee);
            break;
        }
        case 1: { // 1 arg
            VReg arg0 = callee + 1;
            ra_.Emit<EcmaCallarg1dyn>(node, callee, arg0);
            break;
        }
        case 2: { // 2 args
            VReg arg0 = callee + 1;
            VReg arg1 = arg0 + 1;
            ra_.Emit<EcmaCallargs2dyn>(node, callee, arg0, arg1);
            break;
        }
        case 3: { // 3 args
            VReg arg0 = callee + 1;
            VReg arg1 = arg0 + 1;
            VReg arg2 = arg1 + 1;
            ra_.Emit<EcmaCallargs3dyn>(node, callee, arg0, arg1, arg2);
            break;
        }
        default: {
            rra_.Emit<EcmaCallirangedyn>(node, startReg, argCount + 1, static_cast<int64_t>(argCount), startReg);
            break;
        }
    }
}

void PandaGen::SuperCall(const ir::AstNode *node, VReg startReg, size_t argCount)
{
    rra_.Emit<EcmaSupercall>(node, startReg, argCount, static_cast<int64_t>(argCount), startReg);
}

void PandaGen::SuperCallSpread(const ir::AstNode *node, VReg vs)
{
    ra_.Emit<EcmaSupercallspread>(node, vs);
}

void PandaGen::NewObject(const ir::AstNode *node, VReg startReg, size_t argCount)
{
    rra_.Emit<EcmaNewobjdynrange>(node, startReg, argCount, static_cast<int64_t>(argCount), startReg);
}

void PandaGen::LoadHomeObject(const ir::AstNode *node)
{
    sa_.Emit<EcmaLdhomeobject>(node);
}

void PandaGen::DefineFunction(const ir::AstNode *node, const ir::ScriptFunction *realNode, const util::StringView &name)
{
    if (realNode->IsOverload() || realNode->Declare()) {
        return;
    }

    auto formalParamCnt = realNode->FormalParamsLength();
    if (realNode->IsMethod()) {
        ra_.Emit<EcmaDefinemethod>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
    } else if (realNode->IsAsync()) {
        if (realNode->IsGenerator()) {
            ra_.Emit<EcmaDefineasyncgeneratorfunc>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
        } else {
            ra_.Emit<EcmaDefineasyncfunc>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
        }
    } else if (realNode->IsGenerator()) {
        ra_.Emit<EcmaDefinegeneratorfunc>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
    } else if (realNode->IsArrow()) {
        LoadHomeObject(node);
        ra_.Emit<EcmaDefinencfuncdyn>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
    } else {
        ra_.Emit<EcmaDefinefuncdyn>(node, name, static_cast<int64_t>(formalParamCnt), LexEnv());
    }

    strings_.insert(name);
}

void PandaGen::TypeOf(const ir::AstNode *node)
{
    sa_.Emit<EcmaTypeofdyn>(node);
}

void PandaGen::CallSpread(const ir::AstNode *node, VReg func, VReg thisReg, VReg args)
{
    ra_.Emit<EcmaCallspreaddyn>(node, func, thisReg, args);
}

void PandaGen::NewObjSpread(const ir::AstNode *node, VReg obj, VReg target)
{
    ra_.Emit<EcmaNewobjspreaddyn>(node, obj, target);
}

void PandaGen::GetUnmappedArgs(const ir::AstNode *node)
{
    sa_.Emit<EcmaGetunmappedargs>(node);
}

void PandaGen::Negate(const ir::AstNode *node)
{
    auto *falseLabel = AllocLabel();
    auto *endLabel = AllocLabel();
    BranchIfTrue(node, falseLabel);
    LoadConst(node, Constant::JS_TRUE);
    Branch(node, endLabel);
    SetLabel(node, falseLabel);
    LoadConst(node, Constant::JS_FALSE);
    SetLabel(node, endLabel);
}

void PandaGen::ToNumber(const ir::AstNode *node, VReg arg)
{
    ra_.Emit<EcmaTonumber>(node, arg);
}

void PandaGen::ToNumeric(const ir::AstNode *node, VReg arg)
{
    ra_.Emit<EcmaTonumeric>(node, arg);
}

void PandaGen::CreateGeneratorObj(const ir::AstNode *node, VReg funcObj)
{
    ra_.Emit<EcmaCreategeneratorobj>(node, funcObj);
}

void PandaGen::CreateAsyncGeneratorObj(const ir::AstNode *node, VReg funcObj)
{
    ra_.Emit<EcmaCreateasyncgeneratorobj>(node, funcObj);
}

void PandaGen::CreateIterResultObject(const ir::AstNode *node, VReg value, VReg done)
{
    ra_.Emit<EcmaCreateiterresultobj>(node, value, done);
}

void PandaGen::SuspendGenerator(const ir::AstNode *node, VReg genObj, VReg iterResult)
{
    ra_.Emit<EcmaSuspendgenerator>(node, genObj, iterResult);
}

void PandaGen::SuspendAsyncGenerator(const ir::AstNode *node, VReg asyncGenObj)
{
    /*
     *  TODO: suspend async generator
     *  ra_.Emit<EcmaSuspendasyncgenerator>(node, asyncGenObj);
     */
}

void PandaGen::GeneratorYield(const ir::AstNode *node, VReg genObj)
{
    /*
     *  TODO: set generator yield
     *  ra_.Emit<EcmaSetgeneratorstate>(node, genObj, static_cast<int32_t>(GeneratorState::SUSPENDED_YIELD));
     */
}

void PandaGen::GeneratorComplete(const ir::AstNode *node, VReg genObj)
{
    /*
     *  TODO: set generator complete
     *  ra_.Emit<EcmaSetgeneratorstate>(node, genObj, static_cast<int32_t>(GeneratorState::COMPLETED));
     */
}

void PandaGen::ResumeGenerator(const ir::AstNode *node, VReg genObj)
{
    ra_.Emit<EcmaResumegenerator>(node, genObj);
}

void PandaGen::GetResumeMode(const ir::AstNode *node, VReg genObj)
{
    ra_.Emit<EcmaGetresumemode>(node, genObj);
}

void PandaGen::AsyncFunctionEnter(const ir::AstNode *node)
{
    sa_.Emit<EcmaAsyncfunctionenter>(node);
}

void PandaGen::AsyncFunctionAwait(const ir::AstNode *node, VReg asyncFuncObj, VReg retVal)
{
    ra_.Emit<EcmaAsyncfunctionawaituncaught>(node, asyncFuncObj, retVal);
}

void PandaGen::AsyncFunctionResolve(const ir::AstNode *node, VReg asyncFuncObj, VReg value, VReg canSuspend)
{
    ra_.Emit<EcmaAsyncfunctionresolve>(node, asyncFuncObj, canSuspend, value);
}

void PandaGen::AsyncFunctionReject(const ir::AstNode *node, VReg asyncFuncObj, VReg value, VReg canSuspend)
{
    ra_.Emit<EcmaAsyncfunctionreject>(node, asyncFuncObj, canSuspend, value);
}

void PandaGen::AsyncGeneratorResolve(const ir::AstNode *node, VReg asyncGenObj, VReg value, VReg canSuspend)
{
    ra_.Emit<EcmaAsyncgeneratorresolve>(node, asyncGenObj, value, canSuspend);
}

void PandaGen::AsyncGeneratorReject(const ir::AstNode *node, VReg asyncGenObj, VReg value)
{
    ra_.Emit<EcmaAsyncgeneratorreject>(node, asyncGenObj, value);
}

void PandaGen::GetTemplateObject(const ir::AstNode *node, VReg value)
{
    ra_.Emit<EcmaGettemplateobject>(node, value);
}

void PandaGen::CopyRestArgs(const ir::AstNode *node, uint32_t index)
{
    sa_.Emit<EcmaCopyrestargs>(node, index);
}

void PandaGen::GetPropIterator(const ir::AstNode *node)
{
    sa_.Emit<EcmaGetpropiterator>(node);
}

void PandaGen::GetNextPropName(const ir::AstNode *node, VReg iter)
{
    ra_.Emit<EcmaGetnextpropname>(node, iter);
}

void PandaGen::CreateEmptyObject(const ir::AstNode *node)
{
    sa_.Emit<EcmaCreateemptyobject>(node);
}

void PandaGen::CreateObjectWithBuffer(const ir::AstNode *node, uint32_t idx)
{
    ASSERT(util::Helpers::IsInteger<uint32_t>(idx));
    sa_.Emit<EcmaCreateobjectwithbuffer>(node, idx);
}

void PandaGen::CreateObjectHavingMethod(const ir::AstNode *node, uint32_t idx)
{
    ASSERT(util::Helpers::IsInteger<uint32_t>(idx));
    LoadAccumulator(node, LexEnv());
    sa_.Emit<EcmaCreateobjecthavingmethod>(node, idx);
}

void PandaGen::SetObjectWithProto(const ir::AstNode *node, VReg proto, VReg obj)
{
    ra_.Emit<EcmaSetobjectwithproto>(node, proto, obj);
}

void PandaGen::CopyDataProperties(const ir::AstNode *node, VReg dst, VReg src)
{
    ra_.Emit<EcmaCopydataproperties>(node, dst, src);
}

void PandaGen::DefineGetterSetterByValue(const ir::AstNode *node, VReg obj, VReg name, VReg getter, VReg setter,
                                         bool setName)
{
    LoadConst(node, setName ? Constant::JS_TRUE : Constant::JS_FALSE);
    ra_.Emit<EcmaDefinegettersetterbyvalue>(node, obj, name, getter, setter);
}

void PandaGen::CreateEmptyArray(const ir::AstNode *node)
{
    sa_.Emit<EcmaCreateemptyarray>(node);
}

void PandaGen::CreateArrayWithBuffer(const ir::AstNode *node, uint32_t idx)
{
    ASSERT(util::Helpers::IsInteger<uint32_t>(idx));
    sa_.Emit<EcmaCreatearraywithbuffer>(node, idx);
}

void PandaGen::CreateArray(const ir::AstNode *node, const ArenaVector<ir::Expression *> &elements, VReg obj)
{
    if (elements.empty()) {
        CreateEmptyArray(node);
        StoreAccumulator(node, obj);
        return;
    }

    auto *buf = NewLiteralBuffer();

    size_t i = 0;
    // This loop handles constant literal data by collecting it into a literal buffer
    // until a non-constant element is encountered.
    while (i < elements.size() && util::Helpers::IsConstantExpr(elements[i])) {
        buf->Add(elements[i]->AsLiteral());
        i++;
    }

    if (buf->IsEmpty()) {
        CreateEmptyArray(node);
    } else {
        uint32_t bufIdx = AddLiteralBuffer(buf);
        CreateArrayWithBuffer(node, bufIdx);
    }

    StoreAccumulator(node, obj);

    if (i == elements.size()) {
        return;
    }

    bool hasSpread = false;

    // This loop handles array elements until a spread element is encountered
    for (; i < elements.size(); i++) {
        const ir::Expression *elem = elements[i];

        if (elem->IsOmittedExpression()) {
            continue;
        }

        if (elem->IsSpreadElement()) {
            // The next loop will handle arrays that have a spread element
            hasSpread = true;
            break;
        }

        elem->Compile(this);
        StOwnByIndex(elem, obj, i);
    }

    RegScope rs(this);
    VReg idxReg {};

    if (hasSpread) {
        idxReg = AllocReg();
        LoadAccumulatorInt(node, i);
        StoreAccumulator(node, idxReg);
    }

    // This loop handles arrays that contain spread elements
    for (; i < elements.size(); i++) {
        const ir::Expression *elem = elements[i];

        if (elem->IsSpreadElement()) {
            elem->AsSpreadElement()->Argument()->Compile(this);

            StoreArraySpread(elem, obj, idxReg);

            LoadObjByName(node, obj, "length");
            StoreAccumulator(elem, idxReg);
            continue;
        }

        if (!elem->IsOmittedExpression()) {
            elem->Compile(this);
            StOwnByValue(elem, obj, idxReg);
        }

        Unary(elem, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, idxReg);
        StoreAccumulator(elem, idxReg);
    }

    // If the last element is omitted, we also have to update the length property
    if (elements.back()->IsOmittedExpression()) {
        // if there was a spread value then acc already contains the length
        if (!hasSpread) {
            LoadAccumulatorInt(node, i);
        }

        StOwnByName(node, obj, "length");
    }

    LoadAccumulator(node, obj);
}

void PandaGen::StoreArraySpread(const ir::AstNode *node, VReg array, VReg index)
{
    ra_.Emit<EcmaStarrayspread>(node, array, index);
}

void PandaGen::ThrowIfNotObject(const ir::AstNode *node, VReg obj)
{
    ra_.Emit<EcmaThrowifnotobject>(node, obj);
}

void PandaGen::ThrowThrowNotExist(const ir::AstNode *node)
{
    sa_.Emit<EcmaThrowthrownotexists>(node);
}

void PandaGen::GetIterator(const ir::AstNode *node)
{
    sa_.Emit<EcmaGetiterator>(node);
}

void PandaGen::GetAsyncIterator(const ir::AstNode *node)
{
    /*
     *  TODO: async iterator
     *  sa_.Emit<EcmaGetasynciterator>(node);
     */
}

void PandaGen::CreateObjectWithExcludedKeys(const ir::AstNode *node, VReg obj, VReg argStart, size_t argCount)
{
    ASSERT(argStart == obj + 1);
    if (argCount == 0) {
        LoadConst(node, Constant::JS_UNDEFINED);
        StoreAccumulator(node, argStart);
    }

    size_t argRegCnt = (argCount == 0 ? argCount : argCount - 1);
    rra_.Emit<EcmaCreateobjectwithexcludedkeys>(node, argStart, argCount, static_cast<int64_t>(argRegCnt), obj,
                                                argStart);
}

void PandaGen::ThrowObjectNonCoercible(const ir::AstNode *node)
{
    sa_.Emit<EcmaThrowpatternnoncoercible>(node);
}

void PandaGen::CloseIterator(const ir::AstNode *node, VReg iter)
{
    ra_.Emit<EcmaCloseiterator>(node, iter);
}

void PandaGen::DefineClassWithBuffer(const ir::AstNode *node, const util::StringView &ctorId, int32_t litIdx,
                                     VReg lexenv, VReg base)
{
    auto formalParamCnt = node->AsClassDefinition()->Ctor()->Function()->FormalParamsLength();
    ra_.Emit<EcmaDefineclasswithbuffer>(node, ctorId, litIdx, static_cast<int64_t>(formalParamCnt), lexenv, base);
    strings_.insert(ctorId);
}

void PandaGen::LoadModuleVariable(const ir::AstNode *node, const util::StringView &name, bool isLocalExport)
{
    ra_.Emit<EcmaLdmodulevar>(node, name, isLocalExport ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0));
    strings_.insert(name);
}

void PandaGen::StoreModuleVariable(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStmodulevar>(node, name);
    strings_.insert(name);
}

void PandaGen::GetModuleNamespace(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaGetmodulenamespace>(node, name);
    strings_.insert(name);
}

void PandaGen::DynamicImportCall(const ir::AstNode *node, VReg moduleSpecifier)
{
    ra_.Emit<EcmaDynamicimport>(node, moduleSpecifier);
}

void PandaGen::StSuperByName(const ir::AstNode *node, VReg obj, const util::StringView &key)
{
    ra_.Emit<EcmaStsuperbyname>(node, key, obj);
    strings_.insert(key);
}

void PandaGen::LdSuperByName(const ir::AstNode *node, VReg obj, const util::StringView &key)
{
    ra_.Emit<EcmaLdsuperbyname>(node, key, obj);
    strings_.insert(key);
}

void PandaGen::StSuperByValue(const ir::AstNode *node, VReg obj, VReg prop)
{
    ra_.Emit<EcmaStsuperbyvalue>(node, obj, prop);
}

void PandaGen::LdSuperByValue(const ir::AstNode *node, VReg obj, VReg prop)
{
    ra_.Emit<EcmaLdsuperbyvalue>(node, obj, prop);
}

void PandaGen::StoreSuperProperty(const ir::AstNode *node, VReg obj, const Operand &prop)
{
    if (std::holds_alternative<util::StringView>(prop)) {
        StSuperByName(node, obj, std::get<util::StringView>(prop));
        return;
    }

    if (std::holds_alternative<VReg>(prop)) {
        StSuperByValue(node, obj, std::get<VReg>(prop));
        return;
    }

    ASSERT(std::holds_alternative<int64_t>(prop));
    RegScope rs(this);
    VReg property = AllocReg();
    VReg value = AllocReg();

    StoreAccumulator(node, value);
    LoadAccumulatorInt(node, static_cast<size_t>(std::get<int64_t>(prop)));
    StoreAccumulator(node, property);
    LoadAccumulator(node, value);
    StSuperByValue(node, obj, property);
}

void PandaGen::LoadSuperProperty(const ir::AstNode *node, VReg obj, const Operand &prop)
{
    if (std::holds_alternative<util::StringView>(prop)) {
        LdSuperByName(node, obj, std::get<util::StringView>(prop));
        return;
    }

    if (std::holds_alternative<VReg>(prop)) {
        LdSuperByValue(node, obj, std::get<VReg>(prop));
        return;
    }

    ASSERT(std::holds_alternative<int64_t>(prop));
    RegScope rs(this);

    LoadAccumulatorInt(node, static_cast<size_t>(std::get<int64_t>(prop)));
    VReg property = AllocReg();
    StoreAccumulator(node, property);
    LdSuperByValue(node, obj, property);
}

void PandaGen::LoadLexicalVar(const ir::AstNode *node, uint32_t level, uint32_t slot)
{
    sa_.Emit<EcmaLdlexvardyn>(node, level, slot);
}

void PandaGen::LoadLexicalVar(const ir::AstNode *node, uint32_t level, uint32_t slot, const util::StringView &name)
{
    if (context_->HotfixHelper() && context_->HotfixHelper()->IsPatchVar(slot)) {
        uint32_t patchSlot = context_->HotfixHelper()->GetPatchLexicalIdx(std::string(name));
        sa_.Emit<EcmaLdpatchvar>(node, patchSlot);
        return;
    }
    sa_.Emit<EcmaLdlexvardyn>(node, level, slot);
}

void PandaGen::StoreLexicalVar(const ir::AstNode *node, uint32_t level, uint32_t slot)
{
    RegScope rs(this);
    VReg value = AllocReg();
    StoreAccumulator(node, value);
    ra_.Emit<EcmaStlexvardyn>(node, level, slot, value);
}

void PandaGen::StoreLexicalVar(const ir::AstNode *node, uint32_t level, uint32_t slot, VReg value)
{
    ra_.Emit<EcmaStlexvardyn>(node, level, slot, value);
}

void PandaGen::StoreLexicalVar(const ir::AstNode *node, uint32_t level, uint32_t slot, const util::StringView &name)
{
    if (context_->HotfixHelper() && context_->HotfixHelper()->IsPatchVar(slot)) {
        uint32_t patchSlot = context_->HotfixHelper()->GetPatchLexicalIdx(std::string(name));
        sa_.Emit<EcmaStpatchvar>(node, patchSlot);
        return;
    }
    RegScope rs(this);
    VReg value = AllocReg();
    StoreAccumulator(node, value);
    ra_.Emit<EcmaStlexvardyn>(node, level, slot, value);
}

void PandaGen::ThrowIfSuperNotCorrectCall(const ir::AstNode *node, int64_t num)
{
    sa_.Emit<EcmaThrowifsupernotcorrectcall>(node, num);
}

void PandaGen::ThrowUndefinedIfHole(const ir::AstNode *node, const util::StringView &name)
{
    RegScope rs(this);
    VReg holeReg = AllocReg();
    StoreAccumulator(node, holeReg);
    LoadAccumulatorString(node, name);
    VReg nameReg = AllocReg();
    StoreAccumulator(node, nameReg);
    ra_.Emit<EcmaThrowundefinedifhole>(node, holeReg, nameReg);
    LoadAccumulator(node, holeReg);
    strings_.insert(name);
}

void PandaGen::ThrowConstAssignment(const ir::AstNode *node, const util::StringView &name)
{
    RegScope rs(this);
    LoadAccumulatorString(node, name);
    VReg nameReg = AllocReg();
    StoreAccumulator(node, nameReg);
    ra_.Emit<EcmaThrowconstassignment>(node, nameReg);
    strings_.insert(name);
}

void PandaGen::PopLexEnv(const ir::AstNode *node)
{
    sa_.Emit<EcmaPoplexenvdyn>(node);
}

void PandaGen::CopyLexEnv(const ir::AstNode *node)
{
    /*
     *  TODO: add copy lexenv to optimize the loop env creation
     *  sa_.Emit<EcmaCopylexenvdyn>(node);
     */
}

void PandaGen::NewLexicalEnv(const ir::AstNode *node, uint32_t num, binder::VariableScope *scope)
{
    if (IsDebug()) {
        int32_t scopeInfoIdx = AddLexicalVarNamesForDebugInfo(scope->GetLexicalVarNameAndTypes());
        NewLexEnvWithScopeInfo(node, num, scopeInfoIdx);
        return;
    }

    NewLexEnv(node, num);
}

void PandaGen::NewLexEnv(const ir::AstNode *node, uint32_t num)
{
    sa_.Emit<EcmaNewlexenvdyn>(node, num);
}

void PandaGen::NewLexEnvWithScopeInfo(const ir::AstNode *node, uint32_t num, int32_t scopeInfoIdx)
{
    sa_.Emit<EcmaNewlexenvwithnamedyn>(node, num, scopeInfoIdx);
}

void PandaGen::LdLexEnv(const ir::AstNode *node)
{
    sa_.Emit<EcmaLdlexenvdyn>(node);
}

uint32_t PandaGen::TryDepth() const
{
    const auto *iter = dynamicContext_;
    uint32_t depth = 0;

    while (iter) {
        if (iter->HasTryCatch()) {
            depth++;
        }

        iter = iter->Prev();
    }

    return depth;
}

CatchTable *PandaGen::CreateCatchTable()
{
    auto *catchTable = allocator_->New<CatchTable>(this, TryDepth());
    catchList_.push_back(catchTable);
    return catchTable;
}

void PandaGen::SortCatchTables()
{
    std::sort(catchList_.begin(), catchList_.end(),
              [](const CatchTable *a, const CatchTable *b) { return b->Depth() < a->Depth(); });
}

Operand PandaGen::ToNamedPropertyKey(const ir::Expression *prop, bool isComputed)
{
    VReg res {0};

    if (isComputed) {
        return res;
    }

    if (prop->IsIdentifier()) {
        return prop->AsIdentifier()->Name();
    }

    if (prop->IsStringLiteral()) {
        const util::StringView &str = prop->AsStringLiteral()->Str();

        /* TODO(dbatyai): remove this when runtime handles __proto__ as property name correctly */
        if (str.Is("__proto__")) {
            return res;
        }

        int64_t index = util::Helpers::GetIndex(str);
        if (index != util::Helpers::INVALID_INDEX) {
            return index;
        }

        return str;
    }

    if (prop->IsNumberLiteral()) {
        auto num = prop->AsNumberLiteral()->Number<double>();
        if (util::Helpers::IsIndex(num)) {
            return static_cast<int64_t>(num);
        }

        return prop->AsNumberLiteral()->Str();
    }

    return res;
}

Operand PandaGen::ToPropertyKey(const ir::Expression *prop, bool isComputed)
{
    Operand op = ToNamedPropertyKey(prop, isComputed);
    if (std::holds_alternative<util::StringView>(op) || (std::holds_alternative<int64_t>(op) &&
        (std::get<int64_t>(op) <= util::Helpers::MAX_INT32))) {
        return op;
    }

    VReg propReg = AllocReg();

    /**
     * Store index to vreg when index > MAX_INT32 to simplify ASM interpreter If byindex-related instructions support
     * index > MAX_INT32, ASM interpreter will have to add a judgment whether index needs more than 32 bits which will
     * cause inefficiency of it since cases when index > MAX_INT32 can be quite rare
     **/
    if (std::holds_alternative<int64_t>(op) && (std::get<int64_t>(op) > util::Helpers::MAX_INT32)) {
        LoadAccumulatorFloat(prop, std::get<int64_t>(op));
        StoreAccumulator(prop, propReg);
        return propReg;
    }

    ASSERT(std::holds_alternative<VReg>(op));
    prop->Compile(this);
    StoreAccumulator(prop, propReg);

    return propReg;
}

VReg PandaGen::LoadPropertyKey(const ir::Expression *prop, bool isComputed)
{
    Operand op = ToNamedPropertyKey(prop, isComputed);

    if (std::holds_alternative<util::StringView>(op)) {
        LoadAccumulatorString(prop, std::get<util::StringView>(op));
    } else if (std::holds_alternative<int64_t>(op)) {
        LoadAccumulatorInt(prop, static_cast<size_t>(std::get<int64_t>(op)));
    } else {
        prop->Compile(this);
    }

    VReg propReg = AllocReg();
    StoreAccumulator(prop, propReg);

    return propReg;
}

void PandaGen::StLetToGlobalRecord(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStlettoglobalrecord>(node, name);
    strings_.insert(name);
}

void PandaGen::StConstToGlobalRecord(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStconsttoglobalrecord>(node, name);
    strings_.insert(name);
}

void PandaGen::StClassToGlobalRecord(const ir::AstNode *node, const util::StringView &name)
{
    sa_.Emit<EcmaStclasstoglobalrecord>(node, name);
    strings_.insert(name);
}

bool PandaGen::TryCompileFunctionCallOrNewExpression(const ir::Expression *expr)
{
    ASSERT(expr->IsCallExpression() || expr->IsNewExpression());
    const auto *callee = expr->IsCallExpression() ? expr->AsCallExpression()->Callee() :
                         expr->AsNewExpression()->Callee();

    if (!callee->IsIdentifier()) {
        return false;
    }

    if (callee->AsIdentifier()->Name().Is("Function")) {
        auto arguments = expr->IsCallExpression() ? expr->AsCallExpression()->Arguments() :
                         expr->AsNewExpression()->Arguments();
        if (arguments.empty()) {
            return false;
        }

        auto *arg = arguments[arguments.size() - 1];
        if (!arg->IsStringLiteral()) {
            return false;
        }

        if (std::regex_match(arg->AsStringLiteral()->Str().Mutf8(), std::regex(" *return +this[;]? *$"))) {
            LoadConst(arg, Constant::JS_GLOBAL);
            return true;
        }
    }

    return false;
}

}  // namespace panda::es2panda::compiler
