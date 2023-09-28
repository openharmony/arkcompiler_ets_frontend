/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "functionBuilder.h"

#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/ir/statement.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/compiler/base/iterators.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"

namespace panda::es2panda::compiler {
FunctionBuilder::FunctionBuilder(PandaGen *pg, CatchTable *catch_table)
    : pg_(pg), catch_table_(catch_table), func_obj_(catch_table != nullptr ? pg_->AllocReg() : VReg(VReg::REG_START))
{
}

IteratorType FunctionBuilder::GeneratorKind() const
{
    return IteratorType::SYNC;
}

void FunctionBuilder::DirectReturn(const ir::AstNode *node) const
{
    pg_->EmitReturn(node);
}

void FunctionBuilder::ImplicitReturn(const ir::AstNode *node) const
{
    const auto *root_node = pg_->RootNode();

    if (!root_node->IsScriptFunction() || !root_node->AsScriptFunction()->IsConstructor()) {
        pg_->EmitReturnUndefined(node);
        return;
    }

    pg_->GetThis(root_node);
    pg_->ThrowIfSuperNotCorrectCall(root_node, 0);
    pg_->EmitReturn(node);
}

void FunctionBuilder::AsyncYield(const ir::AstNode *node, VReg completion_type, VReg completion_value) const
{
    ASSERT(BuilderKind() == BuilderType::ASYNC_GENERATOR);

    pg_->GeneratorYield(node, func_obj_);
    pg_->SuspendAsyncGenerator(node, func_obj_);

    ResumeGenerator(node, completion_type, completion_value);
}

void FunctionBuilder::SuspendResumeExecution(const ir::AstNode *node, VReg completion_type, VReg completion_value) const
{
    ASSERT(BuilderKind() == BuilderType::ASYNC || BuilderKind() == BuilderType::ASYNC_GENERATOR ||
           BuilderKind() == BuilderType::GENERATOR);

    pg_->SuspendGenerator(node, func_obj_);
    ResumeGenerator(node, completion_type, completion_value);
}

void FunctionBuilder::ResumeGenerator(const ir::AstNode *node, VReg completion_type, VReg completion_value) const
{
    ASSERT(BuilderKind() == BuilderType::ASYNC || BuilderKind() == BuilderType::ASYNC_GENERATOR ||
           BuilderKind() == BuilderType::GENERATOR);

    pg_->ResumeGenerator(node, func_obj_);
    pg_->StoreAccumulator(node, completion_value);
    pg_->GetResumeMode(node, func_obj_);
    pg_->StoreAccumulator(node, completion_type);
}

VReg FunctionBuilder::FunctionReg(const ir::ScriptFunction *node) const
{
    binder::FunctionScope *scope = node->Scope();
    auto res = scope->Find(binder::Binder::MANDATORY_PARAM_FUNC);
    ASSERT(res.level == 0 && res.variable->IsLocalVariable());
    return res.variable->AsLocalVariable()->Vreg();
}

void FunctionBuilder::Await(const ir::AstNode *node)
{
    if (BuilderKind() == BuilderType::NORMAL) {
        // TODO(frobert): Implement top-level await
        PandaGen::Unimplemented();
    }

    ASSERT(BuilderKind() == BuilderType::ASYNC || BuilderKind() == BuilderType::ASYNC_GENERATOR);

    RegScope rs(pg_);
    VReg completion_type = pg_->AllocReg();
    VReg completion_value = pg_->AllocReg();

    pg_->AsyncFunctionAwait(node, func_obj_);
    SuspendResumeExecution(node, completion_type, completion_value);

    HandleCompletion(node, completion_type, completion_value);
}

void FunctionBuilder::HandleCompletion(const ir::AstNode *node, VReg completion_type, VReg completion_value)
{
    // .return(value)
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::RETURN));

    auto *not_ret_label = pg_->AllocLabel();
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, completion_type, not_ret_label);
    if (!handle_return_) {
        handle_return_ = true;
        pg_->ControlFlowChangeBreak();
        handle_return_ = false;
    }

    pg_->LoadAccumulator(node, completion_value);
    pg_->DirectReturn(node);

    // .throw(value)
    pg_->SetLabel(node, not_ret_label);
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::THROW));

    auto *not_throw_label = pg_->AllocLabel();
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, completion_type, not_throw_label);
    pg_->LoadAccumulator(node, completion_value);
    pg_->EmitThrow(node);

    // .next(value)
    pg_->SetLabel(node, not_throw_label);
    pg_->LoadAccumulator(node, completion_value);
}

void FunctionBuilder::YieldStar(const ir::AstNode *node)
{
    ASSERT(BuilderKind() == BuilderType::GENERATOR || BuilderKind() == BuilderType::ASYNC_GENERATOR);

    RegScope rs(pg_);

    auto *loop_start = pg_->AllocLabel();
    auto *return_completion = pg_->AllocLabel();
    auto *throw_completion = pg_->AllocLabel();
    auto *call_method = pg_->AllocLabel();
    auto *normal_or_throw_completion = pg_->AllocLabel();
    auto *iterator_complete = pg_->AllocLabel();

    // 4. Let iteratorRecord be ? GetIterator(value, generatorKind).
    Iterator iterator(pg_, node, GeneratorKind());

    // 6. Let received be NormalCompletion(undefined).
    VReg received_value = iterator.NextResult();
    VReg received_type = pg_->AllocReg();
    VReg next_method = pg_->AllocReg();
    VReg exit_return = pg_->AllocReg();

    pg_->StoreConst(node, received_value, Constant::JS_UNDEFINED);
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::NEXT));
    pg_->StoreAccumulator(node, received_type);
    pg_->MoveVreg(node, next_method, iterator.Method());

    // 7. Repeat
    pg_->SetLabel(node, loop_start);
    pg_->StoreConst(node, exit_return, Constant::JS_FALSE);

    // a. If received.[[Type]] is normal, then
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::NEXT));
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_STRICT_EQUAL, received_type, throw_completion);
    pg_->MoveVreg(node, iterator.Method(), next_method);
    pg_->Branch(node, call_method);

    // b. Else if received.[[Type]] is throw, then
    pg_->SetLabel(node, throw_completion);
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::THROW));
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_STRICT_EQUAL, received_type, return_completion);

    // i. Let throw be ? GetMethod(iterator, "throw").
    iterator.GetMethod("throw");

    // ii. If throw is not undefined, then
    pg_->BranchIfNotUndefined(node, call_method);

    // iii. Else,
    // 1. NOTE: If iterator does not have a throw method, this throw is going to terminate the yield* loop. But first we
    // need to give iterator a chance to clean up.
    // 2. Let closeCompletion be Completion { [[Type]]: normal, [[Value]]: empty, [[Target]]: empty }.
    // 3. If generatorKind is async, perform ? AsyncIteratorClose(iteratorRecord, closeCompletion).
    // 4. Else, perform ? IteratorClose(iteratorRecord, closeCompletion).
    iterator.Close(false);
    // 5. NOTE: The next step throws a TypeError to indicate that there was a yield* protocol violation: iterator does
    // not have a throw method.
    // 6. Throw a TypeError exception.
    pg_->ThrowThrowNotExist(node);

    // c. Else,
    // i. Assert: received.[[Type]] is return.
    pg_->SetLabel(node, return_completion);
    pg_->StoreConst(node, exit_return, Constant::JS_TRUE);
    // ii. Let return be ? GetMethod(iterator, "return").
    iterator.GetMethod("return");

    // iii. If return is undefined, then
    pg_->BranchIfNotUndefined(node, call_method);

    // 1. If generatorKind is async, set received.[[Value]] to ? Await(received.[[Value]]).
    pg_->ControlFlowChangeBreak();
    pg_->LoadAccumulator(node, received_value);

    if (GeneratorKind() == IteratorType::ASYNC) {
        Await(node);
    }

    // 2. Return Completion(received).
    pg_->DirectReturn(node);

    pg_->SetLabel(node, call_method);
    // i. Let innerResult be ? Call(iteratorRecord.[[NextMethod]], iteratorRecord.[[Iterator]], « received.[[Value]] »).
    // 1. Let innerResult be ? Call(throw, iterator, « received.[[Value]] »).
    // iv. Let innerReturnResult be ? Call(return, iterator, « received.[[Value]] »).
    iterator.CallMethodWithValue();

    // ii. ii. If generatorKind is async, set innerResult to ? Await(innerResult).
    // 2. If generatorKind is async, set innerResult to ? Await(innerResult).
    // v. If generatorKind is async, set innerReturnResult to ? Await(innerReturnResult).
    if (GeneratorKind() == IteratorType::ASYNC) {
        Await(node);
    }

    pg_->StoreAccumulator(node, received_value);

    // ii. If Type(innerResult) is not Object, throw a TypeError exception.
    // 4. If Type(innerResult) is not Object, throw a TypeError exception.
    // vi. If Type(innerReturnResult) is not Object, throw a TypeError exception.
    pg_->ThrowIfNotObject(node);

    // iv. Let done be ? IteratorComplete(innerResult).
    // v. Let done be ? IteratorComplete(innerResult).
    // vii. Let done be ? IteratorComplete(innerReturnResult).
    iterator.Complete();
    pg_->BranchIfTrue(node, iterator_complete);

    // vi. If generatorKind is async, set received to AsyncGeneratorYield(? IteratorValue(innerResult)).
    // 7. If generatorKind is async, set received to AsyncGeneratorYield(? IteratorValue(innerResult)).
    // ix. If generatorKind is async, set received to AsyncGeneratorYield(? IteratorValue(innerReturnResult)).
    if (GeneratorKind() == IteratorType::ASYNC) {
        iterator.Value();
        // 27.6.3.8 AsyncGeneratorYield
        // 5. Set value to ? Await(value).
        Await(node);
        // 6. Set generator.[[AsyncGeneratorState]] to suspendedYield.
        AsyncYield(node, received_type, received_value);

        // a. If resumptionValue.[[Type]] is not return
        pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::RETURN));
        pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, received_type, loop_start);

        // b. Let awaited be Await(resumptionValue.[[Value]]).
        pg_->LoadAccumulator(node, received_value);
        pg_->AsyncFunctionAwait(node, func_obj_);
        SuspendResumeExecution(node, received_type, received_value);

        // c. If awaited.[[Type]] is throw, return Completion(awaited).
        pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::THROW));
        // d. Assert: awaited.[[Type]] is normal.
        // e. Return Completion { [[Type]]: return, [[Value]]: awaited.[[Value]], [[Target]]: empty }.
        pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, received_type, return_completion);
    } else {
        // vii. Else, set received to GeneratorYield(innerResult).
        // 8. Else, set received to GeneratorYield(innerResult).
        // x. Else, set received to GeneratorYield(innerReturnResult).
        pg_->LoadAccumulator(node, received_value);
        pg_->GeneratorYield(node, func_obj_);
        SuspendResumeExecution(node, received_type, received_value);
    }

    pg_->Branch(node, loop_start);

    // v. If done is true, then
    // 6. If done is true, then
    // viii. If done is true, then
    pg_->SetLabel(node, iterator_complete);

    pg_->LoadAccumulator(node, exit_return);
    pg_->BranchIfFalse(node, normal_or_throw_completion);

    // 1. Let value be ? IteratorValue(innerReturnResult).
    iterator.Value();

    if (pg_->CheckControlFlowChange()) {
        pg_->StoreAccumulator(node, received_value);
        pg_->ControlFlowChangeBreak();
        pg_->LoadAccumulator(node, received_value);
    }

    // 2. Return Completion { [[Type]]: return, [[Value]]: value, [[Target]]: empty }.
    pg_->DirectReturn(node);

    pg_->SetLabel(node, normal_or_throw_completion);
    // 1. Return ? IteratorValue(innerResult).
    // a. Return ? IteratorValue(innerResult).
    iterator.Value();
}
}  // namespace panda::es2panda::compiler
