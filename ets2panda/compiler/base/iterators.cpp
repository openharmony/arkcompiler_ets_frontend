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

#include "iterators.h"

#include "compiler/core/pandagen.h"
#include "compiler/base/catchTable.h"
#include "compiler/function/functionBuilder.h"

namespace panda::es2panda::compiler {
// Iterator

Iterator::Iterator(PandaGen *pg, const ir::AstNode *node, IteratorType type)
    : pg_(pg),
      node_(node),
      method_(pg->AllocReg()),
      iterator_(pg->AllocReg()),
      next_result_(pg->AllocReg()),
      type_(type)
{
    if (type_ == IteratorType::ASYNC) {
        pg_->GetAsyncIterator(node);
    } else {
        pg_->GetIterator(node);
    }

    pg_->StoreAccumulator(node, iterator_);
    pg_->LoadObjByName(node_, "next");
    pg_->StoreAccumulator(node_, method_);

    pg_->ThrowIfNotObject(node_);
}

void Iterator::GetMethod(util::StringView name) const
{
    pg_->GetMethod(node_, iterator_, name);
    pg_->StoreAccumulator(node_, method_);
}

void Iterator::CallMethodWithValue() const
{
    pg_->Call1This(node_, method_, iterator_, next_result_);
}

void Iterator::CallMethod() const
{
    pg_->Call0This(node_, method_, iterator_);
}

void Iterator::Next() const
{
    CallMethod();

    if (type_ == IteratorType::ASYNC) {
        pg_->FuncBuilder()->Await(node_);
    }

    pg_->ThrowIfNotObject(node_);
    pg_->StoreAccumulator(node_, next_result_);
}

void Iterator::Complete() const
{
    pg_->LoadObjByName(node_, "done");
    pg_->ToBoolean(node_);
}

void Iterator::Value() const
{
    pg_->LoadAccumulator(node_, next_result_);
    pg_->LoadObjByName(node_, "value");
}

void Iterator::Close(bool abrupt_completion) const
{
    if (type_ == IteratorType::SYNC) {
        if (!abrupt_completion) {
            pg_->LoadConst(node_, Constant::JS_HOLE);
        }
        pg_->CloseIterator(node_, iterator_);
        return;
    }

    RegScope rs(pg_);
    VReg completion = pg_->AllocReg();
    VReg inner_result = pg_->AllocReg();
    VReg inner_result_type = pg_->AllocReg();

    pg_->StoreAccumulator(node_, completion);
    pg_->StoreConst(node_, inner_result_type, Constant::JS_HOLE);

    TryContext try_ctx(pg_);
    const auto &label_set = try_ctx.LabelSet();
    Label *return_exits = pg_->AllocLabel();

    pg_->SetLabel(node_, label_set.TryBegin());

    // 4. Let innerResult be GetMethod(iterator, "return").
    GetMethod("return");

    // 5. If innerResult.[[Type]] is normal, then
    {
        // b. If return is undefined, return Completion(completion).
        pg_->BranchIfNotUndefined(node_, return_exits);
        // a. Let return be innerResult.[[Value]].
        pg_->LoadAccumulator(node_, completion);

        if (abrupt_completion) {
            pg_->EmitThrow(node_);
        } else {
            pg_->DirectReturn(node_);
        }

        pg_->SetLabel(node_, return_exits);

        {
            TryContext inner_try_ctx(pg_);
            const auto &inner_label_set = inner_try_ctx.LabelSet();

            pg_->SetLabel(node_, inner_label_set.TryBegin());
            // c. Set innerResult to Call(return, iterator).
            CallMethod();
            // d. If innerResult.[[Type]] is normal, set innerResult to Await(innerResult.[[Value]]).
            pg_->FuncBuilder()->Await(node_);
            pg_->StoreAccumulator(node_, inner_result);
            pg_->SetLabel(node_, inner_label_set.TryEnd());
            pg_->Branch(node_, inner_label_set.CatchEnd());

            pg_->SetLabel(node_, inner_label_set.CatchBegin());
            pg_->StoreAccumulator(node_, inner_result);
            pg_->StoreAccumulator(node_, inner_result_type);
            pg_->SetLabel(node_, inner_label_set.CatchEnd());
        }
    }

    pg_->SetLabel(node_, label_set.TryEnd());
    pg_->Branch(node_, label_set.CatchEnd());

    pg_->SetLabel(node_, label_set.CatchBegin());
    pg_->StoreAccumulator(node_, inner_result);
    pg_->StoreAccumulator(node_, inner_result_type);
    pg_->SetLabel(node_, label_set.CatchEnd());

    // 6. If completion.[[Type]] is throw, return Completion(completion).
    if (abrupt_completion) {
        pg_->LoadAccumulator(node_, completion);
        pg_->EmitThrow(node_);
    } else {
        // 7. If innerResult.[[Type]] is throw, return Completion(innerResult).
        pg_->LoadAccumulator(node_, inner_result_type);
        pg_->EmitRethrow(node_);
    }

    // 8. If Type(innerResult.[[Value]]) is not Object, throw a TypeError exception.
    pg_->LoadAccumulator(node_, inner_result);
    pg_->ThrowIfNotObject(node_);
}

DestructuringIterator::DestructuringIterator(PandaGen *pg, const ir::AstNode *node)
    : Iterator(pg, node, IteratorType::SYNC), done_(pg->AllocReg()), result_(pg->AllocReg())
{
    pg_->StoreConst(node, done_, Constant::JS_FALSE);
    pg_->StoreConst(node, result_, Constant::JS_UNDEFINED);
}

void DestructuringIterator::Step(Label *done_target) const
{
    TryContext try_ctx(pg_);
    const auto &label_set = try_ctx.LabelSet();
    Label *normal_close = pg_->AllocLabel();
    Label *no_close = pg_->AllocLabel();

    pg_->SetLabel(node_, label_set.TryBegin());
    Next();
    Complete();
    pg_->StoreAccumulator(node_, done_);
    pg_->BranchIfFalse(node_, normal_close);
    pg_->StoreConst(node_, done_, Constant::JS_TRUE);
    pg_->LoadConst(node_, Constant::JS_UNDEFINED);
    OnIterDone(done_target);
    pg_->Branch(node_, no_close);

    pg_->SetLabel(node_, normal_close);
    Value();
    pg_->StoreAccumulator(node_, result_);
    pg_->SetLabel(node_, no_close);

    pg_->SetLabel(node_, label_set.TryEnd());
    pg_->Branch(node_, label_set.CatchEnd());

    pg_->SetLabel(node_, label_set.CatchBegin());
    pg_->StoreAccumulator(node_, result_);
    pg_->StoreConst(node_, done_, Constant::JS_TRUE);
    pg_->LoadAccumulator(node_, result_);
    pg_->EmitThrow(node_);
    pg_->SetLabel(node_, label_set.CatchEnd());
}

void DestructuringIterator::OnIterDone([[maybe_unused]] Label *done_target) const
{
    pg_->LoadConst(node_, Constant::JS_UNDEFINED);
}

void DestructuringRestIterator::OnIterDone([[maybe_unused]] Label *done_target) const
{
    pg_->Branch(node_, done_target);
}
}  // namespace panda::es2panda::compiler
