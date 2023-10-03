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

#include "compileQueue.h"

#include "binder/binder.h"
#include "binder/scope.h"
#include "compiler/core/compilerContext.h"
#include "compiler/core/emitter.h"
#include "compiler/core/function.h"
#include "compiler/core/pandagen.h"

namespace panda::es2panda::compiler {
CompileQueue::CompileQueue(size_t thread_count)
{
    threads_.reserve(thread_count);

    for (size_t i = 0; i < thread_count; i++) {
        threads_.push_back(os::thread::ThreadStart(Worker, this));
    }
}

CompileQueue::~CompileQueue()
{
    void *retval = nullptr;

    std::unique_lock<std::mutex> lock(m_);
    terminate_ = true;
    lock.unlock();
    jobs_available_.notify_all();

    for (const auto handle_id : threads_) {
        os::thread::ThreadJoin(handle_id, &retval);
    }
}

void CompileQueue::Schedule(CompilerContext *context)
{
    ASSERT(jobs_count_ == 0);
    std::unique_lock<std::mutex> lock(m_);
    const auto &functions = context->Binder()->Functions();
    jobs_ = new CompileJob[functions.size()]();

    for (auto *function : functions) {
        jobs_[jobs_count_++].SetContext(context, function);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    total_jobs_count_ = jobs_count_;

    lock.unlock();
    jobs_available_.notify_all();
}

void CompileQueue::Worker(CompileQueue *queue)
{
    while (true) {
        std::unique_lock<std::mutex> lock(queue->m_);
        queue->jobs_available_.wait(lock, [queue]() { return queue->terminate_ || queue->jobs_count_ != 0; });

        if (queue->terminate_) {
            return;
        }

        lock.unlock();

        queue->Consume();
        queue->jobs_finished_.notify_one();
    }
}

void CompileQueue::Consume()
{
    std::unique_lock<std::mutex> lock(m_);
    active_workers_++;

    while (jobs_count_ > 0) {
        --jobs_count_;
        auto &job = jobs_[jobs_count_];  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        lock.unlock();

        try {
            job.Run();
        } catch (const Error &e) {
            lock.lock();
            errors_.push_back(e);
            lock.unlock();
        }

        lock.lock();
    }

    active_workers_--;
}

void CompileQueue::Wait(const JobsFinishedCb &on_finished_cb)
{
    std::unique_lock<std::mutex> lock(m_);
    jobs_finished_.wait(lock, [this]() { return active_workers_ == 0 && jobs_count_ == 0; });

    if (!errors_.empty()) {
        delete[] jobs_;
        // NOLINTNEXTLINE
        throw errors_.front();
    }

    for (uint32_t i = 0; i < total_jobs_count_; i++) {
        on_finished_cb(jobs_ + i);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    delete[] jobs_;
}
}  // namespace panda::es2panda::compiler
