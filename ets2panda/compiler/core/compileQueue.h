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

#ifndef ES2PANDA_COMPILER_CORE_COMPILE_QUEUE_H
#define ES2PANDA_COMPILER_CORE_COMPILE_QUEUE_H

#include "macros.h"
#include "os/thread.h"
#include "es2panda.h"
#include "compiler/core/compileJob.h"

#include <condition_variable>
#include <functional>
#include <mutex>

namespace panda::es2panda::binder {
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::compiler {
class CompilerContext;

class CompileQueue {
public:
    using JobsFinishedCb = std::function<void(CompileJob *)>;

    explicit CompileQueue(size_t thread_count);
    NO_COPY_SEMANTIC(CompileQueue);
    NO_MOVE_SEMANTIC(CompileQueue);
    ~CompileQueue();

    void Schedule(CompilerContext *context);
    void Consume();
    void Wait(const JobsFinishedCb &on_finished_cb);

private:
    static void Worker(CompileQueue *queue);

    std::vector<os::thread::NativeHandleType> threads_;
    std::vector<Error> errors_;
    std::mutex m_;
    std::condition_variable jobs_available_;
    std::condition_variable jobs_finished_;
    CompileJob *jobs_ {};
    size_t jobs_count_ {0};
    size_t total_jobs_count_ {0};
    size_t active_workers_ {0};
    bool terminate_ {};
};
}  // namespace panda::es2panda::compiler

#endif
