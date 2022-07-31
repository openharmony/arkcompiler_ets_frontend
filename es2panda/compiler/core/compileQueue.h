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

#ifndef ES2PANDA_COMPILER_CORE_COMPILEQUEUE_H
#define ES2PANDA_COMPILER_CORE_COMPILEQUEUE_H

#include <macros.h>
#include <os/thread.h>
#include <es2panda.h>

#include <condition_variable>
#include <mutex>

namespace panda::es2panda::binder {
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::compiler {

class CompilerContext;

class CompileJob {
public:
    explicit CompileJob(CompilerContext *context) : context_(context) {};
    NO_COPY_SEMANTIC(CompileJob);
    NO_MOVE_SEMANTIC(CompileJob);
    virtual ~CompileJob() = default;

    virtual void Run() = 0;
    void DependsOn(CompileJob *job);
    void Signal();

protected:
    [[maybe_unused]] CompilerContext *context_ {};
    std::mutex m_;
    std::condition_variable cond_;
    CompileJob *dependant_ {};
    size_t dependencies_ {0};
};

class CompileFunctionJob : public CompileJob {
public:
    explicit CompileFunctionJob(CompilerContext *context) : CompileJob(context) {};
    NO_COPY_SEMANTIC(CompileFunctionJob);
    NO_MOVE_SEMANTIC(CompileFunctionJob);
    ~CompileFunctionJob() = default;

    binder::FunctionScope *Scope() const
    {
        return scope_;
    }

    void SetFunctionScope(binder::FunctionScope *scope)
    {
        scope_ = scope;
    }

    void Run() override;
private:
    binder::FunctionScope *scope_ {};
};

class CompileModuleRecordJob : public CompileJob {
public:
    explicit CompileModuleRecordJob(CompilerContext *context) : CompileJob(context) {};
    NO_COPY_SEMANTIC(CompileModuleRecordJob);
    NO_MOVE_SEMANTIC(CompileModuleRecordJob);
    ~CompileModuleRecordJob() = default;

    void Run() override;
};

class CompileQueue {
public:
    explicit CompileQueue(size_t threadCount);
    NO_COPY_SEMANTIC(CompileQueue);
    NO_MOVE_SEMANTIC(CompileQueue);
    ~CompileQueue();

    void Schedule(CompilerContext *context);
    void Consume();
    void Wait();

private:
    static void Worker(CompileQueue *queue);

    std::vector<os::thread::native_handle_type> threads_;
    std::vector<Error> errors_;
    std::mutex m_;
    std::condition_variable jobsAvailable_;
    std::condition_variable jobsFinished_;
    std::vector<CompileJob *> jobs_ {};
    size_t jobsCount_ {0};
    size_t activeWorkers_ {0};
    bool terminate_ {false};
};

}  // namespace panda::es2panda::compiler

#endif
