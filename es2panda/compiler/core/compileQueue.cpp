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

#include "compileQueue.h"

#include <binder/binder.h>
#include <binder/scope.h>
#include <compiler/core/compilerContext.h>
#include <compiler/core/emitter/emitter.h>
#include <compiler/core/function.h>
#include <compiler/core/pandagen.h>
#include <es2panda.h>
#include <mem/arena_allocator.h>
#include <mem/pool_manager.h>
#include <util/dumper.h>
#include <util/helpers.h>

#include <fstream>
#include <iostream>
#include <dirent.h>

#include <chrono>

#include <assembly-literals.h>
#include <es2panda.h>
#include <mem/arena_allocator.h>
#include <mem/pool_manager.h>
#include <util/dumper.h>

#include <fstream>
#include <iostream>
#include <dirent.h>

#include <chrono>

namespace panda::es2panda::compiler {

std::mutex CompileFileJob::global_m_;

void CompileJob::DependsOn(CompileJob *job)
{
    job->dependant_ = this;
    dependencies_++;
}

void CompileJob::Signal()
{
    {
        std::lock_guard<std::mutex> lock(m_);
        dependencies_--;
    }

    cond_.notify_one();
}

void CompileFunctionJob::Run()
{
    std::unique_lock<std::mutex> lock(m_);
    cond_.wait(lock, [this] { return dependencies_ == 0; });

    ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    PandaGen pg(&allocator, context_, scope_);

    Function::Compile(&pg);

    FunctionEmitter funcEmitter(&allocator, &pg);
    funcEmitter.Generate(context_->HotfixHelper());

    context_->GetEmitter()->AddFunction(&funcEmitter);

    if (dependant_) {
        dependant_->Signal();
    }
}

void CompileModuleRecordJob::Run()
{
    std::unique_lock<std::mutex> lock(m_);
    cond_.wait(lock, [this] { return dependencies_ == 0; });

    ModuleRecordEmitter moduleEmitter(context_->Binder()->Program()->ModuleRecord(), context_->NewLiteralIndex());
    moduleEmitter.Generate();

    context_->GetEmitter()->AddSourceTextModuleRecord(&moduleEmitter, context_);

    if (dependant_) {
        dependant_->Signal();
    }
}

void CompileFileJob::Run()
{
    es2panda::Compiler compiler(options_->extension, options_->functionThreadCount);

    auto *prog = compiler.CompileFile(*options_, src_, symbolTable_);

    if (prog == nullptr) {
        return;
    }

    if (prog == nullptr) {
        return;
    }

    if (options_->optLevel != 0) {
        util::Helpers::OptimizeProgram(prog, options_);
    }

    {
        std::unique_lock<std::mutex> lock(global_m_);
        auto *cache = allocator_->New<util::ProgramCache>(src_->hash, prog);
        progsInfo_.insert({src_->fileName, cache});
    }
}

CompileQueue::CompileQueue(size_t threadCount)
{
    threads_.reserve(threadCount);

    for (size_t i = 0; i < threadCount; i++) {
        threads_.push_back(os::thread::ThreadStart(Worker, this));
    }
}

CompileQueue::~CompileQueue()
{
    void *retval = nullptr;

    std::unique_lock<std::mutex> lock(m_);
    terminate_ = true;
    lock.unlock();
    jobsAvailable_.notify_all();

    for (const auto handle_id : threads_) {
        os::thread::ThreadJoin(handle_id, &retval);
    }
}

void CompileQueue::Worker(CompileQueue *queue)
{
    while (true) {
        std::unique_lock<std::mutex> lock(queue->m_);
        queue->jobsAvailable_.wait(lock, [queue]() { return queue->terminate_ || queue->jobsCount_ != 0; });

        if (queue->terminate_) {
            return;
        }

        lock.unlock();

        queue->Consume();
        queue->jobsFinished_.notify_one();
    }
}

void CompileQueue::Consume()
{
    std::unique_lock<std::mutex> lock(m_);
    activeWorkers_++;

    while (jobsCount_ > 0) {
        --jobsCount_;
        auto &job = *(jobs_[jobsCount_]);

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

    activeWorkers_--;
}

void CompileQueue::Wait()
{
    std::unique_lock<std::mutex> lock(m_);
    jobsFinished_.wait(lock, [this]() { return activeWorkers_ == 0 && jobsCount_ == 0; });
    for (auto it = jobs_.begin(); it != jobs_.end(); it++) {
        if (*it != nullptr) {
            delete *it;
            *it =nullptr;
        }
    }
    jobs_.clear();

    if (!errors_.empty()) {
        // NOLINTNEXTLINE
        throw errors_.front();
    }
}

void CompileFuncQueue::Schedule()
{
    ASSERT(jobsCount_ == 0);
    std::unique_lock<std::mutex> lock(m_);
    const auto &functions = context_->Binder()->Functions();

    for (auto *function : functions) {
        auto *funcJob = new CompileFunctionJob(context_);
        funcJob->SetFunctionScope(function);
        jobs_.push_back(funcJob);
        jobsCount_++;
    }

    if (context_->Binder()->Program()->Kind() == parser::ScriptKind::MODULE) {
        auto *moduleRecordJob = new CompileModuleRecordJob(context_);
        jobs_.push_back(moduleRecordJob);
        jobsCount_++;
    }

    lock.unlock();
    jobsAvailable_.notify_all();
}

void CompileFileQueue::Schedule()
{
    ASSERT(jobsCount_ == 0);
    std::unique_lock<std::mutex> lock(m_);

    for (auto &input: options_->sourceFiles) {
        auto *fileJob = new CompileFileJob(&input, options_, progsInfo_, symbolTable_, allocator_);
        jobs_.push_back(fileJob);
        jobsCount_++;
    }

    lock.unlock();
    jobsAvailable_.notify_all();
}

}  // namespace panda::es2panda::compiler
