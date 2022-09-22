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

#include <aot/options.h>
#include <macros.h>
#include <os/thread.h>
#include <util/symbolTable.h>

#include <condition_variable>
#include <mutex>

namespace panda::es2panda::binder {
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::compiler {

class CompilerContext;

class CompileJob {
public:
    explicit CompileJob() {};
    NO_COPY_SEMANTIC(CompileJob);
    NO_MOVE_SEMANTIC(CompileJob);
    virtual ~CompileJob() = default;

    virtual void Run() = 0;
    void DependsOn(CompileJob *job);
    void Signal();

protected:
    std::mutex m_;
    std::condition_variable cond_;
    CompileJob *dependant_ {};
    size_t dependencies_ {0};
};

class CompileFunctionJob : public CompileJob {
public:
    explicit CompileFunctionJob(CompilerContext *context) : context_(context) {};
    NO_COPY_SEMANTIC(CompileFunctionJob);
    NO_MOVE_SEMANTIC(CompileFunctionJob);
    ~CompileFunctionJob() override = default;

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
    CompilerContext *context_ {};
    binder::FunctionScope *scope_ {};
};

class CompileModuleRecordJob : public CompileJob {
public:
    explicit CompileModuleRecordJob(CompilerContext *context) : context_(context) {};
    NO_COPY_SEMANTIC(CompileModuleRecordJob);
    NO_MOVE_SEMANTIC(CompileModuleRecordJob);
    ~CompileModuleRecordJob() override = default;

    void Run() override;

private:
    CompilerContext *context_ {};
};

class CompileFileJob : public CompileJob {
public:
    explicit CompileFileJob(es2panda::SourceFile *src, es2panda::CompilerOptions *options,
                            std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
                            util::SymbolTable *symbolTable, panda::ArenaAllocator *allocator)
        : src_(src), options_(options), progsInfo_(progsInfo), symbolTable_(symbolTable), allocator_(allocator) {};
    NO_COPY_SEMANTIC(CompileFileJob);
    NO_MOVE_SEMANTIC(CompileFileJob);
    ~CompileFileJob() override = default;

    void Run() override;

private:
    static std::mutex global_m_;
    es2panda::SourceFile *src_;
    es2panda::CompilerOptions *options_;
    std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo_;
    util::SymbolTable *symbolTable_;
    panda::ArenaAllocator *allocator_;
};

class CompileQueue {
public:
    explicit CompileQueue(size_t threadCount);
    NO_COPY_SEMANTIC(CompileQueue);
    NO_MOVE_SEMANTIC(CompileQueue);
    virtual ~CompileQueue();

    virtual void Schedule() = 0;
    void Consume();
    void Wait();

protected:
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

class CompileFuncQueue : public CompileQueue {
public:
    explicit CompileFuncQueue(size_t threadCount, CompilerContext *context)
        : CompileQueue(threadCount), context_(context) {}

    NO_COPY_SEMANTIC(CompileFuncQueue);
    NO_MOVE_SEMANTIC(CompileFuncQueue);
    ~CompileFuncQueue() override = default;

    void Schedule() override;

private:
    CompilerContext *context_;
};

class CompileFileQueue : public CompileQueue {
public:
    explicit CompileFileQueue(size_t threadCount, es2panda::CompilerOptions *options,
                              std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
                              util::SymbolTable *symbolTable, panda::ArenaAllocator *allocator)
        : CompileQueue(threadCount), options_(options), progsInfo_(progsInfo),
        symbolTable_(symbolTable), allocator_(allocator) {}

    NO_COPY_SEMANTIC(CompileFileQueue);
    NO_MOVE_SEMANTIC(CompileFileQueue);
    ~CompileFileQueue() override = default;

    void Schedule() override;

private:
    es2panda::CompilerOptions *options_;
    std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo_;
    util::SymbolTable *symbolTable_;
    panda::ArenaAllocator *allocator_;
};

}  // namespace panda::es2panda::compiler

#endif
