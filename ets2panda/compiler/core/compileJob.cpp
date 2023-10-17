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

#include "compiler/core/compilerContext.h"

namespace panda::es2panda::compiler {

void CompileJob::Run()
{
    std::unique_lock<std::mutex> lock(m_);
    cond_.wait(lock, [this] { return dependencies_ == 0; });

    context_->GetCodeGenCb()(context_, scope_, &program_element_);

    if (dependant_ != nullptr) {
        dependant_->Signal();
    }
}

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
}  // namespace panda::es2panda::compiler
