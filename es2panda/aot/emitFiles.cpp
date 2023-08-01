/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "emitFiles.h"

#include <assembly-emitter.h>
#include <es2panda.h>
#include <mem/arena_allocator.h>
#include <protobufSnapshotGenerator.h>

namespace panda::es2panda::aot {
void EmitFileQueue::Schedule()
{
    ASSERT(jobsCount_ == 0);
    std::unique_lock<std::mutex> lock(m_);

    if (mergeAbc_) {
        // generate merged abc
        auto emitMergedAbcJob = new EmitMergedAbcJob(options_->CompilerOutput(), progsInfo_);
        for (const auto &info: progsInfo_) {
            // generate cache protoBins and set dependencies
            if (!info.second->needUpdateCache) {
                continue;
            }
            auto outputCacheIter = options_->CompilerOptions().cacheFiles.find(info.first);
            if (outputCacheIter != options_->CompilerOptions().cacheFiles.end()) {
                auto emitProtoJob = new EmitCacheJob(outputCacheIter->second, info.second);
                emitProtoJob->DependsOn(emitMergedAbcJob);
                jobs_.push_back(emitProtoJob);
                jobsCount_++;
            }
        }
        //  One job should be placed after those jobs which depend on it to prevent blocking
        jobs_.push_back(emitMergedAbcJob);
        jobsCount_++;
    } else {
        for (const auto &info: progsInfo_) {
            try {
                // generate multi abcs
                auto outputFileName = options_->OutputFiles().empty() ? options_->CompilerOutput() :
                    options_->OutputFiles().at(info.first);
                auto emitSingleAbcJob = new EmitSingleAbcJob(outputFileName, &(info.second->program), statp_);
                jobs_.push_back(emitSingleAbcJob);
                jobsCount_++;
            } catch (std::exception &error) {
                throw Error(ErrorType::GENERIC, error.what());
            }
        }
    }

    lock.unlock();
    jobsAvailable_.notify_all();
}

void EmitSingleAbcJob::Run()
{
    if (!panda::pandasm::AsmEmitter::Emit(panda::os::file::File::GetExtendedFilePath(outputFileName_), *prog_, statp_,
        nullptr, true)) {
        throw Error(ErrorType::GENERIC, "Failed to emit " + outputFileName_ + ", error: " +
            panda::pandasm::AsmEmitter::GetLastError());
    }
    for (auto *dependant : dependants_) {
        dependant->Signal();
    }
}

void EmitMergedAbcJob::Run()
{
    std::vector<panda::pandasm::Program*> progs;
    progs.reserve(progsInfo_.size());
    for (const auto &info: progsInfo_) {
        progs.push_back(&(info.second->program));
    }
    if (!panda::pandasm::AsmEmitter::EmitPrograms(panda::os::file::File::GetExtendedFilePath(outputFileName_), progs,
        true)) {
        throw Error(ErrorType::GENERIC, "Failed to emit " + outputFileName_ + ", error: " +
            panda::pandasm::AsmEmitter::GetLastError());
    }
    for (auto *dependant : dependants_) {
        dependant->Signal();
    }
}

void EmitCacheJob::Run()
{
    std::unique_lock<std::mutex> lock(m_);
    cond_.wait(lock, [this] { return dependencies_ == 0; });
    panda::proto::ProtobufSnapshotGenerator::UpdateCacheFile(progCache_, outputProtoName_);
}

}  // namespace panda::es2panda::util
