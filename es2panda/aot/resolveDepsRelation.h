/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_AOT_DEPEND_RELATION_H
#define ES2PANDA_AOT_DEPEND_RELATION_H
#include <aot/options.h>
#include <es2panda.h>
#include <string>
#include <queue>
#include <util/workerQueue.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace panda::es2panda::aot {

class ResolveDepsRelation {
public:
    explicit ResolveDepsRelation(const std::unique_ptr<panda::es2panda::aot::Options> &options,
                                 const std::map<std::string, panda::es2panda::util::ProgramCache *> &progsInfo,
                                 std::unordered_map<std::string, std::unordered_set<std::string>> *resolveDepsRelation)
        : progsInfo_(progsInfo), resolveDepsRelation_(resolveDepsRelation),
        compileContextInfo_(options->CompilerOptions().compileContextInfo)
    {
    }

    ~ResolveDepsRelation() = default;
    void CollectRecordDepsRelation(std::string recordName, const panda::pandasm::Program *program,
                                   std::string compileEntryKey);
    void CollectRecord(std::string recordName, std::string compileEntryKey);
    std::string TransformRecordName(std::string ohmUrl);
    bool CheckIsHspOHMUrl(std::string ohmUrl);
    bool CheckShouldCollectDepsLiteralValue(std::string literalValue);
    std::string RecordNameForliteralKey(std::string literalKey);

    void Resolve();

private:
    // const std::unique_ptr<panda::es2panda::aot::Options> &options_;
    const std::map<std::string, panda::es2panda::util::ProgramCache *> &progsInfo_;
    std::unordered_map<std::string, std::unordered_set<std::string>> *resolveDepsRelation_;
    CompileContextInfo compileContextInfo_;
    std::queue<std::string> bfsQueue_ {};
};
} // namespace panda::es2panda::aot

#endif

