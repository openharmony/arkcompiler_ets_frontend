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

#include "resolveDepsRelation.h"

namespace panda::es2panda::aot {

void ResolveDepsRelation::Resolve()
{
    for (auto recordName : compileContextInfo_.compileEntries) {
        for (auto &[key, value] : progsInfo_) {
            for (auto &[recordKey, record] : value->program.record_table) {
                if (recordKey == recordName) {
                    if (resolveDepsRelation_->find(key) == resolveDepsRelation_->end()) {
                        std::unordered_set<std::string> depsSet{};
                        resolveDepsRelation_->insert(std::pair<std::string, std::unordered_set<std::string>>(key, depsSet));
                    }
                    CollectRecord(recordName, key);
                    break;
                }
            }
        }
        // try {
        //     CollectRecordKey(recordName);
        // } catch (std::exception &error) {
        //     throw Error(ErrorType::GENERIC, error.what());
        // }
    }
}

std::string ResolveDepsRelation::RecordNameForliteralKey(std::string literalKey)
{
    size_t pos = literalKey.rfind('_');
    if (pos != std::string::npos) {
        return literalKey.substr(0, pos);
    } else {
        std::cerr << "The literalKey format is error!" << std::endl;
    }
    return literalKey;
}


bool ResolveDepsRelation::CheckIsHspOHMUrl(std::string ohmUrl)
{
    size_t prev = 0;
    constexpr int pos = 3;
    for (int i = 0; i < pos; i++) {
        prev = ohmUrl.find('&', prev) + 1;
    }
    size_t behindPos = ohmUrl.find('&', prev);
    std::string normalizedPath =  ohmUrl.substr(prev, behindPos);
    
    size_t slashPos = normalizedPath.find('/', 0);
    if (normalizedPath[0] == '@') {
        slashPos = normalizedPath.find('/', slashPos + 1);
    }
    std::string pkgName =  normalizedPath.substr(0, slashPos);
    auto it = std::find(compileContextInfo_.hspPkgNames.begin(), compileContextInfo_.hspPkgNames.end(), pkgName);
    return it != compileContextInfo_.hspPkgNames.end();
}

bool ResolveDepsRelation::CheckShouldCollectDepsLiteralValue(std::string literalValue)
{
    const std::string normalizedPrefix = "@normalized:N";
    if (literalValue.substr(0, normalizedPrefix.length()) == normalizedPrefix &&
        !CheckIsHspOHMUrl(literalValue)) {
        return true;
    }
    return false;
}

std::string ResolveDepsRelation::TransformRecordName(std::string ohmUrl)
{
    size_t prev = 0;
    constexpr int pos = 2;
    for (int i = 0; i < pos; i++) {
        prev = ohmUrl.find('&', prev) + 1;
    }
    return ohmUrl.substr(prev, ohmUrl.length());
}

void ResolveDepsRelation::CollectRecord(std::string recordName, std::string compileEntryKey) {
    for (auto &[key, value] : progsInfo_) {
        for (auto &[recordKey, record] : value->program.record_table) {
            if (recordKey == recordName) {
                CollectRecordDepsRelation(recordName, &value->program, compileEntryKey);
                break;
            }
        }
    }
}

void ResolveDepsRelation::CollectRecordDepsRelation(std::string recordName, const panda::pandasm::Program *program,
                                                    std::string compileEntryKey)
{
    // resolve static deps
    for (auto &literalarrayPair : program->literalarray_table) {
        std::cout << "literalarrayKey:" << literalarrayPair.first << std::endl;
        std::string literalKeyRecord = RecordNameForliteralKey(literalarrayPair.first);
        if (literalKeyRecord != recordName) {
            continue;
        }
        for (auto& literal : literalarrayPair.second.literals_) {
            std::visit([this, &compileEntryKey](auto&& element) {
                std::cout<< "literalValue:" << element <<std::endl;
                if constexpr (std::is_same_v<std::decay_t<decltype(element)>, std::string>) {
                    if (this->CheckShouldCollectDepsLiteralValue(element)) {
                        auto recordSet = this->resolveDepsRelation_->find(compileEntryKey);
                        auto collectRecord = this->TransformRecordName(element);
                        std::cout << "collectRecord:" << collectRecord << std::endl;
                        if (std::find(recordSet->second.begin(), recordSet->second.end(), collectRecord) ==
                            recordSet->second.end()) {
                            recordSet->second.insert(collectRecord);
                            this->bfsQueue_.push(collectRecord);
                        }
                    }
                }
            }, literal.value_);
        }
    }
    // dynamic collection


    while (!bfsQueue_.empty()) {
        std::string targetRecord = bfsQueue_.front();
        bfsQueue_.pop();
        CollectRecord(targetRecord, compileEntryKey);
    }
}

}
