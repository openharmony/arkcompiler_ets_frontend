/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.Apache.Org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "moduleHelpers.h"

#include <libpandabase/utils/hash.h>

namespace panda::es2panda::util {
void ModuleHelpers::CompileNpmModuleEntryList(const std::string &entriesInfo,
    std::map<std::string, panda::es2panda::util::ProgramCache*> *cacheProgs,
    std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
    panda::ArenaAllocator *allocator)
{
    std::stringstream ss;
    std::ifstream inputStream(entriesInfo);
    if (inputStream.fail()) {
        std::cerr << "Failed to read file to buffer: " << entriesInfo << std::endl;
        return;
    }
    ss << inputStream.rdbuf();

    uint32_t hash = GetHash32String(reinterpret_cast<const uint8_t *>(ss.str().c_str()));

    if (cacheProgs != nullptr) {
        auto it = cacheProgs->find(entriesInfo);
        if (it != cacheProgs->end() && hash == it->second->hashCode) {
            auto *cache = allocator->New<util::ProgramCache>(it->second->hashCode, it->second->program);
            progsInfo.insert({entriesInfo, cache});
            return;
        }
    }

    auto *prog = allocator->New<panda::pandasm::Program>();
    std::string line;
    while (getline(ss, line)) {
        std::size_t pos = line.find(":");
        std::string recordName = line.substr(0, pos);
        std::string field = line.substr(pos + 1);

        auto langExt = panda::pandasm::extensions::Language::ECMASCRIPT;
        auto entryNameField = panda::pandasm::Field(langExt);
        entryNameField.name = field;
        entryNameField.type = panda::pandasm::Type("u8", 0);
        entryNameField.metadata->SetValue(panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U8>(
            static_cast<bool>(0)));

        panda::pandasm::Record *entryRecord = new panda::pandasm::Record(recordName, langExt);
        entryRecord->field_list.emplace_back(std::move(entryNameField));
        prog->record_table.emplace(recordName, std::move(*entryRecord));
    }

    auto *cache = allocator->New<util::ProgramCache>(hash, prog);
    progsInfo.insert({entriesInfo, cache});
}
}  // namespace panda::es2panda::util
