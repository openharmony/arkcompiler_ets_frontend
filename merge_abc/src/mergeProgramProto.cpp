/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mergeProgramProto.h"
#include "protobufSnapshotGenerator.h"
#include "arena_allocator.h"
#include "mergeOptions.h"
#include "assembler/assembly-function.h"
#include "libpandafile/literal_data_accessor.h"
#include <assembly-emitter.h>

#include <filesystem>
#include <mem/pool_manager.h>

namespace panda::proto {

using mem::MemConfig;

class ProtoMemManager {
public:
    explicit ProtoMemManager()
    {
        constexpr auto COMPILER_SIZE = 512_MB;

        MemConfig::Initialize(0, 0, COMPILER_SIZE, 0);
        PoolManager::Initialize(PoolType::MMAP);
    }

    NO_COPY_SEMANTIC(ProtoMemManager);
    NO_MOVE_SEMANTIC(ProtoMemManager);

    ~ProtoMemManager()
    {
        PoolManager::Finalize();
        MemConfig::Finalize();
    }
};

int TraverseProtoBinPath(const std::string &protoBinPath, const std::string &protoBinSuffix, MergeProgram *mergeProgram,
                         std::unique_ptr<panda::ArenaAllocator> &&allocator)
{
    panda::pandasm::Program program;

    const std::filesystem::path fsPath(protoBinPath);
    if (!std::filesystem::exists(fsPath)) {
        return 1;
    }
    for (auto &itr : std::filesystem::directory_iterator(fsPath)) {
        if (std::filesystem::is_directory(itr.status())) {
            if (TraverseProtoBinPath(itr.path().string(), protoBinSuffix, mergeProgram, std::move(allocator)) != 0) {
                return 1;
            }
        } else {
            auto fileName = itr.path().string();
            std::string suffixStr = fileName.substr(fileName.find_last_of(".") + 1);
            if (suffixStr.compare(protoBinSuffix) == 0) {
                proto::ProtobufSnapshotGenerator::GenerateProgram(fileName, program, std::move(allocator));
                mergeProgram->Merge(&program);
            }
        }
    }
    return 0;
}

void MergeProgram::Merge(panda::pandasm::Program *src) {
    CorrectLiteraArrayId(src);

    bool hasTypeAnnoRecord = false;
    for (auto &iter : src->record_table) {
        auto &name = iter.first;
        bool isTypeAnnoRecord = name == std::string(TYPE_ANNOTATION_RECORD.data());
        if (hasTypeAnnoRecord && isTypeAnnoRecord) {
            continue;
        }
        ASSERT(prog_->record_table.find(name) == prog_->record_table.end());
        prog_->record_table.insert(std::move(iter));
        hasTypeAnnoRecord = hasTypeAnnoRecord || isTypeAnnoRecord;
    }

    for (auto &[name, func] : src->function_table) {
        ASSERT(prog_->function_table.find(name) == prog_->function_table.end());
        prog_->function_table.emplace(name, std::move(func));
    }

    ASSERT(src->function_synonyms.empty());

    const auto base = prog_->literalarray_table.size();
    size_t count = 0;
    for (auto &[id, litArray] : src->literalarray_table) {
        prog_->literalarray_table.emplace(std::to_string(base + count), std::move(litArray));
        count++;
    }

    for (const auto &str : src->strings) {
        prog_->strings.insert(str);
    }

    for (const auto &type: src->array_types) {
        prog_->array_types.insert(type);
    }
}

void MergeProgram::CorrectLiteraArrayId(panda::pandasm::Program *src)
{
    const auto base = prog_->literalarray_table.size();

    for (auto &[name, litArray] : src->literalarray_table) {
        for (auto &lit : litArray.literals_) {
            if (lit.tag_ == panda_file::LiteralTag::TYPEINDEX) {
                lit.value_ = std::get<uint32_t>(lit.value_) + base;
            }
        }
    }

    for (auto &[name, func] : src->function_table) {
        for (auto &insn : func.ins) {
            IncreaseInsLiteralArrayIdByBase(insn, base);
        }
    }

    for (auto &[name, record] : src->record_table) {
        for (auto &field : record.field_list) {
            if (field.type.GetId() != panda_file::Type::TypeId::U32) {
                continue;
            }
            auto addedVal = static_cast<uint32_t>(base) + field.metadata->GetValue().value().GetValue<uint32_t>();
            field.metadata->SetValue(panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U32>(addedVal));
        }
    }
}

// TODO: let it be auto-generated after isa-refactoring
void MergeProgram::IncreaseInsLiteralArrayIdByBase(panda::pandasm::Ins &insn, size_t base)
{
    switch (insn.opcode) {
        case panda::pandasm::Opcode::ECMA_CREATEARRAYWITHBUFFER:
        case panda::pandasm::Opcode::ECMA_CREATEOBJECTWITHBUFFER:
        case panda::pandasm::Opcode::ECMA_CREATEOBJECTHAVINGMETHOD:
        case panda::pandasm::Opcode::ECMA_DEFINECLASSWITHBUFFER:
            insn.imms[0] = std::get<int64_t>(insn.imms[0]) + static_cast<int64_t>(base);
            return;
        case panda::pandasm::Opcode::ECMA_NEWLEXENVWITHNAMEDYN:
            insn.imms[1] = std::get<int64_t>(insn.imms[1]) + static_cast<int64_t>(base);
            return;
        default:
            return;
    }
}

int Run(int argc, const char **argv)
{
    auto options = std::make_unique<Options>();
    if (!options->Parse(argc, argv)) {
        std::cerr << options->ErrorMsg() << std::endl;
        return 1;
    }

    std::string protoBinPath = options->protoBinPath();
    std::string protoBinSuffix = options->protoBinSuffix();

    std::unique_ptr<panda::ArenaAllocator> allocator = std::make_unique<panda::ArenaAllocator>(
        panda::SpaceType::SPACE_TYPE_COMPILER, nullptr, true);

    panda::pandasm::Program program;
    MergeProgram mergeProgram(&program);
    if (panda::proto::TraverseProtoBinPath(protoBinPath, protoBinSuffix, &mergeProgram, std::move(allocator))) {
        return 1;
    }

    std::map<std::string, size_t> stat;
    std::map<std::string, size_t> *statp = nullptr;
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps maps {};
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps *mapsp = nullptr;

    std::string outputPandaFile = options->outputPandaFile();
    outputPandaFile = std::filesystem::path(protoBinPath).append(outputPandaFile);
    if (!panda::pandasm::AsmEmitter::Emit(outputPandaFile, *(mergeProgram.GetResult()), statp, mapsp, true)) {
        return 1;
    }

    return 0;
}
}

int main(int argc, const char **argv)
{
    panda::proto::ProtoMemManager mm;
    return panda::proto::Run(argc, argv);
}
