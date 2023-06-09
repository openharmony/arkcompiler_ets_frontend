/*
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

#include "typeExtractorEmitter.h"

#include <assembly-emitter.h>
#include <binder/binder.h>
#include <compiler/core/compilerContext.h>
#include <compiler/core/emitter/emitter.h>

namespace panda::es2panda::compiler {

using AnnotationElement = panda::pandasm::AnnotationElement;
using ArrayValue = panda::pandasm::ArrayValue;
using Field = panda::pandasm::Field;
using Record = panda::pandasm::Record;
using ScalarValue = panda::pandasm::ScalarValue;
using Type = panda::pandasm::Type;
using ValueType = panda::pandasm::Value::Type;

TypeExtractorEmitter::TypeExtractorEmitter(const PandaGen *pg, panda::pandasm::Function *func) : pg_(pg), func_(func)
{
    auto prog = pg_->Context()->GetEmitter()->GetProgram();
    GenFunctionTypeInfo(prog);
    if (IsFuncMain0(func->name, pg_->Context()->IsMergeAbc())) {
        if (pg_->Context()->TypeRecorder()->ExportType().size() > 0U) {
            GenExportTypeInfo(prog);
        }
        if (pg_->Context()->TypeRecorder()->DeclareType().size() > 0U) {
            GenDeclareTypeInfo(prog);
        }
    }
}

bool TypeExtractorEmitter::IsFuncMain0(const std::string &funcName, bool isMergeAbc) const
{
    std::string expectedName(binder::Binder::MAIN_FUNC_NAME);
    if (isMergeAbc) {
        expectedName = std::string(pg_->Context()->RecordName()) + "." + expectedName;
    }
    return funcName == expectedName;
}

static void GenTypeInfo(const extractor::TypeRecorder *recorder, int64_t typeIndex, std::vector<Literal> &typeInfo)
{
    Literal typeTag;
    Literal typeValue;
    typeTag.tag_ = panda::panda_file::LiteralTag::TAGVALUE;
    if (typeIndex >= recorder->GetUserTypeIndexShift()) {
        typeTag.value_ = static_cast<uint8_t>(panda::panda_file::LiteralTag::LITERALARRAY);
        typeValue.tag_ = panda::panda_file::LiteralTag::LITERALARRAY;
        typeValue.value_ = std::string(recorder->GetRecordName()) + "_" +
            std::to_string(typeIndex - recorder->GetUserTypeIndexShift());
    } else {
        typeTag.value_ = static_cast<uint8_t>(panda::panda_file::LiteralTag::BUILTINTYPEINDEX);
        typeValue.tag_ = panda::panda_file::LiteralTag::BUILTINTYPEINDEX;
        typeValue.value_ = static_cast<uint8_t>(typeIndex);
    }
    typeInfo.emplace_back(typeTag);
    typeInfo.emplace_back(typeValue);
}

static void GenInsnTypeInfo(const extractor::TypeRecorder *recorder, uint32_t orderIndex, int64_t typeIndex,
    std::vector<Literal> &typedInsns)
{
    Literal insnOrderTag;
    Literal insnOrderValue;
    insnOrderTag.tag_ = panda::panda_file::LiteralTag::TAGVALUE;
    insnOrderTag.value_ = static_cast<uint8_t>(panda::panda_file::LiteralTag::INTEGER);
    insnOrderValue.tag_ = panda::panda_file::LiteralTag::INTEGER;
    insnOrderValue.value_ = static_cast<uint32_t>(orderIndex);
    typedInsns.emplace_back(insnOrderTag);
    typedInsns.emplace_back(insnOrderValue);

    GenTypeInfo(recorder, typeIndex, typedInsns);
}

void TypeExtractorEmitter::GenFunctionTypeInfo(panda::pandasm::Program *prog)
{
    auto recorder = pg_->Context()->TypeRecorder();
    std::vector<Literal> typedInsns;
    typedInsns.reserve(pg_->TypedInsns().size() * 4U);  // Expand to 4 pieces of information
    uint32_t index = 0;
    uint32_t remove = 0;
    for (const auto *ins : pg_->Insns()) {
        if (func_->ins[index].opcode == panda::pandasm::Opcode::INVALID) {
            remove++;
            index++;
            continue;
        }
        auto t = pg_->TypedInsns().find(ins);
        if (t != pg_->TypedInsns().end()) {
            int64_t typeIndex = t->second;
            uint32_t orderIndex = index;
            if (typeIndex > extractor::TypeRecorder::PRIMITIVETYPE_ANY) {
                uint32_t realOrderIndex = orderIndex - remove;
                GenInsnTypeInfo(recorder, realOrderIndex, typeIndex, typedInsns);
                DCOUT << "[LOG] " << func_->name << ": " << func_->ins[index].ToString("", true, func_->regs_num) <<
                    " | " << realOrderIndex << " | " << typeIndex << std::endl;
            }
        }
        index++;
    }

    if (pg_->TypedFunc().first != extractor::TypeRecorder::PRIMITIVETYPE_ANY) {
        // -1 for function type
        GenInsnTypeInfo(recorder, static_cast<uint32_t>(-1), pg_->TypedFunc().first, typedInsns);
        DCOUT << "[LOG]" << func_->name << ": -1 | " << pg_->TypedFunc().first << std::endl;
    }
    if (pg_->TypedFunc().second > extractor::TypeRecorder::PRIMITIVETYPE_ANY) {
        // -2 for method 'this' type
        GenInsnTypeInfo(recorder, static_cast<uint32_t>(-2), pg_->TypedFunc().second, typedInsns);
        DCOUT << "[LOG]" << func_->name << ": -2 | " << pg_->TypedFunc().second << std::endl;
    }

    if (typedInsns.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(pg_->Context()->GetEmitter()->GetEmitterLock());
    std::string literalId = std::string(recorder->GetRecordName()) + "_" +
        func_->name + "_" + std::to_string(literalId_--);
    auto literalArrayInstance = panda::pandasm::LiteralArray(std::move(typedInsns));
    prog->literalarray_table.emplace(literalId, std::move(literalArrayInstance));

    AnnotationData funcTypeAnnotation(TypeExtractorEmitter::TYPE_ANNOTATION);
    AnnotationElement funcTypeAnnotationElement(TypeExtractorEmitter::TYPE_INSTRUCTION,
        std::make_unique<ScalarValue>(ScalarValue::Create<ValueType::LITERALARRAY>(literalId)));
    funcTypeAnnotation.AddElement(std::move(funcTypeAnnotationElement));
    func_->metadata->AddAnnotations({ funcTypeAnnotation });
}

template <bool isExport, typename M>
void TypeExtractorEmitter::GenImportOrDeclareTypeInfo(panda::pandasm::Program *prog,
    const extractor::TypeRecorder *recorder, const M &map, AnnotationData &funcTypeAnnotation)
{
    std::string symbolTypeStr;
    if constexpr (isExport) {
        symbolTypeStr = TypeExtractorEmitter::EXPORTED_SYMBOL_TYPES;
    } else {
        symbolTypeStr = TypeExtractorEmitter::DECLARED_SYMBOL_TYPES;
    }

    std::vector<Literal> typedSymbols;
    typedSymbols.reserve(map.size() * 4U);  // Expand to 4 pieces of information
    for (const auto &t : map) {
        Literal symbolTag;
        Literal symbolValue;
        symbolTag.tag_ = panda::panda_file::LiteralTag::TAGVALUE;
        symbolTag.value_ = static_cast<uint8_t>(panda::panda_file::LiteralTag::STRING);
        symbolValue.tag_ = panda::panda_file::LiteralTag::STRING;
        symbolValue.value_ = t.first;
        typedSymbols.emplace_back(symbolTag);
        typedSymbols.emplace_back(symbolValue);

        GenTypeInfo(recorder, t.second, typedSymbols);
    }

    std::lock_guard<std::mutex> lock(pg_->Context()->GetEmitter()->GetEmitterLock());
    std::string literalId = std::string(recorder->GetRecordName()) + "_" +
        func_->name + "_" + std::to_string(literalId_--);
    auto literalArrayInstance = panda::pandasm::LiteralArray(std::move(typedSymbols));
    prog->literalarray_table.emplace(literalId, std::move(literalArrayInstance));

    AnnotationElement funcSymbolTypeElement(symbolTypeStr,
        std::make_unique<ScalarValue>(ScalarValue::Create<ValueType::LITERALARRAY>(literalId)));
    funcTypeAnnotation.AddElement(std::move(funcSymbolTypeElement));
}

void TypeExtractorEmitter::GenExportTypeInfo(panda::pandasm::Program *prog)
{
    AnnotationData funcTypeAnnotation(TypeExtractorEmitter::TYPE_ANNOTATION);
    GenImportOrDeclareTypeInfo<true>(prog, pg_->Context()->TypeRecorder(),
        pg_->Context()->TypeRecorder()->ExportType(), funcTypeAnnotation);
    func_->metadata->AddAnnotations({ funcTypeAnnotation });
}

void TypeExtractorEmitter::GenDeclareTypeInfo(panda::pandasm::Program *prog)
{
    AnnotationData funcTypeAnnotation(TypeExtractorEmitter::TYPE_ANNOTATION);
    GenImportOrDeclareTypeInfo<false>(prog, pg_->Context()->TypeRecorder(),
        pg_->Context()->TypeRecorder()->DeclareType(), funcTypeAnnotation);
    func_->metadata->AddAnnotations({ funcTypeAnnotation });
}

static void GenTypeSummaryInfo(bool typeFlag, int64_t typeSummaryIndex, const std::string &recordName, Record &record)
{
    constexpr const auto LANG_EXT = panda::pandasm::extensions::Language::ECMASCRIPT;

    auto typeFlagField = Field(LANG_EXT);
    typeFlagField.name = TypeExtractorEmitter::TYPE_FLAG;
    typeFlagField.type = Type("u8", 0);
    typeFlagField.metadata->SetValue(ScalarValue::Create<ValueType::U8>(static_cast<uint8_t>(typeFlag)));
    record.field_list.emplace_back(std::move(typeFlagField));

    if (typeFlag) {
        auto typeSummaryIndexField = Field(LANG_EXT);
        typeSummaryIndexField.name = TypeExtractorEmitter::TYPE_SUMMARY;
        typeSummaryIndexField.type = Type("u32", 0);
        typeSummaryIndexField.metadata->SetValue(ScalarValue::Create<ValueType::LITERALARRAY>(
            "" + recordName + "_" + std::to_string(typeSummaryIndex)));
        record.field_list.emplace_back(std::move(typeSummaryIndexField));
    }
}

// static
void TypeExtractorEmitter::GenTypeInfoRecord(panda::pandasm::Program *prog, bool typeFlag,
    int64_t typeSummaryIndex, const std::string &recordName)
{
    auto iter = prog->record_table.find(TypeExtractorEmitter::TYPE_INFO_RECORD);
    ASSERT(iter != prog->record_table.end());
    GenTypeSummaryInfo(typeFlag, typeSummaryIndex, recordName, iter->second);
}

void TypeExtractorEmitter::GenTypeInfoRecordForMergeABC(panda::pandasm::Program *prog, bool typeFlag,
    int64_t typeSummaryIndex, const std::string &recordName)
{
    auto iter = prog->record_table.find(recordName);
    ASSERT(iter != prog->record_table.end());
    GenTypeSummaryInfo(typeFlag, typeSummaryIndex, recordName, iter->second);
}

void TypeExtractorEmitter::GenTypeLiteralBuffers(panda::pandasm::Program *prog,
                                                 const extractor::TypeRecorder *recorder)
{
    ArenaVector<std::pair<int32_t, std::vector<Literal>>> literalBuffers(recorder->Allocator()->Adapter());
    for (const auto *buff : recorder->BuffStorage()) {
        Emitter::GenBufferLiterals(literalBuffers, buff);
    }

    for (auto &[idx, buf] : literalBuffers) {
        std::string literalId = std::string(recorder->GetRecordName()) + "_" + std::to_string(idx);
        auto literalArrayInstance = panda::pandasm::LiteralArray(std::move(buf));
        prog->literalarray_table.emplace(literalId, std::move(literalArrayInstance));
    }
}

}  // namespace panda::es2panda::compiler
