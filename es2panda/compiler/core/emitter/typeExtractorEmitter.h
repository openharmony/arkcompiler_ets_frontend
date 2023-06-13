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

#ifndef ES2PANDA_COMPILER_CORE_EMITTER_TYPEEXTRACTOR_EMITTER_H
#define ES2PANDA_COMPILER_CORE_EMITTER_TYPEEXTRACTOR_EMITTER_H

#include <macros.h>

#include <assembly-function.h>
#include <assembly-program.h>

#include <compiler/core/pandagen.h>
#include <typescript/extractor/typeRecorder.h>

namespace panda::es2panda::compiler {

using AnnotationData = panda::pandasm::AnnotationData;

class TypeExtractorEmitter {
public:
    explicit TypeExtractorEmitter(const PandaGen *pg, panda::pandasm::Function *func);
    ~TypeExtractorEmitter() = default;
    NO_COPY_SEMANTIC(TypeExtractorEmitter);
    NO_MOVE_SEMANTIC(TypeExtractorEmitter);

    static void GenTypeInfoRecord(panda::pandasm::Program *prog, bool typeFlag, int64_t typeSummaryIndex,
        const std::string &recordName);
    static void GenTypeInfoRecordForMergeABC(panda::pandasm::Program *prog, bool typeFlag, int64_t typeSummaryIndex,
        const std::string &recordName);
    static void GenTypeLiteralBuffers(panda::pandasm::Program *prog, const extractor::TypeRecorder *recorder);

    static constexpr const char *TYPE_INFO_RECORD = "_ESTypeInfoRecord";
    static constexpr const char *TYPE_ANNOTATION = "_ESTypeAnnotation";
    static constexpr const char *TYPE_INSTRUCTION = "_TypeOfInstruction";

    static constexpr const char *TYPE_FLAG = "typeFlag";
    static constexpr const char *TYPE_SUMMARY = "typeSummaryOffset";
    static constexpr const char *EXPORTED_SYMBOL_TYPES = "exportedSymbolTypes";
    static constexpr const char *DECLARED_SYMBOL_TYPES = "declaredSymbolTypes";

private:
    int32_t literalId_ = -1;
    const PandaGen *pg_;
    panda::pandasm::Function *func_;

    bool IsFuncMain0(const std::string &funcName, bool isMergeAbc) const;
    void GenFunctionTypeInfo(panda::pandasm::Program *prog);
    void GenExportTypeInfo(panda::pandasm::Program *prog);
    void GenDeclareTypeInfo(panda::pandasm::Program *prog);

    template <bool isExport, typename M>
    void GenImportOrDeclareTypeInfo(panda::pandasm::Program *prog, const extractor::TypeRecorder *recorder,
        const M &map, AnnotationData &funcTypeAnnotation);
};

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_EMITTER_TYPEEXTRACTOR_EMITTER_H
