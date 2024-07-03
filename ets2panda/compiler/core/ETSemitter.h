/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ETS_EMITTER_H
#define ES2PANDA_COMPILER_CORE_ETS_EMITTER_H

#include "emitter.h"

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::varbinder {
class RecordTable;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::ir {
class ClassDefinition;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::checker {
class ETSObjectType;
class ETSArrayType;
class Signature;
}  // namespace ark::es2panda::checker

namespace ark::pandasm {
struct Field;
struct Record;
class ItemMetadata;
class AnnotationData;
}  // namespace ark::pandasm

namespace ark::es2panda::compiler {

class ETSFunctionEmitter : public FunctionEmitter {
public:
    ETSFunctionEmitter(const CodeGen *cg, ProgramElement *programElement) : FunctionEmitter(cg, programElement) {}
    ~ETSFunctionEmitter() override = default;
    NO_COPY_SEMANTIC(ETSFunctionEmitter);
    NO_MOVE_SEMANTIC(ETSFunctionEmitter);

protected:
    const ETSGen *Etsg() const
    {
        return reinterpret_cast<const ETSGen *>(Cg());
    }

    pandasm::Function *GenFunctionSignature() override;

    void GenFunctionAnnotations(pandasm::Function *func) override;
    void GenVariableSignature(pandasm::debuginfo::LocalVariable &variableDebug,
                              varbinder::LocalVariable *variable) const override;
};

class ETSEmitter : public Emitter {
public:
    explicit ETSEmitter(const public_lib::Context *context) : Emitter(context) {}
    ~ETSEmitter() override = default;
    NO_COPY_SEMANTIC(ETSEmitter);
    NO_MOVE_SEMANTIC(ETSEmitter);

    void GenAnnotation() override;

private:
    using DynamicCallNamesMap = ArenaMap<const ArenaVector<util::StringView>, uint32_t>;

    void GenExternalRecord(varbinder::RecordTable *recordTable);
    void GenGlobalArrayRecord(checker::ETSArrayType *arrayType, checker::Signature *signature);
    std::vector<pandasm::AnnotationData> GenAnnotations(const ir::ClassDefinition *classDef);
    void GenClassRecord(const ir::ClassDefinition *classDef, bool external);
    void GenEnumRecord(const ir::TSEnumDeclaration *enumDecl, bool external);
    void GenAnnotationRecord(std::string_view recordNameView, bool isRuntime = false, bool isType = false);
    void GenInterfaceRecord(const ir::TSInterfaceDeclaration *interfaceDecl, bool external);
    void EmitDefaultFieldValue(pandasm::Field &classField, const ir::Expression *init);
    void GenClassField(const ir::ClassProperty *field, pandasm::Record &classRecord, bool external);

    // Struct to reduce number of arguments to pass code checker
    struct GenFieldArguments {
        const checker::Type *tsType;
        const util::StringView &name;
        const ir::Expression *value;
        uint32_t accesFlags;
        pandasm::Record &record;
        bool external;
    };

    void GenField(const GenFieldArguments &data);

    void GenInterfaceMethodDefinition(const ir::MethodDefinition *methodDef, bool external);
    void GenClassInheritedFields(const checker::ETSObjectType *baseType, pandasm::Record &classRecord);
    pandasm::AnnotationData GenAnnotationSignature(const ir::ClassDefinition *classDef);
    pandasm::AnnotationData GenAnnotationEnclosingClass(std::string_view className);
    pandasm::AnnotationData GenAnnotationEnclosingMethod(const ir::MethodDefinition *methodDef);
    pandasm::AnnotationData GenAnnotationInnerClass(const ir::ClassDefinition *classDef, const ir::AstNode *parent);
    pandasm::AnnotationData GenAnnotationAsync(ir::ScriptFunction *scriptFunc);
    pandasm::AnnotationData GenAnnotationDynamicCall(DynamicCallNamesMap &callNames);
    ir::MethodDefinition *FindAsyncImpl(ir::ScriptFunction *asyncFunc);
};
}  // namespace ark::es2panda::compiler

#endif
