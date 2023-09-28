/**
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

#ifndef ES2PANDA_COMPILER_CORE_ETS_EMITTER_H
#define ES2PANDA_COMPILER_CORE_ETS_EMITTER_H

#include "emitter.h"

namespace panda::es2panda::binder {
class RecordTable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class ClassDefinition;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class ETSObjectType;
class ETSArrayType;
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::pandasm {
struct Field;
struct Record;
class ItemMetadata;
class AnnotationData;
}  // namespace panda::pandasm

namespace panda::es2panda::compiler {

class ETSFunctionEmitter : public FunctionEmitter {
public:
    ETSFunctionEmitter(const CodeGen *cg, ProgramElement *program_element) : FunctionEmitter(cg, program_element) {}
    ~ETSFunctionEmitter() = default;
    NO_COPY_SEMANTIC(ETSFunctionEmitter);
    NO_MOVE_SEMANTIC(ETSFunctionEmitter);

protected:
    const ETSGen *Etsg() const
    {
        return reinterpret_cast<const ETSGen *>(Cg());
    }

    pandasm::Function *GenFunctionSignature() override;

    void GenFunctionAnnotations(pandasm::Function *func) override;
    void GenVariableSignature(pandasm::debuginfo::LocalVariable &variable_debug,
                              binder::LocalVariable *variable) const override;
};

class ETSEmitter : public Emitter {
public:
    explicit ETSEmitter(const CompilerContext *context) : Emitter(context) {}
    ~ETSEmitter() override = default;
    NO_COPY_SEMANTIC(ETSEmitter);
    NO_MOVE_SEMANTIC(ETSEmitter);

    void GenAnnotation() override;

private:
    void GenExternalRecord(binder::RecordTable *record_table);
    void GenGlobalArrayRecord(checker::ETSArrayType *array_type, checker::Signature *signature);
    void GenClassRecord(const ir::ClassDefinition *class_def, bool external);
    void GenEnumRecord(const ir::TSEnumDeclaration *enum_decl, bool external);
    void GenAnnotationRecord(std::string_view record_name_view, bool is_runtime = false, bool is_type = false);
    void GenInterfaceRecord(const ir::TSInterfaceDeclaration *interface_decl, bool external);
    void EmitDefaultFieldValue(pandasm::Field &class_field, const ir::Expression *init);
    void GenClassField(const ir::ClassProperty *field, pandasm::Record &class_record, bool external);
    void GenField(const checker::Type *ts_type, const util::StringView &name, const ir::Expression *value,
                  uint32_t acces_flags, pandasm::Record &record, bool external);
    void GenInterfaceMethodDefinition(const ir::MethodDefinition *method_def, bool external);
    void GenClassInheritedFields(const checker::ETSObjectType *base_type, pandasm::Record &class_record);
    pandasm::AnnotationData GenAnnotationSignature(const ir::ClassDefinition *class_def);
    pandasm::AnnotationData GenAnnotationEnclosingClass(std::string_view class_name);
    pandasm::AnnotationData GenAnnotationEnclosingMethod(const ir::MethodDefinition *method_def);
    pandasm::AnnotationData GenAnnotationInnerClass(const ir::ClassDefinition *class_def, const ir::AstNode *parent);
    pandasm::AnnotationData GenAnnotationAsync(ir::ScriptFunction *script_func);
    ir::MethodDefinition *FindAsyncImpl(ir::ScriptFunction *async_func);
};
}  // namespace panda::es2panda::compiler

#endif
