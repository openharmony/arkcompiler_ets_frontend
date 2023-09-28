/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "JSemitter.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/compiler/core/compilerContext.h"
#include "assembly-program.h"

namespace panda::es2panda::compiler {
pandasm::Function *JSFunctionEmitter::GenFunctionSignature()
{
    auto *func = new pandasm::Function(Cg()->InternalName().Mutf8(), panda_file::SourceLang::ECMASCRIPT);
    GetProgramElement()->SetFunction(func);

    size_t param_count = Cg()->InternalParamCount();
    func->params.reserve(param_count);

    for (uint32_t i = 0; i < param_count; ++i) {
        func->params.emplace_back(pandasm::Type("any", 0), panda_file::SourceLang::ECMASCRIPT);
    }

    func->regs_num = VReg::REG_START - Cg()->TotalRegsNum();
    func->return_type = pandasm::Type("any", 0);

    return func;
}

void JSFunctionEmitter::GenVariableSignature(pandasm::debuginfo::LocalVariable &variable_debug,
                                             [[maybe_unused]] binder::LocalVariable *variable) const
{
    variable_debug.signature = "any";
    variable_debug.signature_type = "any";
}

void JSFunctionEmitter::GenFunctionAnnotations(pandasm::Function *func)
{
    pandasm::AnnotationData func_annotation_data("_ESAnnotation");
    pandasm::AnnotationElement ic_size_annotation_element(
        "icSize", std::make_unique<pandasm::ScalarValue>(
                      pandasm::ScalarValue::Create<pandasm::Value::Type::U32>(Pg()->IcSize())));
    func_annotation_data.AddElement(std::move(ic_size_annotation_element));

    pandasm::AnnotationElement parameter_length_annotation_element(
        "parameterLength", std::make_unique<pandasm::ScalarValue>(
                               pandasm::ScalarValue::Create<pandasm::Value::Type::U32>(Pg()->FormalParametersCount())));
    func_annotation_data.AddElement(std::move(parameter_length_annotation_element));

    pandasm::AnnotationElement func_name_annotation_element(
        "funcName", std::make_unique<pandasm::ScalarValue>(
                        pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(Pg()->FunctionName().Mutf8())));
    func_annotation_data.AddElement(std::move(func_name_annotation_element));

    func->metadata->AddAnnotations({func_annotation_data});
}

void JSEmitter::GenAnnotation()
{
    Program()->lang = panda_file::SourceLang::ECMASCRIPT;
    GenESAnnotationRecord();
    GenESModuleModeRecord(Context()->Binder()->Program()->Kind() == parser::ScriptKind::MODULE);
}

void JSEmitter::GenESAnnotationRecord()
{
    auto annotation_record = pandasm::Record("_ESAnnotation", Program()->lang);
    annotation_record.metadata->SetAttribute("external");
    annotation_record.metadata->SetAccessFlags(ACC_ANNOTATION);
    Program()->record_table.emplace(annotation_record.name, std::move(annotation_record));
}

void JSEmitter::GenESModuleModeRecord(bool is_module)
{
    auto mode_record = pandasm::Record("_ESModuleMode", Program()->lang);
    mode_record.metadata->SetAccessFlags(ACC_PUBLIC);

    auto mode_field = pandasm::Field(Program()->lang);
    mode_field.name = "isModule";
    mode_field.type = pandasm::Type("u8", 0);
    mode_field.metadata->SetValue(
        pandasm::ScalarValue::Create<pandasm::Value::Type::U8>(static_cast<uint8_t>(is_module)));

    mode_record.field_list.emplace_back(std::move(mode_field));

    Program()->record_table.emplace(mode_record.name, std::move(mode_record));
}
}  // namespace panda::es2panda::compiler
