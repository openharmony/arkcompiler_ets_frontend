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

#include "emitter.h"

#include "ir/irnode.h"
#include "util/helpers.h"
#include "binder/scope.h"
#include "binder/variable.h"
#include "compiler/base/literals.h"
#include "compiler/core/compilerContext.h"
#include "compiler/core/codeGen.h"
#include "compiler/core/regSpiller.h"
#include "compiler/debugger/debuginfoDumper.h"
#include "compiler/base/catchTable.h"
#include "es2panda.h"
#include "ir/statements/blockStatement.h"
#include "parser/program/program.h"
#include "checker/types/type.h"
#include "generated/isa.h"
#include "macros.h"

#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace panda::es2panda::compiler {
using LiteralPair = std::pair<pandasm::LiteralArray::Literal, pandasm::LiteralArray::Literal>;

static LiteralPair TransformLiteral(const compiler::Literal *literal)
{
    pandasm::LiteralArray::Literal value_lit;
    pandasm::LiteralArray::Literal tag_lit;

    compiler::LiteralTag tag = literal->Tag();

    switch (tag) {
        case compiler::LiteralTag::BOOLEAN: {
            value_lit.tag = panda_file::LiteralTag::BOOL;
            value_lit.value = literal->GetBoolean();
            break;
        }
        case compiler::LiteralTag::INTEGER: {
            value_lit.tag = panda_file::LiteralTag::INTEGER;
            value_lit.value = literal->GetInteger();
            break;
        }
        case compiler::LiteralTag::DOUBLE: {
            value_lit.tag = panda_file::LiteralTag::DOUBLE;
            value_lit.value = literal->GetDouble();
            break;
        }
        case compiler::LiteralTag::STRING: {
            value_lit.tag = panda_file::LiteralTag::STRING;
            value_lit.value = literal->GetString();
            break;
        }
        case compiler::LiteralTag::ACCESSOR: {
            value_lit.tag = panda_file::LiteralTag::ACCESSOR;
            value_lit.value = static_cast<uint8_t>(0);
            break;
        }
        case compiler::LiteralTag::METHOD: {
            value_lit.tag = panda_file::LiteralTag::METHOD;
            value_lit.value = literal->GetMethod();
            break;
        }
        case compiler::LiteralTag::ASYNC_METHOD: {
            value_lit.tag = panda_file::LiteralTag::ASYNCMETHOD;
            value_lit.value = literal->GetMethod();
            break;
        }
        case compiler::LiteralTag::GENERATOR_METHOD: {
            value_lit.tag = panda_file::LiteralTag::GENERATORMETHOD;
            value_lit.value = literal->GetMethod();
            break;
        }
        case compiler::LiteralTag::ASYNC_GENERATOR_METHOD: {
            value_lit.tag = panda_file::LiteralTag::ASYNCGENERATORMETHOD;
            value_lit.value = literal->GetMethod();
            break;
        }
        case compiler::LiteralTag::NULL_VALUE: {
            value_lit.tag = panda_file::LiteralTag::NULLVALUE;
            value_lit.value = static_cast<uint8_t>(0);
            break;
        }
        default:
            UNREACHABLE();
            break;
    }

    tag_lit.tag = panda_file::LiteralTag::TAGVALUE;
    tag_lit.value = static_cast<uint8_t>(value_lit.tag);

    return {tag_lit, value_lit};
}

void FunctionEmitter::Generate()
{
    auto *func = GenFunctionSignature();
    GenFunctionInstructions(func);
    GenVariablesDebugInfo(func);
    GenSourceFileDebugInfo(func);
    GenFunctionCatchTables(func);
    GenFunctionAnnotations(func);
}

util::StringView FunctionEmitter::SourceCode() const
{
    return cg_->Binder()->Program()->SourceCode();
}

static Format MatchFormat(const IRNode *node, const Formats &formats)
{
    std::array<const VReg *, IRNode::MAX_REG_OPERAND> regs {};
    auto reg_cnt = node->Registers(&regs);
    auto registers = Span<const VReg *>(regs.data(), regs.data() + reg_cnt);

    const auto *iter = formats.begin();

    for (; iter != formats.end(); iter++) {  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        auto format = *iter;
        size_t limit = 0;
        for (const auto &format_item : format.GetFormatItem()) {
            if (format_item.IsVReg()) {
                limit = 1U << format_item.BitWidth();
                break;
            }
        }

        if (std::all_of(registers.begin(), registers.end(), [limit](const VReg *reg) { return reg->IsValid(limit); })) {
            return format;
        }
    }

    UNREACHABLE();
    return *iter;
}

static size_t GetIRNodeWholeLength(const IRNode *node)
{
    Formats formats = node->GetFormats();
    if (formats.empty()) {
        return 0;
    }

    size_t len = 1;
    const auto format = MatchFormat(node, formats);

    for (auto fi : format.GetFormatItem()) {
        len += fi.BitWidth() / 8;
    }

    return len;
}

static std::string WholeLine(const util::StringView &source, lexer::SourceRange range)
{
    if (source.Empty()) {
        return {};
    }
    ASSERT(range.end.index <= source.Length());
    return source.Substr(range.start.index, range.end.index).EscapeSymbol<util::StringView::Mutf8Encode>();
}

void FunctionEmitter::GenInstructionDebugInfo(const IRNode *ins, pandasm::Ins *panda_ins)
{
    const ir::AstNode *ast_node = ins->Node();

    ASSERT(ast_node != nullptr);

    if (ast_node == FIRST_NODE_OF_FUNCTION) {
        ast_node = cg_->Debuginfo().FirstStatement();
        if (ast_node == nullptr) {
            return;
        }
    }

    panda_ins->ins_debug.line_number = ast_node->Range().start.line + 1;

    if (cg_->IsDebug()) {
        size_t ins_len = GetIRNodeWholeLength(ins);
        if (ins_len != 0) {
            panda_ins->ins_debug.bound_left = offset_;
            panda_ins->ins_debug.bound_right = offset_ + ins_len;
        }

        offset_ += ins_len;
        panda_ins->ins_debug.whole_line = WholeLine(SourceCode(), ast_node->Range());
    }
}

void FunctionEmitter::GenFunctionInstructions(pandasm::Function *func)
{
    func->ins.reserve(cg_->Insns().size());

    uint32_t total_regs = cg_->TotalRegsNum();

    for (const auto *ins : cg_->Insns()) {
        auto &panda_ins = func->ins.emplace_back();

        ins->Transform(&panda_ins, program_element_, total_regs);
        GenInstructionDebugInfo(ins, &panda_ins);
    }
}

void FunctionEmitter::GenFunctionAnnotations(pandasm::Function *func)
{
    pandasm::AnnotationData func_annotation_data("_ESAnnotation");
    pandasm::AnnotationElement ic_size_annotation_element(
        "icSize",
        std::make_unique<pandasm::ScalarValue>(pandasm::ScalarValue::Create<pandasm::Value::Type::U32>(cg_->IcSize())));
    func_annotation_data.AddElement(std::move(ic_size_annotation_element));

    pandasm::AnnotationElement parameter_length_annotation_element(
        "parameterLength", std::make_unique<pandasm::ScalarValue>(
                               pandasm::ScalarValue::Create<pandasm::Value::Type::U32>(cg_->FormalParametersCount())));
    func_annotation_data.AddElement(std::move(parameter_length_annotation_element));

    pandasm::AnnotationElement func_name_annotation_element(
        "funcName", std::make_unique<pandasm::ScalarValue>(
                        pandasm::ScalarValue::Create<pandasm::Value::Type::STRING>(cg_->FunctionName().Mutf8())));
    func_annotation_data.AddElement(std::move(func_name_annotation_element));

    func->metadata->AddAnnotations({func_annotation_data});
}

void FunctionEmitter::GenFunctionCatchTables(pandasm::Function *func)
{
    func->catch_blocks.reserve(cg_->CatchList().size());

    for (const auto *catch_block : cg_->CatchList()) {
        const auto &label_set = catch_block->LabelSet();

        auto &panda_catch_block = func->catch_blocks.emplace_back();
        panda_catch_block.exception_record = catch_block->Exception();
        panda_catch_block.try_begin_label = label_set.TryBegin()->Id();
        panda_catch_block.try_end_label = label_set.TryEnd()->Id();
        panda_catch_block.catch_begin_label = label_set.CatchBegin()->Id();
        panda_catch_block.catch_end_label = label_set.CatchBegin()->Id();
    }
}

void FunctionEmitter::GenSourceFileDebugInfo(pandasm::Function *func)
{
    func->source_file = std::string {cg_->Binder()->Program()->AbsoluteName()};

    if (!cg_->IsDebug()) {
        return;
    }

    if (cg_->RootNode()->IsProgram()) {
        func->source_code = SourceCode().EscapeSymbol<util::StringView::Mutf8Encode>();
    }
}

static void GenLocalVariableInfo(pandasm::debuginfo::LocalVariable &variable_debug, binder::Variable *var,
                                 uint32_t start, uint32_t vars_length, uint32_t total_regs_num,
                                 const ScriptExtension extension)
{
    variable_debug.name = var->Name().Mutf8();

    if (extension == ScriptExtension::JS) {
        variable_debug.signature = "any";
        variable_debug.signature_type = "any";
    } else {
        std::stringstream ss;
        var->AsLocalVariable()->TsType()->ToDebugInfoType(ss);
        variable_debug.signature = ss.str();
        variable_debug.signature_type = ss.str();  // TODO() Handle typeParams, either class or interface
    }

    variable_debug.reg =
        static_cast<int32_t>(IRNode::MapRegister(var->AsLocalVariable()->Vreg().GetIndex(), total_regs_num));
    variable_debug.start = start;
    variable_debug.length = static_cast<uint32_t>(vars_length);
}

void FunctionEmitter::GenScopeVariableInfo(pandasm::Function *func, const binder::Scope *scope) const
{
    const auto *start_ins = scope->ScopeStart();
    const auto *end_ins = scope->ScopeEnd();

    uint32_t start = 0;
    uint32_t count = 0;

    const auto extension = cg_->Binder()->Program()->Extension();

    for (const auto *it : cg_->Insns()) {
        if (start_ins == it) {
            start = count;
        } else if (end_ins == it) {
            auto vars_length = static_cast<uint32_t>(count - start + 1);

            if (scope->IsFunctionScope()) {
                for (auto *param : scope->AsFunctionScope()->ParamScope()->Params()) {
                    auto &variable_debug = func->local_variable_debug.emplace_back();
                    GenLocalVariableInfo(variable_debug, param, start, vars_length, cg_->TotalRegsNum(), extension);
                }
            }

            for (const auto &[_, variable] : scope->Bindings()) {
                (void)_;
                if (!variable->IsLocalVariable() || variable->LexicalBound() ||
                    variable->Declaration()->IsParameterDecl() || variable->Declaration()->IsTypeAliasDecl()) {
                    continue;
                }

                auto &variable_debug = func->local_variable_debug.emplace_back();
                GenLocalVariableInfo(variable_debug, variable, start, vars_length, cg_->TotalRegsNum(), extension);
            }

            break;
        }

        count++;
    }
}

void FunctionEmitter::GenVariablesDebugInfo(pandasm::Function *func)
{
    if (!cg_->IsDebug()) {
        return;
    }

    for (const auto *scope : cg_->Debuginfo().VariableDebugInfo()) {
        GenScopeVariableInfo(func, scope);
    }
}

// Emitter

Emitter::Emitter(const CompilerContext *context) : context_(context)
{
    prog_ = new pandasm::Program();
    prog_->function_table.reserve(context->Binder()->Functions().size());
}

Emitter::~Emitter()
{
    delete prog_;
}

static void UpdateLiteralBufferId(panda::pandasm::Ins *ins, uint32_t offset)
{
#ifdef PANDA_WITH_ECMASCRIPT
    switch (ins->opcode) {
        case pandasm::Opcode::ECMA_DEFINECLASSWITHBUFFER: {
            ins->imms.back() = std::get<int64_t>(ins->imms.back()) + offset;
            break;
        }
        case pandasm::Opcode::ECMA_CREATEARRAYWITHBUFFER:
        case pandasm::Opcode::ECMA_CREATEOBJECTWITHBUFFER:
        case pandasm::Opcode::ECMA_CREATEOBJECTHAVINGMETHOD:
        case pandasm::Opcode::ECMA_DEFINECLASSPRIVATEFIELDS: {
            uint32_t stored_offset = std::stoi(ins->ids.back());
            stored_offset += offset;
            ins->ids.back() = std::to_string(stored_offset);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }
#else
    (void) ins;
    (void) offset;
    UNREACHABLE();
#endif
}

void Emitter::AddProgramElement(ProgramElement *program_element)
{
    prog_->strings.merge(program_element->Strings());

    uint32_t new_literal_buffer_index = literal_buffer_index_;
    for (const auto &buff : program_element->BuffStorage()) {
        AddLiteralBuffer(buff, new_literal_buffer_index++);
    }

    for (auto *ins : program_element->LiteralBufferIns()) {
        UpdateLiteralBufferId(ins, literal_buffer_index_);
    }

    literal_buffer_index_ = new_literal_buffer_index;

    auto *function = program_element->Function();
    prog_->function_table.emplace(function->name, std::move(*function));
}

static std::string CanonicalizeName(std::string name)
{
    std::replace_if(
        name.begin(), name.end(), [](char c) { return (c == '<' || c == '>' || c == '.' || c == ':' || c == ';'); },
        '-');
    name.append(std::to_string(0));
    return name;
}

void Emitter::DumpAsm(const pandasm::Program *prog)
{
    auto &ss = std::cout;

    ss << ".language ECMAScript" << std::endl << std::endl;

    for (auto &[name, func] : prog->function_table) {
        ss << ".function any " << CanonicalizeName(name) << '(';

        for (uint32_t i = 0; i < func.GetParamsNum(); i++) {
            ss << "any a" << std::to_string(i);

            if (i != func.GetParamsNum() - 1) {
                ss << ", ";
            }
        }

        ss << ") {" << std::endl;

        for (const auto &ins : func.ins) {
            ss << (ins.set_label ? "" : "\t") << ins.ToString("", true, func.GetTotalRegs()) << std::endl;
        }

        ss << "}" << std::endl << std::endl;

        for (const auto &ct : func.catch_blocks) {
            if (ct.exception_record.empty()) {
                ss << ".catchall ";
            } else {
                ss << ".catch " << ct.exception_record << ", ";
            }
            ss << ct.try_begin_label << ", " << ct.try_end_label << ", " << ct.catch_begin_label << std::endl
               << std::endl;
        }
    }

    ss << std::endl;
}

void Emitter::AddLiteralBuffer(const LiteralBuffer &literals, uint32_t index)
{
    std::vector<pandasm::LiteralArray::Literal> literal_array;

    for (const auto &literal : literals) {
        auto [tagLit, valueLit] = TransformLiteral(&literal);
        literal_array.emplace_back(tagLit);
        literal_array.emplace_back(valueLit);
    }

    auto literal_array_instance = pandasm::LiteralArray(std::move(literal_array));
    prog_->literalarray_table.emplace(std::to_string(index), std::move(literal_array_instance));
}

pandasm::Program *Emitter::Finalize(bool dump_debug_info, std::string_view global_class)
{
    if (dump_debug_info) {
        debuginfo::DebugInfoDumper dumper(prog_);
        dumper.Dump();
    }

    if (context_->Binder()->IsGenStdLib()) {
        auto it = prog_->record_table.find(std::string(global_class));
        if (it != prog_->record_table.end()) {
            prog_->record_table.erase(it);
        }
    }
    auto *prog = prog_;
    prog_ = nullptr;
    return prog;
}
}  // namespace panda::es2panda::compiler
