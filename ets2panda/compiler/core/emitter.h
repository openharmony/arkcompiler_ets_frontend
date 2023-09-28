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

#ifndef ES2PANDA_COMPILER_CORE_EMITTER_H
#define ES2PANDA_COMPILER_CORE_EMITTER_H

#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"

#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace panda::pandasm {
struct Program;
struct Function;
struct Ins;
namespace debuginfo {
struct LocalVariable;
}  // namespace debuginfo
}  // namespace panda::pandasm

namespace panda::es2panda::binder {
class Scope;
class LocalVariable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::compiler {
class CodeGen;
class DebugInfo;
class Label;
class IRNode;
class CompilerContext;
class ProgramElement;
class RegSpiller;

class FunctionEmitter {
public:
    explicit FunctionEmitter(const CodeGen *cg, ProgramElement *program_element)
        : cg_(cg), program_element_(program_element)
    {
    }

    ~FunctionEmitter() = default;
    NO_COPY_SEMANTIC(FunctionEmitter);
    NO_MOVE_SEMANTIC(FunctionEmitter);

    void Generate();

protected:
    virtual pandasm::Function *GenFunctionSignature() = 0;
    virtual void GenFunctionAnnotations(pandasm::Function *func) = 0;
    virtual void GenVariableSignature(pandasm::debuginfo::LocalVariable &variable_debug,
                                      binder::LocalVariable *variable) const = 0;

    void GenInstructionDebugInfo(const IRNode *ins, panda::pandasm::Ins *panda_ins);
    void GenFunctionInstructions(pandasm::Function *func);
    void GenScopeVariableInfo(pandasm::Function *func, const binder::Scope *scope) const;
    void GenSourceFileDebugInfo(pandasm::Function *func);
    void GenFunctionCatchTables(panda::pandasm::Function *func);
    void GenVariablesDebugInfo(pandasm::Function *func);
    util::StringView SourceCode() const;

    const CodeGen *Cg() const
    {
        return cg_;
    }

    ProgramElement *GetProgramElement() const
    {
        return program_element_;
    }

private:
    const CodeGen *cg_;
    ProgramElement *program_element_;
    size_t offset_ {0};
};

class Emitter {
public:
    virtual ~Emitter();
    NO_COPY_SEMANTIC(Emitter);
    NO_MOVE_SEMANTIC(Emitter);

    void AddLiteralBuffer(const LiteralBuffer &literals, uint32_t index);
    void AddProgramElement(ProgramElement *program_element);
    static void DumpAsm(const pandasm::Program *prog);
    pandasm::Program *Finalize(bool dump_debug_info, std::string_view global_class = "");

    uint32_t &LiteralBufferIndex()
    {
        return literal_buffer_index_;
    }

    virtual void GenAnnotation() = 0;

protected:
    explicit Emitter(const CompilerContext *context);

    pandasm::Program *Program() const
    {
        return prog_;
    }

    const CompilerContext *Context() const
    {
        return context_;
    }

private:
    pandasm::Program *prog_;
    const CompilerContext *context_;
    uint32_t literal_buffer_index_ {};
};
}  // namespace panda::es2panda::compiler

#endif
