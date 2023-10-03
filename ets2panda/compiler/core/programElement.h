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

#ifndef ES2PANDA_COMPILER_CORE_PROGRAM_ELEMENT_H
#define ES2PANDA_COMPILER_CORE_PROGRAM_ELEMENT_H

#include "macros.h"
#include "compiler/base/literals.h"

namespace panda::pandasm {
struct Ins;
struct Function;
}  // namespace panda::pandasm

namespace panda::es2panda::compiler {
class ProgramElement {
public:
    explicit ProgramElement() = default;
    ~ProgramElement();
    NO_COPY_SEMANTIC(ProgramElement);
    NO_MOVE_SEMANTIC(ProgramElement);

    std::unordered_set<std::string> &Strings();
    std::vector<pandasm::Ins *> &LiteralBufferIns();
    std::vector<LiteralBuffer> &BuffStorage();
    pandasm::Function *Function();
    void SetFunction(pandasm::Function *func);

private:
    std::unordered_set<std::string> strings_;
    std::vector<pandasm::Ins *> literal_buffer_ins_;
    std::vector<LiteralBuffer> buff_storage_;
    pandasm::Function *func_ {};
};
}  // namespace panda::es2panda::compiler
#endif
