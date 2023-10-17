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

#include "programElement.h"

#include <assembly-program.h>

namespace panda::es2panda::compiler {
std::unordered_set<std::string> &ProgramElement::Strings()
{
    return strings_;
}

std::vector<pandasm::Ins *> &ProgramElement::LiteralBufferIns()
{
    return literal_buffer_ins_;
}

std::vector<LiteralBuffer> &ProgramElement::BuffStorage()
{
    return buff_storage_;
}

pandasm::Function *ProgramElement::Function()
{
    return func_;
}

void ProgramElement::SetFunction(pandasm::Function *func)
{
    func_ = func;
}

ProgramElement::~ProgramElement()
{
    delete func_;
}
}  // namespace panda::es2panda::compiler
