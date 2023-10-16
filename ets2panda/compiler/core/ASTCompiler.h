/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ASTCOMPILER_H
#define ES2PANDA_COMPILER_CORE_ASTCOMPILER_H

#include "plugins/ecmascript/es2panda/compiler/core/dynamicContext.h"

namespace panda::es2panda::compiler {
class CodeGen;

class AstCompiler {
public:
    AstCompiler()
    {
        cg_ = nullptr;
    }
    virtual ~AstCompiler() = default;
    NO_COPY_SEMANTIC(AstCompiler);
    NO_MOVE_SEMANTIC(AstCompiler);

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AST_NODE_COMPILE_METHOD(_, nodeType) virtual void Compile(const ir::nodeType *node) const = 0;
    AST_NODE_MAPPING(DECLARE_AST_NODE_COMPILE_METHOD)
#undef DECLARE_AST_NODE_COMPILE_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AST_NODE_COMPILE_METHOD(_, __, nodeType, ___) virtual void Compile(const ir::nodeType *node) const = 0;
    AST_NODE_REINTERPRET_MAPPING(DECLARE_AST_NODE_COMPILE_METHOD)
#undef DECLARE_AST_NODE_COMPILE_METHOD

    void SetCodeGen(CodeGen *cg)
    {
        cg_ = cg;
    }

protected:
    CodeGen *GetCodeGen() const
    {
        return cg_;
    }

private:
    CodeGen *cg_;
};

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ASTCOMPILER_H
