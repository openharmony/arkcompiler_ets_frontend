/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
#ifndef ES2PANDA_COMPILER_CORE_ETSCOMPILER_H
#define ES2PANDA_COMPILER_CORE_ETSCOMPILER_H

#include "compiler/core/ASTCompiler.h"

namespace panda::es2panda::compiler {

class ETSCompiler final : public AstCompiler {
public:
    ETSCompiler() = default;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSCOMPILER_COMPILE_METHOD(_, nodeType) void Compile(const ir::nodeType *node) const override;
    AST_NODE_MAPPING(DECLARE_ETSCOMPILER_COMPILE_METHOD)
#undef DECLARE_ETSCOMPILER_COMPILE_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSCOMPILER_COMPILE_METHOD(_, __, nodeType, ___) void Compile(const ir::nodeType *node) const override;
    AST_NODE_REINTERPRET_MAPPING(DECLARE_ETSCOMPILER_COMPILE_METHOD)
#undef DECLARE_ETSCOMPILER_COMPILE_METHOD

private:
    bool IsSucceedCompilationProxyMemberExpr(const ir::CallExpression *expr) const;
    void CompileDynamic(const ir::CallExpression *expr, compiler::VReg &calleeReg) const;
    void CompileCastUnboxable(const ir::TSAsExpression *expr) const;
    void CompileCast(const ir::TSAsExpression *expr) const;
    void EmitCall(const ir::CallExpression *expr, compiler::VReg &calleeReg, bool isStatic) const;

    ETSGen *GetETSGen() const;
};

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ETSCOMPILER_H
