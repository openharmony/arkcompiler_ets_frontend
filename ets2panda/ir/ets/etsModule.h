/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_ETS_MODULE_H
#define ES2PANDA_IR_ETS_MODULE_H

#include "ir/statements/blockStatement.h"
#include "ir/annotationAllowed.h"
#include "ir/jsDocAllowed.h"
#include "ir/expressions/identifier.h"
#include "ir/srcDump.h"

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::ir {

using ENUMBITOPS_OPERATORS;

enum class ModuleFlag : uint32_t {
    NONE = 0,
    ETSSCRIPT = 1U << 0U,
    NAMESPACE = 1U << 1U,
    NAMESPACE_CHAIN_LAST_NODE = 1U << 2U
};
}  // namespace ark::es2panda::ir

template <>
struct enumbitops::IsAllowedType<ark::es2panda::ir::ModuleFlag> : std::true_type {
};

namespace ark::es2panda::ir {

class ETSModule : public JsDocAllowed<AnnotationAllowed<BlockStatement>> {
public:
    explicit ETSModule(ArenaAllocator *allocator, ArenaVector<Statement *> &&statementList, Identifier *ident,
                       ModuleFlag flag, parser::Program *program)
        : JsDocAllowed<AnnotationAllowed<BlockStatement>>(allocator, std::move(statementList)),
          ident_(ident),
          flag_(flag),
          program_(program)
    {
        type_ = AstNodeType::ETS_MODULE;
    }

    ir::Identifier *Ident()
    {
        return ident_;
    }

    const ir::Identifier *Ident() const
    {
        return ident_;
    }

    parser::Program *Program()
    {
        return program_;
    }

    [[nodiscard]] bool IsETSScript() const noexcept
    {
        return (flag_ & ModuleFlag::ETSSCRIPT) != 0;
    }

    [[nodiscard]] bool IsNamespace() const noexcept
    {
        return (flag_ & ModuleFlag::NAMESPACE) != 0;
    }

    [[nodiscard]] bool IsNamespaceChainLastNode() const noexcept
    {
        return (flag_ & ModuleFlag::NAMESPACE_CHAIN_LAST_NODE) != 0;
    }

    void SetNamespaceChainLastNode() noexcept
    {
        ES2PANDA_ASSERT(IsNamespace());
        flag_ |= ModuleFlag::NAMESPACE_CHAIN_LAST_NODE;
    }

    const parser::Program *Program() const
    {
        return program_;
    }
    void Dump(ir::SrcDumper *dumper) const override;
    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

    ETSModule *Construct(ArenaAllocator *allocator) override;
    void CopyTo(AstNode *other) const override;

private:
    friend class SizeOfNodeTest;
    Identifier *ident_;
    ModuleFlag flag_;
    parser::Program *program_;
};
}  // namespace ark::es2panda::ir

#endif
