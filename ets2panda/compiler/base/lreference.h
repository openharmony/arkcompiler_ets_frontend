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

#ifndef ES2PANDA_COMPILER_BASE_JSLREFERENCE_H
#define ES2PANDA_COMPILER_BASE_JSLREFERENCE_H

#include "binder/scope.h"
#include "ir/irnode.h"

namespace panda::es2panda::ir {
class AstNode;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class ETSObjectType;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::compiler {
enum class ReferenceKind {
    MEMBER,
    PRIVATE,
    SUPER,
    VAR_OR_GLOBAL,
    DESTRUCTURING,
    LOCAL,
    STATIC_FIELD,
    FIELD,
    CLASS,
    STATIC_CLASS,
    METHOD,
    STATIC_METHOD,
};

class CodeGen;
class ETSGen;
class PandaGen;

class LReference {
public:
    ~LReference() = default;
    NO_COPY_SEMANTIC(LReference);
    DEFAULT_MOVE_SEMANTIC(LReference);

    ReferenceKind Kind() const
    {
        return ref_kind_;
    }

    void SetKind(ReferenceKind ref_kind)
    {
        ref_kind_ = ref_kind;
    }

    binder::Variable *Variable() const
    {
        return res_.variable;
    }

    const ir::AstNode *Node() const
    {
        return node_;
    }

    binder::ConstScopeFindResult &Result()
    {
        return res_;
    }

    const binder::ConstScopeFindResult &Result() const
    {
        return res_;
    }

    bool IsDeclaration() const
    {
        return is_declaration_;
    }

protected:
    using LReferenceBase =
        std::tuple<CodeGen *, const ir::AstNode *, ReferenceKind, binder::ConstScopeFindResult, bool>;
    static LReferenceBase CreateBase(CodeGen *cg, const ir::AstNode *node, bool is_declaration);

    explicit LReference(const ir::AstNode *node, ReferenceKind ref_kind, binder::ConstScopeFindResult res,
                        bool is_declaration)
        : node_(node), ref_kind_(ref_kind), res_(res), is_declaration_(is_declaration)
    {
    }

private:
    const ir::AstNode *node_;
    ReferenceKind ref_kind_;
    binder::ConstScopeFindResult res_;
    bool is_declaration_;
};

class JSLReference : public LReference {
public:
    JSLReference(CodeGen *cg, const ir::AstNode *node, ReferenceKind ref_kind, binder::ConstScopeFindResult res,
                 bool is_declaration);
    ~JSLReference() = default;
    NO_COPY_SEMANTIC(JSLReference);
    NO_MOVE_SEMANTIC(JSLReference);

    void GetValue() const;
    void SetValue() const;

    static JSLReference Create(CodeGen *cg, const ir::AstNode *node, bool is_declaration)
    {
        return std::make_from_tuple<JSLReference>(CreateBase(cg, node, is_declaration));
    }

private:
    PandaGen *pg_;
    VReg obj_;
    VReg private_ctor_ {};
    Operand prop_;
};

class ETSLReference : public LReference {
public:
    ETSLReference(CodeGen *cg, const ir::AstNode *node, ReferenceKind ref_kind, binder::ConstScopeFindResult res,
                  bool is_declaration);
    ~ETSLReference() = default;
    NO_COPY_SEMANTIC(ETSLReference);
    NO_MOVE_SEMANTIC(ETSLReference);

    void GetValue() const;
    void SetValue() const;

    static ETSLReference Create(CodeGen *cg, const ir::AstNode *node, bool is_declaration);
    static ReferenceKind ResolveReferenceKind(const binder::Variable *variable);

private:
    ETSGen *etsg_;
    const checker::Type *static_obj_ref_ {};
    VReg base_reg_ {};
    VReg prop_reg_ {};
};
}  // namespace panda::es2panda::compiler

#endif
