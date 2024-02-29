/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_EVALUATE_NON_RECURSIVE_IR_CHECKER_H
#define ES2PANDA_EVALUATE_NON_RECURSIVE_IR_CHECKER_H

#include "libpandabase/mem/arena_allocator.h"
#include "libpandabase/utils/arena_containers.h"

namespace ark::es2panda::checker {
class ETSChecker;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::ir {
class AstNode;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::varbinder {
class Scope;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::evaluate {

/**
 * @brief Helper class for running type checks
 * All newly created IR nodes from debug-info must be checked through this class,
 * otherwise recursive class creations can lead to varbinder scopes errors.
 */
class NonRecursiveIrChecker final {
public:
    struct ScopedAstNode {
        ScopedAstNode(parser::Program *p, varbinder::Scope *s, ir::AstNode *parent, ir::AstNode *n)
            : program(p), scope(s), parentClass(parent), node(n)
        {
        }

        parser::Program *program {nullptr};
        varbinder::Scope *scope {nullptr};
        ir::AstNode *parentClass {nullptr};
        ir::AstNode *node {nullptr};
    };

public:
    NonRecursiveIrChecker(ArenaAllocator *allocator);
    NO_COPY_SEMANTIC(NonRecursiveIrChecker);
    NO_MOVE_SEMANTIC(NonRecursiveIrChecker);
    ~NonRecursiveIrChecker() noexcept = default;

    /**
     * @brief Runs scope and type checks on the given IR node
     * Returns false if check was delayed until recursion end, true if check was done immediately.
     */
    bool CheckNewNode(checker::ETSChecker *checker, ir::AstNode *node, varbinder::Scope *scope,
                      ir::AstNode *parentClass, parser::Program *program);

    void PreCheck(checker::ETSChecker *checker);

private:
    void HandleCustomNodes(checker::ETSChecker *checker);
    void CheckDecls(checker::ETSChecker *checker);

    bool isRecursive_ {false};
    // List is required due to possible push-backs during iteration.
    ArenaList<ScopedAstNode> recursiveDecls_;
    // Indicates that PreCheck was called from ETSChecker::StartChecker()
    bool isPrecheckPassed_ = {false};
};

}  // namespace ark::es2panda::evaluate

#endif /* NON_RECURSIVE_IR_CHECKER_H */
