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

#include "compiler/lowering/util.h"
#include "evaluate/helpers.h"
#include "evaluate/nonRecursiveIrChecker.h"

namespace ark::es2panda::evaluate {

NonRecursiveIrChecker::NonRecursiveIrChecker(ArenaAllocator *allocator) : recursiveDecls_(allocator->Adapter()) {}

bool NonRecursiveIrChecker::CheckNewNode(checker::ETSChecker *checker, ir::AstNode *node, varbinder::Scope *scope,
                                         ir::AstNode *parentClass, parser::Program *program)
{
    ASSERT(checker);
    ASSERT(node);

    if (program == nullptr) {
        program = checker->VarBinder()->Program();
    }
    if (scope == nullptr) {
        scope = checker->Scope();
    }

    recursiveDecls_.emplace_back(program, scope, parentClass, node);

    if (isRecursive_) {
        return false;
    }
    isRecursive_ = true;

    if (isPrecheckPassed_) {
        HandleCustomNodes(checker);
        CheckDecls(checker);
    }

    isRecursive_ = false;

    return true;
}

void NonRecursiveIrChecker::PreCheck(checker::ETSChecker *checker)
{
    ASSERT(checker);

    HandleCustomNodes(checker);
    CheckDecls(checker);

    isPrecheckPassed_ = true;
}

void NonRecursiveIrChecker::CheckDecls(checker::ETSChecker *checker)
{
    ASSERT(checker);

    auto *binder = checker->VarBinder()->AsETSBinder();
    // All dependent user-classes must be created at this point, so we can run checker.
    while (!recursiveDecls_.empty()) {
        auto [program, scope, parent, node] = recursiveDecls_.front();
        recursiveDecls_.pop_front();
        DoScopedAction(checker, program, scope, parent, [checker, binder, node = node, scope = scope]() {
            binder->ResolveReferencesForScope(node, scope);
            node->Check(checker);
        });
    }
}

void NonRecursiveIrChecker::HandleCustomNodes(checker::ETSChecker *checker)
{
    ASSERT(checker);

    auto *binder = checker->VarBinder()->AsETSBinder();
    auto iter = recursiveDecls_.begin();
    while (iter != recursiveDecls_.end()) {
        // Can trigger `ETSBinder::BuildClassDefinition`,
        // which can eventually call debug-info plugin to create another class.
        // Hence we delay `ETSChecker::Check` until all required classes are built and initialized in varbinder.
        auto [program, scope, parent, node] = *iter;
        DoScopedAction(checker, program, scope, parent, [binder, node = node]() { binder->HandleCustomNodes(node); });
        ++iter;
    }
}

}  // namespace ark::es2panda::evaluate
