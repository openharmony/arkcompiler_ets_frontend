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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_ALIVE_ANALYZER_H
#define ES2PANDA_COMPILER_CHECKER_ETS_ALIVE_ANALYZER_H

#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/baseAnalyzer.h"

#include "utils/arena_containers.h"

namespace panda::es2panda::ir {
class AstNode;
class Statement;
class ClassDefinition;
class MethodDefinition;
class DoWhileStatement;
class VariableDeclaration;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class AliveAnalyzer : public BaseAnalyzer {
public:
    // NOLINTNEXTLINE(readability-redundant-member-init)
    AliveAnalyzer(const ir::AstNode *node, ETSChecker *checker) : BaseAnalyzer(), checker_(checker)
    {
        AnalyzeNodes(node);
    }

    void MarkDead() override
    {
        status_ = LivenessStatus::DEAD;
    }

    LivenessStatus Or(LivenessStatus left, LivenessStatus right)
    {
        return static_cast<LivenessStatus>(left | right);
    }

    LivenessStatus And(LivenessStatus left, LivenessStatus right)
    {
        return static_cast<LivenessStatus>(left & right);
    }

private:
    void AnalyzeNodes(const ir::AstNode *node);
    void AnalyzeNode(const ir::AstNode *node);
    void AnalyzeDef(const ir::AstNode *node);
    void AnalyzeStat(const ir::AstNode *node);
    void AnalyzeStats(const ArenaVector<ir::Statement *> &stats);
    void AnalyzeStructDecl(const ir::ETSStructDeclaration *struct_decl);
    void AnalyzeClassDecl(const ir::ClassDeclaration *class_decl);
    void AnalyzeClassDef(const ir::ClassDefinition *class_def);
    void AnalyzeMethodDef(const ir::MethodDefinition *method_def);
    void AnalyzeVarDef(const ir::VariableDeclaration *var_def);
    void AnalyzeDoLoop(const ir::DoWhileStatement *do_while);
    void AnalyzeWhileLoop(const ir::WhileStatement *while_stmt);
    void AnalyzeForLoop(const ir::ForUpdateStatement *for_stmt);
    void AnalyzeForOfLoop(const ir::ForOfStatement *for_of_stmt);
    void AnalyzeIf(const ir::IfStatement *if_stmt);
    void AnalyzeLabelled(const ir::LabelledStatement *labelled_stmt);
    void AnalyzeNewClass(const ir::ETSNewClassInstanceExpression *new_class);
    void AnalyzeCall(const ir::CallExpression *call_expr);
    void AnalyzeThrow(const ir::ThrowStatement *throw_stmt);
    void AnalyzeSwitch(const ir::SwitchStatement *switch_stmt);
    void AnalyzeTry(const ir::TryStatement *try_stmt);
    void AnalyzeBreak(const ir::BreakStatement *break_stmt);
    void AnalyzeContinue(const ir::ContinueStatement *cont_stmt);
    void AnalyzeReturn(const ir::ReturnStatement *ret_stmt);

    ETSChecker *checker_;
    LivenessStatus status_ {LivenessStatus::ALIVE};
};
}  // namespace panda::es2panda::checker

#endif
