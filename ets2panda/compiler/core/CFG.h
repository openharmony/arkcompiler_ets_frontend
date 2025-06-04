/**
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

#ifndef ES2PANDA_COMPILER_CORE_CFG_H
#define ES2PANDA_COMPILER_CORE_CFG_H

#include "ir/astNode.h"
#include "ir/expressions/literals/booleanLiteral.h"

namespace ark::es2panda::public_lib {
struct Context;
}  // namespace ark::es2panda::public_lib

namespace ark::es2panda::compiler {
using ENUMBITOPS_OPERATORS;

class CFG {
public:
    enum class BasicBlockFlags : uint8_t {
        NONE = 0,
        ENTRY = 1U << 0U,
        EXIT = 1U << 1U,
        CONDITION = 1U << 2U,
        LOOP = 1U << 3U
    };
    class BasicBlock {
    public:
        std::pair<size_t, size_t> AddSuccessor(BasicBlock *successor);
        std::pair<size_t, size_t> AddPredecessor(BasicBlock *predecessor);

        [[nodiscard]] size_t GetIndex() const;
        [[nodiscard]] BasicBlockFlags GetFlags() const;

        bool HasFlag(BasicBlockFlags flag) const;
        void SetFlag(BasicBlockFlags flag);
        void ClearFlag(BasicBlockFlags flag);

        [[nodiscard]] const ArenaVector<BasicBlock *> &GetSuccessors() const;
        [[nodiscard]] const ArenaVector<BasicBlock *> &GetPredecessors() const;
        [[nodiscard]] const ArenaVector<ir::AstNode *> &GetNodes() const;
        [[nodiscard]] ir::AstNode *GetLastNode() const;
        [[nodiscard]] size_t GetSize() const;
        friend class CFG;
        BasicBlock(ArenaAllocator *allocator, size_t index) noexcept;

    private:
        size_t AddNode(ir::AstNode *node);
        size_t index_;
        ArenaVector<ir::AstNode *> nodes_;
        ArenaVector<BasicBlock *> succs_;
        ArenaVector<BasicBlock *> preds_;
        BasicBlockFlags flags_ {BasicBlockFlags::NONE};
    };

    struct VisitResult {
        ArenaList<const CFG::BasicBlock *> &orderedList;
        ArenaSet<const CFG::BasicBlock *> &visitedBlocks;
        ArenaSet<const CFG::BasicBlock *> &markedBlocks;
    };

    explicit CFG(ArenaAllocator *allocator);

    BasicBlock *Build(ir::ScriptFunction *scriptFunctionNode);
    void MergeEmptyBlocks();
    bool DumpDot(const char *filename) const;

    using BBTraverser = std::function<bool(const BasicBlock *)>;

    [[nodiscard]] const ArenaSet<BasicBlock *> &GetBasicBlocks() const;
    // NOTE: We could make them faster by adding markers to the basic blocks.
    void IterateForwardDepthFirst(const BBTraverser &traverser, const BasicBlock *start = nullptr,
                                  bool allPath = false) const;
    [[nodiscard]] ArenaList<const BasicBlock *> GetForwardDepthFirstOrder(const BasicBlock *start = nullptr,
                                                                          bool allPath = false) const;
    void IterateBackwardDepthFirst(const BBTraverser &traverser, const BasicBlock *start = nullptr,
                                   bool allPath = false) const;
    [[nodiscard]] ArenaList<const BasicBlock *> GetBackwardDepthFirstOrder(const BasicBlock *start = nullptr,
                                                                           bool allPath = false) const;
    void IterateForwardTopologicalOrder(const BBTraverser &traverser, const BasicBlock *start = nullptr,
                                        bool closeLoop = false) const;
    [[nodiscard]] ArenaList<const BasicBlock *> GetForwardTopologicalOrder(const BasicBlock *start = nullptr,
                                                                           bool closeLoop = false) const;
    void IterateBackwardTopologicalOrder(const BBTraverser &traverser, const BasicBlock *start = nullptr,
                                         bool closeLoop = false) const;

    [[nodiscard]] ArenaList<const BasicBlock *> GetBackwardTopologicalOrder(const BasicBlock *start = nullptr,
                                                                            bool closeLoop = false) const;

    [[nodiscard]] std::pair<BasicBlock *, size_t> FindBasicBlock(ir::AstNode *node) const;
    [[nodiscard]] BasicBlock *FindEntryBasicBlock(ir::ScriptFunction *function) const;
    [[nodiscard]] const ir::AstNode *GetBBPredEdgeLabel(const BasicBlock *bb, size_t index) const;
    /* pair<condition, label> */
    [[nodiscard]] std::pair<ir::AstNode *, const ir::AstNode *> GetBBPredCondition(const BasicBlock *bb,
                                                                                   size_t index) const;

    [[nodiscard]] const ir::AstNode *GetBBSuccEdgeLabel(const BasicBlock *bb, size_t index) const;
    [[nodiscard]] ArenaAllocator *Allocator() const;
    [[nodiscard]] const ArenaUnorderedMap<ir::ScriptFunction *, BasicBlock *> &GetFunctionEntries() const;

    [[nodiscard]] const util::UString *GetAnnotation(const BasicBlock *bb) const;

    [[nodiscard]] const ArenaUnorderedMap<ir::AstNode *, ir::AstNode *> &GetSwitchCaseMap() const;

private:
    [[nodiscard]] BasicBlock *CreateNewBB(const std::vector<BasicBlock *> &&preds,
                                          const std::vector<const ir::AstNode *> &&labels = {});

    BasicBlock *Build(ir::AstNode *node, BasicBlock *bb);
    BasicBlock *Build(ir::ArrayExpression *arrayExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::ArrowFunctionExpression *arrowFunctionExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::AssignmentExpression *assignmentExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::BinaryExpression *binaryExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::BlockExpression *blockExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::BlockStatement *blockStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::BreakStatement *breakStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::CallExpression *callExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::CatchClause *catchClauseNode, BasicBlock *bb);
    BasicBlock *Build(ir::ChainExpression *chainExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::ConditionalExpression *conditionalExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::ContinueStatement *continueStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::DoWhileStatement *doWhileStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::ExpressionStatement *expressionStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::ETSNewClassInstanceExpression *etsNewClassInstanceExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::ForOfStatement *forOfStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::ForUpdateStatement *forUpdateStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::IfStatement *ifStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::LabelledStatement *labelledStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::MemberExpression *memberExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::ReturnStatement *returnStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::SwitchStatement *switchStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::ThrowStatement *throwStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::TryStatement *tryStatementNode, BasicBlock *bb);
    BasicBlock *Build(ir::TSAsExpression *asExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::TSNonNullExpression *tsNonNullExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::TypeofExpression *typeofExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::UnaryExpression *unaryExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::UpdateExpression *updateExpressionNode, BasicBlock *bb);
    BasicBlock *Build(ir::VariableDeclaration *variableDeclarationNode, BasicBlock *bb);
    BasicBlock *Build(ir::WhileStatement *whileStatementNode, BasicBlock *bb);

    size_t AddNodeToBB(ir::AstNode *node, BasicBlock *bb);

    void AddBBEdge(BasicBlock *from, BasicBlock *to, const ir::AstNode *label = nullptr);
    void SetBBPredEdgeLabel(const BasicBlock *bb, size_t index, const ir::AstNode *label);
    void SetBBSuccEdgeLabel(const BasicBlock *bb, size_t index, const ir::AstNode *label);

    bool VisitDepthFirst(const CFG::BBTraverser &traverser, const CFG::BasicBlock *bb,
                         ArenaSet<const CFG::BasicBlock *> &visitedBlocks,
                         ArenaVector<BasicBlock *> CFG::BasicBlock::*edges, bool allPath) const;

    void VisitTopOrder(VisitResult &visitResult, const CFG::BasicBlock *bb,
                       ArenaVector<BasicBlock *> CFG::BasicBlock::*edges, bool closeLoop) const;

    void DumpSuccessorEdges(std::ofstream &ofs, BasicBlock *const bb) const;
    void DumpPredecessorEdges(std::ofstream &ofs, BasicBlock *const bb) const;
    void RedirectEmptyBBEdges(CFG::BasicBlock *bb) const;

    BasicBlock *BuildExpressions(ir::AstNode *node, CFG::BasicBlock *bb);
    BasicBlock *BuildETSExpressions(ir::AstNode *node, CFG::BasicBlock *bb);
    BasicBlock *BuildStatements(ir::AstNode *node, CFG::BasicBlock *bb);

private:
    size_t basicBlockIdx_ {0};
    ArenaAllocator *allocator_;
    ArenaSet<BasicBlock *> blocks_;
    ArenaUnorderedMap<ir::AstNode *, std::pair<BasicBlock *, size_t>> nodeBBMap_;
    ArenaUnorderedMap<ir::ScriptFunction *, BasicBlock *> functionNodeBBMap_;
    ArenaUnorderedMap<const BasicBlock *, util::UString> bbAnnotationMap_;
    ArenaUnorderedMap<ir::AstNode *, ir::AstNode *> switchCaseMap_;
    ArenaDoubleUnorderedMap<const BasicBlock *, size_t, const ir::AstNode *> bbSuccLabelMap_;
    ArenaDoubleUnorderedMap<const BasicBlock *, size_t, const ir::AstNode *> bbPredLabelMap_;
    /* Pair of <Continue target, Break target> */
    ArenaUnorderedMap<const ir::AstNode *, std::pair<BasicBlock *, BasicBlock *>> loopStmtJumpTargetMap_;
    size_t inLoop_ {0};
    const ir::BooleanLiteral trueLabel_;
    const ir::BooleanLiteral falseLabel_;
};

}  // namespace ark::es2panda::compiler

namespace enumbitops {

template <>
struct IsAllowedType<ark::es2panda::compiler::CFG::BasicBlockFlags> : std::true_type {
};

}  // namespace enumbitops

#endif
