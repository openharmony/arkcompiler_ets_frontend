/**
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "util.h"

#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/expressions/identifier.h"

namespace ark::es2panda::compiler {

varbinder::Scope *NearestScope(const ir::AstNode *ast)
{
    while (ast != nullptr && !ast->IsScopeBearer()) {
        ast = ast->Parent();
    }

    return ast == nullptr ? nullptr : ast->Scope();
}

checker::ETSObjectType const *ContainingClass(const ir::AstNode *ast)
{
    while (ast != nullptr && !ast->IsClassDefinition()) {
        ast = ast->Parent();
    }

    return ast == nullptr ? nullptr : ast->AsClassDefinition()->TsType()->AsETSObjectType();
}

ir::Identifier *Gensym(ArenaAllocator *const allocator)
{
    util::UString const s = GenName(allocator);
    return allocator->New<ir::Identifier>(s.View(), allocator);
}

util::UString GenName(ArenaAllocator *const allocator)
{
    static std::size_t gensymCounter = 0U;
    return util::UString {std::string(GENSYM_CORE) + std::to_string(++gensymCounter), allocator};
}

void SetSourceRangesRecursively(ir::AstNode *node, const lexer::SourceRange &range)
{
    node->SetRange(range);
    node->IterateRecursively([](ir::AstNode *n) { n->SetRange(n->Parent()->Range()); });
}

// Function to clear expression node types and identifier node variables (for correct re-binding and re-checking)
void ClearTypesVariablesAndScopes(ir::AstNode *node) noexcept
{
    std::function<void(ir::AstNode *)> doNode = [&](ir::AstNode *nn) {
        if (nn->IsScopeBearer()) {
            nn->ClearScope();
        }
        if (nn->IsTyped() && !(nn->IsExpression() && nn->AsExpression()->IsTypeNode())) {
            nn->AsTyped()->SetTsType(nullptr);
        }
        if (nn->IsIdentifier()) {
            nn->AsIdentifier()->SetVariable(nullptr);
        }
        if (!nn->IsETSTypeReference()) {
            nn->Iterate([&](ir::AstNode *child) { doNode(child); });
        }
    };

    doNode(node);
}

ArenaSet<varbinder::Variable *> FindCaptured(ArenaAllocator *allocator, ir::AstNode *scopeBearer) noexcept
{
    auto result = ArenaSet<varbinder::Variable *> {allocator->Adapter()};
    auto scopes = ArenaSet<varbinder::Scope *> {allocator->Adapter()};
    scopeBearer->IterateRecursivelyPreorder([&result, &scopes](ir::AstNode *ast) {
        if (ast->IsScopeBearer() && ast->Scope() != nullptr) {
            scopes.insert(ast->Scope());
            if (ast->Scope()->IsFunctionScope()) {
                scopes.insert(ast->Scope()->AsFunctionScope()->ParamScope());
            } else if (ast->IsForUpdateStatement() || ast->IsForInStatement() || ast->IsForOfStatement() ||
                       ast->IsCatchClause()) {
                // NOTE(gogabr) LoopScope _does not_ currently respond to IsLoopScope().
                // For now, this is the way to reach LoopDeclarationScope.
                scopes.insert(ast->Scope()->Parent());
            }
        }
        if (ast->IsIdentifier() && !ast->Parent()->IsLabelledStatement()) {
            auto *var = ast->AsIdentifier()->Variable();
            if (var == nullptr || !var->HasFlag(varbinder::VariableFlags::LOCAL)) {
                return;
            }
            auto *sc = var->GetScope();
            if (sc != nullptr && !sc->IsClassScope() && !sc->IsGlobalScope() && scopes.count(var->GetScope()) == 0) {
                result.insert(var);
            }
        }
    });
    return result;
}

// Rerun varbinder on the node. (First clear typesVariables and scopes)
varbinder::Scope *Rebind(varbinder::ETSBinder *varBinder, ir::AstNode *node)
{
    auto *scope = NearestScope(node->Parent());
    auto bscope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, scope);

    ClearTypesVariablesAndScopes(node);
    InitScopesPhaseETS::RunExternalNode(node, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(node, scope);

    return scope;
}

// Rerun varbinder and checker on the node.
void Recheck(varbinder::ETSBinder *varBinder, checker::ETSChecker *checker, ir::AstNode *node)
{
    auto *scope = Rebind(varBinder, node);

    // NOTE(gogabr: should determine checker status more finely.
    auto *containingClass = ContainingClass(node);
    checker::CheckerStatus newStatus =
        (containingClass == nullptr) ? checker::CheckerStatus::NO_OPTS : checker::CheckerStatus::IN_CLASS;
    if ((checker->Context().Status() & checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK) != 0) {
        newStatus |= checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK;
    }
    auto checkerCtx = checker::SavedCheckerContext(checker, newStatus, containingClass);
    auto scopeCtx = checker::ScopeContext(checker, scope);

    node->Check(checker);
}

// NOTE: used to get the declaration from identifier in Plugin API and LSP
ir::AstNode *DeclarationFromIdentifier(ir::Identifier *node)
{
    auto idVar = node->Variable();
    if (idVar == nullptr) {
        return nullptr;
    }
    auto decl = idVar->Declaration();
    if (decl == nullptr) {
        return nullptr;
    }
    return decl->Node();
}

// Note: run varbinder and checker on the new node generated in lowering phases (without ClearTypesVariablesAndScopes)
void CheckLoweredNode(varbinder::ETSBinder *varBinder, checker::ETSChecker *checker, ir::AstNode *node)
{
    InitScopesPhaseETS::RunExternalNode(node, varBinder);
    auto *scope = NearestScope(node);
    varBinder->ResolveReferencesForScopeWithContext(node, scope);

    auto *containingClass = ContainingClass(node);
    checker::CheckerStatus newStatus =
        (containingClass == nullptr) ? checker::CheckerStatus::NO_OPTS : checker::CheckerStatus::IN_CLASS;
    if ((checker->Context().Status() & checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK) != 0) {
        newStatus |= checker::CheckerStatus::IN_EXTENSION_ACCESSOR_CHECK;
    }
    auto checkerCtx = checker::SavedCheckerContext(checker, newStatus, containingClass);
    auto scopeCtx = checker::ScopeContext(checker, scope);

    node->Check(checker);
}

bool IsAnonymousClassType(const checker::Type *type)
{
    if (type == nullptr || !type->IsETSObjectType()) {
        return false;
    }

    auto declNode = type->AsETSObjectType()->GetDeclNode();
    return declNode != nullptr && declNode->IsClassDefinition() && declNode->AsClassDefinition()->IsAnonymous();
}
}  // namespace ark::es2panda::compiler
