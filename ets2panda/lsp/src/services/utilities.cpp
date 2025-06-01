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

#include "services/utilities.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/base/classProperty.h"
#include "varbinder/variable.h"
#include "varbinder/declaration.h"
#include "api.h"

namespace ark::es2panda::lsp {

bool IsValidImplementation(ir::AstNode *astNode)
{
    if (astNode == nullptr) {
        return false;
    }

    return !IsThis(astNode) && !IsInitializer(astNode) && !IsReturnNode(astNode) && !IsAsTypeNode(astNode);
}

bool IsInitializer(ir::AstNode *astNode)
{
    return astNode != nullptr && astNode->Parent() != nullptr &&
           ((astNode->IsClassProperty() && astNode->AsClassProperty()->Value() != nullptr) ||
            (astNode->IsAssignmentExpression() &&
             astNode->AsAssignmentExpression()->Target()->Declaration()->IsLetOrConstDecl()) ||
            astNode->IsVariableDeclaration());
}

bool IsThis(ir::AstNode *astNode)
{
    return astNode->IsThisExpression() || astNode->IsTSThisType();
}

bool IsReturnNode(ir::AstNode *astNode)
{
    return astNode != nullptr && astNode->Parent() != nullptr && astNode->Parent()->IsReturnStatement();
}

bool IsAsTypeNode(ir::AstNode *astNode)
{
    return astNode != nullptr && astNode->IsAssignmentExpression() &&
           astNode->AsAssignmentExpression()->Right()->IsTSAsExpression();
}

}  // namespace ark::es2panda::lsp
