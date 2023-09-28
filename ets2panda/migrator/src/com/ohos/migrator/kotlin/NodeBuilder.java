/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.kotlin;

import com.ohos.migrator.staticTS.NodeBuilderBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import org.eclipse.jdt.core.dom.Assignment;
import org.jetbrains.kotlin.lexer.KtSingleValueToken;
import org.jetbrains.kotlin.lexer.KtTokens;
import org.jetbrains.kotlin.psi.KtElement;
import org.jetbrains.kotlin.psi.KtModifierListOwner;
import org.jetbrains.kotlin.psi.psiUtil.KtPsiUtilKt;

public class NodeBuilder extends NodeBuilderBase {

    public static AccessibilityModifierContext accessibilityModifier(KtModifierListOwner ktModifierListOwner) {
        int stsModifierCode = -1;
        if (KtPsiUtilKt.isPublic(ktModifierListOwner))
            stsModifierCode = StaticTSParser.Public;
        if (KtPsiUtilKt.isProtected(ktModifierListOwner))
            stsModifierCode = StaticTSParser.Protected;
        if (KtPsiUtilKt.isPrivate(ktModifierListOwner))
            stsModifierCode = StaticTSParser.Private;

        if (stsModifierCode == -1) return null;

        AccessibilityModifierContext stsAccessMod = new AccessibilityModifierContext(null, 0);
        stsAccessMod.addChild(terminalNode(stsModifierCode));
        return stsAccessMod;
    }


    public static SingleExpressionContext untranslatedExpression(KtElement ktElement) {
        return dummyCall(UNTRANSLATED_EXPRESSION, ktElement.getText());
    }

    public static StatementContext untranslatedStatement(KtElement ktElement) {
        StatementContext stsStatement = new StatementContext(null, 0);
        ExpressionStatementContext stsExprStatement = new ExpressionStatementContext(stsStatement, 0);
        stsStatement.addChild(stsExprStatement);
        stsExprStatement.addChild(dummyCall(UNTRANSLATED_STATEMENT, ktElement.getText())).setParent(stsExprStatement);
        return stsStatement;
    }

    public static ClassMemberContext classMember(KtModifierListOwner ktModifierListOwner) {
        ClassMemberContext stsClassMember = new ClassMemberContext(null, 0);
        AccessibilityModifierContext stsAccessMod = NodeBuilder.accessibilityModifier(ktModifierListOwner);
        if (stsAccessMod != null) stsClassMember.addChild(stsAccessMod).setParent(stsClassMember);
        return stsClassMember;
    }

    public static AssignmentOperatorContext assignmentOperator(KtSingleValueToken ktAssignOpToken) {
        int stsOperatorCode = -1;

        if (ktAssignOpToken == KtTokens.PLUSEQ)
            stsOperatorCode = StaticTSParser.PlusAssign;
        else if (ktAssignOpToken == KtTokens.MINUSEQ)
            stsOperatorCode = StaticTSParser.MinusAssign;
        else if (ktAssignOpToken == KtTokens.MULTEQ)
            stsOperatorCode = StaticTSParser.MultiplyAssign;
        else if (ktAssignOpToken == KtTokens.DIVEQ)
            stsOperatorCode = StaticTSParser.DivideAssign;
        else if (ktAssignOpToken == KtTokens.PERCEQ)
            stsOperatorCode = StaticTSParser.ModulusAssign;

        if (stsOperatorCode == -1) return null;

        AssignmentOperatorContext stsAssignOp = new AssignmentOperatorContext(null, 0);
        stsAssignOp.addChild(terminalNode(stsOperatorCode));
        return stsAssignOp;
    }
}
