/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

package com.ohos.migrator.staticTS;

import com.ohos.migrator.java.NodeBuilder;
import com.ohos.migrator.staticTS.parser.StaticTSContextBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.TerminalNode;

import static com.ohos.migrator.staticTS.parser.StaticTSParser.*;

import java.util.List;

public class NodeClonner {
    static private void copyApiMapperAttrs(StaticTSContextBase origNode, StaticTSContextBase cloneNode) {
        cloneNode.javaImport = origNode.javaImport;
        cloneNode.javaType = origNode.javaType;
        cloneNode.javaTypeArgs = origNode.javaTypeArgs;
        cloneNode.javaName = origNode.javaName;
        cloneNode.javaMethodArgs = origNode.javaMethodArgs;
        cloneNode.javaMethodTypeArgs = origNode.javaMethodTypeArgs;
    }

    // predefinedType: { this.predefinedTypeAhead() }? Identifier
    static public PredefinedTypeContext clone(PredefinedTypeContext srcPredType) {
        PredefinedTypeContext clonePredType = new PredefinedTypeContext(null, 0);

        assert srcPredType.getChild(0) instanceof TerminalNode;

        clonePredType.addChild(NodeBuilder.terminalIdentifier(((TerminalNode)srcPredType.getChild(0)).getText()));

        return clonePredType;
    }

    // qualifiedName: Identifier (Dot Identifier)*
    static public QualifiedNameContext clone(QualifiedNameContext srcQName) {
        QualifiedNameContext cloneQName = new QualifiedNameContext(null, 0);

        for (TerminalNode srcIdent : srcQName.Identifier()) {
            cloneQName.addChild(NodeBuilder.terminalIdentifier(srcIdent.getText()));
        }

        return cloneQName;
    }

    // arrayType
    //    : (predefinedType | typeReference | functionType | (OpenParen nullableType CloseParen))
    //      {this.notLineTerminator()}? (OpenBracket CloseBracket)+
    static public ArrayTypeContext clone(ArrayTypeContext srcArrayType) {
        ArrayTypeContext cloneArrayType = new ArrayTypeContext(null, 0);

        PredefinedTypeContext srcPredType = srcArrayType.predefinedType();
        TypeReferenceContext srcTypeRef = srcArrayType.typeReference();
        FunctionTypeContext srcFunctionType = srcArrayType.functionType();
        if (srcPredType != null) {
            cloneArrayType.addChild(clone(srcPredType)).setParent(cloneArrayType);
        }
        else if (srcTypeRef != null) {
            cloneArrayType.addChild(clone(srcTypeRef)).setParent(cloneArrayType);
        }
        else if (srcFunctionType != null) {
            cloneArrayType.addChild(clone(srcFunctionType)).setParent(cloneArrayType);
        }
        else {
            NullableTypeContext srcNullableType = srcArrayType.nullableType();
            assert(srcNullableType != null);

            cloneArrayType.addChild(clone(srcNullableType)).setParent(cloneArrayType);
        }

        int srcDims = srcArrayType.OpenBracket().size();
        for (int i = 0; i < srcDims; ++i) {
            cloneArrayType.addChild(NodeBuilder.terminalNode(OpenBracket));
            cloneArrayType.addChild(NodeBuilder.terminalNode(CloseBracket));
        }

        return cloneArrayType;
    }

    // wildcardType
    //    : Identifier typeReference
    //    | Identifier typeReference?
    static public WildcardTypeContext clone(WildcardTypeContext srcWildcardType) {
        WildcardTypeContext cloneWildcardType = new WildcardTypeContext(null, 0);

        cloneWildcardType.addChild(NodeBuilder.terminalIdentifier(srcWildcardType.Identifier().getText()));

        TypeReferenceContext srcTypeRef = srcWildcardType.typeReference();
        if (srcTypeRef != null) {
            cloneWildcardType.addChild(clone(srcTypeRef)).setParent(cloneWildcardType);
        }

        return cloneWildcardType;
    }

    // typeArgument: typeReference | arrayType | functionType | wildcardType | nullableType
    static public TypeArgumentContext clone(TypeArgumentContext srcTypArg) {
        TypeArgumentContext cloneTypeArg = new TypeArgumentContext(null, 0);

        TypeReferenceContext srcTypeRef = srcTypArg.typeReference();
        if (srcTypeRef != null) {
            cloneTypeArg.addChild(clone(srcTypeRef)).setParent(cloneTypeArg);
            return cloneTypeArg;
        }

        ArrayTypeContext srcArrayType = srcTypArg.arrayType();
        if (srcArrayType != null) {
            cloneTypeArg.addChild(clone(srcArrayType)).setParent(cloneTypeArg);
            return cloneTypeArg;
        }

        FunctionTypeContext srcFunctionType = srcTypArg.functionType();
        if (srcFunctionType != null) {
            cloneTypeArg.addChild(clone(srcFunctionType)).setParent(cloneTypeArg);
            return cloneTypeArg;
        }

        WildcardTypeContext srcWindcardType = srcTypArg.wildcardType();
        if (srcWindcardType != null) {
            cloneTypeArg.addChild(clone(srcWindcardType)).setParent(cloneTypeArg);
            return cloneTypeArg;
        }

        NullableTypeContext srcNullableType = srcTypArg.nullableType();
        assert(srcNullableType != null);
        cloneTypeArg.addChild(clone(srcNullableType)).setParent(cloneTypeArg);
        return cloneTypeArg;
    }

    // typeArgumentList: typeArgument (Comma typeArgument)*
    static public TypeArgumentListContext clone(TypeArgumentListContext srcTypeArgsList) {
        TypeArgumentListContext cloneTypeArgsList = new TypeArgumentListContext(null, 0);

        for (TypeArgumentContext srcTypeArg : srcTypeArgsList.typeArgument()) {
            cloneTypeArgsList.addChild(clone(srcTypeArg)).setParent(cloneTypeArgsList);
        }

        return cloneTypeArgsList;
    }

    // typeArguments: LessThan typeArgumentList? MoreThan
    static public TypeArgumentsContext clone(TypeArgumentsContext srcTypeArgs) {
        TypeArgumentsContext cloneTypeArgs = new TypeArgumentsContext(null, 0);

        TypeArgumentListContext srcTypeArgsList = srcTypeArgs.typeArgumentList();
        if (srcTypeArgsList != null) {
            cloneTypeArgs.addChild(clone(srcTypeArgsList)).setParent(cloneTypeArgs);
        }

        return cloneTypeArgs;
    }

    // typeReferencePart: qualifiedName typeArguments?
    static public TypeReferencePartContext clone(TypeReferencePartContext srcTypeRefPart) {
        TypeReferencePartContext cloneTypeRefPart = new TypeReferencePartContext(null, 0);

        cloneTypeRefPart.addChild(clone(srcTypeRefPart.qualifiedName())).setParent(cloneTypeRefPart);

        TypeArgumentsContext srcTypeArgs = srcTypeRefPart.typeArguments();
        if (srcTypeArgs != null) {
            cloneTypeRefPart.addChild(clone(srcTypeArgs)).setParent(cloneTypeRefPart);
        }

        return cloneTypeRefPart;
    }

    //typeReference: typeReferencePart (Dot typeReferencePart)*
    static public TypeReferenceContext clone(TypeReferenceContext srcTypeRef) {
        TypeReferenceContext cloneTypeRef = new TypeReferenceContext(null, 0);

        for (TypeReferencePartContext srcTypeRefPart : srcTypeRef.typeReferencePart()) {
            cloneTypeRef.addChild(clone(srcTypeRefPart)).setParent(cloneTypeRef);
        }

        copyApiMapperAttrs(srcTypeRef, cloneTypeRef);
        return cloneTypeRef;
    }

    // functionType
    //    : OpenParen parameterList? CloseParen typeAnnotation Identifier)?
    static public FunctionTypeContext clone(FunctionTypeContext srcFunType) {
        FunctionTypeContext cloneFunType = new FunctionTypeContext(null, 0);

        ParameterListContext srcParamsList = srcFunType.parameterList();
        if (srcParamsList != null) {
            cloneFunType.addChild(clone(srcParamsList)).setParent(cloneFunType);
        }

        TypeAnnotationContext srcTypeAnnot = srcFunType.typeAnnotation();
        cloneFunType.addChild(clone(srcTypeAnnot)).setParent(cloneFunType);

        ThrowsAnnotationContext srcThrowsAnno = srcFunType.throwsAnnotation();
        if (srcThrowsAnno != null) cloneFunType.addChild(clone(srcThrowsAnno)).setParent(cloneFunType);

        return cloneFunType;
    }

    static public ThrowsAnnotationContext clone(ThrowsAnnotationContext srcThowsAnno) {
        ThrowsAnnotationContext cloneThrowsAnno = new ThrowsAnnotationContext(null, 0);

        TerminalNode srcIdentifier = srcThowsAnno.Identifier();
        cloneThrowsAnno.addChild(NodeBuilder.terminalIdentifier(srcIdentifier.getText()));

        return cloneThrowsAnno;
    }

    // primaryType
    //    : predefinedType
    //    | typeReference
    //    | functionType
    //    | arrayType
    //    | nullableType
    static public PrimaryTypeContext clone(PrimaryTypeContext srcPrimType) {
        PrimaryTypeContext clonePrimType = new PrimaryTypeContext(null, 0);

        PredefinedTypeContext srcPredefinedType = srcPrimType.predefinedType();
        if (srcPredefinedType != null) {
            clonePrimType.addChild(clone(srcPredefinedType)).setParent(clonePrimType);
            return clonePrimType;
        }

        TypeReferenceContext srcTypeRef = srcPrimType.typeReference();
        if (srcTypeRef != null) {
            clonePrimType.addChild(clone(srcTypeRef)).setParent(clonePrimType);
            return clonePrimType;
        }

        FunctionTypeContext srcFunType = srcPrimType.functionType();
        if (srcFunType != null) {
            clonePrimType.addChild(clone(srcFunType)).setParent(clonePrimType);
            return clonePrimType;
        }

        ArrayTypeContext srcArrayType = srcPrimType.arrayType();
        if (srcArrayType != null) {
            clonePrimType.addChild(clone(srcArrayType)).setParent(clonePrimType);
            return clonePrimType;
        }

        NullableTypeContext srcNullableType = srcPrimType.nullableType();
        assert(srcNullableType != null);
        clonePrimType.addChild(clone(srcNullableType)).setParent(clonePrimType);
        return clonePrimType;
    }

    // nullableType
    //    : (predefinedType | typeReference | functionType | arrayType | wildcardType) BitOr Null
    static public NullableTypeContext clone(NullableTypeContext srcNullableType) {
        NullableTypeContext cloneNullableType = new NullableTypeContext(null, 0);

        PredefinedTypeContext srcPredefType = srcNullableType.predefinedType();
        if (srcPredefType != null) {
            cloneNullableType.addChild(clone(srcPredefType)).setParent(cloneNullableType);
            return cloneNullableType;
        }

        TypeReferenceContext srcTypeRef = srcNullableType.typeReference();
        if (srcTypeRef != null) {
            cloneNullableType.addChild(clone(srcTypeRef)).setParent(cloneNullableType);
            return cloneNullableType;
        }

        FunctionTypeContext srcFunctionType = srcNullableType.functionType();
        if (srcFunctionType != null) {
            cloneNullableType.addChild(clone(srcFunctionType)).setParent(cloneNullableType);
            return cloneNullableType;
        }

        ArrayTypeContext srcArrayType = srcNullableType.arrayType();
        if (srcArrayType != null) {
            cloneNullableType.addChild(clone(srcArrayType)).setParent(cloneNullableType);
            return cloneNullableType;
        }

        WildcardTypeContext srcWildcardType = srcNullableType.wildcardType();
        assert(srcWildcardType != null);
        cloneNullableType.addChild(clone(srcWildcardType)).setParent(cloneNullableType);
        return cloneNullableType;
    }

    // typeAnnotation: Colon primaryType
    static public TypeAnnotationContext clone(TypeAnnotationContext srcType) {
        TypeAnnotationContext cloneType = new TypeAnnotationContext(null, 0);

        cloneType.addChild(clone(srcType.primaryType())).setParent(cloneType);

        return cloneType;
    }

    // parameter: Identifier typeAnnotation
    static public ParameterContext clone(ParameterContext srcParam) {
        ParameterContext cloneParam = new ParameterContext(null, 0);

        cloneParam.addChild(NodeBuilder.terminalIdentifier(srcParam.Identifier().getText()));
        cloneParam.addChild(clone(srcParam.typeAnnotation())).setParent(cloneParam);

        return cloneParam;
    }

    // variadicParameter: Ellipsis Identifier typeAnnotation
    static public VariadicParameterContext clone(VariadicParameterContext srcVarParam) {
        VariadicParameterContext cloneVarParam = new VariadicParameterContext(null, 0);

        cloneVarParam.addChild(NodeBuilder.terminalIdentifier(srcVarParam.Identifier().getText()));

        TypeAnnotationContext srcTypeAnnot = srcVarParam.typeAnnotation();
        cloneVarParam.addChild(clone(srcTypeAnnot)).setParent(cloneVarParam);

        return cloneVarParam;
    }

    // parameterList:
    //    parameter (Comma parameter)* (Comma variadicParameter)?
    //            | variadicParameter
    static public ParameterListContext clone(ParameterListContext srcParamsList) {
        ParameterListContext cloneParamsList = new ParameterListContext(null, 0);

        List<ParameterContext> srcParams = srcParamsList.parameter();
        if (srcParams != null) {
            for (ParameterContext srcParam : srcParams) {
                cloneParamsList.addChild(clone(srcParam));
            }
        }

        VariadicParameterContext srcVarParam = srcParamsList.variadicParameter();
        if (srcVarParam != null) {
            cloneParamsList.addChild(clone(srcVarParam));
        }

        return cloneParamsList;
    }

    // assertStatement: Assert condition=singleExpression (Colon message=singleExpression)? SemiColon
    static public AssertStatementContext clone(AssertStatementContext srcAssert) {
        AssertStatementContext cloneAssert = new AssertStatementContext(null, 0);

        cloneAssert.addChild(NodeBuilder.terminalNode(Assert));
        cloneAssert.addChild(clone(srcAssert.condition)).setParent(cloneAssert);

        if (srcAssert.message != null) {
            cloneAssert.addChild(clone(srcAssert.message)).setParent(cloneAssert);
        }

        return cloneAssert;
    }

    // ifStatement: If OpenParen singleExpression CloseParen ifStmt=statement (Else elseStmt=statement)?
    static public IfStatementContext clone(IfStatementContext srcIf) {
        IfStatementContext cloneIf = new IfStatementContext(null, 0);

        cloneIf.addChild(NodeBuilder.terminalNode(If));
        cloneIf.addChild(clone(srcIf.singleExpression())).setParent(cloneIf);
        cloneIf.addChild(clone(srcIf.ifStmt)).setParent(cloneIf);

        if (srcIf.elseStmt != null) {
            cloneIf.addChild(NodeBuilder.terminalNode(Else));
            cloneIf.addChild(clone(srcIf.elseStmt)).setParent(cloneIf);
        }

        return cloneIf;
    }

    // variableDeclarationList: variableDeclaration (Comma variableDeclaration)*
    static public VariableDeclarationListContext clone(VariableDeclarationListContext srcVarDeclList) {
        VariableDeclarationListContext cloneVarDeclList = new VariableDeclarationListContext(null, 0);

        for (VariableDeclarationContext srcVarDecl : srcVarDeclList.variableDeclaration()) {
            cloneVarDeclList.addChild(clone(srcVarDecl)).setParent(cloneVarDeclList);
        }

        return cloneVarDeclList;
    }

    // forInit: expressionSequence | Let variableDeclarationList
    static public ForInitContext clone(ForInitContext srcInit) {
        ForInitContext cloneInit = new ForInitContext(null, 0);

        ExpressionSequenceContext srcExprSequence = srcInit.expressionSequence();
        if (srcExprSequence != null) {
            cloneInit.addChild(clone(srcExprSequence)).setParent(cloneInit);
        }
        else {
            cloneInit.addChild(NodeBuilder.terminalNode(Let));
            cloneInit.addChild(clone(srcInit.variableDeclarationList())).setParent(cloneInit);
        }

        return cloneInit;
    }

    // iterationStatement
    //    : Do statement While OpenParen singleExpression CloseParen SemiColon                                     # DoStatement
    //    | While OpenParen singleExpression CloseParen statement                                                  # WhileStatement
    //    | For OpenParen forInit? SemiColon singleExpression? SemiColon expressionSequence? CloseParen statement  # ForStatement
    //    | For OpenParen Let Identifier typeAnnotation? Of singleExpression CloseParen statement                  # ForOfStatement
    static public IterationStatementContext clone(IterationStatementContext srcIteration) {
        IterationStatementContext cloneIteration = new IterationStatementContext(null, 0);

        ParseTree srcChild = srcIteration.getChild(0);

        if (srcChild instanceof DoStatementContext) {
            // : Do statement While OpenParen singleExpression CloseParen SemiColon   # DoStatement
            DoStatementContext srcDo = (DoStatementContext)srcChild;
            DoStatementContext cloneDo = new DoStatementContext(cloneIteration);
            cloneIteration.addChild(cloneDo);
            cloneDo.addChild(NodeBuilder.terminalNode(Do));
            cloneDo.addChild(clone(srcDo.statement())).setParent(cloneDo);
            cloneDo.addChild(NodeBuilder.terminalNode(While));
            cloneDo.addChild(NodeBuilder.terminalNode(OpenParen));
            cloneDo.addChild(clone(srcDo.singleExpression())).setParent(cloneDo);
            cloneDo.addChild(NodeBuilder.terminalNode(CloseParen));
        }
        else if (srcChild instanceof WhileStatementContext) {
            // | While OpenParen singleExpression CloseParen statement  # WhileStatement
            WhileStatementContext srcWhile = (WhileStatementContext)srcChild;
            WhileStatementContext cloneWile = new WhileStatementContext(cloneIteration);
            cloneIteration.addChild(cloneWile);
            cloneWile.addChild(NodeBuilder.terminalNode(OpenParen));
            cloneWile.addChild(clone(srcWhile.singleExpression())).setParent(cloneWile);
            cloneWile.addChild(NodeBuilder.terminalNode(CloseParen));
        }
        else if (srcChild instanceof ForStatementContext) {
            // | For OpenParen forInit? SemiColon singleExpression? SemiColon expressionSequence? CloseParen statement  # ForStatement
            ForStatementContext srcFor = (ForStatementContext)srcChild;
            ForStatementContext cloneFor = new ForStatementContext(cloneIteration);
            cloneIteration.addChild(cloneFor);
            cloneFor.addChild(NodeBuilder.terminalNode(For));
            cloneFor.addChild(NodeBuilder.terminalNode(OpenParen));

            ForInitContext srcInit = srcFor.forInit();
            if (srcInit != null) {
                cloneFor.addChild(clone(srcInit)).setParent(cloneFor);
            }

            SingleExpressionContext srcExpr = srcFor.singleExpression();
            if (srcExpr != null) {
                cloneFor.addChild(clone(srcExpr)).setParent(cloneFor);
            }

            ExpressionSequenceContext srcExprSequence = srcFor.expressionSequence();
            if (srcExprSequence != null) {
                cloneFor.addChild(clone(srcExprSequence)).setParent(cloneFor);
            }

            cloneFor.addChild(NodeBuilder.terminalNode(CloseParen));
        }
        else {
            // | For OpenParen Let Identifier typeAnnotation? Of singleExpression CloseParen statement # ForOfStatement
            // | For OpenParen Let Identifier typeAnnotation? { this.next(OF) }? Identifier singleExpression CloseParen statement                                                                  # ForOfStatement
            assert (srcChild instanceof ForOfStatementContext);
            ForOfStatementContext srcFor = (ForOfStatementContext)srcChild;
            ForOfStatementContext cloneFor = new ForOfStatementContext(cloneIteration);
            cloneIteration.addChild(cloneFor);
            cloneFor.addChild(NodeBuilder.terminalNode(For));
            cloneFor.addChild(NodeBuilder.terminalNode(OpenParen));
            cloneFor.addChild(NodeBuilder.terminalNode(Let));


            List<TerminalNode> identifiers = srcFor.Identifier();
            String identifier = identifiers.get(0).getText();
            // Note: there is no 100% guaranty the first identifier in the list is not 'of'.
            if (OF.equals(identifier))
                identifier = identifiers.get(1).getText();

            cloneFor.addChild(NodeBuilder.terminalIdentifier(identifier));

            TypeAnnotationContext srcTypeAnn = srcFor.typeAnnotation();
            if (srcTypeAnn != null) {
                cloneFor.addChild(clone(srcTypeAnn)).setParent(cloneFor);
            }

            cloneFor.addChild(NodeBuilder.terminalIdentifier(OF));
            cloneFor.addChild(clone(srcFor.singleExpression())).setParent(cloneFor);
            cloneFor.addChild(NodeBuilder.terminalNode(CloseParen));
        }

        return cloneIteration;
    }

    // continueStatement: Continue ({this.notLineTerminator()}? Identifier)? SemiColon
    static public ContinueStatementContext clone(ContinueStatementContext srcContinue) {
        ContinueStatementContext cloneContinue = new ContinueStatementContext(null, 0);

        cloneContinue.addChild(NodeBuilder.terminalNode(Continue));

        TerminalNode srcIdentifier = srcContinue.Identifier();
        if (srcIdentifier != null) {
            cloneContinue.addChild(NodeBuilder.terminalIdentifier(srcIdentifier.getText()));
        }

        return cloneContinue;
    }

    // breakStatement: Break ({this.notLineTerminator()}? Identifier)? SemiColon
    static public BreakStatementContext clone(BreakStatementContext srcBreak) {
        BreakStatementContext cloneBreak = new BreakStatementContext(null, 0);

        cloneBreak.addChild(NodeBuilder.terminalNode(Break));

        TerminalNode srcIdentifier = srcBreak.Identifier();
        if (srcIdentifier != null) {
            cloneBreak.addChild(NodeBuilder.terminalIdentifier(srcIdentifier.getText()));
        }

        return cloneBreak;
    }

    // returnStatement: Return ({this.notLineTerminator()}? singleExpression)? SemiColon
    static public ReturnStatementContext clone(ReturnStatementContext srcReturn) {
        ReturnStatementContext cloneReturn = new ReturnStatementContext(null, 0);

        cloneReturn.addChild(NodeBuilder.terminalNode(Return));

        SingleExpressionContext srcExpr = srcReturn.singleExpression();
        if (srcExpr != null) {
            cloneReturn.addChild(clone(srcExpr)).setParent(cloneReturn);
        }

        return cloneReturn;
    }

    // labelledStatement: Identifier Colon statement
    static public LabelledStatementContext clone(LabelledStatementContext srcLabelled) {
        LabelledStatementContext cloneLabelled = new LabelledStatementContext(null, 0);
        cloneLabelled.addChild(NodeBuilder.terminalIdentifier(srcLabelled.Identifier().getText()));
        cloneLabelled.addChild(NodeBuilder.terminalNode(Colon));
        cloneLabelled.addChild(clone(srcLabelled.statement())).setParent(cloneLabelled);
        return cloneLabelled;
    }

    // caseClause: Case singleExpression ':' statement*
    static public CaseClauseContext clone(CaseClauseContext srcCase) {
        CaseClauseContext cloneCase = new CaseClauseContext(null, 0);
        cloneCase.addChild(NodeBuilder.terminalNode(Case));
        cloneCase.addChild(clone(srcCase.singleExpression())).setParent(cloneCase);
        cloneCase.addChild(NodeBuilder.terminalNode(Colon));

        for (StatementContext srcStmt : srcCase.statement()) {
            cloneCase.addChild(clone(srcStmt)).setParent(cloneCase);
        }

        return cloneCase;
    }

    // caseClauses: caseClause+
    static public CaseClausesContext clone(CaseClausesContext srcCaseClasuses) {
        CaseClausesContext cloneCaseClauses = new CaseClausesContext(null, 0);

        for (CaseClauseContext srcCase : srcCaseClasuses.caseClause()) {
            cloneCaseClauses.addChild(clone(srcCase)).setParent(cloneCaseClauses);
        }

        return cloneCaseClauses;
    }

    // defaultClause: { DEFAULT }? Identifier ':' statement*
    static public DefaultClauseContext clone(DefaultClauseContext srcDefault) {
        DefaultClauseContext cloneDefault = new DefaultClauseContext(null, 0);
        cloneDefault.addChild(NodeBuilder.terminalIdentifier(DEFAULT));
        cloneDefault.addChild(NodeBuilder.terminalNode(Colon));

        for (StatementContext srcStmt : srcDefault.statement()) {
            cloneDefault.addChild(clone(srcStmt)).setParent(cloneDefault);
        }

        return cloneDefault;
    }

    // caseBlock: OpenBrace leftCases=caseClauses? defaultClause? rightCases=caseClauses? CloseBrace
    static public CaseBlockContext clone(CaseBlockContext srcCaseBlock) {
        CaseBlockContext cloneCaseBlock = new CaseBlockContext(null, 0);

        cloneCaseBlock.addChild(NodeBuilder.terminalNode(OpenBrace));

        if (srcCaseBlock.leftCases != null) {
            cloneCaseBlock.addChild(clone(srcCaseBlock.leftCases)).setParent(cloneCaseBlock);
        }

        DefaultClauseContext srcDefault = srcCaseBlock.defaultClause();
        if (srcDefault != null) {
            cloneCaseBlock.addChild(clone(srcDefault)).setParent(cloneCaseBlock);
        }

        if (srcCaseBlock.rightCases != null) {
            cloneCaseBlock.addChild(clone(srcCaseBlock.rightCases)).setParent(cloneCaseBlock);
        }

        cloneCaseBlock.addChild(NodeBuilder.terminalNode(CloseBrace));

        return cloneCaseBlock;
    }

    // switchStatement: Switch OpenParen singleExpression CloseParen caseBlock
    static public SwitchStatementContext clone(SwitchStatementContext srcSwitch) {
        SwitchStatementContext cloneSwitch = new SwitchStatementContext(null, 0);
        cloneSwitch.addChild(NodeBuilder.terminalNode(Switch));
        cloneSwitch.addChild(NodeBuilder.terminalNode(OpenParen));
        cloneSwitch.addChild(clone(srcSwitch.singleExpression())).setParent(cloneSwitch);
        cloneSwitch.addChild(NodeBuilder.terminalNode(CloseParen));
        cloneSwitch.addChild(clone(srcSwitch.caseBlock())).setParent(cloneSwitch);
        return cloneSwitch;
    }
    
    // throwStatement: Throw {this.notLineTerminator()}? singleExpression SemiColon
    static public ThrowStatementContext clone(ThrowStatementContext srcThrow) {
        ThrowStatementContext cloneThrow = new ThrowStatementContext(null, 0);
        cloneThrow.addChild(NodeBuilder.terminalNode(Throw));
        cloneThrow.addChild(clone(srcThrow.singleExpression())).setParent(cloneThrow);
        return cloneThrow;
    }

    // deferStatement: Defer statement
    static public DeferStatementContext clone(DeferStatementContext srcDefer) {
        DeferStatementContext cloneDefer = new DeferStatementContext(null, 0);
        cloneDefer.addChild(NodeBuilder.terminalNode(Defer));
        cloneDefer.addChild(clone(srcDefer.statement())).setParent(cloneDefer);
        return cloneDefer;
    }

    // exceptionParameter: OpenParen Identifier typeAnnotation CloseParen
    static public ExceptionParameterContext clone(ExceptionParameterContext srcExeptionParam) {
        ExceptionParameterContext cloneExceptionParam = new ExceptionParameterContext(null, 0);
        cloneExceptionParam.addChild(NodeBuilder.terminalNode(OpenParen));
        cloneExceptionParam.addChild(NodeBuilder.terminalIdentifier(srcExeptionParam.Identifier().getText()));
        cloneExceptionParam.addChild(clone(srcExeptionParam.typeAnnotation())).setParent(cloneExceptionParam);
        cloneExceptionParam.addChild(NodeBuilder.terminalNode(CloseParen));
        return cloneExceptionParam;
    }

    // catchClause: CATCH exceptionParameter block
    static public CatchClauseContext clone(CatchClauseContext srcCatch) {
        CatchClauseContext cloneCatch = new CatchClauseContext(null, 0);

        cloneCatch.addChild(NodeBuilder.terminalIdentifier(srcCatch.Identifier().getText()));

        ExceptionParameterContext srcExeptionParam = srcCatch.exceptionParameter();
        if (srcExeptionParam != null) {
            cloneCatch.addChild(clone(srcExeptionParam)).setParent(cloneCatch);
        }

        cloneCatch.addChild(clone(srcCatch.block())).setParent(cloneCatch);

        return cloneCatch;
    }

    // tryStatement: Try block (catchClause+ | catchClause* defaultCatch)
    static public TryStatementContext clone(TryStatementContext srcTry) {
        TryStatementContext cloneTry = new TryStatementContext(null, 0);
        cloneTry.addChild(NodeBuilder.terminalNode(Try));
        cloneTry.addChild(clone(srcTry.block())).setParent(cloneTry);

        for (CatchClauseContext srcCatch : srcTry.catchClause()) {
            cloneTry.addChild(clone(srcCatch)).setParent(cloneTry);
        }

        return cloneTry;
    }

    // expressionStatement: {this.notOpenBraceAndNotFunction()}? singleExpression SemiColon?
    static public ExpressionStatementContext clone(ExpressionStatementContext srcExpr) {
        ExpressionStatementContext cloneExpr = new ExpressionStatementContext(null, 0);
        cloneExpr.addChild(clone(srcExpr.singleExpression())).setParent(cloneExpr);
        return cloneExpr;
    }

    // statement
    //    : block
    //    | assertStatement
    //    | ifStatement
    //    | iterationStatement
    //    | continueStatement
    //    | breakStatement
    //    | returnStatement
    //    | labelledStatement
    //    | switchStatement
    //    | throwStatement
    //    | deferStatement
    //    | tryStatement
    //    | expressionStatement
    static public StatementContext clone(StatementContext srcStmt) {
        StatementContext cloneStmt = new StatementContext(null, 0);

        BlockContext srcBlock = srcStmt.block();
        if (srcBlock != null) {
            cloneStmt.addChild(clone(srcBlock)).setParent(cloneStmt);
            return cloneStmt;
        }

        AssertStatementContext srcAssert = srcStmt.assertStatement();
        if (srcAssert != null) {
            cloneStmt.addChild(clone(srcAssert)).setParent(cloneStmt);
            return cloneStmt;
        }

        IfStatementContext srcIf = srcStmt.ifStatement();
        if (srcIf != null) {
            cloneStmt.addChild(clone(srcIf)).setParent(cloneStmt);
            return cloneStmt;
        }

        IterationStatementContext srcIteration = srcStmt.iterationStatement();
        if (srcIteration != null) {
            cloneStmt.addChild(clone(srcIteration)).setParent(cloneStmt);
            return cloneStmt;
        }

        ContinueStatementContext srcContinue = srcStmt.continueStatement();
        if (srcContinue != null) {
            cloneStmt.addChild(clone(srcContinue)).setParent(cloneStmt);
            return cloneStmt;
        }

        BreakStatementContext srcBreak = srcStmt.breakStatement();
        if (srcBreak != null) {
            cloneStmt.addChild(clone(srcBreak)).setParent(cloneStmt);
            return cloneStmt;
        }

        ReturnStatementContext srcReturn = srcStmt.returnStatement();
        if (srcReturn != null) {
            cloneStmt.addChild(clone(srcReturn)).setParent(cloneStmt);
            return cloneStmt;
        }

        LabelledStatementContext srcLabeled = srcStmt.labelledStatement();
        if (srcLabeled != null) {
            cloneStmt.addChild(clone(srcLabeled)).setParent(cloneStmt);
            return cloneStmt;
        }

        SwitchStatementContext srcSwitch = srcStmt.switchStatement();
        if (srcSwitch != null) {
            cloneStmt.addChild(clone(srcSwitch)).setParent(cloneStmt);
            return cloneStmt;
        }

        ThrowStatementContext srcThrow = srcStmt.throwStatement();
        if (srcThrow != null) {
            cloneStmt.addChild(clone(srcThrow)).setParent(cloneStmt);
            return cloneStmt;
        }

        DeferStatementContext srcDefer = srcStmt.deferStatement();
        if (srcDefer != null) {
            cloneStmt.addChild(clone(srcDefer)).setParent(cloneStmt);
            return cloneStmt;
        }

        TryStatementContext srcTry = srcStmt.tryStatement();
        if (srcTry != null) {
            cloneStmt.addChild(clone(srcTry)).setParent(cloneStmt);
            return cloneStmt;
        }

        ExpressionStatementContext srcExpr = srcStmt.expressionStatement();
        assert (srcExpr != null);
        cloneStmt.addChild(clone(srcExpr)).setParent(cloneStmt);
        return cloneStmt;
    }

    // constantDeclarationList: constantDeclaration (Comma constantDeclaration)*
    static public ConstantDeclarationListContext clone(ConstantDeclarationListContext srcConstList) {
        ConstantDeclarationListContext cloneConstList = new ConstantDeclarationListContext(null, 0);

        for (ConstantDeclarationContext srcConst : srcConstList.constantDeclaration()) {
            cloneConstList.addChild(clone(srcConst)).setParent(cloneConstList);
        }

        return cloneConstList;
    }

    // variableOrConstantDeclaration: ((Let variableDeclarationList) | (Const constantDeclarationList)) SemiColon
    static public VariableOrConstantDeclarationContext clone(VariableOrConstantDeclarationContext srcVarOrConstDecl) {
        VariableOrConstantDeclarationContext cloneVarOrConstDecl = new VariableOrConstantDeclarationContext(null, 0);

        if (srcVarOrConstDecl.Let() != null) {
            cloneVarOrConstDecl.addChild(NodeBuilder.terminalNode(Let));
            cloneVarOrConstDecl.addChild(clone(srcVarOrConstDecl.variableDeclarationList())).setParent(cloneVarOrConstDecl);
        }
        else {
            cloneVarOrConstDecl.addChild(NodeBuilder.terminalNode(Const));
            cloneVarOrConstDecl.addChild(clone(srcVarOrConstDecl.constantDeclarationList())).setParent(cloneVarOrConstDecl);
        }

        return cloneVarOrConstDecl;
    }

    // statementOrLocalDeclaration
    //    : statement
    //    | variableOrConstantDeclaration
    //    | interfaceDeclaration
    //    | classDeclaration
    //    | enumDeclaration
    static public StatementOrLocalDeclarationContext clone(StatementOrLocalDeclarationContext srcStmtOrDecl) {
        StatementOrLocalDeclarationContext cloneStmtOrDecl = new StatementOrLocalDeclarationContext(null, 0);

        StatementContext srcStmt = srcStmtOrDecl.statement();
        if (srcStmt != null) {
            cloneStmtOrDecl.addChild(clone(srcStmt)).setParent(cloneStmtOrDecl);
        }

        VariableOrConstantDeclarationContext srcVarOrConst = srcStmtOrDecl.variableOrConstantDeclaration();
        if (srcVarOrConst != null) {
            cloneStmtOrDecl.addChild(clone(srcVarOrConst)).setParent(cloneStmtOrDecl);
        }

        InterfaceDeclarationContext srcInterfaceDecl = srcStmtOrDecl.interfaceDeclaration();
        if (srcInterfaceDecl != null) {
            cloneStmtOrDecl.addChild(clone(srcInterfaceDecl)).setParent(cloneStmtOrDecl);
        }

        ClassDeclarationContext srcClassDecl = srcStmtOrDecl.classDeclaration();
        if (srcClassDecl != null) {
            cloneStmtOrDecl.addChild(clone(srcClassDecl)).setParent(cloneStmtOrDecl);
        }

        EnumDeclarationContext srcEnumDecl = srcStmtOrDecl.enumDeclaration();
        if (srcEnumDecl != null) {
            cloneStmtOrDecl.addChild(clone(srcEnumDecl)).setParent(cloneStmtOrDecl);
        }

        return cloneStmtOrDecl;
    }

    // block: OpenBrace statementOrLocalDeclaration* CloseBrace
    static public BlockContext clone(BlockContext srcBlock) {
        BlockContext cloneBlock = new BlockContext(null, 0);

        for (StatementOrLocalDeclarationContext srcStmt : srcBlock.statementOrLocalDeclaration()) {
            cloneBlock.addChild(clone(srcStmt)).setParent(cloneBlock);
        }

        return cloneBlock;
    }

    // lambdaBody: singleExpression | block
    static public LambdaBodyContext clone(LambdaBodyContext srcLambda) {
        LambdaBodyContext cloneLambda = new LambdaBodyContext(null, 0);

        SingleExpressionContext srcSinglExpr = srcLambda.singleExpression();
        if (srcSinglExpr != null) {
            cloneLambda.addChild(clone(srcSinglExpr)).setParent(cloneLambda);
        }

        BlockContext srcBlock = srcLambda.block();
        if (srcBlock != null) {
            cloneLambda.addChild(clone(srcBlock)).setParent(cloneLambda);
        }

        return cloneLambda;
    }

    // indexExpression: OpenBracket singleExpression CloseBracket
    static public IndexExpressionContext clone(IndexExpressionContext srcIndex) {
        IndexExpressionContext cloneIndex = new IndexExpressionContext(null, 0);
        cloneIndex.addChild(clone(srcIndex.singleExpression())).setParent(cloneIndex);
        return cloneIndex;
    }

    // expressionSequence: singleExpression (Comma singleExpression)*
    static public ExpressionSequenceContext clone(ExpressionSequenceContext srcExprSeq) {
        ExpressionSequenceContext cloneExprSeq = new ExpressionSequenceContext(null, 0);

        for (SingleExpressionContext srcExpr : srcExprSeq.singleExpression()) {
            cloneExprSeq.addChild(clone(srcExpr)).setParent(cloneExprSeq);
        }

        return cloneExprSeq;
    }

    // arguments: OpenParen expressionSequence? CloseParen
    static public ArgumentsContext clone(ArgumentsContext srcArgs) {
        ArgumentsContext cloneArgs = new ArgumentsContext(null, 0);

        ExpressionSequenceContext srcExprSeq = srcArgs.expressionSequence();
        if (srcExprSeq != null) {
            cloneArgs.addChild(clone(srcExprSeq)).setParent(cloneArgs);
        }

        return cloneArgs;
    }

    // accessibilityModifier: Public | Private | Protected
    static public AccessibilityModifierContext clone(AccessibilityModifierContext srcModifier) {
        AccessibilityModifierContext cloneModifier = new AccessibilityModifierContext(null, 0);
        assert (srcModifier.getChildCount() > 0);
        TerminalNode srcTerminal = (TerminalNode)srcModifier.getChild(0);
        cloneModifier.addChild(NodeBuilder.terminalNode(srcTerminal.getSymbol().getType()));
        return cloneModifier;
    }

    // intersectionType: OpenParen typeReference (BitAnd typeReference)+ CloseParen
    static public IntersectionTypeContext clone(IntersectionTypeContext srcIntersection) {
        IntersectionTypeContext cloneIntersection = new IntersectionTypeContext(null, 0);

        for (TypeReferenceContext srcTypeRef : srcIntersection.typeReference()) {
            cloneIntersection.addChild(clone(srcTypeRef)).setParent(cloneIntersection);
        }

        return cloneIntersection;
    }

    // constraint: { EXTENDS }? Identifier (typeReference | intersectionType)
    static public ConstraintContext clone(ConstraintContext srcConstraint) {
        ConstraintContext cloneConstraint = new ConstraintContext(null, 0);

        cloneConstraint.addChild(NodeBuilder.terminalIdentifier(EXTENDS));

        TypeReferenceContext srcTypeRef = srcConstraint.typeReference();
        if (srcTypeRef != null) {
            cloneConstraint.addChild(clone(srcTypeRef)).setParent(cloneConstraint);
        }

        IntersectionTypeContext srcIntersection = srcConstraint.intersectionType();
        if (srcIntersection != null) {
            cloneConstraint.addChild(clone(srcIntersection)).setParent(cloneConstraint);
        }

        return cloneConstraint;
    }

    // typeParameter: ({ IN) || OUT) }? Identifier)? Identifier constraint?
    static public TypeParameterContext clone(TypeParameterContext srcTypeParam) {
        TypeParameterContext cloneTypeParam = new TypeParameterContext(null, 0);

        for (TerminalNode srcTerm : srcTypeParam.Identifier()) {
            cloneTypeParam.addChild(NodeBuilder.terminalIdentifier(srcTerm.getText()));
        }

        ConstraintContext srcConstraint = srcTypeParam.constraint();
        if (srcConstraint != null) {
            cloneTypeParam.addChild(clone(srcConstraint)).setParent(cloneTypeParam);
        }

        return cloneTypeParam;
    }

    // typeParameterList: typeParameter (Comma typeParameter)*
    static public TypeParameterListContext clone(TypeParameterListContext srcTypeParamsList) {
        TypeParameterListContext cloneTypeParamsList = new TypeParameterListContext(null, 0);

        for (TypeParameterContext srcTypeParam : srcTypeParamsList.typeParameter()) {
            cloneTypeParamsList.addChild(clone(srcTypeParam)).setParent(cloneTypeParamsList);
        }

        return cloneTypeParamsList;
    }

    // typeParameters: LessThan typeParameterList MoreThan
    static public TypeParametersContext clone(TypeParametersContext srcTypeParams) {
        TypeParametersContext cloneTypeParams = new TypeParametersContext(null, 0);

        TypeParameterListContext srcTypeParamsList = srcTypeParams.typeParameterList();
        cloneTypeParams.addChild(clone(srcTypeParamsList)).setParent(cloneTypeParams);

        return cloneTypeParams;
    }

    // constructorCall
    //      This typeArguments? arguments
    //      | (singleExpression Dot)? Super typeArguments? arguments
    static public ConstructorCallContext clone(ConstructorCallContext srcConstCall) {
        ConstructorCallContext cloneConstCall = new ConstructorCallContext(null, 0);

        if (srcConstCall.This() != null) {
            cloneConstCall.addChild(NodeBuilder.terminalNode(This));
        }
        else {
            assert (srcConstCall.Super() != null);
            SingleExpressionContext srcSingleExpr = srcConstCall.singleExpression();
            if (srcSingleExpr != null) {
                cloneConstCall.addChild(clone(srcSingleExpr)).setParent(cloneConstCall);
            }
        }

        TypeArgumentsContext srcTypeArgs = srcConstCall.typeArguments();
        if (srcTypeArgs != null) {
            cloneConstCall.addChild(clone(srcTypeArgs)).setParent(cloneConstCall);
        }

        ArgumentsContext srcArgs = srcConstCall.arguments();
        cloneConstCall.addChild(clone(srcArgs)).setParent(cloneConstCall);

        return cloneConstCall;
    }

    // constructorBody: OpenBrace constructorCall? statementOrLocalDeclaration* CloseBrace
    static public ConstructorBodyContext clone(ConstructorBodyContext srcConstBody) {
        ConstructorBodyContext cloneConstBody = new ConstructorBodyContext(null, 0);

        ConstructorCallContext srcConstCall = srcConstBody.constructorCall();
        if (srcConstCall != null) {
            cloneConstBody.addChild(clone(srcConstCall)).setParent(cloneConstBody);
        }

        for (StatementOrLocalDeclarationContext srcStmtOrDecl : srcConstBody.statementOrLocalDeclaration()) {
            cloneConstBody.addChild(clone(srcStmtOrDecl)).setParent(cloneConstBody);
        }

        return cloneConstBody;
    }

    // constructorDeclaration: Constructor typeParameters? OpenParen parameterList? CloseParen ({ THROWS) || RETHROWS) }? Identifier)? constructorBody
    static public ConstructorDeclarationContext clone(ConstructorDeclarationContext srcConstructor) {
        ConstructorDeclarationContext cloneConstructor = new ConstructorDeclarationContext(null, 0);

        cloneConstructor.addChild(NodeBuilder.terminalNode(Constructor));

        TypeParametersContext srcTypeParams = srcConstructor.typeParameters();
        if (srcTypeParams != null) {
            cloneConstructor.addChild(clone(srcTypeParams)).setParent(cloneConstructor);
        }

        ParameterListContext srcParamsList = srcConstructor.parameterList();
        if (srcParamsList != null) {
            cloneConstructor.addChild(clone(srcParamsList)).setParent(cloneConstructor);
        }

        ThrowsAnnotationContext srcThrowsAnno = srcConstructor.throwsAnnotation();
        if (srcThrowsAnno != null) {
            cloneConstructor.addChild(clone(srcThrowsAnno)).setParent(cloneConstructor);
        }

        ConstructorBodyContext srcConstBody = srcConstructor.constructorBody();
        cloneConstructor.addChild(clone(srcConstBody)).setParent(cloneConstructor);

        return cloneConstructor;
    }

    // initializer: Assign singleExpression
    static public InitializerContext clone(InitializerContext srcInit) {
        InitializerContext cloneInit = new InitializerContext(null, 0);

        cloneInit.addChild(clone(srcInit.singleExpression())).setParent(cloneInit);

        return cloneInit;
    }

    // variableDeclaration: Identifier typeAnnotation initializer? | Identifier initializer
    static public VariableDeclarationContext clone(VariableDeclarationContext srcVar) {
        VariableDeclarationContext cloneVar = new VariableDeclarationContext(null, 0);

        TerminalNode srcIdentifier = srcVar.Identifier();
        cloneVar.addChild(NodeBuilder.terminalIdentifier(srcIdentifier.getText()));

        TypeAnnotationContext srcTypeAnn = srcVar.typeAnnotation();
        if (srcTypeAnn != null) {
            cloneVar.addChild(clone(srcTypeAnn)).setParent(cloneVar);
        }

        InitializerContext srcInit = srcVar.initializer();
        if (srcInit != null) {
            cloneVar.addChild(clone(srcInit)).setParent(cloneVar);
        }

        return cloneVar;
    }

    // constantDeclaration: Identifier typeAnnotation? initializer
    static public ConstantDeclarationContext clone(ConstantDeclarationContext srcConst) {
        ConstantDeclarationContext cloneConst = new ConstantDeclarationContext(null, 0);

        cloneConst.addChild(NodeBuilder.terminalIdentifier(srcConst.Identifier().getText()));

        TypeAnnotationContext srcTypeAnn = srcConst.typeAnnotation();
        if (srcTypeAnn != null) {
            cloneConst.addChild(clone(srcTypeAnn)).setParent(cloneConst);
        }

        cloneConst.addChild(clone(srcConst.initializer())).setParent(cloneConst);

        return cloneConst;
    }

    // classFieldDeclaration
    //    : Static? (variableDeclaration | Const constantDeclaration) SemiColon
    //    | Const Static? constantDeclaration SemiColon
    static public ClassFieldDeclarationContext clone(ClassFieldDeclarationContext srcFieldDecl) {
        ClassFieldDeclarationContext cloneFieldDecl = new ClassFieldDeclarationContext(null, 0);

        if (srcFieldDecl.Static() != null) {
            cloneFieldDecl.addChild(NodeBuilder.terminalNode(Static));
        }

        if (srcFieldDecl.Identifier() != null) {
            cloneFieldDecl.addChild(NodeBuilder.terminalIdentifier(srcFieldDecl.Identifier().getText()));
        }

        VariableDeclarationContext srcVar = srcFieldDecl.variableDeclaration();
        if (srcVar != null) {
            cloneFieldDecl.addChild(clone(srcVar)).setParent(cloneFieldDecl);
        }

        ConstantDeclarationContext srcConst = srcFieldDecl.constantDeclaration();
        if (srcConst != null) {
            cloneFieldDecl.addChild(clone(srcConst)).setParent(cloneFieldDecl);
        }

        return cloneFieldDecl;
    }

    // classGetterDeclaration
    //    : (Static | Override | Open)? getterHeader block
    //    | Abstract getterHeader SemiColon?
    static public ClassGetterDeclarationContext clone(ClassGetterDeclarationContext srcGetter) {
        ClassGetterDeclarationContext cloneGetter = new ClassGetterDeclarationContext(null, 0);

        if (srcGetter.Abstract() != null) cloneGetter.addChild(NodeBuilder.terminalNode(Abstract));
        if (srcGetter.Override() != null) cloneGetter.addChild(NodeBuilder.terminalNode(Override));
        if (srcGetter.Static() != null) cloneGetter.addChild(NodeBuilder.terminalNode(Static));
        if (srcGetter.Open() != null) cloneGetter.addChild(NodeBuilder.terminalNode(Open));

        cloneGetter.addChild(clone(srcGetter.getterHeader())).setParent(cloneGetter);

        if (srcGetter.block() != null)
            cloneGetter.addChild(clone(srcGetter.block())).setParent(cloneGetter);

        return cloneGetter;
    }

    // getterHeader
    //    : { this.next(StaticTSParser.GET) }? Identifier Identifier OpenParen CloseParen typeAnnotation
    static public GetterHeaderContext clone(GetterHeaderContext srcGetterHeader) {
        GetterHeaderContext cloneGetterHeader = new GetterHeaderContext(null, 0);

        cloneGetterHeader.addChild(NodeBuilder.terminalIdentifier(srcGetterHeader.Identifier(0).getText()));
        cloneGetterHeader.addChild(NodeBuilder.terminalIdentifier(srcGetterHeader.Identifier(1).getText()));

        cloneGetterHeader.addChild(clone(srcGetterHeader.typeAnnotation())).setParent(cloneGetterHeader);

        return cloneGetterHeader;
    }

    // classSetterDeclaration
    //    : (Static | Override | Open)? setterHeader block
    //    | Abstract setterHeader SemiColon?
    static public ClassSetterDeclarationContext clone(ClassSetterDeclarationContext srcSetter) {
        ClassSetterDeclarationContext cloneSetter = new ClassSetterDeclarationContext(null, 0);

        if (srcSetter.Abstract() != null) cloneSetter.addChild(NodeBuilder.terminalNode(Abstract));
        if (srcSetter.Override() != null) cloneSetter.addChild(NodeBuilder.terminalNode(Override));
        if (srcSetter.Static() != null) cloneSetter.addChild(NodeBuilder.terminalNode(Static));
        if (srcSetter.Open() != null) cloneSetter.addChild(NodeBuilder.terminalNode(Open));

        cloneSetter.addChild(clone(srcSetter.setterHeader())).setParent(cloneSetter);

        if (srcSetter.block() != null)
            cloneSetter.addChild(clone(srcSetter.block())).setParent(cloneSetter);

        return cloneSetter;
    }

    // setterHeader
    //    : { this.next(StaticTSParser.SET) }? Identifier Identifier OpenParen parameter CloseParen
    static public SetterHeaderContext clone(SetterHeaderContext srcSetterHeader) {
        SetterHeaderContext cloneSetterHeader = new SetterHeaderContext(null, 0);

        cloneSetterHeader.addChild(NodeBuilder.terminalIdentifier(srcSetterHeader.Identifier(0).getText()));
        cloneSetterHeader.addChild(NodeBuilder.terminalIdentifier(srcSetterHeader.Identifier(1).getText()));

        cloneSetterHeader.addChild(clone(srcSetterHeader.parameter())).setParent(cloneSetterHeader);

        return cloneSetterHeader;
    }

    // signature
    //    : typeParameters? OpenParen parameterList? CloseParen typeAnnotation ({ THROWS) || RETHROWS) }? Identifier)?
    static public SignatureContext clone(SignatureContext srcSignature) {
        SignatureContext cloneSignature = new SignatureContext(null, 0);

        TypeParametersContext srcTypeParams = srcSignature.typeParameters();
        if (srcTypeParams != null) {
            cloneSignature.addChild(clone(srcTypeParams)).setParent(cloneSignature);
        }

        ParameterListContext srcParamsList = srcSignature.parameterList();
        if (srcParamsList != null) {
            cloneSignature.addChild(clone(srcParamsList)).setParent(cloneSignature);
        }

        cloneSignature.addChild(clone(srcSignature.typeAnnotation())).setParent(cloneSignature);

        ThrowsAnnotationContext srcThrowsAnno = srcSignature.throwsAnnotation();
        if (srcThrowsAnno != null) {
            cloneSignature.addChild(clone(srcThrowsAnno)).setParent(cloneSignature);
        }

        return cloneSignature;
    }

    // classMethodDeclaration
    //    : (Static | Override | Open)? Identifier signature block                        #ClassMethodWithBody
    //    | (Abstract | Static? Native | Native Static)? Identifier signature SemiColon   #AbstractOrNativeClassMethod
    static public ClassMethodDeclarationContext clone(ClassMethodDeclarationContext srcMethodDecl) {
        ClassMethodDeclarationContext cloneMethoDecl = new ClassMethodDeclarationContext();

        ParseTree srcChild = srcMethodDecl.getChild(0);
        if (srcChild instanceof ClassMethodWithBodyContext) {
            ClassMethodWithBodyContext srcMethodWithBody = (ClassMethodWithBodyContext)srcChild;
            ClassMethodWithBodyContext cloneMethodWithBody = new ClassMethodWithBodyContext(cloneMethoDecl);
            cloneMethoDecl.addChild(cloneMethodWithBody);

            if (srcMethodWithBody.Static() != null) {
                cloneMethodWithBody.addChild(NodeBuilder.terminalNode(Static));
            }
            else if (srcMethodWithBody.Override() != null) {
                cloneMethodWithBody.addChild(NodeBuilder.terminalNode(Override));
            }
            else if (srcMethodWithBody.Open() != null) {
                cloneMethodWithBody.addChild(NodeBuilder.terminalNode(Open));
            }

            cloneMethodWithBody.addChild(NodeBuilder.terminalIdentifier(srcMethodWithBody.Identifier().getText()));
            cloneMethodWithBody.addChild(clone(srcMethodWithBody.signature())).setParent(cloneMethodWithBody);
            cloneMethodWithBody.addChild(clone(srcMethodWithBody.block())).setParent(cloneMethodWithBody);
        }
        else {
            assert (srcChild instanceof AbstractOrNativeClassMethodContext);
            AbstractOrNativeClassMethodContext srcAbstractOrNativeMethod = (AbstractOrNativeClassMethodContext)srcChild;
            AbstractOrNativeClassMethodContext cloneAbstractOrNativeMethod = new AbstractOrNativeClassMethodContext(cloneMethoDecl);
            cloneMethoDecl.addChild(cloneAbstractOrNativeMethod);

            if (srcAbstractOrNativeMethod.Static() != null) {
                cloneAbstractOrNativeMethod.addChild(NodeBuilder.terminalNode(Static));
            }
            else {
                if (srcAbstractOrNativeMethod.Static() != null) {
                    cloneAbstractOrNativeMethod.addChild(NodeBuilder.terminalNode(Static));
                }

                if (srcAbstractOrNativeMethod.Native() != null) {
                    cloneAbstractOrNativeMethod.addChild(NodeBuilder.terminalNode(Native));
                }
            }

            cloneAbstractOrNativeMethod.addChild(NodeBuilder.terminalIdentifier(srcAbstractOrNativeMethod.Identifier().getText()));
            cloneAbstractOrNativeMethod.addChild(clone(srcAbstractOrNativeMethod.signature())).setParent(cloneAbstractOrNativeMethod);
        }

        return cloneMethoDecl;
    }

    // interfaceTypeList: typeReference (Comma typeReference)*
    static public InterfaceTypeListContext clone(InterfaceTypeListContext srcTypeList) {
        InterfaceTypeListContext cloneTypeList = new InterfaceTypeListContext(null, 0);

        for(TypeReferenceContext srcType : srcTypeList.typeReference()) {
            cloneTypeList.addChild(clone(srcType)).setParent(cloneTypeList);
        }

        return cloneTypeList;
    }

    // interfaceExtendsClause: { EXTENDS }? Identifier interfaceTypeList
    static public InterfaceExtendsClauseContext clone(InterfaceExtendsClauseContext srcExtends) {
        InterfaceExtendsClauseContext cloneExtends = new InterfaceExtendsClauseContext(null, 0);

        cloneExtends.addChild(NodeBuilder.terminalIdentifier(EXTENDS));
        cloneExtends.addChild(clone(srcExtends.interfaceTypeList())).setParent(cloneExtends);

        return cloneExtends;
    }

    // classExtendsClause: { EXTENDS }? Identifier typeReference
    static public ClassExtendsClauseContext clone(ClassExtendsClauseContext srcExtends) {
        ClassExtendsClauseContext cloneExtends = new ClassExtendsClauseContext(null, 0);

        cloneExtends.addChild(NodeBuilder.terminalIdentifier(EXTENDS));
        cloneExtends.addChild(clone(srcExtends.typeReference())).setParent(cloneExtends);

        return cloneExtends;
    }

    // implementsClause: { IMPLEMENTS }? Identifier interfaceTypeList
    static public ImplementsClauseContext clone(ImplementsClauseContext srcImplements) {
        ImplementsClauseContext cloneImplements = new ImplementsClauseContext(null, 0);

        cloneImplements.addChild(NodeBuilder.terminalIdentifier(IMPLEMENTS));
        cloneImplements.addChild(clone(srcImplements.interfaceTypeList())).setParent(cloneImplements);

        return cloneImplements;
    }

    // classDeclaration: (Inner? (Abstract | Open) | (Abstract | Open)? Inner)?
    //      Class { !predefinedTypeAhead() }? Identifier typeParameters? classExtendsClause? implementsClause? classBody
    static public ClassDeclarationContext clone(ClassDeclarationContext srcClassDecl) {
        ClassDeclarationContext cloneClassDecl = new ClassDeclarationContext(null, 0);

        if (srcClassDecl.Inner() != null) {
            cloneClassDecl.addChild(NodeBuilder.terminalNode(Inner));
        }

        if (srcClassDecl.Abstract() != null) {
            cloneClassDecl.addChild(NodeBuilder.terminalNode(Abstract));
        }

        if (srcClassDecl.Open() != null) {
            cloneClassDecl.addChild(NodeBuilder.terminalNode(Open));
        }

        cloneClassDecl.addChild(NodeBuilder.terminalNode(Class));
        cloneClassDecl.addChild(NodeBuilder.terminalIdentifier(srcClassDecl.Identifier().getText()));

        TypeParametersContext srcTypeParams = srcClassDecl.typeParameters();
        if (srcTypeParams != null) {
            cloneClassDecl.addChild(clone(srcTypeParams)).setParent(cloneClassDecl);
        }

        ClassExtendsClauseContext srcExtends = srcClassDecl.classExtendsClause();
        if (srcExtends != null) {
            cloneClassDecl.addChild(clone(srcExtends)).setParent(cloneClassDecl);
        }

        ImplementsClauseContext srcImplements = srcClassDecl.implementsClause();
        if (srcImplements != null) {
            cloneClassDecl.addChild(clone(srcImplements)).setParent(cloneClassDecl);
        }

        cloneClassDecl.addChild(clone(srcClassDecl.classBody())).setParent(cloneClassDecl);

        return cloneClassDecl;
    }

    // enumMember: Identifier (Assign singleExpression)?
    static public EnumMemberContext clone(EnumMemberContext srcMember) {
        EnumMemberContext cloneMember = new EnumMemberContext(null, 0);

        cloneMember.addChild(NodeBuilder.terminalIdentifier(srcMember.Identifier().getText()));

        if (srcMember.Assign() != null) {
            cloneMember.addChild(NodeBuilder.terminalNode(Assign));
            cloneMember.addChild(clone(srcMember.singleExpression())).setParent(cloneMember);
        }

        return cloneMember;
    }

    // enumBody: enumMember (Comma enumMember)*
    static public EnumBodyContext clone(EnumBodyContext srcBody) {
        EnumBodyContext cloneBody = new EnumBodyContext(null, 0);

        for (EnumMemberContext srcMember : srcBody.enumMember()) {
            cloneBody.addChild(clone(srcMember)).setParent(cloneBody);
        }

        return cloneBody;
    }

    // enumDeclaration: Enum Identifier OpenBrace enumBody? CloseBrace
    static public EnumDeclarationContext clone(EnumDeclarationContext srcEnum) {
        EnumDeclarationContext cloneEnum = new EnumDeclarationContext(null, 0);

        cloneEnum.addChild(NodeBuilder.terminalNode(Enum));
        cloneEnum.addChild(NodeBuilder.terminalIdentifier(srcEnum.Identifier().getText()));

        EnumBodyContext srcBody = srcEnum.enumBody();
        if (srcBody != null) {
            cloneEnum.addChild(clone(srcBody)).setParent(cloneEnum);
        }

        return cloneEnum;
    }

    //     | enumDeclaration                                 #EnumInInterface
    static public EnumInInterfaceContext clone(EnumInInterfaceContext srcEnum) {
        EnumInInterfaceContext cloneEnum = new EnumInInterfaceContext(null);

        cloneEnum.addChild(clone(srcEnum.enumDeclaration())).setParent(cloneEnum);

        return cloneEnum;
    }

    // interfaceMember
    //    : Identifier signature SemiColon                  #InterfaceMethod
    //    | (Static | Private)? Identifier signature block  #InterfaceMethodWithBody
    //    | ({this.next(StaticTSParser.READONLY)}? Identifier)?
    //      variableDeclaration SemiColon?                  #InterfaceField
    //    | getterHeader SemiColon?                         #InterfaceGetter
    //    | setterHeader SemiColon?                         #InterfaceSetter
    //    | interfaceDeclaration                            #InterfaceInInterface
    //    | classDeclaration                                #ClassInInterface
    //    | enumDeclaration                                 #EnumInInterface
    static public InterfaceMemberContext clone(InterfaceMemberContext srcMember) {
        InterfaceMemberContext cloneMember = new InterfaceMemberContext(null, 0);

        ParseTree srcChild = srcMember.getChild(0);
        if (srcChild instanceof InterfaceMethodContext) {
            InterfaceMethodContext srcMethod = (InterfaceMethodContext)srcChild;
            InterfaceMethodContext cloneMethod = new InterfaceMethodContext(cloneMember);
            cloneMember.addChild(cloneMethod);

            cloneMethod.addChild(NodeBuilder.terminalNode(Identifier));
            cloneMethod.addChild(clone(srcMethod.signature())).setParent(cloneMethod);
        }
        else if (srcChild instanceof InterfaceMethodWithBodyContext) {
            InterfaceMethodWithBodyContext srcMethod = (InterfaceMethodWithBodyContext)srcChild;
            InterfaceMethodWithBodyContext cloneMethod = new InterfaceMethodWithBodyContext(cloneMember);
            cloneMember.addChild(cloneMethod);

            if (srcMethod.Private() != null) {
                cloneMethod.addChild(NodeBuilder.terminalNode(Private));
            }
            else if (srcMethod.Static() != null) {
                cloneMethod.addChild(NodeBuilder.terminalNode(Static));
            }

            cloneMethod.addChild(NodeBuilder.terminalNode(Identifier));
            cloneMethod.addChild(clone(srcMethod.signature())).setParent(cloneMethod);
            cloneMethod.addChild(clone(srcMethod.block())).setParent(cloneMethod);
        }
        else if (srcChild instanceof InterfaceFieldContext) {
            InterfaceFieldContext srcField = (InterfaceFieldContext)srcChild;
            InterfaceFieldContext cloneField = new InterfaceFieldContext(cloneMember);
            cloneMember.addChild(cloneField);

            if (srcField.Identifier() != null)
                cloneField.addChild(NodeBuilder.terminalIdentifier(srcField.Identifier().getText()));

            cloneField.addChild(clone(srcField.variableDeclaration())).setParent(cloneField);
        }
        else if (srcChild instanceof InterfaceGetterContext) {
            InterfaceGetterContext srcGetter = (InterfaceGetterContext)srcChild;
            InterfaceGetterContext cloneGetter = new InterfaceGetterContext(cloneMember);
            cloneMember.addChild(cloneGetter).setParent(cloneMember);

            cloneGetter.addChild(clone(srcGetter.getterHeader())).setParent(cloneGetter);
        }
        else if (srcChild instanceof InterfaceSetterContext) {
            InterfaceSetterContext srcSetter = (InterfaceSetterContext)srcChild;
            InterfaceSetterContext cloneSetter = new InterfaceSetterContext(cloneMember);
            cloneMember.addChild(cloneSetter).setParent(cloneMember);

            cloneSetter.addChild(clone(srcSetter.setterHeader())).setParent(cloneSetter);
        }
        else if (srcChild instanceof InterfaceInInterfaceContext) {
            InterfaceInInterfaceContext srcInterface = (InterfaceInInterfaceContext)srcChild;
            InterfaceInInterfaceContext cloneInterface = new InterfaceInInterfaceContext(cloneMember);
            cloneMember.addChild(cloneInterface);

            cloneInterface.addChild(clone(srcInterface.interfaceDeclaration())).setParent(cloneInterface);
        }
        else if (srcChild instanceof ClassInInterfaceContext) {
            ClassInInterfaceContext srcClass = (ClassInInterfaceContext)srcMember;
            ClassInInterfaceContext cloneClass = new ClassInInterfaceContext(cloneMember);
            cloneMember.addChild(cloneClass);

            cloneClass.addChild(clone(srcClass.classDeclaration())).setParent(cloneClass);
        }
        else if (srcChild instanceof EnumInInterfaceContext) {
            EnumInInterfaceContext srcEnum = (EnumInInterfaceContext)srcChild;
            EnumInInterfaceContext cloneEnum = new EnumInInterfaceContext(cloneMember);
            cloneMember.addChild(cloneEnum);

            cloneEnum.addChild(clone(srcEnum.enumDeclaration())).setParent(cloneEnum);
        }

        return cloneMember;
    }

    // interfaceBody: interfaceMember*
    static public InterfaceBodyContext clone(InterfaceBodyContext srcBody) {
        InterfaceBodyContext cloneBody = new InterfaceBodyContext(null, 0);

        for (InterfaceMemberContext srcMember : srcBody.interfaceMember()) {
            cloneBody.addChild(clone(srcMember)).setParent(cloneBody);
        }

        return cloneBody;
    }

    // interfaceDeclaration: Interface Identifier typeParameters? interfaceExtendsClause? OpenBrace interfaceBody CloseBrace
    static public InterfaceDeclarationContext clone(InterfaceDeclarationContext srcInterface) {
        InterfaceDeclarationContext cloneInterface = new InterfaceDeclarationContext(null, 0);

        cloneInterface.addChild(NodeBuilder.terminalNode(Interface));
        cloneInterface.addChild(NodeBuilder.terminalIdentifier(srcInterface.Identifier().getText()));

        TypeParametersContext srcTypeParams = srcInterface.typeParameters();
        if (srcTypeParams != null) {
            cloneInterface.addChild(clone(srcTypeParams)).setParent(cloneInterface);
        }

        InterfaceExtendsClauseContext srcExtends = srcInterface.interfaceExtendsClause();
        if (srcExtends != null) {
            cloneInterface.addChild(clone(srcExtends)).setParent(cloneInterface);
        }

        InterfaceBodyContext srcInterfaceBody = srcInterface.interfaceBody();
        if (srcInterfaceBody != null) {
            cloneInterface.addChild(clone(srcInterfaceBody)).setParent(cloneInterface);
        }

        return cloneInterface;
    }

    // classMember: accessibilityModifier?
    //    (
    //          constructorDeclaration
    //        | classFieldDeclaration
    //        | classMethodDeclaration
    //        | classGetterDeclaration
    //        | classSetterDeclaration
    //        | interfaceDeclaration
    //        | enumDeclaration
    //        | classDeclaration
    //    )
    static public ClassMemberContext clone(ClassMemberContext srcMember) {
        ClassMemberContext cloneMember = new ClassMemberContext(null, 0);

        AccessibilityModifierContext srcModifier = srcMember.accessibilityModifier();
        if (srcModifier != null) {
            cloneMember.addChild(clone(srcModifier)).setParent(cloneMember);
        }

        ConstructorDeclarationContext srcConstructor = srcMember.constructorDeclaration();
        if (srcConstructor != null) {

            cloneMember.addChild(clone(srcConstructor)).setParent(cloneMember);
        }

        ClassFieldDeclarationContext srcField = srcMember.classFieldDeclaration();
        if (srcField != null) {
            cloneMember.addChild(clone(srcField)).setParent(cloneMember);
        }

        ClassMethodDeclarationContext srcMethod = srcMember.classMethodDeclaration();
        if (srcMethod != null) {
            cloneMember.addChild(clone(srcMethod)).setParent(cloneMember);
        }

        ClassGetterDeclarationContext srcGetter = srcMember.classGetterDeclaration();
        if (srcGetter != null) {
            cloneMember.addChild(clone(srcGetter)).setParent(cloneMember);
        }

        ClassSetterDeclarationContext srcSetter = srcMember.classSetterDeclaration();
        if (srcSetter != null) {
            cloneMember.addChild(clone(srcSetter)).setParent(cloneMember);
        }

        InterfaceDeclarationContext srcInterface = srcMember.interfaceDeclaration();
        if (srcInterface != null) {
            cloneMember.addChild(clone(srcInterface)).setParent(cloneMember);
        }

        EnumDeclarationContext srcEnum = srcMember.enumDeclaration();
        if (srcEnum != null) {
            cloneMember.addChild(clone(srcEnum)).setParent(cloneMember);
        }

        ClassDeclarationContext srcClass = srcMember.classDeclaration();
        if (srcClass != null) {
            cloneMember.addChild(clone(srcClass)).setParent(cloneMember);
        }

        return cloneMember;
    }

    // classInitializer: Static block
    static public ClassInitializerContext clone(ClassInitializerContext srcInit) {
        ClassInitializerContext cloneInit = new ClassInitializerContext(null, 0);

        cloneInit.addChild(NodeBuilder.terminalNode(Static));
        cloneInit.addChild(clone(srcInit.block())).setParent(cloneInit);

        return cloneInit;
    }

    // lassBody:  OpenBrace classMember* clinit=classInitializer? classMember* CloseBrace
    static public ClassBodyContext clone(ClassBodyContext srcClassBody) {
        ClassBodyContext cloneClassBody = new ClassBodyContext(null, 0);

        for (ClassMemberContext srcClassMember : srcClassBody.classMember()) {
            cloneClassBody.addChild(clone(srcClassMember)).setParent(cloneClassBody);
        }

        if (srcClassBody.clinit != null) {
            cloneClassBody.addChild(clone(srcClassBody.clinit)).setParent(cloneClassBody);
        }

        return cloneClassBody;
    }

    // shiftOperator
    //    : first=LessThan second=LessThan {$first.index + 1 == $second.index}?
    //    | first=MoreThan second=MoreThan {$first.index + 1 == $second.index}?
    //    | first=MoreThan second=MoreThan third=MoreThan {$first.index + 1 == $second.index && $second.index + 1 == $third.index}?
    static public ShiftOperatorContext clone(ShiftOperatorContext srcShiftOp) {
        ShiftOperatorContext cloneShiftOp = new ShiftOperatorContext(null, 0);

        int n = srcShiftOp.LessThan().size();
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                cloneShiftOp.addChild(NodeBuilder.terminalNode(LessThan));
            }
        }
        else {
            n = srcShiftOp.MoreThan().size();
            for (int i = 0; i < n; i++) {
                cloneShiftOp.addChild(NodeBuilder.terminalNode(MoreThan));
            }
        }

        return cloneShiftOp;
    }

    // assignmentOperator
    //    : MultiplyAssign
    //    | DivideAssign
    //    | ModulusAssign
    //    | PlusAssign
    //    | MinusAssign
    //    | LeftShiftArithmeticAssign
    //    | RightShiftArithmeticAssign
    //    | RightShiftLogicalAssign
    //    | BitAndAssign
    //    | BitXorAssign
    //    | BitOrAssign
    static public AssignmentOperatorContext clone(AssignmentOperatorContext srcOp) {
        TerminalNode srcOpTerm = (TerminalNode)srcOp.getChild(0);

        AssignmentOperatorContext stsAssignOp = new AssignmentOperatorContext(null, 0);
        stsAssignOp.addChild(NodeBuilder.terminalNode(srcOpTerm.getSymbol().getType()));
        return stsAssignOp;
    }

    static public NumericLiteralContext clone(NumericLiteralContext srcNumeric) {
        NumericLiteralContext cloneNumeric = new NumericLiteralContext(null, 0);
        TerminalNode srcTerm = (TerminalNode)srcNumeric.getChild(0);
        cloneNumeric.addChild(NodeBuilder.terminalNode(srcTerm.getSymbol().getType(), srcTerm.getText()));
        return cloneNumeric;
    }

    // literal: Null | True | False | StringLiteral | CharLiteral | numericLiteral
    static public LiteralContext clone(LiteralContext srcLiteral) {
        LiteralContext cloneLiteral = new LiteralContext(null, 0);

        if (srcLiteral.Null() != null) {
            cloneLiteral.addChild(NodeBuilder.terminalNode(Null));
            return cloneLiteral;
        }

        if (srcLiteral.True() != null) {
            cloneLiteral.addChild(NodeBuilder.terminalNode(True));
            return cloneLiteral;
        }

        if (srcLiteral.False() != null) {
            cloneLiteral.addChild(NodeBuilder.terminalNode(False));
            return cloneLiteral;
        }

        TerminalNode srcTerm = srcLiteral.StringLiteral();

        if (srcTerm == null) {
            srcTerm = srcLiteral.CharLiteral();
        }

        if (srcTerm != null) {
            cloneLiteral.addChild(NodeBuilder.terminalNode(srcTerm.getSymbol().getType(), srcTerm.getText()));
            return cloneLiteral;
        }

        //cloneLiteral.addChild(clone(srcLiteral.numericLiteral())).setParent(cloneLiteral);
        ParseTree srcChild = srcLiteral.getChild(0);

        if (srcChild instanceof TerminalNode) {
            TerminalNode srcTerminal = (TerminalNode)srcChild;
            cloneLiteral.addChild(NodeBuilder.terminalNode(srcTerminal.getSymbol().getType(), srcTerminal.getText())).setParent(cloneLiteral);
        }

        return cloneLiteral;
    }

    static public LambdaExpressionContext clone(LambdaExpressionContext srcLambda) {
        LambdaExpressionContext cloneLambda = new LambdaExpressionContext(new SingleExpressionContext());

        ParameterListContext srcParamsList = srcLambda.parameterList();
        if (srcParamsList != null) {
            cloneLambda.addChild(clone(srcParamsList)).setParent(cloneLambda);
        }

        cloneLambda.addChild(clone(srcLambda.typeAnnotation())).setParent(cloneLambda);

        ThrowsAnnotationContext srcThrowsAnno = srcLambda.throwsAnnotation();
        if (srcThrowsAnno != null) cloneLambda.addChild(clone(srcThrowsAnno)).setParent(cloneLambda);

        cloneLambda.addChild(clone(srcLambda.lambdaBody())).setParent(cloneLambda);

        return cloneLambda;
    }

    static public ArrayAccessExpressionContext clone(ArrayAccessExpressionContext srcArrayAccess) {
        ArrayAccessExpressionContext cloneArrayAccess = new ArrayAccessExpressionContext(new SingleExpressionContext());
        cloneArrayAccess.addChild(clone(srcArrayAccess.singleExpression())).setParent(cloneArrayAccess);
        cloneArrayAccess.addChild(clone(srcArrayAccess.indexExpression())).setParent(cloneArrayAccess);

        return cloneArrayAccess;
    }

    static public MemberAccessExpressionContext clone(MemberAccessExpressionContext srcMemberAccess) {
        MemberAccessExpressionContext cloneMemberAccess = new MemberAccessExpressionContext(new SingleExpressionContext());
        cloneMemberAccess.addChild(clone(srcMemberAccess.singleExpression())).setParent(cloneMemberAccess);
        cloneMemberAccess.addChild(NodeBuilder.terminalIdentifier(srcMemberAccess.Identifier().getText()));

        return cloneMemberAccess;
    }

    static public NewClassInstanceExpressionContext clone(NewClassInstanceExpressionContext srcNewInstance) {
        NewClassInstanceExpressionContext cloneNewInstance = new NewClassInstanceExpressionContext(new SingleExpressionContext());

        cloneNewInstance.addChild(NodeBuilder.terminalNode(New));

        TypeArgumentsContext srcTypeArgs = srcNewInstance.typeArguments();
        if (srcTypeArgs != null) {
            cloneNewInstance.addChild(clone(srcTypeArgs)).setParent(cloneNewInstance);
        }

        cloneNewInstance.addChild(clone(srcNewInstance.typeReference())).setParent(cloneNewInstance);

        ArgumentsContext srcArgs = srcNewInstance.arguments();
        if (srcArgs != null) {
            cloneNewInstance.addChild(clone(srcArgs)).setParent(cloneNewInstance);
        }

        return cloneNewInstance;
    }

    static public NewInnerClassInstanceExpressionContext clone(NewInnerClassInstanceExpressionContext srcNewInner) {
        NewInnerClassInstanceExpressionContext cloneNewInner = new NewInnerClassInstanceExpressionContext(new SingleExpressionContext());

        cloneNewInner.addChild(clone(srcNewInner.singleExpression())).setParent(cloneNewInner);
        cloneNewInner.addChild(NodeBuilder.terminalNode(New));

        TypeArgumentsContext srcTypeArgs = srcNewInner.typeArguments();
        if (srcTypeArgs != null) {
            cloneNewInner.addChild(clone(srcTypeArgs)).setParent(cloneNewInner);
        }

        cloneNewInner.addChild(clone(srcNewInner.typeReference())).setParent(cloneNewInner);

        ArgumentsContext srcArgs = srcNewInner.arguments();
        if (srcArgs != null) {
            cloneNewInner.addChild(clone(srcArgs)).setParent(cloneNewInner);
        }

        ClassBodyContext srcClassBody = srcNewInner.classBody();
        if (srcClassBody != null) {
            cloneNewInner.addChild(clone(srcClassBody)).setParent(cloneNewInner);
        }

        return cloneNewInner;
    }

    static public NewArrayExpressionContext clone(NewArrayExpressionContext srcNewArray) {
        NewArrayExpressionContext cloneNewArray = new NewArrayExpressionContext(new SingleExpressionContext());

        cloneNewArray.addChild(NodeBuilder.terminalNode(New));
        cloneNewArray.addChild(clone(srcNewArray.primaryType())).setParent(cloneNewArray);

        for (IndexExpressionContext srcIndex : srcNewArray.indexExpression()) {
            cloneNewArray.addChild(clone(srcIndex)).setParent(cloneNewArray);
        }

        return cloneNewArray;
    }

    static public CallExpressionContext clone(CallExpressionContext srcCall) {
        CallExpressionContext cloneCall = new CallExpressionContext(new SingleExpressionContext());

        cloneCall.addChild(clone(srcCall.singleExpression())).setParent(cloneCall);

        TypeArgumentsContext srcTypeArgs = srcCall.typeArguments();
        if (srcTypeArgs != null) {
            cloneCall.addChild(clone(srcTypeArgs)).setParent(cloneCall);
        }

        cloneCall.addChild(clone(srcCall.arguments())).setParent(cloneCall);

        return cloneCall;
    }

    static public PostIncrementExpressionContext clone(PostIncrementExpressionContext srcPostInc) {
        PostIncrementExpressionContext clonePostInc = new PostIncrementExpressionContext(new SingleExpressionContext());
        clonePostInc.addChild(clone(srcPostInc.singleExpression())).setParent(clonePostInc);
        clonePostInc.addChild(NodeBuilder.terminalNode(PlusPlus));
        return clonePostInc;
    }

    static public PostDecreaseExpressionContext clone(PostDecreaseExpressionContext srcPostDec) {
        PostDecreaseExpressionContext clonePostDec = new PostDecreaseExpressionContext(new SingleExpressionContext());
        clonePostDec.addChild(clone(srcPostDec.singleExpression())).setParent(clonePostDec);
        clonePostDec.addChild(NodeBuilder.terminalNode(MinusMinus));
        return clonePostDec;
    }

    static public PreIncrementExpressionContext cline(PreIncrementExpressionContext srcPreInc) {
        PreIncrementExpressionContext clonePreInc = new PreIncrementExpressionContext(new SingleExpressionContext());
        clonePreInc.addChild(clone(srcPreInc.singleExpression())).setParent(clonePreInc);
        return clonePreInc;
    }

    static public PreDecreaseExpressionContext clone(PreDecreaseExpressionContext srcPreDec) {
        PreDecreaseExpressionContext clonePreDec = new PreDecreaseExpressionContext(new SingleExpressionContext());
        clonePreDec.addChild(NodeBuilder.terminalNode(MinusMinus));
        clonePreDec.addChild(clone(srcPreDec.singleExpression())).setParent(clonePreDec);
        return clonePreDec;
    }

    static public UnaryPlusExpressionContext clone(UnaryPlusExpressionContext srcUnaryPlus) {
        UnaryPlusExpressionContext cloneUnaryPlus = new UnaryPlusExpressionContext(new SingleExpressionContext());
        cloneUnaryPlus.addChild(NodeBuilder.terminalNode(Plus));
        cloneUnaryPlus.addChild(clone(srcUnaryPlus.singleExpression())).setParent(cloneUnaryPlus);
        return cloneUnaryPlus;
    }

    static public UnaryMinusExpressionContext clone(UnaryMinusExpressionContext srcUnaryMinus) {
        UnaryMinusExpressionContext cloneUnaryMinus = new UnaryMinusExpressionContext(new SingleExpressionContext());
        cloneUnaryMinus.addChild(NodeBuilder.terminalNode(Minus));
        cloneUnaryMinus.addChild(clone(srcUnaryMinus.singleExpression())).setParent(cloneUnaryMinus);
        return cloneUnaryMinus;
    }

    static public BitNotExpressionContext clone(BitNotExpressionContext srcBitNot) {
        BitNotExpressionContext cloneBitNot = new BitNotExpressionContext(new SingleExpressionContext());
        cloneBitNot.addChild(NodeBuilder.terminalNode(BitNot));
        cloneBitNot.addChild(clone(srcBitNot.singleExpression())).setParent(cloneBitNot);
        return cloneBitNot;
    }

    static public NotExpressionContext clone(NotExpressionContext srcNot) {
        NotExpressionContext cloneNot = new NotExpressionContext(new SingleExpressionContext());
        cloneNot.addChild(NodeBuilder.terminalNode(Not));
        cloneNot.addChild(clone(srcNot.singleExpression()));
        return cloneNot;
    }

    static public MultiplicativeExpressionContext clone(MultiplicativeExpressionContext srcMult) {
        MultiplicativeExpressionContext cloneMult = new MultiplicativeExpressionContext(new SingleExpressionContext());

        List<SingleExpressionContext> srcArgs = srcMult.singleExpression();
        cloneMult.addChild(clone(srcArgs.get(0))).setParent(cloneMult);

        if (srcMult.Multiply() != null) {
            cloneMult.addChild(NodeBuilder.terminalNode(Multiply));
        }
        else if (srcMult.Divide() != null) {
            cloneMult.addChild(NodeBuilder.terminalNode(Divide));
        }
        else {
            cloneMult.addChild(NodeBuilder.terminalNode(Modulus));
        }

        cloneMult.addChild(clone(srcArgs.get(1))).setParent(cloneMult);

        return cloneMult;
    }

    static public AdditiveExpressionContext clone(AdditiveExpressionContext srcAdditive) {
        AdditiveExpressionContext cloneAdditive = new AdditiveExpressionContext(new SingleExpressionContext());

        List<SingleExpressionContext> srcArgs = srcAdditive.singleExpression();
        cloneAdditive.addChild(clone(srcArgs.get(0))).setParent(cloneAdditive);

        if (srcAdditive.Plus() != null) {
            cloneAdditive.addChild(NodeBuilder.terminalNode(Plus));
        }
        else {
            cloneAdditive.addChild(NodeBuilder.terminalNode(Minus));
        }

        cloneAdditive.addChild(clone(srcArgs.get(1))).setParent(cloneAdditive);
        return cloneAdditive;
    }

    static public BitShiftExpressionContext clone(BitShiftExpressionContext srcShift) {
        BitShiftExpressionContext cloneShift = new BitShiftExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcShift.singleExpression();
        cloneShift.addChild(clone(srcArgs.get(0))).setParent(cloneShift);
        cloneShift.addChild(clone(srcShift.shiftOperator())).setParent(cloneShift);
        cloneShift.addChild(clone(srcArgs.get(0))).setParent(cloneShift);
        return cloneShift;
    }

    static public RelationalExpressionContext clone(RelationalExpressionContext srcRelation) {
        RelationalExpressionContext cloneRelation = new RelationalExpressionContext(new SingleExpressionContext());

        List<SingleExpressionContext> srcArgs = srcRelation.singleExpression();
        cloneRelation.addChild(clone(srcArgs.get(0))).setParent(cloneRelation);

        if (srcRelation.LessThan() != null) {
            cloneRelation.addChild(NodeBuilder.terminalNode(LessThan));
        }
        else if (srcRelation.MoreThan() != null) {
            cloneRelation.addChild(NodeBuilder.terminalNode(MoreThan));
        }
        else if (srcRelation.LessThanEquals() != null) {
            cloneRelation.addChild(NodeBuilder.terminalNode(LessThanEquals));
        }
        else {
            cloneRelation.addChild(NodeBuilder.terminalNode(GreaterThanEquals));
        }

        cloneRelation.addChild(clone(srcArgs.get(0))).setParent(cloneRelation);
        return cloneRelation;
    }

    static public InstanceofExpressionContext clone(InstanceofExpressionContext srcInstanceOf) {
        InstanceofExpressionContext cloneInstaceOf = new InstanceofExpressionContext(new SingleExpressionContext());
        cloneInstaceOf.addChild(clone(srcInstanceOf.singleExpression())).setParent(cloneInstaceOf);
        cloneInstaceOf.addChild(NodeBuilder.terminalNode(Instanceof));
        cloneInstaceOf.addChild(clone(srcInstanceOf.primaryType())).setParent(cloneInstaceOf);
        return cloneInstaceOf;
    }

    static public EqualityExpressionContext clone(EqualityExpressionContext srcEquality) {
        EqualityExpressionContext cloneEquality = new EqualityExpressionContext(new SingleExpressionContext());

        List<SingleExpressionContext> srcArgs = srcEquality.singleExpression();
        cloneEquality.addChild(clone(srcArgs.get(0))).setParent(cloneEquality);

        if (srcEquality.Equals() != null) {
            cloneEquality.addChild(NodeBuilder.terminalNode(Equals));
        }
        else if (srcEquality.NotEquals() != null) {
            cloneEquality.addChild(NodeBuilder.terminalNode(NotEquals));
        }
        else if (srcEquality.IdentityEquals() != null) {
            cloneEquality.addChild(NodeBuilder.terminalNode(IdentityEquals));
        }
        else {
            cloneEquality.addChild(NodeBuilder.terminalNode(IdentityNotEquals));
        }

        cloneEquality.addChild(clone(srcArgs.get(1))).setParent(cloneEquality);

        return cloneEquality;
    }

    static public BitAndExpressionContext clone(BitAndExpressionContext srcAnd) {
        BitAndExpressionContext cloneAnd = new BitAndExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcAnd.singleExpression();
        cloneAnd.addChild(clone(srcArgs.get(0))).setParent(cloneAnd);
        cloneAnd.addChild(NodeBuilder.terminalNode(BitAnd));
        cloneAnd.addChild(clone(srcArgs.get(1))).setParent(cloneAnd);
        return cloneAnd;
    }

    static public BitXOrExpressionContext clone(BitXOrExpressionContext srcBitXOr) {
        BitXOrExpressionContext cloneBitXOr = new BitXOrExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcBitXOr.singleExpression();
        cloneBitXOr.addChild(clone(srcArgs.get(0))).setParent(cloneBitXOr);
        cloneBitXOr.addChild(NodeBuilder.terminalNode(BitXor));
        cloneBitXOr.addChild(clone(srcArgs.get(1))).setParent(cloneBitXOr);
        return cloneBitXOr;
    }

    static public BitOrExpressionContext clone(BitOrExpressionContext srcBitOr) {
        BitOrExpressionContext cloneBitOr = new BitOrExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcBitOr.singleExpression();
        cloneBitOr.addChild(clone(srcArgs.get(0))).setParent(cloneBitOr);
        cloneBitOr.addChild(NodeBuilder.terminalNode(BitOr));
        cloneBitOr.addChild(clone(srcArgs.get(1))).setParent(cloneBitOr);
        return cloneBitOr;
    }

    static public LogicalAndExpressionContext clone(LogicalAndExpressionContext srcAnd) {
        LogicalAndExpressionContext cloneAnd = new LogicalAndExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcAnd.singleExpression();
        cloneAnd.addChild(clone(srcArgs.get(0))).setParent(cloneAnd);
        cloneAnd.addChild(NodeBuilder.terminalNode(And));
        cloneAnd.addChild(clone(srcArgs.get(1))).setParent(cloneAnd);
        return cloneAnd;
    }

    static public LogicalOrExpressionContext clone(LogicalOrExpressionContext srcOr) {
        LogicalOrExpressionContext cloneOr = new LogicalOrExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcArgs = srcOr.singleExpression();
        cloneOr.addChild(clone(srcArgs.get(0))).setParent(cloneOr);
        cloneOr.addChild(NodeBuilder.terminalNode(Or));
        cloneOr.addChild(clone(srcArgs.get(1))).setParent(cloneOr);
        return cloneOr;
    }

    static public TernaryExpressionContext clone(TernaryExpressionContext srcTernary) {
        TernaryExpressionContext cloneTernary = new TernaryExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcExpr = srcTernary.singleExpression();
        cloneTernary.addChild(clone(srcExpr.get(0))).setParent(cloneTernary);
        cloneTernary.addChild(NodeBuilder.terminalNode(QuestionMark));
        cloneTernary.addChild(clone(srcExpr.get(1))).setParent(cloneTernary);
        cloneTernary.addChild(NodeBuilder.terminalNode(Colon));
        cloneTernary.addChild(clone(srcExpr.get(2))).setParent(cloneTernary);
        return cloneTernary;
    }

    static public AssignmentExpressionContext clone(AssignmentExpressionContext srcAssign) {
        AssignmentExpressionContext cloneAssing = new AssignmentExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcExpr = srcAssign.singleExpression();
        cloneAssing.addChild(clone(srcExpr.get(0))).setParent(cloneAssing);
        cloneAssing.addChild(NodeBuilder.terminalNode(Assign));
        cloneAssing.addChild(clone(srcExpr.get(1))).setParent(cloneAssing);
        return cloneAssing;
    }

    static public AssignmentOperatorExpressionContext clone(AssignmentOperatorExpressionContext srcAssign) {
        AssignmentOperatorExpressionContext cloneAssign = new AssignmentOperatorExpressionContext(new SingleExpressionContext());
        List<SingleExpressionContext> srcExpr = srcAssign.singleExpression();
        cloneAssign.addChild(clone(srcExpr.get(0))).setParent(cloneAssign);
        cloneAssign.addChild(clone(srcAssign.assignmentOperator())).setParent(cloneAssign);
        cloneAssign.addChild(clone(srcExpr.get(1))).setParent(cloneAssign);
        return cloneAssign;
    }

    static public ThisExpressionContext clone(ThisExpressionContext srcThis) {
        ThisExpressionContext cloneThis = new ThisExpressionContext(new SingleExpressionContext());

        TypeReferenceContext srcTypeRef = srcThis.typeReference();
        if (srcTypeRef != null) {
            cloneThis.addChild(clone(srcTypeRef)).setParent(cloneThis);
        }

        cloneThis.addChild(NodeBuilder.terminalNode(This));

        return cloneThis;
    }

    static public IdentifierExpressionContext clone(IdentifierExpressionContext srcIdentifier) {
        IdentifierExpressionContext cloneIdentifier = new IdentifierExpressionContext(new SingleExpressionContext());
        cloneIdentifier.addChild(NodeBuilder.terminalIdentifier(srcIdentifier.getText()));
        return cloneIdentifier;
    }

    static public SuperExpressionContext clone(SuperExpressionContext srcSuper) {
        SuperExpressionContext cloneSuper = new SuperExpressionContext(new SingleExpressionContext());

        TypeReferenceContext srcTypeRef = srcSuper.typeReference();
        if (srcTypeRef != null) {
            cloneSuper.addChild(clone(srcTypeRef)).setParent(cloneSuper);
        }

        cloneSuper.addChild(NodeBuilder.terminalNode(Super));

        return cloneSuper;
    }

    static public LiteralExpressionContext clone(LiteralExpressionContext srcLiteral) {
        LiteralExpressionContext cloneLiteral = new LiteralExpressionContext(new SingleExpressionContext());
        cloneLiteral.addChild(clone(srcLiteral.literal())).setParent(cloneLiteral);
        return cloneLiteral;
    }

    static public ArrayLiteralExpressionContext clone(ArrayLiteralExpressionContext srcArrayLiteral) {
        ArrayLiteralExpressionContext cloneArrayLiteral = new ArrayLiteralExpressionContext(new SingleExpressionContext());
        cloneArrayLiteral.addChild(NodeBuilder.terminalNode(OpenBracket));
        cloneArrayLiteral.addChild(clone(srcArrayLiteral.expressionSequence())).setParent(cloneArrayLiteral);
        cloneArrayLiteral.addChild(NodeBuilder.terminalNode(CloseBracket));
        return cloneArrayLiteral;
    }

    static public ClassLiteralExpressionContext clone(ClassLiteralExpressionContext srcClassLiteral) {
        ClassLiteralExpressionContext cloneClassLiteral = new ClassLiteralExpressionContext(new SingleExpressionContext());
        cloneClassLiteral.addChild(clone(srcClassLiteral.primaryType())).setParent(cloneClassLiteral);
        cloneClassLiteral.addChild(NodeBuilder.terminalNode(Dot));
        cloneClassLiteral.addChild(NodeBuilder.terminalNode(Class));
        return cloneClassLiteral;
    }

    static public ParenthesizedExpressionContext clone(ParenthesizedExpressionContext srcParenthesized) {
        ParenthesizedExpressionContext cloneParenthesized = new ParenthesizedExpressionContext(new SingleExpressionContext());
        cloneParenthesized.addChild(NodeBuilder.terminalNode(OpenParen));
        cloneParenthesized.addChild(clone(srcParenthesized.singleExpression())).setParent(cloneParenthesized);
        cloneParenthesized.addChild(NodeBuilder.terminalNode(CloseParen));
        return cloneParenthesized;
    }

    static public CastExpressionContext clone(CastExpressionContext srcCast) {
        CastExpressionContext cloneCast = new CastExpressionContext(new SingleExpressionContext());

        cloneCast.addChild(clone(srcCast.singleExpression())).setParent(cloneCast);
        cloneCast.addChild(NodeBuilder.terminalNode(As));

        IntersectionTypeContext srcIntersctionType = srcCast.intersectionType();
        if (srcIntersctionType != null) {
            cloneCast.addChild(clone(srcIntersctionType)).setParent(cloneCast);
        }

        PrimaryTypeContext srcPrimaryType = srcCast.primaryType();
        if (srcPrimaryType != null) {
            cloneCast.addChild(clone(srcPrimaryType)).setParent(cloneCast);
        }

        return cloneCast;
    }

    static public AwaitExpressionContext clone(AwaitExpressionContext srcAwaitExpr) {
        AwaitExpressionContext result = new AwaitExpressionContext(new SingleExpressionContext());

        result.addChild(NodeBuilder.terminalNode(Await));
        result.addChild(clone(srcAwaitExpr.singleExpression())).setParent(result);

        return result;
    }

    // singleExpression
    static public SingleExpressionContext clone(SingleExpressionContext srcSingleExpr) {
        SingleExpressionContext cloneSingleExpr = new SingleExpressionContext();

        ParseTree srcChild = srcSingleExpr.getChild(0);

        //    : OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody    # LambdaExpression
        if (srcChild instanceof LambdaExpressionContext) {
            cloneSingleExpr.addChild(clone((LambdaExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression indexExpression                                       # ArrayAccessExpression
        else if (srcChild instanceof ArrayAccessExpressionContext) {
            cloneSingleExpr.addChild(clone((ArrayAccessExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression Dot Identifier                                        # MemberAccessExpression
        else if (srcChild instanceof MemberAccessExpressionContext) {
            cloneSingleExpr.addChild(clone((MemberAccessExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | New typeArguments? typeReference arguments? classBody?                 # NewClassInstanceExpression
        else if (srcChild instanceof NewClassInstanceExpressionContext) {
            cloneSingleExpr.addChild(clone((NewClassInstanceExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression Dot New typeArguments? typeReference arguments? classBody? # NewInnerClassInstanceExpression
        else if (srcChild instanceof NewInnerClassInstanceExpressionContext) {
            cloneSingleExpr.addChild(clone((NewInnerClassInstanceExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | New primaryType indexExpression+ (OpenBracket CloseBracket)*           # NewArrayExpression
        else if (srcChild instanceof NewArrayExpressionContext) {
            cloneSingleExpr.addChild(clone((NewArrayExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression typeArguments? arguments                              # CallExpression
        else if (srcChild instanceof CallExpressionContext) {
            cloneSingleExpr.addChild(clone((CallExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression {this.notLineTerminator()}? PlusPlus                  # PostIncrementExpression
        else if (srcChild instanceof PostIncrementExpressionContext) {
            cloneSingleExpr.addChild(clone((PostIncrementExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression {this.notLineTerminator()}? MinusMinus                # PostDecreaseExpression
        else if (srcChild instanceof PostDecreaseExpressionContext) {
            cloneSingleExpr.addChild(clone((PostDecreaseExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | PlusPlus singleExpression                                              # PreIncrementExpression
        else if (srcChild instanceof PreIncrementExpressionContext) {
            cloneSingleExpr.addChild(clone((PreIncrementExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | MinusMinus singleExpression                                            # PreDecreaseExpression
        else if (srcChild instanceof PreDecreaseExpressionContext) {
            cloneSingleExpr.addChild(clone((PreDecreaseExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | Plus singleExpression                                                  # UnaryPlusExpression
        else if (srcChild instanceof UnaryPlusExpressionContext) {
            cloneSingleExpr.addChild(clone((UnaryPlusExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | Minus singleExpression                                                 # UnaryMinusExpression
        else if (srcChild instanceof UnaryMinusExpressionContext) {
            cloneSingleExpr.addChild(clone((UnaryMinusExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | BitNot singleExpression                                                # BitNotExpression
        else if (srcChild instanceof BitNotExpressionContext) {
            cloneSingleExpr.addChild(clone((BitNotExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | Not singleExpression                                                   # NotExpression
        else if (srcChild instanceof NotExpressionContext) {
            cloneSingleExpr.addChild(clone((NotExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression (Multiply | Divide | Modulus) singleExpression        # MultiplicativeExpression
        else if (srcChild instanceof MultiplicativeExpressionContext) {
            cloneSingleExpr.addChild(clone((MultiplicativeExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression (Plus | Minus) singleExpression                       # AdditiveExpression
        else if (srcChild instanceof AdditiveExpressionContext) {
            cloneSingleExpr.addChild(clone((AdditiveExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression shiftOperator singleExpression                        # BitShiftExpression
        else if (srcChild instanceof BitShiftExpressionContext) {
            cloneSingleExpr.addChild(clone((BitShiftExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression (LessThan | MoreThan | LessThanEquals | GreaterThanEquals) singleExpression # RelationalExpression
        else if (srcChild instanceof RelationalExpressionContext) {
            cloneSingleExpr.addChild(clone((RelationalExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression Instanceof primaryType                                # InstanceofExpression
        else if (srcChild instanceof InstanceofExpressionContext) {
            cloneSingleExpr.addChild(clone((InstanceofExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression (Equals | NotEquals | IdentityEquals | IdentityNotEquals) singleExpression # EqualityExpression
        else if (srcChild instanceof EqualityExpressionContext) {
            cloneSingleExpr.addChild(clone((EqualityExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression BitAnd singleExpression                               # BitAndExpression
        else if (srcChild instanceof BitAndExpressionContext) {
            cloneSingleExpr.addChild(clone((BitAndExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression BitXor singleExpression                               # BitXOrExpression
        else if (srcChild instanceof BitXOrExpressionContext) {
            cloneSingleExpr.addChild(clone((BitXOrExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression BitOr singleExpression                                # BitOrExpression
        else if (srcChild instanceof BitOrExpressionContext) {
            cloneSingleExpr.addChild(clone((BitOrExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression And singleExpression                                  # LogicalAndExpression
        else if (srcChild instanceof LogicalAndExpressionContext) {
            cloneSingleExpr.addChild(clone((LogicalAndExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression Or singleExpression                                   # LogicalOrExpression
        else if (srcChild instanceof LogicalOrExpressionContext) {
            cloneSingleExpr.addChild(clone((LogicalOrExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression QuestionMark singleExpression Colon singleExpression  # TernaryExpression
        else if (srcChild instanceof TernaryExpressionContext) {
            cloneSingleExpr.addChild(clone((TernaryExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression Assign singleExpression                               # AssignmentExpression
        else if (srcChild instanceof AssignmentExpressionContext) {
            cloneSingleExpr.addChild(clone((AssignmentExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression assignmentOperator singleExpression                   # AssignmentOperatorExpression
        else if (srcChild instanceof AssignmentOperatorExpressionContext) {
            cloneSingleExpr.addChild(clone((AssignmentOperatorExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | (typeReference Dot)? This                                              # ThisExpression
        else if (srcChild instanceof ThisExpressionContext) {
            cloneSingleExpr.addChild(clone((ThisExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | Identifier                                                             # IdentifierExpression
        else if (srcChild instanceof IdentifierExpressionContext) {
            cloneSingleExpr.addChild(clone((IdentifierExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | (typeReference Dot)? Super                                             # SuperExpression
        else if (srcChild instanceof SuperExpressionContext) {
            cloneSingleExpr.addChild(clone((SuperExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        else if (srcChild instanceof LiteralContext) {
            cloneSingleExpr.addChild(clone((LiteralContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | literal                                                                # LiteralExpression
        else if (srcChild instanceof LiteralExpressionContext) {
            cloneSingleExpr.addChild(clone((LiteralExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | OpenBracket expressionSequence? CloseBracket                           # ArrayLiteralExpression
        else if (srcChild instanceof ArrayLiteralExpressionContext) {
            cloneSingleExpr.addChild(clone((ArrayLiteralExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | primaryType Dot Class                                                  # ClassLiteralExpression
        else if (srcChild instanceof ClassLiteralExpressionContext) {
            cloneSingleExpr.addChild(clone((ClassLiteralExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | OpenParen singleExpression CloseParen                                  # ParenthesizedExpression
        else if (srcChild instanceof ParenthesizedExpressionContext) {
            cloneSingleExpr.addChild(clone((ParenthesizedExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        //    | singleExpression As (intersectionType | primaryType)                   # CastExpression
        else if (srcChild instanceof CastExpressionContext) {
            cloneSingleExpr.addChild(clone((CastExpressionContext) srcChild)).setParent(cloneSingleExpr);
        }
        //    | Await singleExpression                                                 # AwaitExpression
        else if (srcChild instanceof AwaitExpressionContext) {
            cloneSingleExpr.addChild(clone((AwaitExpressionContext)srcChild)).setParent(cloneSingleExpr);
        }
        else
            assert false;

        return cloneSingleExpr;
    }
}
