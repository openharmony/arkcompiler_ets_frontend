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

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.Transformer;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;

import org.antlr.v4.runtime.ParserRuleContext;

import com.intellij.openapi.util.TextRange;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.psi.PsiElement;
import com.intellij.psi.tree.IElementType;
import org.jetbrains.kotlin.KtNodeTypes;
import org.jetbrains.kotlin.analyzer.AnalysisResult;
import org.jetbrains.kotlin.descriptors.ClassifierDescriptor;
import org.jetbrains.kotlin.descriptors.DeclarationDescriptor;
import org.jetbrains.kotlin.descriptors.SimpleFunctionDescriptor;
import org.jetbrains.kotlin.diagnostics.PsiDiagnosticUtils;
import org.jetbrains.kotlin.lexer.KtSingleValueToken;
import org.jetbrains.kotlin.lexer.KtTokens;
import org.jetbrains.kotlin.name.FqName;
import org.jetbrains.kotlin.psi.*;
import org.jetbrains.kotlin.psi.psiUtil.KtPsiUtilKt;
import org.jetbrains.kotlin.psi.psiUtil.PsiUtilsKt;
import org.jetbrains.kotlin.resolve.BindingContext;
import org.jetbrains.kotlin.resolve.descriptorUtil.DescriptorUtilsKt;
import org.jetbrains.kotlin.types.KotlinType;
import org.jetbrains.kotlin.types.error.ErrorUtils;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Performs transformation of the Kotlin AST into StaticTS AST.
 */
public class KotlinTransformer extends KtVisitor<ParserRuleContext, Void> implements Transformer {
    File srcFile;
    KtFile ktFile;
    AnalysisResult analysisResult;
    BindingContext bindingContext;
    CompilationUnitContext stsCU;

    private Map<String, String> importAliasMap = new HashMap<>();
    public KotlinTransformer(KtFile ktFile, File srcFile, AnalysisResult analysisResult) {
        this.srcFile = srcFile;
        this.ktFile = ktFile;
        this.analysisResult = analysisResult;
        this.bindingContext = analysisResult.getBindingContext();
    }

    public CompilationUnitContext transform() {
        return visitKtFile(ktFile, null);
    }

    private PsiDiagnosticUtils.LineAndColumn getLineAndColumn(PsiElement psiElement) {
        TextRange textRange;

        if (psiElement == null) {
            return PsiDiagnosticUtils.LineAndColumn.NONE;
        }

        if (psiElement instanceof KtDeclaration) {
            // If any comment precedes function or class declaration, then it will
            // be considered a part of declaration and will affect the calculation
            // of node's line number.
            textRange = PsiUtilsKt.getTextRangeWithoutComments(psiElement);
        } else {
            textRange = psiElement.getTextRange();
        }

        return PsiDiagnosticUtils.offsetToLineAndColumn(ktFile.getViewProvider().getDocument(), textRange.getStartOffset());
    }

    private void reportError(String message, PsiElement ktNode) {
        String loc = srcFile.getPath() + ":" + getLineAndColumn(ktNode);
        Main.addError(ResultCode.TranspileError, message + " at " + loc);
    }

    public static boolean isErrorDescriptor(DeclarationDescriptor ktDescriptor) {
        return ktDescriptor == null || ErrorUtils.isError(ktDescriptor);
    }

    public static boolean isErrorType(KotlinType ktType) {
        return ktType == null || ErrorUtils.INSTANCE.containsErrorType(ktType);
    }

    private TypeReferenceContext translateType(KotlinType ktType, KtElement ktElement) {
        if (isErrorType(ktType)) {
            reportError("Failed to resolve type", ktElement);
            return NodeBuilder.unknownTypeReference(null);
        }

        ClassifierDescriptor ktClassifierDescriptor = ktType.getConstructor().getDeclarationDescriptor();
        if (isErrorDescriptor(ktClassifierDescriptor)) {
            reportError("Failed to resolve type", ktElement);
            return NodeBuilder.unknownTypeReference(null);
        }

        String typeName;
        FqName ktFqName = DescriptorUtilsKt.getFqNameSafe(ktClassifierDescriptor);
        if (ktFqName != null) {
            typeName = ktFqName.asString();
        } else {
            typeName = ktClassifierDescriptor.getName().asString();
        }

        return NodeBuilder.typeReference(typeName);
    }

    /**
     * Visit element's children and add result of translation of each child to the specified STS context.
     */
    private void visitChildren(KtElement ktElement, ParserRuleContext stsContext) {
        for (PsiElement child : ktElement.getChildren()) {
            if (child instanceof KtElement) {
                ParserRuleContext stsResult = ((KtElement) child).accept(this, null);

                if (stsResult != null && stsContext != null) {
                    stsContext.addChild(stsResult).setParent(stsContext);
                }
            }
        }
    }

    // Default visit method for kotlin node. Simply visit all children of the element.
    @Override
    public ParserRuleContext visitKtElement(KtElement ktElement, Void data) {
        visitChildren(ktElement, null);
        return null;
    }

    @Override
    public CompilationUnitContext visitKtFile(KtFile ktFile, Void data) {
        stsCU = new CompilationUnitContext(null, 0);
        visitChildren(ktFile, stsCU);
        return stsCU;
    }

    @Override
    public ParserRuleContext visitPackageDirective(KtPackageDirective ktPackageDirective, Void data) {
        PackageDeclarationContext stsPackage = new PackageDeclarationContext(null, 0);
        stsPackage.addChild(NodeBuilder.terminalNode(StaticTSParser.Package));
        stsPackage.addChild(NodeBuilder.qualifiedName(ktPackageDirective.getQualifiedName())).setParent(stsPackage);
        return stsPackage;
    }

    @Override
    public ParserRuleContext visitImportDirective(KtImportDirective ktImportDirective, Void data) {
        ImportDeclarationContext stsImport = new ImportDeclarationContext(stsCU, 0);
        stsImport.addChild(NodeBuilder.terminalNode(StaticTSParser.Import));

        ImportBindingContext stsImportBinding = new ImportBindingContext(stsImport, 0);

        // TODO: Handle imports from types and other nested entities.
        String importedFQN = ktImportDirective.getImportedFqName().asString();
        String importedFromPath = importedFQN;
        if (!ktImportDirective.isAllUnder()) {
            int lastDotPos = importedFQN.lastIndexOf('.');
            importedFromPath = importedFQN.substring(0, lastDotPos);
            String className = importedFQN.substring(lastDotPos + 1);

            stsImportBinding.addChild(NodeBuilder.qualifiedName(className)).setParent(stsImportBinding);

            String alias = ktImportDirective.getAliasName();
            if (alias != null) {
                stsImportBinding.addChild(NodeBuilder.terminalNode(StaticTSParser.As));
                stsImportBinding.addChild(NodeBuilder.terminalIdentifier(alias));
            }
        }

        stsImport.addChild(stsImportBinding).setParent(stsImport);

        // Replace dots with slashes to get the path.
        importedFromPath = importedFromPath.replace('.', '/');

        stsImport.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.FROM));
        stsImport.addChild(NodeBuilder.terminalNode(StaticTSParser.StringLiteral, importedFromPath));

        stsCU.addChild(stsImport).setParent(stsCU);

        return null;
    }

    @Override
    public ParserRuleContext visitClass(KtClass ktClass, Void data) {
        ParserRuleContext stsResult;

//        if (ktClass.isInterface()) {
//            stsResult = new InterfaceDeclarationContext(null, 0);
//            stsResult.addChild(NodeBuilder.terminalNode(StaticTSParser.Interface));
//        } else {
            stsResult = new ClassDeclarationContext(null, 0);
            stsResult.addChild(NodeBuilder.terminalNode(StaticTSParser.Class));
//        }

        if (ktClass.hasModifier(KtTokens.ABSTRACT_KEYWORD))
            stsResult.addChild(NodeBuilder.terminalNode(StaticTSParser.Abstract));
        else if (ktClass.hasModifier(KtTokens.OPEN_KEYWORD))
            stsResult.addChild(NodeBuilder.terminalNode(StaticTSParser.Open));

        stsResult.addChild(NodeBuilder.terminalIdentifier(ktClass.getName()));

        ClassBodyContext stsClassBody = new ClassBodyContext(stsResult, 0);
        stsResult.addChild(stsClassBody).setParent(stsResult);

        KtClassBody ktClassBody = ktClass.getBody();
        if (ktClassBody != null) {
            visitChildren(ktClassBody, stsClassBody);
        }

        if (ktClass.isTopLevel()) {
            TopDeclarationContext stsTopDecl = new TopDeclarationContext(null, 0);

            if (KtPsiUtilKt.isPublic(ktClass)) {
                stsTopDecl.addChild(NodeBuilder.terminalNode(StaticTSParser.Export));
            }

            stsTopDecl.addChild(stsResult).setParent(stsTopDecl);
            stsResult = stsTopDecl;
        }
        // else {
        //    TODO: inner, nested, local
        // }

        return stsResult;
    }

    @Override
    public TypeReferenceContext visitTypeReference(KtTypeReference ktTypeReference, Void data) {
        TypeReferenceContext stsTypeRef = (TypeReferenceContext) ktTypeReference.getTypeElement().accept(this, data);

        if (stsTypeRef == null) {
            reportError("Failed to translate type", ktTypeReference);
            stsTypeRef = NodeBuilder.unknownTypeReference(ktTypeReference.getText());
        }

        return stsTypeRef;
    }

    @Override
    public TypeReferenceContext visitUserType(KtUserType ktUserType, Void data) {
        TypeReferenceContext stsTypeRef;

        KtUserType ktQualifier = ktUserType.getQualifier();
        if (ktQualifier != null) {
            stsTypeRef = (TypeReferenceContext) ktQualifier.accept(this, data);
        }
        else {
            stsTypeRef = new TypeReferenceContext(null, 0);
        }

        TypeReferencePartContext stsTypeRefPart = NodeBuilder.typeReferencePart(ktUserType.getReferencedName());
        stsTypeRef.addChild(stsTypeRefPart).setParent(stsTypeRef);

        // TODO: Translate type arguments

        return stsTypeRef;
    }

    @Override
    public ParserRuleContext visitNamedFunction(KtNamedFunction ktNamedFunction, Void data) {
        if (ktNamedFunction.isTopLevel()) {
            return translateTopLevelFunction(ktNamedFunction);
        }
//      else if (ktNamedFunction.isLocal()) {
//          TODO:
//      }
        else {
            return translateClassMethod(ktNamedFunction);
        }
    }

    private ParserRuleContext translateTopLevelFunction(KtNamedFunction ktNamedFunction) {
        TopDeclarationContext stsTopDecl = new TopDeclarationContext(null, 0);

        if (KtPsiUtilKt.isPublic(ktNamedFunction)) {
            stsTopDecl.addChild(NodeBuilder.terminalNode(StaticTSParser.Export));
        }

        FunctionDeclarationContext stsFunctionDecl = new FunctionDeclarationContext(stsTopDecl, 0);
        stsTopDecl.addChild(stsFunctionDecl).setParent(stsTopDecl);

        stsFunctionDecl.addChild(NodeBuilder.terminalNode(StaticTSParser.Function));

        translateFunction(ktNamedFunction, stsFunctionDecl);

        return stsTopDecl;
    }

    private ParserRuleContext translateClassMethod(KtNamedFunction ktNamedFunction) {
        ClassMethodDeclarationContext stsClassMethod = new ClassMethodDeclarationContext(null, 0);
        ParserRuleContext stsMethod;
        if (ktNamedFunction.getBodyExpression() != null) {
            stsMethod = new ClassMethodWithBodyContext(stsClassMethod);
        } else {
            stsMethod = new AbstractOrNativeClassMethodContext(stsClassMethod);
        }
        stsClassMethod.addChild(stsMethod).setParent(stsClassMethod);

        if (ktNamedFunction.hasModifier(KtTokens.ABSTRACT_KEYWORD))
            stsMethod.addChild(NodeBuilder.terminalNode(StaticTSParser.Abstract));
        else if (ktNamedFunction.hasModifier(KtTokens.OPEN_KEYWORD))
            stsMethod.addChild(NodeBuilder.terminalNode(StaticTSParser.Open));
        else if (ktNamedFunction.hasModifier(KtTokens.OVERRIDE_KEYWORD))
            stsMethod.addChild(NodeBuilder.terminalNode(StaticTSParser.Override));

        translateFunction(ktNamedFunction, stsMethod);

        ClassMemberContext stsClassMember = NodeBuilder.classMember(ktNamedFunction);
        stsClassMember.addChild(stsClassMethod).setParent(stsClassMember);

        return stsClassMember;
    }

    private void translateFunction(KtNamedFunction ktNamedFunction, ParserRuleContext stsFunction) {
        stsFunction.addChild(NodeBuilder.terminalIdentifier(ktNamedFunction.getName()));

        SignatureContext stsSignature = translateFunctionHeader(ktNamedFunction);
        stsFunction.addChild(stsSignature).setParent(stsFunction);

        KtExpression ktBodyExpr = ktNamedFunction.getBodyExpression();
        if (ktBodyExpr != null) {
            BlockContext stsBlock = translateFunctionBody(ktBodyExpr);
            stsFunction.addChild(stsBlock).setParent(stsFunction);
        }
    }

    private SignatureContext translateFunctionHeader(KtNamedFunction ktNamedFunction) {
        SignatureContext stsSignature = new SignatureContext(null, 0);

        // TODO: Translate type parameters

        ParameterListContext stsParameterList = translateFunctionParameters(ktNamedFunction.getValueParameters());
        if (stsParameterList != null) {
            stsSignature.addChild(stsParameterList).setParent(stsSignature);
        }

        TypeReferenceContext stsTypeRef;

        KtTypeReference ktReturnType = ktNamedFunction.getTypeReference();
        if (ktReturnType != null) {
            stsTypeRef = (TypeReferenceContext) ktNamedFunction.getTypeReference().accept(this, null);
        } else {
            // The return type might be omitted in source code. In this case,
            // it is inferred by compiler. Use the function descriptor to
            // retrieve the return type.
            SimpleFunctionDescriptor ktDescriptor = bindingContext.get(BindingContext.FUNCTION, ktNamedFunction);
            if (isErrorDescriptor(ktDescriptor)) {
                reportError("Failed to resolve return type of function", ktNamedFunction);
                stsTypeRef = NodeBuilder.unknownTypeReference(null);
            } else {
                stsTypeRef = translateType(ktDescriptor.getReturnType(), ktNamedFunction);
            }
        }

        stsSignature.addChild(NodeBuilder.typeAnnotation(stsTypeRef)).setParent(stsSignature);

        return stsSignature;
    }

    private ParameterListContext translateFunctionParameters(List<KtParameter> ktParameters) {
        if (ktParameters == null || ktParameters.isEmpty())
            return null;

        ParameterListContext stsParameterList = new ParameterListContext(null, 0);

        for (KtParameter ktParameter : ktParameters) {
            ParserRuleContext stsParam = ktParameter.accept(this, null);
            stsParameterList.addChild(stsParam).setParent(stsParameterList);
        }

        return stsParameterList;
    }

    @Override
    public ParserRuleContext visitParameter(KtParameter ktParameter, Void data) {
        ParserRuleContext stsParam;

        if (ktParameter.isVarArg()) {
            stsParam = new VariadicParameterContext(null, 0);
            stsParam.addChild(NodeBuilder.terminalNode(StaticTSParser.Ellipsis));
        }
        else {
            stsParam = new ParameterContext(null, 0);
        }

        stsParam.addChild(NodeBuilder.terminalIdentifier(ktParameter.getName()));

        TypeReferenceContext stsTypeRef = (TypeReferenceContext) ktParameter.getTypeReference().accept(this, null);
        stsParam.addChild(NodeBuilder.typeAnnotation(stsTypeRef)).setParent(stsParam);

        return stsParam;
    }

    private BlockContext translateFunctionBody(KtExpression ktBodyExpression) {
        BlockContext stsBlock;

        if (ktBodyExpression instanceof KtBlockExpression) {
            stsBlock = (BlockContext) ktBodyExpression.accept(this, null);
        } else {
            stsBlock = new BlockContext(null, 0);

            StatementOrLocalDeclarationContext stsStmtOrLocalDecl = new StatementOrLocalDeclarationContext(stsBlock, 0);
            stsBlock.addChild(stsStmtOrLocalDecl);

            StatementContext stsStmt = new StatementContext(stsStmtOrLocalDecl, 0);
            stsStmtOrLocalDecl.addChild(stsStmt);

            ReturnStatementContext stsReturn = new ReturnStatementContext(stsStmt, 0);
            stsReturn.addChild(NodeBuilder.terminalNode(StaticTSParser.Return));
            stsStmt.addChild(stsReturn);

            ParserRuleContext stsRetExpr = ktBodyExpression.accept(this, null);
            stsReturn.addChild(stsRetExpr).setParent(stsReturn);
        }

        return stsBlock;
    }


    @Override
    public BlockContext visitBlockExpression(KtBlockExpression ktBlockExpression, Void data) {
        BlockContext stsBlock = new BlockContext(null, 0);

        for (KtExpression ktExpr : ktBlockExpression.getStatements()) {
            ParserRuleContext stsStmtResult = ktExpr.accept(this, data);

            // If an expression is used as a statement, wrap it up
            // with a statement context.
            if (stsStmtResult.getRuleIndex() == StaticTSParser.RULE_singleExpression) {
                stsStmtResult = NodeBuilder.expressionStatement((SingleExpressionContext) stsStmtResult);
            }

            StatementOrLocalDeclarationContext stsStmtOrLocalDecl = new StatementOrLocalDeclarationContext(stsBlock, 0);
            stsStmtOrLocalDecl.addChild(stsStmtResult).setParent(stsStmtOrLocalDecl);
            stsBlock.addChild(stsStmtOrLocalDecl);
        }

        return stsBlock;
    }

    @Override
    public ParserRuleContext visitProperty(KtProperty ktProperty, Void data) {
        if (ktProperty.isTopLevel()) {
            // TODO: Translate top-level property.
        }
        else if (ktProperty.isMember()) {
            // TODO: Translate class member property.
        }
        else {
            return translateLocalVariableDeclaration(ktProperty);
        }

        return super.visitProperty(ktProperty, data);
    }

    private ParserRuleContext translateLocalVariableDeclaration(KtProperty ktProperty) {
        VariableOrConstantDeclarationContext stsVarOrConstDecl = new VariableOrConstantDeclarationContext(null, 0);

        // Note: Kotlin allows read-only variables declared without initializer.
        // STS doesn't allow const variables without initializer, thus translate
        // such variables without const modifier.
        KtExpression ktInitExpr = ktProperty.getInitializer();
        boolean isConst = !ktProperty.isVar() && ktInitExpr != null;
        ParserRuleContext stsDeclList;
        if (isConst) {
            stsVarOrConstDecl.addChild(NodeBuilder.terminalNode(StaticTSParser.Const));
            stsDeclList = new ConstantDeclarationListContext(stsVarOrConstDecl, 0);
        } else {
            stsVarOrConstDecl.addChild(NodeBuilder.terminalNode(StaticTSParser.Let));
            stsDeclList = new VariableDeclarationListContext(stsVarOrConstDecl, 0);
        }
        stsVarOrConstDecl.addChild(stsDeclList);

        ParserRuleContext stsDecl;
        if (isConst) {
            stsDecl = new ConstantDeclarationContext(stsVarOrConstDecl, 0);
        } else {
            stsDecl = new VariableDeclarationContext(stsVarOrConstDecl, 0);
        }
        stsDeclList.addChild(stsDecl);

        stsDecl.addChild(NodeBuilder.terminalIdentifier(ktProperty.getName()));

        KtTypeReference ktTypeRef = ktProperty.getTypeReference();
        if (ktTypeRef != null) {
            TypeReferenceContext stsTypeRef = (TypeReferenceContext) ktTypeRef.accept(this, null);
            stsDecl.addChild(NodeBuilder.typeAnnotation(stsTypeRef)).setParent(stsDecl);
        }

        if (ktInitExpr != null) {
            InitializerContext stsInit = new InitializerContext(stsDecl, 0);
            stsInit.addChild(ktInitExpr.accept(this, null)).setParent(stsInit);
            stsDecl.addChild(stsInit);
        }

        return stsVarOrConstDecl;
    }

    @Override
    public SingleExpressionContext visitConstantExpression(KtConstantExpression ktConstantExpression, Void data) {
        SingleExpressionContext stsConstExpr;

        String ktConstText = ktConstantExpression.getText();
        IElementType ktElementType = ktConstantExpression.getNode().getElementType();
        if (ktElementType == KtNodeTypes.BOOLEAN_CONSTANT) {
            stsConstExpr = NodeBuilder.boolLiteral(Boolean.parseBoolean(ktConstText));
        }
        else if (ktElementType == KtNodeTypes.INTEGER_CONSTANT || ktElementType == KtNodeTypes.FLOAT_CONSTANT) {
            stsConstExpr = NodeBuilder.numericLiteral(ktConstText);
        }
        else if (ktElementType == KtNodeTypes.CHARACTER_CONSTANT) {
            stsConstExpr = NodeBuilder.charLiteral(ktConstText);
        }
        else if (ktElementType == KtNodeTypes.NULL) {
            stsConstExpr = NodeBuilder.nullLiteral();
        }
        else {
            reportError("Unknown constant expression kind", ktConstantExpression);
            stsConstExpr = NodeBuilder.untranslatedExpression(ktConstantExpression);
        }

        return stsConstExpr;
    }

    public ParserRuleContext visitBinaryExpression(KtBinaryExpression ktBinaryExpr, Void data) {
        KtOperationReferenceExpression ktOpRef = ktBinaryExpr.getOperationReference();
        KtSingleValueToken ktOpToken = ktOpRef.getOperationSignTokenType();

        if (KtPsiUtil.isAssignment(ktBinaryExpr)) {
            SingleExpressionContext stsExpr = new SingleExpressionContext(null, 0);

            ParserRuleContext stsAssignExpr;
            if(ktOpToken == KtTokens.EQ) {
                stsAssignExpr = new AssignmentExpressionContext(stsExpr);
            } else {
                stsAssignExpr = new AssignmentOperatorExpressionContext(stsExpr);
            }
            stsExpr.addChild(stsAssignExpr).setParent(stsExpr);

            ParserRuleContext stsLeftExpr = ktBinaryExpr.getLeft().accept(this, data);
            stsAssignExpr.addChild(stsLeftExpr).setParent(stsAssignExpr);

            if(ktOpToken == KtTokens.EQ) {
                stsAssignExpr.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
            } else {
                AssignmentOperatorContext stsAssignOp = NodeBuilder.assignmentOperator(ktOpToken);
                stsAssignExpr.addChild(stsAssignOp).setParent(stsAssignExpr);
            }

            ParserRuleContext stsRightExpr = ktBinaryExpr.getRight().accept(this, data);
            stsAssignExpr.addChild(stsRightExpr).setParent(stsAssignExpr);

            return stsExpr;
        } else {
            // TODO: Translate binary expressions.

            return super.visitBinaryExpression(ktBinaryExpr, data);
        }
    }

    @Override
    public ParserRuleContext visitSimpleNameExpression(KtSimpleNameExpression ktSimpleName, Void data) {
        return NodeBuilder.identifierExpression(ktSimpleName.getReferencedName());
    }

    @Override
    public ParserRuleContext visitStringTemplateExpression(KtStringTemplateExpression ktStringTemplateExpr, Void data) {
        if (ktStringTemplateExpr.hasInterpolation()) {
            // TODO: Translate string interpolation.
            return super.visitStringTemplateExpression(ktStringTemplateExpr, data);
        } else {
            // Collect all string template entries into one string literal.
            StringBuilder literal = new StringBuilder();
            for (KtStringTemplateEntry ktTemplateEntry : ktStringTemplateExpr.getEntries()) {
                literal.append(ktTemplateEntry.getText());
            }

            // Escape line-terminating characters that might appear from the multi-line string.
            literal = StringUtil.escapeStringCharacters(literal.length(), literal.toString(), null, false, false, new StringBuilder());
            return NodeBuilder.stringLiteral('\"' + literal.toString() + '\"');
        }
    }

    @Override
    public ParserRuleContext visitExpression(KtExpression ktExpression, Void data) {
        // For the moment, return untranslated expression/statement in order
        // to avoid possible NullPointerExceptions while developing the translator.
        // TODO: Remove this code, once all expressions are supported.
        if (KtPsiUtil.isStatement(ktExpression))
            return NodeBuilder.untranslatedStatement(ktExpression);
        else
            return NodeBuilder.untranslatedExpression(ktExpression);
    }

}