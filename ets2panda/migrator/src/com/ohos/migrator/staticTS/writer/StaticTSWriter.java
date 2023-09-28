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

package com.ohos.migrator.staticTS.writer;

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.staticTS.parser.StaticTSContextBase;
import com.ohos.migrator.staticTS.parser.StaticTSLexer;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import com.ohos.migrator.staticTS.parser.StaticTSParserBaseVisitor;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.RuleNode;
import org.antlr.v4.runtime.tree.TerminalNode;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.List;

public class StaticTSWriter extends StaticTSParserBaseVisitor<Void> {
    private final Writer out;
    private final String outPath;
    private final String indentStep = "    "; // 4 spaces
    private final StringBuffer sb = new StringBuffer();
    private String indentCurrent = "";

    public StaticTSWriter(String path) throws IOException {
        outPath = path;
        out = new FileWriter(path);
    }
    public void close() {
        if (out != null) {
            try {
                out.write(sb.toString());
                out.flush();
                out.close();
            } catch (IOException e) {
                System.out.print("Fail to flush and close the output file.");
            }
        }
    }

    public static void main(String[] args) {
        if (args.length >= 1) {
            try {
                CharStream input = CharStreams.fromFileName(args[0]);
                StaticTSLexer lexer = new StaticTSLexer(input);
                CommonTokenStream tokens = new CommonTokenStream(lexer);
                StaticTSParser parser = new StaticTSParser(tokens);

                CompilationUnitContext compilationUnit = parser.compilationUnit();

                if (args.length >= 2) {
                    try {
                        StaticTSWriter writer = new StaticTSWriter(args[1]);
                        writer.visit(compilationUnit);
                        writer.close();
                    } catch (IOException e) {
                        System.out.printf("Fail to open the specified out file: \"%s\"", args[1]);
                    }
                }
            } catch (IOException e) {
                System.out.printf("Fail to open the specified input file: \"%s\"", args[0]);
            }
        }
        else
            System.out.println("The first argument to specify file to parse.");
    }

    private void indentIncrement() {
        indentCurrent += indentStep;
    }

    private void indentDecrement() {
        indentCurrent = indentCurrent.substring(0, indentCurrent.length() - indentStep.length());
    }

    // Return is a boolean value. Maybe sometime if indent is not inserted there will be need in a white space char.
    private boolean doNeededIndent() {
        if (sb.length() > 1 && sb.charAt(sb.length()-1) == '\n') {
            sb.append(indentCurrent);
            return true;
        }

        return false;
    }
    private void writeLeadingComments(StaticTSContextBase stsNode) {
        if (stsNode == null || !stsNode.hasLeadingComments()) return;

        for (TerminalNode stsComment : stsNode.getLeadingComments()) {
            stsComment.accept(this);
            sb.append('\n');
        }
    }

    private void writeTrailingComments(StaticTSContextBase stsNode) {
        if (stsNode == null || !stsNode.hasTrailingComments()) return;
        List<TerminalNode> stsComments = stsNode.getTrailingComments();

        int numLF = 0;
        // Check that sb is not empty to avoid StringIndexOutOfBounds thrown here.
        while (sb.length() > 0 && sb.charAt(sb.length()-numLF-1) == '\n')
            ++numLF;

        TerminalNode stsFirstComment = stsComments.get(0);
        if (stsComments.size() == 1 && stsFirstComment.getText().indexOf('\n') == -1) {
            // Special treatment for the single one-line trailing comment:
            // Make sure there is always a space in front of the comment.
            // If there are line terminators there, emit them after the comment.
            if (numLF > 0)
                sb.setLength(sb.length()-numLF);

            sb.append(' ');

            stsFirstComment.accept(this);
            if (numLF > 0) sb.append("\n".repeat(numLF));
        }
        else {
            // Otherwise, emit line terminator after each comment, adding
            // one in front of the first comment if it's not there already.
            if (numLF == 0) sb.append('\n');
            for (TerminalNode stsComment : stsComments) {
                stsComment.accept(this);
                sb.append('\n');
            }
        }
    }

    // initializer: '=' (arrayLiteral | singleExpression)
    @Override
    public Void visitInitializer(InitializerContext stsInitializer) {
        writeLeadingComments(stsInitializer);

        sb.append("= ");

        SingleExpressionContext stsExpression = stsInitializer.singleExpression();
        assert(stsExpression != null);
        stsExpression.accept(this);

        writeTrailingComments(stsInitializer);
        return null;
    }

    // typeParameters: '<' typeParameterList? '>'
    @Override
    public Void visitTypeParameters(TypeParametersContext stsTypeParameters) {
        writeLeadingComments(stsTypeParameters);
        sb.append('<');

        TypeParameterListContext stsTypeParameterList = stsTypeParameters.typeParameterList();
        if (stsTypeParameterList != null) {
            visitTypeParameterList(stsTypeParameterList);
        }

        sb.append('>');

        writeTrailingComments(stsTypeParameters);
        return null;
    }

    // typeParameterList: typeParameter (',' typeParameter)*;
    @Override
    public Void visitTypeParameterList(TypeParameterListContext stsTypeParameterList) {
        writeLeadingComments(stsTypeParameterList);

        int i = 0;
        for (TypeParameterContext stsTypeParameter : stsTypeParameterList.typeParameter()) {
            if (i > 0) sb.append(", ");
            visitTypeParameter(stsTypeParameter);
            ++i;
        }

        writeTrailingComments(stsTypeParameterList);
        return null;
    }

    // typeParameter: ({ this.next(IN) || this.next(OUT) }? Identifier)? Identifier constraint?
    @Override
    public Void visitTypeParameter(TypeParameterContext stsTypeParameter) {
        writeLeadingComments(stsTypeParameter);
        List<TerminalNode> stsIdentifiers = stsTypeParameter.Identifier();

        if (stsIdentifiers.size() > 1) {
            // Sanity check: First identifier should be either 'in' or 'out'
            String stsInOrOutKeyword = stsIdentifiers.get(0).getText();
            if (!StaticTSParser.IN.equals(stsInOrOutKeyword) && !StaticTSParser.OUT.equals(stsInOrOutKeyword)) {
                reportError("Unexpected token " + stsInOrOutKeyword + " in type parameter", stsTypeParameter);
                stsInOrOutKeyword = "/* Unexpected token: " + stsInOrOutKeyword + " */";
            }

            sb.append(stsInOrOutKeyword).append(' ');
            sb.append(stsIdentifiers.get(1).getText());
        }
        else {
            sb.append(stsIdentifiers.get(0).getText());
        }

        ConstraintContext stsConstraint = stsTypeParameter.constraint();
        if (stsConstraint != null) {
            sb.append(' ');
            visitConstraint(stsConstraint);
        }

        writeTrailingComments(stsTypeParameter);
        return null;
    }

    // constraint: 'extends' type_
    @Override
    public Void visitConstraint(ConstraintContext stsConstraint) {
        writeLeadingComments(stsConstraint);

        String stsExtendsKeyword = stsConstraint.Identifier().getText();
        if (!StaticTSParser.EXTENDS.equals(stsExtendsKeyword)) {
            reportError("Unexpected keyword " + stsExtendsKeyword + " in type parameter constraint", stsConstraint);
            stsExtendsKeyword = StaticTSParser.EXTENDS;
        }
        sb.append(stsExtendsKeyword).append(' ');

        TypeReferenceContext stsType = stsConstraint.typeReference();
        if (stsType != null) {
            visitTypeReference(stsType);
        }
        else {
            IntersectionTypeContext stsIntersectionType = stsConstraint.intersectionType();
            assert stsIntersectionType != null;
            visitIntersectionType(stsIntersectionType);
        }

        writeTrailingComments(stsConstraint);
        return null;
    }

    // typeArguments: '<' typeArgumentList? '>'
    @Override
    public Void visitTypeArguments(TypeArgumentsContext stsTypeArguments) {
        writeLeadingComments(stsTypeArguments);
        sb.append('<');

        TypeArgumentListContext stsTypeArgumentList = stsTypeArguments.typeArgumentList();
        if (stsTypeArgumentList != null) {
            visitTypeArgumentList(stsTypeArgumentList);
        }

        sb.append('>');

        writeTrailingComments(stsTypeArguments);
        return null;
    }

    // typeArgumentList: typeArgument (',' typeArgument)*
    @Override
    public Void visitTypeArgumentList(TypeArgumentListContext stsTypeArgumentList) {
        writeLeadingComments(stsTypeArgumentList);

        int i = 0;
        for (TypeArgumentContext stsTypeArgument : stsTypeArgumentList.typeArgument()) {
            if (i > 0) sb.append(", ");
            visitTypeArgument(stsTypeArgument);
            ++i;
        }

        writeTrailingComments(stsTypeArgumentList);
        return null;
    }

    // typeArgument: typeReference | arrayType | functionType | wildcardType | nullableType
    @Override
    public Void visitTypeArgument(TypeArgumentContext stsTypeArgument) {
        writeLeadingComments(stsTypeArgument);

        TypeReferenceContext stsTypeReference = stsTypeArgument.typeReference();
        ArrayTypeContext stsArrayType = stsTypeArgument.arrayType();
        FunctionTypeContext stsFunctionType = stsTypeArgument.functionType();
        WildcardTypeContext stsWildcardType = stsTypeArgument.wildcardType();
        if (stsTypeReference != null) {
            visitTypeReference(stsTypeReference);
        }
        else if (stsArrayType != null) {
            visitArrayType(stsArrayType);
        }
        else if (stsFunctionType != null) {
            visitFunctionType(stsFunctionType);
        }
        else if (stsWildcardType != null) {
            visitWildcardType(stsWildcardType);
        }
        else {
            NullableTypeContext stsNullableType = stsTypeArgument.nullableType();
            assert(stsNullableType != null);

            visitNullableType(stsNullableType);
        }

        writeTrailingComments(stsTypeArgument);
        return null;
    }

    // wildcardType: { this.next(IN) }? Identifier typeReference | { this.next(OUT) }? Identifier typeReference?
    @Override
    public Void visitWildcardType(WildcardTypeContext stsWildcardType) {
        writeLeadingComments(stsWildcardType);

        // Sanity check: Leading identifier should be either 'in' or 'out'
        String stsIdentifier = stsWildcardType.Identifier().getText();
        if (!StaticTSParser.IN.equals(stsIdentifier) && !StaticTSParser.OUT.equals(stsIdentifier)) {
            reportError("Unexpected token " + stsIdentifier + " in wildcard type", stsWildcardType);
            stsIdentifier = "/* Unexpected token: " + stsIdentifier + " */";
        }

        sb.append(stsIdentifier);

        TypeReferenceContext stsTypeRef = stsWildcardType.typeReference();
        if (stsTypeRef != null) {
            sb.append(' ');
            visitTypeReference(stsTypeRef);
        }

        writeTrailingComments(stsWildcardType);
        return null;
    }

    private void reportError(String message, ParserRuleContext stsNode) {
        String loc = outPath + ":" + stsNode.getStart().getLine();
        Main.addError(ResultCode.TranspileError, message + " at " + loc);
    }

    @Override
    public Void visitIntersectionType(IntersectionTypeContext stsIntersectionType) {
        writeLeadingComments(stsIntersectionType);
        sb.append('(');

        for (int i = 0; i < stsIntersectionType.getChildCount(); ++i) {
            ParseTree stsChildNode = stsIntersectionType.getChild(i);

            if (i > 0) sb.append(" & ");
            stsChildNode.accept(this);
        }

        sb.append(')');

        writeTrailingComments(stsIntersectionType);
        return null;
    }

    // typeReference: typeReferencePart (Dot typeReferencePart)?
    @Override
    public Void visitTypeReference(TypeReferenceContext stsTypeReference) {
        writeLeadingComments(stsTypeReference);

        List<TypeReferencePartContext> stsTypeParts = stsTypeReference.typeReferencePart();
        for (int i = 0; i < stsTypeParts.size(); ++i) {
            if (i > 0) sb.append('.');
            visitTypeReferencePart(stsTypeParts.get(i));
        }

        writeTrailingComments(stsTypeReference);
        return null;
    }

    // typeReferencePart: qualifiedName typeArguments?
    @Override
    public Void visitTypeReferencePart(TypeReferencePartContext stsTypeReferencePart) {
        writeLeadingComments(stsTypeReferencePart);
        visitQualifiedName(stsTypeReferencePart.qualifiedName());

        TypeArgumentsContext stsTypeArguments = stsTypeReferencePart.typeArguments();
        if (stsTypeArguments != null) {
            visitTypeArguments(stsTypeArguments);
        }

        writeTrailingComments(stsTypeReferencePart);
        return null;
    }

    // qualifiedName: Identifier (Dot Identifier)*
    @Override
    public Void visitQualifiedName(QualifiedNameContext stsQualName) {
        writeLeadingComments(stsQualName);

        int i = 0;
        for (TerminalNode identifier : stsQualName.Identifier()) {
            if (i > 0) sb.append('.');
            sb.append(identifier.getText());
            ++i;
        }

        writeTrailingComments(stsQualName);
        return null;
    }

//    predefinedType
//    : Byte
//    | Short
//    | Int
//    | Long
//    | Float
//    | Double
//    | Boolean
//    | String
//    | Char
//    | Void
//    ;
    @Override
    public Void visitPredefinedType(PredefinedTypeContext stsPredefinedType) {
        writeLeadingComments(stsPredefinedType);

        sb.append(stsPredefinedType.getText());

        writeTrailingComments(stsPredefinedType);
        return null;
    }

    // arrayType: (predefinedType | typeReference | functionType | '(' nullableType ')' ) ('[' ']')+
    @Override
    public Void visitArrayType(ArrayTypeContext stsArrayType) {
        writeLeadingComments(stsArrayType);

        TypeReferenceContext stsTypeRef = stsArrayType.typeReference();
        PredefinedTypeContext stsPredefType = stsArrayType.predefinedType();
        FunctionTypeContext stsFunctionType = stsArrayType.functionType();
        if (stsTypeRef != null) {
            visitTypeReference(stsTypeRef);
        }
        else if (stsPredefType != null) {
            visitPredefinedType(stsPredefType);
        }
        else if (stsFunctionType != null) {
            visitFunctionType(stsFunctionType);
        }
        else {
            NullableTypeContext stsNullableType = stsArrayType.nullableType();
            assert(stsNullableType != null);

            sb.append('(');
            visitNullableType(stsNullableType);
            sb.append(')');
        }

        List<TerminalNode> openBrackets = stsArrayType.OpenBracket();
        List<TerminalNode> closeBrackets = stsArrayType.CloseBracket();
        int openBracketsNum = openBrackets.size();
        int closeBracketsNum = closeBrackets.size();
        assert(openBracketsNum > 0 && openBracketsNum == closeBracketsNum);
        for (int i = 0; i < openBracketsNum; ++i)
            sb.append("[]");

        writeTrailingComments(stsArrayType);
        return null;
    }

    @Override
    public Void visitFunctionType(FunctionTypeContext stsFunctionType) {
        writeLeadingComments(stsFunctionType);

        sb.append("(");
        ParameterListContext stsParamList = stsFunctionType.parameterList();
        if (stsParamList != null) visitParameterList(stsParamList);
        sb.append(")");

        TypeAnnotationContext stsTypeAnno = stsFunctionType.typeAnnotation();
        visitTypeAnnotation(stsTypeAnno);

        ThrowsAnnotationContext stsThrowsAnno = stsFunctionType.throwsAnnotation();
        if (stsThrowsAnno != null) visitThrowsAnnotation(stsThrowsAnno);

        writeTrailingComments(stsFunctionType);
        return null;
    }

    // nullableType
    //    : (predefinedType | typeReference | functionType | arrayType | wildcardType) BitOr Null
    @Override
    public Void visitNullableType(NullableTypeContext stsNullableType) {
        writeLeadingComments(stsNullableType);

        PredefinedTypeContext stsPredefType = stsNullableType.predefinedType();
        TypeReferenceContext stsTypeRef = stsNullableType.typeReference();
        FunctionTypeContext stsFunctionType = stsNullableType.functionType();
        ArrayTypeContext stsArrayType = stsNullableType.arrayType();
        if (stsPredefType != null) {
            visitPredefinedType(stsPredefType);
        }
        else if (stsTypeRef != null) {
            visitTypeReference(stsTypeRef);
        }
        else if (stsFunctionType != null) {
            visitFunctionType(stsFunctionType);
        }
        else if (stsArrayType != null) {
            visitArrayType(stsArrayType);
        }
        else {
            WildcardTypeContext stsWildcardType = stsNullableType.wildcardType();

            assert(stsWildcardType != null);
            visitWildcardType(stsWildcardType);
        }

        sb.append(" | null");

        writeTrailingComments(stsNullableType);
        return null;
    }

    // typeAnnotation: ':' primaryType
    @Override
    public Void visitTypeAnnotation(TypeAnnotationContext stsTypeAnnotation) {
        writeLeadingComments(stsTypeAnnotation);
        sb.append(": ");

        PrimaryTypeContext stsType = stsTypeAnnotation.primaryType();
        stsType.accept(this);

        if (stsTypeAnnotation.parent.getRuleIndex() != StaticTSParser.RULE_parameter &&
            stsTypeAnnotation.parent.getRuleIndex() != StaticTSParser.RULE_exceptionParameter)
            sb.append(' ');

        writeTrailingComments(stsTypeAnnotation);
        return null;
    }

    // signature: typeParameters? '(' parameterList? ')' typeAnnotation
    @Override
    public Void visitSignature(SignatureContext stsSignature) {
        writeLeadingComments(stsSignature);

        TypeParametersContext stsTypeParameters = stsSignature.typeParameters();
        if (stsTypeParameters != null) {
            visitTypeParameters(stsTypeParameters);
        }

        sb.append('(');

        ParameterListContext stsParameterList = stsSignature.parameterList();
        if (stsParameterList != null) {
            visitParameterList(stsParameterList);
        }

        sb.append(')');

        visitTypeAnnotation(stsSignature.typeAnnotation());

        ThrowsAnnotationContext stsThrowsAnno = stsSignature.throwsAnnotation();
        if (stsThrowsAnno != null) visitThrowsAnnotation(stsThrowsAnno);

        writeTrailingComments(stsSignature);
        return null;
    }

    @Override
    public Void visitThrowsAnnotation(ThrowsAnnotationContext stsThrowsAnno) {
        TerminalNode stsIdentifier = stsThrowsAnno.Identifier();
        if (stsIdentifier != null) {
            String stsIdentifierText = stsIdentifier.getText();
            if (StaticTSParser.THROWS.equals(stsIdentifierText) ||
                StaticTSParser.RETHROWS.equals(stsIdentifierText)) {
                sb.append(' ').append(stsIdentifierText).append(' ');
            }
            else {
                reportError("Unexpected token " + stsIdentifierText +
                            " in throws/rethrows annotation", stsThrowsAnno);
            }
        }

        return null;
    }

    // accessibilityModifier: Public | Private | Protected
    @Override
    public Void visitAccessibilityModifier(AccessibilityModifierContext stsAccessibilityModifier) {
        doNeededIndent();
        writeLeadingComments(stsAccessibilityModifier);

        sb.append(stsAccessibilityModifier.getText()).append(' ');

        writeTrailingComments(stsAccessibilityModifier);
        return null;
    }

    // constructorDeclaration: Constructor typeParameters? '(' parameterList? ')' constructorBody
    @Override
    public Void visitConstructorDeclaration(ConstructorDeclarationContext stsConstructorDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsConstructorDeclaration);

        sb.append(stsConstructorDeclaration.Constructor().getText());

        TypeParametersContext stsTypeParameters = stsConstructorDeclaration.typeParameters();
        if (stsTypeParameters != null) {
            visitTypeParameters(stsTypeParameters);
        }

        sb.append('(');

        ParameterListContext stsParameterList = stsConstructorDeclaration.parameterList();
        if (stsParameterList != null) {
            visitParameterList(stsParameterList);
        }

        sb.append(')');

        ThrowsAnnotationContext stsThrowsAnno = stsConstructorDeclaration.throwsAnnotation();
        if (stsThrowsAnno != null)
            visitThrowsAnnotation(stsThrowsAnno);
        else
            sb.append(' ');

        sb.append("{\n");

        indentIncrement();
        visitConstructorBody(stsConstructorDeclaration.constructorBody());
        indentDecrement();

        sb.append(indentCurrent).append("}\n\n");

        writeTrailingComments(stsConstructorDeclaration);
        return null;
    }

    @Override
    public Void visitConstructorBody(ConstructorBodyContext stsConstructorBody) {
        writeLeadingComments(stsConstructorBody);

        ConstructorCallContext stsConstructorCall = stsConstructorBody.constructorCall();
        if (stsConstructorCall != null) visitConstructorCall(stsConstructorCall);

        for (StatementOrLocalDeclarationContext stsStatementOrLocalDecl : stsConstructorBody.statementOrLocalDeclaration())
            visitStatementOrLocalDeclaration(stsStatementOrLocalDecl);

        writeTrailingComments(stsConstructorBody);
        return null;
    }

    @Override
    public Void visitConstructorCall(ConstructorCallContext stsConstructorCall) {
        doNeededIndent();
        writeLeadingComments(stsConstructorCall);

        SingleExpressionContext stsSuperExpr = stsConstructorCall.singleExpression();
        if (stsSuperExpr != null) {
            stsSuperExpr.accept(this);
            sb.append('.');
        }

        TerminalNode term = stsConstructorCall.This();
        if (term == null) term = stsConstructorCall.Super();

        assert(term != null);
        sb.append(term.getText());

        TypeArgumentsContext stsTypeArguments = stsConstructorCall.typeArguments();
        if (stsTypeArguments != null) visitTypeArguments(stsTypeArguments);

        ArgumentsContext stsArguments = stsConstructorCall.arguments();
        assert(stsArguments != null);
        visitArguments(stsArguments);

        sb.append(";\n");

        writeTrailingComments(stsConstructorCall);
        return null;
    }

    // interfaceDeclaration: accessibilityModifier? Interface Identifier typeParameters? interfaceExtendsClause? '{' interfaceBody '}'
    @Override
    public Void visitInterfaceDeclaration(InterfaceDeclarationContext stsInterfaceDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceDeclaration);

        sb.append(stsInterfaceDeclaration.Interface().getText()).append(' ');
        sb.append(stsInterfaceDeclaration.Identifier().getText());

        TypeParametersContext stsTypeParameters = stsInterfaceDeclaration.typeParameters();
        if (stsTypeParameters != null) {
            visitTypeParameters(stsTypeParameters);
        }

        InterfaceExtendsClauseContext stsInterfaceExtendsClause = stsInterfaceDeclaration.interfaceExtendsClause();
        if (stsInterfaceExtendsClause != null) {
            sb.append(' ');
            visitInterfaceExtendsClause(stsInterfaceExtendsClause);
        }

        sb.append(" {\n");

        indentIncrement();
        visitInterfaceBody(stsInterfaceDeclaration.interfaceBody());
        indentDecrement();

        sb.append(indentCurrent).append("}\n\n");

        writeTrailingComments(stsInterfaceDeclaration);
        return null;
    }

    // interfaceBody: interfaceMember+
    @Override
    public Void visitInterfaceBody(InterfaceBodyContext stsInterfaceBody) {
        writeLeadingComments(stsInterfaceBody);

        visitChildren(stsInterfaceBody);

        writeTrailingComments(stsInterfaceBody);
        return null;
    }

    // : Identifier signature SemiColon                                           #InterfaceMethod
    @Override
    public Void visitInterfaceMethod(InterfaceMethodContext stsInterfaceMethod) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceMethod);

        sb.append(stsInterfaceMethod.Identifier().getText());
        visitSignature(stsInterfaceMethod.signature());
        sb.append(";\n");

        writeTrailingComments(stsInterfaceMethod);
        return null;
    }

    // | (Static | Private)? methodSignature block   #InterfaceMethodWithBody
    @Override
    public Void visitInterfaceMethodWithBody(InterfaceMethodWithBodyContext stsInterfaceMethodWithBody) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceMethodWithBody);

        modifierWriteSafe(stsInterfaceMethodWithBody.Private());
        modifierWriteSafe(stsInterfaceMethodWithBody.Static());

        sb.append(stsInterfaceMethodWithBody.Identifier().getText());
        visitSignature(stsInterfaceMethodWithBody.signature());

        visitBlock(stsInterfaceMethodWithBody.block());

        writeTrailingComments(stsInterfaceMethodWithBody);
        return null;
    }

    //     | ({this.next(StaticTSParser.READONLY)}? Identifier)?
    //      variableDeclaration SemiColon?                  #InterfaceField
    @Override
    public Void visitInterfaceField(InterfaceFieldContext stsInterfaceField) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceField);

        if (stsInterfaceField.Identifier() != null)
            sb.append(stsInterfaceField.Identifier().getText()).append(' ');

        visitVariableDeclaration(stsInterfaceField.variableDeclaration());
        sb.append(";\n");

        writeTrailingComments(stsInterfaceField);
        return null;
    }

    //    | getterHeader SemiColon?                         #InterfaceGetter
    @Override
    public Void visitInterfaceGetter(InterfaceGetterContext stsInterfaceGetter) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceGetter);

        visitGetterHeader(stsInterfaceGetter.getterHeader());
        sb.append(";\n");

        writeTrailingComments(stsInterfaceGetter);
        return null;
    }

    //    | setterHeader SemiColon?                         #InterfaceSetter
    @Override
    public Void visitInterfaceSetter(InterfaceSetterContext stsInterfaceSetter) {
        doNeededIndent();
        writeLeadingComments(stsInterfaceSetter);

        visitSetterHeader(stsInterfaceSetter.setterHeader());
        sb.append(";\n");

        writeTrailingComments(stsInterfaceSetter);
        return null;
    }

    // | interfaceDeclaration                                                #InterfaceInInterface
    @Override
    public Void visitInterfaceInInterface(InterfaceInInterfaceContext stsInnerInterface) {
        writeLeadingComments(stsInnerInterface);

        visitInterfaceDeclaration(stsInnerInterface.interfaceDeclaration());

        writeTrailingComments(stsInnerInterface);
        return null;
    }

    // | classDeclaration                                                    #ClassInInterface
    @Override
    public Void visitClassInInterface(ClassInInterfaceContext stsInnerClass) {
        writeLeadingComments(stsInnerClass);

        visitClassDeclaration(stsInnerClass.classDeclaration());

        writeTrailingComments(stsInnerClass);
        return null;
    }

    @Override
    public Void visitEnumInInterface(EnumInInterfaceContext stsInnerEnum) {
        writeLeadingComments(stsInnerEnum);

        visitEnumDeclaration(stsInnerEnum.enumDeclaration());

        writeTrailingComments(stsInnerEnum);
        return null;
    }

    // interfaceExtendsClause: Extends classOrInterfaceTypeList
    @Override
    public Void visitInterfaceExtendsClause(InterfaceExtendsClauseContext stsInterfaceExtendsClause) {
        writeLeadingComments(stsInterfaceExtendsClause);

        String stsExtendsKeyword = stsInterfaceExtendsClause.Identifier().getText();
        if (!StaticTSParser.EXTENDS.equals(stsExtendsKeyword)) {
            reportError("Unexpected keyword " + stsExtendsKeyword + " in interface declaration", stsInterfaceExtendsClause);
            stsExtendsKeyword = StaticTSParser.EXTENDS;
        }
        sb.append(stsExtendsKeyword).append(' ');

        visitInterfaceTypeList(stsInterfaceExtendsClause.interfaceTypeList());

        writeTrailingComments(stsInterfaceExtendsClause);
        return null;
    }

    // classOrInterfaceTypeList: typeReference (',' typeReference)*
    @Override
    public Void visitInterfaceTypeList(InterfaceTypeListContext stsClassOrInterfaceTypeList) {
        writeLeadingComments(stsClassOrInterfaceTypeList);
        int i = 0;
        for (TypeReferenceContext stsTypeReference : stsClassOrInterfaceTypeList.typeReference()) {
            if (i > 0) sb.append(", ");
            visitTypeReference(stsTypeReference);
            ++i;
        }

        writeTrailingComments(stsClassOrInterfaceTypeList);
        return null;
    }

    // enumDeclaration: Enum Identifier '{' enumBody? '}'
    @Override
    public Void visitEnumDeclaration(EnumDeclarationContext stsEnumDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsEnumDeclaration);

        sb.append(stsEnumDeclaration.Enum().getText()).append(' ');
        sb.append(stsEnumDeclaration.Identifier().getText());

        sb.append(" {\n");

        EnumBodyContext stsEnumBody = stsEnumDeclaration.enumBody();
        if (stsEnumBody != null) {
            indentIncrement();
            visitEnumBody(stsEnumBody);
            indentDecrement();

            sb.append('\n');
        }

        sb.append(indentCurrent).append("}\n");

        writeTrailingComments(stsEnumDeclaration);
        return null;
    }

    // enumBody: enumMember (',' enumMember)*
    @Override
    public Void visitEnumBody(EnumBodyContext stsEnumBody) {
        writeLeadingComments(stsEnumBody);

        boolean isFirstMember = true;
        for (EnumMemberContext stsEnumMember : stsEnumBody.enumMember()) {
            if (!isFirstMember) {
                sb.append(",\n");
            } else {
                isFirstMember = false;
            }

            doNeededIndent();
            visitEnumMember(stsEnumMember);
        }

        writeTrailingComments(stsEnumBody);
        return null;
    }

    // enumMember: Identifier ('=' singleExpression)?
    @Override
    public Void visitEnumMember(EnumMemberContext stsEnumMember) {
        writeLeadingComments(stsEnumMember);

        sb.append(stsEnumMember.Identifier().getText());

        SingleExpressionContext stsInitializer = stsEnumMember.singleExpression();
        if (stsInitializer != null) {
            sb.append(" = ");
            stsInitializer.accept(this);
        }

        writeTrailingComments(stsEnumMember);
        return null;
    }

    // compilationUnit: packageDeclaration? importStatement* topDeclaration* EOF;
    @Override
    public Void visitCompilationUnit(CompilationUnitContext stsCompilationUnit) {
        writeLeadingComments(stsCompilationUnit);

        PackageDeclarationContext stsPackageDecl = stsCompilationUnit.packageDeclaration();
        if (stsPackageDecl != null) visitPackageDeclaration(stsPackageDecl);

        for (ImportDeclarationContext stsImportDeclaration : stsCompilationUnit.importDeclaration()) {
            visitImportDeclaration(stsImportDeclaration);
        }

        for (TopDeclarationContext stsTopDeclaration : stsCompilationUnit.topDeclaration()) {
            stsTopDeclaration.accept(this);
        }

        // trailing comments may be present as
        // comments that weren't picked up by the
        // last top declaration.
        writeTrailingComments(stsCompilationUnit);
        return null;
    }

    @Override
    public Void visitTopDeclaration(TopDeclarationContext stsTopDeclaration) {
        writeLeadingComments(stsTopDeclaration);

        int declIndex = 0;
        TerminalNode termExport = stsTopDeclaration.Export();
        if (termExport != null) {
            sb.append(termExport.getText()).append(' ');
            declIndex = 1;
        }
        assert(stsTopDeclaration.getChildCount() == declIndex+1);
        stsTopDeclaration.getChild(declIndex).accept(this);

        writeTrailingComments(stsTopDeclaration);
        return null;
    }

    @Override
    public Void visitNamespaceDeclaration(NamespaceDeclarationContext stsNamespaceDecl) {
        writeLeadingComments(stsNamespaceDecl);

        sb.append(stsNamespaceDecl.Namespace().getText()).append(' ');
        sb.append(stsNamespaceDecl.Identifier().getText()).append(' ');

        visitNamespaceBody(stsNamespaceDecl.namespaceBody());

        writeTrailingComments(stsNamespaceDecl);
        return null;
    }

    @Override
    public Void visitNamespaceBody(NamespaceBodyContext stsNamespaceBody) {
        sb.append("{\n");
        indentIncrement();

        visitChildren(stsNamespaceBody);

        indentDecrement();
        sb.append(indentCurrent).append("}\n\n");

        return null;
    }

    @Override
    public Void visitNamespaceMember(NamespaceMemberContext stsNamespaceMember) {
        doNeededIndent();
        writeLeadingComments(stsNamespaceMember);

        TerminalNode stsTerm = stsNamespaceMember.Export();
        if (stsTerm != null) {
            sb.append(stsTerm.getText()).append(' ');
        }

        ClassDeclarationContext stsClassDecl = stsNamespaceMember.classDeclaration();
        InterfaceDeclarationContext stsInterfaceDecl = stsNamespaceMember.interfaceDeclaration();
        EnumDeclarationContext stsEnumDecl = stsNamespaceMember.enumDeclaration();
        FunctionDeclarationContext stsFunctionDecl = stsNamespaceMember.functionDeclaration();
        VariableOrConstantDeclarationContext stsVarOrConstDecl = stsNamespaceMember.variableOrConstantDeclaration();
        if (stsClassDecl != null) {
            visitClassDeclaration(stsClassDecl);
        }
        else if (stsInterfaceDecl != null) {
            visitInterfaceDeclaration(stsInterfaceDecl);
        }
        else if (stsEnumDecl != null) {
            visitEnumDeclaration(stsEnumDecl);
        }
        else if (stsFunctionDecl != null) {
            visitFunctionDeclaration(stsFunctionDecl);
        }
        else if (stsVarOrConstDecl != null) {
            visitVariableOrConstantDeclaration(stsVarOrConstDecl);
        }
        else {
            TypeAliasDeclarationContext stsTypeAliasDecl = stsNamespaceMember.typeAliasDeclaration();
            assert(stsTypeAliasDecl != null);

            visitTypeAliasDeclaration(stsTypeAliasDecl);
        }

        writeTrailingComments(stsNamespaceMember);
        return null;
    }

    @Override
    public Void visitPackageDeclaration(PackageDeclarationContext stsPackageDecl) {
        writeLeadingComments(stsPackageDecl);

        sb.append(stsPackageDecl.Package().getText()).append(' ');
        visitQualifiedName(stsPackageDecl.qualifiedName());
        sb.append(";\n\n");

        writeTrailingComments(stsPackageDecl);
        return null;
    }

    //    statement
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
    @Override
    public Void visitStatement(StatementContext stsStatement) {
        doNeededIndent();
        writeLeadingComments(stsStatement);

        assert(stsStatement.getChildCount() == 1);
        stsStatement.getChild(0).accept(this);

        writeTrailingComments(stsStatement);
        return null;
    }

    // block: '{' statementOrLocalDeclaration* '}'
    @Override
    public Void visitBlock(BlockContext stsBlock) {
        doNeededIndent();
        writeLeadingComments(stsBlock);

        sb.append("{\n");
        indentIncrement();

        List<StatementOrLocalDeclarationContext> stsStatementList = stsBlock.statementOrLocalDeclaration();
        if (stsStatementList != null) {
            for (StatementOrLocalDeclarationContext stsStatementOrLocalDecl : stsStatementList)
                visitStatementOrLocalDeclaration(stsStatementOrLocalDecl);
        }
        indentDecrement();
        sb.append(indentCurrent).append("}\n");

        writeTrailingComments(stsBlock);
        return null;
    }

    // importDeclaration: Import importBinding (Comma importBinding)* Comma? From StringLiteral SemiColon?
    // importBinding: (Multiply | qualifiedName (Dot Multiply)?) (As Identifier)?
    public Void visitImportDeclaration(ImportDeclarationContext stsImportDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsImportDeclaration);

        sb.append(stsImportDeclaration.Import().getText()).append(' ');

        int i = 0;
        for (ImportBindingContext stsImportBinding : stsImportDeclaration.importBinding()) {
            if (i > 0) sb.append(", ");
            visitImportBinding(stsImportBinding);
            ++i;
        }

        String stsFromIdentifier = stsImportDeclaration.Identifier().getText();
        if (!StaticTSParser.FROM.equals(stsFromIdentifier)) {
            reportError("Unexpected token " + stsFromIdentifier +
                        " in import declaration", stsImportDeclaration);
            stsFromIdentifier = StaticTSParser.FROM;
        }

        sb.append(' ').append(stsFromIdentifier);
        sb.append(' ').append(stsImportDeclaration.StringLiteral().getText());
        sb.append(";\n");

        writeTrailingComments(stsImportDeclaration);
        return null;
    }

    public Void visitImportBinding(ImportBindingContext stsImportBinding) {
        QualifiedNameContext stsQualName = stsImportBinding.qualifiedName();
        if (stsQualName != null) {
            visitQualifiedName(stsQualName);

            if (stsImportBinding.Multiply() != null)
                sb.append(".*");
        }
        else
            sb.append("*");

        TerminalNode stsAsTerm = stsImportBinding.As();
        if (stsAsTerm != null) {
            sb.append(' ').append(stsAsTerm.getText());
            sb.append(' ').append(stsImportBinding.Identifier().getText());
        }

        return null;
    }

    @Override
    public Void visitAssertStatement(AssertStatementContext stsAssertStatement) {
        writeLeadingComments(stsAssertStatement);

        TerminalNode termAssert = stsAssertStatement.Assert();
        sb.append(termAssert.getText()).append(' ');

        assert(stsAssertStatement.condition != null);
        stsAssertStatement.condition.accept(this);

        if (stsAssertStatement.message != null) {
            sb.append(" : ");
            stsAssertStatement.message.accept(this);
        }

        sb.append(";\n");

        writeTrailingComments(stsAssertStatement);
        return null;
    }

    // variableOrConstDeclaration: ((Let variableDeclarationList) | (Const constantDeclarationList)) SemiColon
    @Override
    public Void visitVariableOrConstantDeclaration(VariableOrConstantDeclarationContext stsVarOrConstDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsVarOrConstDeclaration);

        // Variable and constant declaration lists can now contain DummyContext nodes
        // (see translateVariableDeclaration function in TypeScriptTransformer.ts),
        // so emit only if we have at least one real declaration in the list.
        VariableDeclarationListContext stsVarDeclList = stsVarOrConstDeclaration.variableDeclarationList();
        ConstantDeclarationListContext stsConstDeclList = stsVarOrConstDeclaration.constantDeclarationList();
        if (stsVarDeclList != null && !stsVarDeclList.variableDeclaration().isEmpty()) {
            assert(stsVarOrConstDeclaration.Let() != null);
            sb.append(stsVarOrConstDeclaration.Let().getText()).append(' ');
            visitVariableDeclarationList(stsVarOrConstDeclaration.variableDeclarationList());
            sb.append(";\n");
        }
        else if (stsConstDeclList != null && !stsConstDeclList.constantDeclaration().isEmpty()) {
            assert (stsVarOrConstDeclaration.Const() != null);
            modifierWriteSafe(stsVarOrConstDeclaration.Const());
            visitConstantDeclarationList(stsVarOrConstDeclaration.constantDeclarationList());
            sb.append(";\n");
        }

        writeTrailingComments(stsVarOrConstDeclaration);
        return null;
    }

    // variableDeclarationList: variableDeclaration (',' variableDeclaration)*
    @Override
    public Void visitVariableDeclarationList(VariableDeclarationListContext stsVariableDeclarationList) {
        writeLeadingComments(stsVariableDeclarationList);

        int i = 0;
        for (VariableDeclarationContext stsVariableDeclaration : stsVariableDeclarationList.variableDeclaration()) {
            if (i > 0) sb.append(", ");
            visitVariableDeclaration(stsVariableDeclaration);
            ++i;
        }

        writeTrailingComments(stsVariableDeclarationList);
        return null;
    }

    // constantDeclarationList: constantDeclaration (',' constantDeclaration)*
    @Override
    public Void visitConstantDeclarationList(ConstantDeclarationListContext stsConstantDeclarationList) {
        writeLeadingComments(stsConstantDeclarationList);

        int i = 0;
        for (ConstantDeclarationContext stsConstantDeclaration : stsConstantDeclarationList.constantDeclaration()) {
            if (i > 0) sb.append(", ");
            visitConstantDeclaration(stsConstantDeclaration);
            ++i;
        }

        writeTrailingComments(stsConstantDeclarationList);
        return null;
    }

    // variableDeclaration    : Identifier typeAnnotation initializer? | Identifier initializer
    @Override
    public Void visitVariableDeclaration(VariableDeclarationContext stsVariableDeclaration) {
        writeLeadingComments(stsVariableDeclaration);

        sb.append(stsVariableDeclaration.Identifier().getText()).append(' ');

        TypeAnnotationContext stsTypeAnnotation = stsVariableDeclaration.typeAnnotation();
        if (stsTypeAnnotation != null) {
            visitTypeAnnotation(stsTypeAnnotation);
        }

        InitializerContext stsInitializer = stsVariableDeclaration.initializer();
        if (stsInitializer != null) {
            visitInitializer(stsInitializer);
        }

        writeTrailingComments(stsVariableDeclaration);
        return null;
    }

    // constantDeclaration: Identifier typeAnnotation? initializer
    @Override
    public Void visitConstantDeclaration(ConstantDeclarationContext stsConstantDeclaration) {
        writeLeadingComments(stsConstantDeclaration);

        TerminalNode termIdentifier = stsConstantDeclaration.Identifier();
        sb.append(termIdentifier.getText()).append(' ');

        TypeAnnotationContext stsTypeAnnotation = stsConstantDeclaration.typeAnnotation();
        if (stsTypeAnnotation != null) {
            visitTypeAnnotation(stsTypeAnnotation);
        }

        InitializerContext stsInitializer = stsConstantDeclaration.initializer();
        if (stsInitializer != null) {
            visitInitializer(stsInitializer);
        }

        writeTrailingComments(stsConstantDeclaration);
        return null;
    }

    // expressionStatement: singleExpression SemiColon?
    @Override
    public Void visitExpressionStatement(ExpressionStatementContext stsExpressionStatement) {
        doNeededIndent();
        writeLeadingComments(stsExpressionStatement);

        stsExpressionStatement.singleExpression().accept(this);
        sb.append(";\n");

        writeTrailingComments(stsExpressionStatement);
        return null;
    }

    // ifStatement: If OpenParent singleExpression CloseParen ifStmt=statement (Else elseStmt=statement)?
    @Override
    public Void visitIfStatement(IfStatementContext stsIfStatement) {
        doNeededIndent();
        writeLeadingComments(stsIfStatement);

        sb.append(stsIfStatement.If().getText()).append(" (");

        stsIfStatement.singleExpression().accept(this);

        sb.append(") ");

        assert(stsIfStatement.ifStmt != null);
        visitStatement(stsIfStatement.ifStmt);

        TerminalNode termElse = stsIfStatement.Else();
        if (termElse != null) {
            sb.append(indentCurrent).append(termElse.getText()).append(" ");

            assert(stsIfStatement.elseStmt != null);
            visitStatement(stsIfStatement.elseStmt);
        }

        writeTrailingComments(stsIfStatement);
        return null;
    }

    // : Do statement* While '(' singleExpression ')' SemiColon # DoStatement
    @Override
    public Void visitDoStatement(DoStatementContext stsDoStatement) {
        doNeededIndent();
        writeLeadingComments(stsDoStatement);

        sb.append(stsDoStatement.Do().getText()).append("\n");

        StatementContext stsStmt = stsDoStatement.statement();
        assert(stsStmt != null);
        visitStatement(stsStmt);

        sb.append(indentCurrent).append(stsDoStatement.While().getText()).append('(');

        stsDoStatement.singleExpression().accept(this);

        sb.append(");\n");

        writeTrailingComments(stsDoStatement);
        return null;
    }

    // | While '(' singleExpression ')' (statement | block) # WhileStatement
    @Override
    public Void visitWhileStatement(WhileStatementContext stsWhileStatement) {
        doNeededIndent();
        writeLeadingComments(stsWhileStatement);

        sb.append(stsWhileStatement.While().getText()).append('(');
        stsWhileStatement.singleExpression().accept(this);
        sb.append(")\n");

        StatementContext stsStmt = stsWhileStatement.statement();
        assert (stsStmt != null);
        visitStatement(stsStmt);

        writeTrailingComments(stsWhileStatement);
        return null;
    }

    // | For '(' forInit? SemiColon singleExpression? SemiColon expressionSequence ')' statement  # ForStatement
    @Override
    public Void visitForStatement(ForStatementContext stsForStatement) {
        doNeededIndent();
        writeLeadingComments(stsForStatement);

        sb.append(stsForStatement.For().getText()).append(" (");

        ForInitContext stsForInit = stsForStatement.forInit();
        if (stsForInit != null) {
            visitForInit(stsForInit);
        }

        sb.append("; ");

        SingleExpressionContext stsCondition = stsForStatement.singleExpression();
        if (stsCondition != null) {
            stsCondition.accept(this);
        }

        sb.append("; ");

        ExpressionSequenceContext stsUpdaters = stsForStatement.expressionSequence();
        if (stsUpdaters != null) {
            visitExpressionSequence(stsUpdaters);
        }

        sb.append(") ");

        StatementContext stsStmt = stsForStatement.statement();
        assert(stsStmt != null);
        visitStatement(stsStmt);

        writeTrailingComments(stsForStatement);
        return null;
    }

    // forInit: ExpressionSequence | Let variableDeclarationList
    @Override
    public Void visitForInit(ForInitContext stsForInit) {
        writeLeadingComments(stsForInit);

        ExpressionSequenceContext stsExprSeq = stsForInit.expressionSequence();
        if (stsExprSeq != null) {
            visitExpressionSequence(stsExprSeq);
        } else {
            sb.append(stsForInit.Let().getText()).append(' ');
            visitVariableDeclarationList(stsForInit.variableDeclarationList());
        }

        writeTrailingComments(stsForInit);
        return null;
    }

    // expressionSequence: singleExpression (',' singleExpression)*
    @Override
    public Void visitExpressionSequence(ExpressionSequenceContext stsExpressionSequence) {
        writeLeadingComments(stsExpressionSequence);
        int i = 0;
        for (SingleExpressionContext stsExpression : stsExpressionSequence.singleExpression()) {
            if (i > 0) sb.append(", ");
            stsExpression.accept(this);
            ++i;
        }

        writeTrailingComments(stsExpressionSequence);
        return null;
    }

     // | For '(' Let Identifier typeAnnotation? Of singleExpression ')' (statement | block)  # ForInOfStatement
    @Override
    public Void visitForOfStatement(ForOfStatementContext stsForOfStatement) {
        doNeededIndent();
        writeLeadingComments(stsForOfStatement);

        sb.append(stsForOfStatement.For().getText()).append(" (");
        sb.append(stsForOfStatement.Let().getText()).append(' ');
        sb.append(stsForOfStatement.Identifier(0).getText()).append(' ');

        TypeAnnotationContext stsTypeAnnotation = stsForOfStatement.typeAnnotation();
        if (stsTypeAnnotation != null) {
            visitTypeAnnotation(stsTypeAnnotation);
        }

        String stsOfKeyword = stsForOfStatement.Identifier(1).getText();
        if (!StaticTSParser.OF.equals(stsOfKeyword)) {
            reportError("Unexpected keyword " + stsOfKeyword + " in for-of statement", stsForOfStatement);
            stsOfKeyword = StaticTSParser.OF;
        }
        sb.append(stsOfKeyword).append(' ');

        stsForOfStatement.singleExpression().accept(this);
        sb.append(')');

        StatementContext stsStmt = stsForOfStatement.statement();
        assert(stsStmt != null);
        visitStatement(stsStmt);

        writeTrailingComments(stsForOfStatement);
        return null;
    }

    // continueStatement: Continue Identifier? SemiColon
    @Override
    public Void visitContinueStatement(ContinueStatementContext stsContinueStatement) {
        doNeededIndent();
        writeLeadingComments(stsContinueStatement);

        sb.append(stsContinueStatement.Continue().getText());

        TerminalNode termIdentifier = stsContinueStatement.Identifier();
        if (termIdentifier != null) {
            sb.append(' ').append(termIdentifier.getText());
        }

        sb.append(";\n");

        writeTrailingComments(stsContinueStatement);
        return null;
    }

    // breakStatement: Break Identifier? SemiColon
    @Override
    public Void visitBreakStatement(BreakStatementContext stsBreakStatement) {
        doNeededIndent();
        writeLeadingComments(stsBreakStatement);

        sb.append(stsBreakStatement.Break().getText());

        TerminalNode termIdentifier = stsBreakStatement.Identifier();
        if (termIdentifier != null) {
            sb.append(' ').append(termIdentifier.getText());
        }

        sb.append(";\n");

        writeTrailingComments(stsBreakStatement);
        return null;
    }

    // returnStatement: Return (singleExpression)? SemiColon
    @Override
    public Void visitReturnStatement(ReturnStatementContext stsReturnStatement) {
        doNeededIndent();
        writeLeadingComments(stsReturnStatement);

        sb.append(stsReturnStatement.Return().getText());

        SingleExpressionContext stsSingleExpression = stsReturnStatement.singleExpression();
        if (stsSingleExpression != null) {
            sb.append(' ');
            stsSingleExpression.accept(this);
        }

        sb.append(";\n");

        writeTrailingComments(stsReturnStatement);
        return null;
    }

    //    | (typeReference Dot)? This  # ThisExpression
    @Override
    public Void visitThisExpression(ThisExpressionContext stsThisExpression) {
        writeLeadingComments(stsThisExpression);

        TypeReferenceContext stsTypeReference = stsThisExpression.typeReference();
        if (stsTypeReference != null) {
            visitTypeReference(stsTypeReference);
            sb.append('.');
        }

        sb.append(stsThisExpression.This().getText());

        writeTrailingComments(stsThisExpression);
        return null;
    }

    //    | Identifier                                                             # IdentifierExpression
    @Override
    public Void visitIdentifierExpression(IdentifierExpressionContext stsIdentifierExpression) {
        writeLeadingComments(stsIdentifierExpression);

        sb.append(stsIdentifierExpression.Identifier().getText());

        writeTrailingComments(stsIdentifierExpression);
        return null;
    }

    //    | (typeReference Dot)? Super # SuperExpression
    @Override
    public Void visitSuperExpression(SuperExpressionContext stsSuperExpression) {
        writeLeadingComments(stsSuperExpression);

        TypeReferenceContext stsTypeReference = stsSuperExpression.typeReference();
        if (stsTypeReference != null) {
            visitTypeReference(stsTypeReference);
            sb.append('.');
        }

        sb.append(stsSuperExpression.Super().getText());

        writeTrailingComments(stsSuperExpression);
        return null;
    }

        // switchStatement: Switch '(' singleExpression ')' caseBlock
    @Override
    public Void visitSwitchStatement(SwitchStatementContext stsSwitchStatement) {
        doNeededIndent();
        writeLeadingComments(stsSwitchStatement);

        sb.append(stsSwitchStatement.Switch().getText()).append(" (");
        stsSwitchStatement.singleExpression().accept(this);
        sb.append(')');

        visitCaseBlock(stsSwitchStatement.caseBlock());
        sb.append('\n');

        writeTrailingComments(stsSwitchStatement);
        return null;
    }

    // caseBlock: '{' leftCases=caseClauses? defaultClause? rightCases=caseClauses? '}'
    @Override
    public Void visitCaseBlock(CaseBlockContext stsCaseBlock) {
        boolean needSpace = !doNeededIndent();
        writeLeadingComments(stsCaseBlock);

        if (needSpace) sb.append(' ');

        sb.append("{\n");
        indentIncrement();

        if (stsCaseBlock.leftCases != null) {
            visitCaseClauses(stsCaseBlock.leftCases);
        }

        DefaultClauseContext stsDefaultClause = stsCaseBlock.defaultClause();
        if (stsDefaultClause != null) {
            visitDefaultClause(stsDefaultClause);
        }

        if (stsCaseBlock.rightCases != null) {
            visitCaseClauses(stsCaseBlock.rightCases);
        }

        indentDecrement();
        sb.append(indentCurrent).append("}\n");

        writeTrailingComments(stsCaseBlock);
        return null;
    }

    // caseClauses: caseClause+
    @Override
    public Void visitCaseClauses(CaseClausesContext stsCaseClauses) {
        writeLeadingComments(stsCaseClauses);

        List<CaseClauseContext> stsCaseClauseList = stsCaseClauses.caseClause();
        for (CaseClauseContext stsCaseClause : stsCaseClauseList) {
            visitCaseClause(stsCaseClause);
        }

        writeTrailingComments(stsCaseClauses);
        return null;
    }

    // caseClause: Case singleExpression ':' statement*
    @Override
    public Void visitCaseClause(CaseClauseContext stsCaseClause) {
        doNeededIndent();
        writeLeadingComments(stsCaseClause);

        sb.append(stsCaseClause.Case().getText()).append(' ');
        stsCaseClause.singleExpression().accept(this);
        sb.append(":\n");

        List<StatementContext> stsStatementList = stsCaseClause.statement();

        indentIncrement();
        for (StatementContext stsStatement : stsStatementList)
            visitStatement(stsStatement);
        indentDecrement();

        writeTrailingComments(stsCaseClause);
        return null;
    }

    // defaultClause: Default ':' statement*
    @Override
    public Void visitDefaultClause(DefaultClauseContext stsDefaultClause) {
        doNeededIndent();
        writeLeadingComments(stsDefaultClause);

        String stsDefaultKeyword = stsDefaultClause.Identifier().getText();
        if (!StaticTSParser.DEFAULT.equals(stsDefaultKeyword)) {
            reportError("Unexpected keyword " + stsDefaultKeyword + " in switch statement", stsDefaultClause);
            stsDefaultKeyword = StaticTSParser.DEFAULT;
        }
        sb.append(stsDefaultKeyword).append(":\n");

        List<StatementContext> stsStatementList = stsDefaultClause.statement();

        indentIncrement();
        for (StatementContext stsStatement : stsStatementList)
            visitStatement(stsStatement);
        indentDecrement();

        writeTrailingComments(stsDefaultClause);
        return null;
    }

    // labelledStatement: Identifier ':' statement
    @Override
    public Void visitLabelledStatement(LabelledStatementContext stsLabelledStatement) {
        doNeededIndent();
        writeLeadingComments(stsLabelledStatement);

        sb.append(stsLabelledStatement.Identifier().getText()).append(": ");
        // after removing Block node from statements we got hanging labels before java blocks
        if( stsLabelledStatement.statement() !=null )
            visitStatement(stsLabelledStatement.statement());

        writeTrailingComments(stsLabelledStatement);
        return null;
    }

    // throwStatement: Throw singleExpression SemiColon
    @Override
    public Void visitThrowStatement(ThrowStatementContext stsThrowStatement) {
        doNeededIndent();
        writeLeadingComments(stsThrowStatement);

        sb.append(stsThrowStatement.Throw().getText()).append(' ');
        stsThrowStatement.singleExpression().accept(this);
        sb.append(";\n");

        writeTrailingComments(stsThrowStatement);
        return null;
    }

    // tryStatement: Try block catchOrRecoverClause+;
    @Override
    public Void visitTryStatement(TryStatementContext stsTryStatement) {
        doNeededIndent();
        writeLeadingComments(stsTryStatement);

        sb.append(stsTryStatement.Try().getText()).append(' ');

        visitBlock(stsTryStatement.block());

        List<CatchClauseContext> stsCatches = stsTryStatement.catchClause();
        if (stsCatches != null) {
            for (CatchClauseContext stsCatch : stsCatches) {
                visitCatchClause(stsCatch);
            }
        }

        DefaultCatchContext stsDefaultCatch = stsTryStatement.defaultCatch();
        if (stsDefaultCatch != null) visitDefaultCatch(stsDefaultCatch);

        sb.append('\n');

        writeTrailingComments(stsTryStatement);
        return null;
    }

    // catchOrRecoverClause: (Catch|Recover) exceptionParameter? block

    @Override
    public Void visitCatchClause(CatchClauseContext stsCatchClause) {
        doNeededIndent();
        writeLeadingComments(stsCatchClause);

        String stsCatchKeyword = stsCatchClause.Identifier().getText();
        if (!StaticTSParser.CATCH.equals(stsCatchKeyword)) {
            reportError("Unexpected keyword " + stsCatchKeyword + " in catch clause", stsCatchClause);
            stsCatchKeyword = StaticTSParser.CATCH;
        }
        sb.append(stsCatchKeyword).append(' ');

        ExceptionParameterContext stsExceptionParam = stsCatchClause.exceptionParameter();
        if (stsExceptionParam != null) {
            visitExceptionParameter(stsExceptionParam);
        }

        BlockContext stsBlock = stsCatchClause.block();
        assert(stsBlock != null);
        visitBlock(stsBlock);

        writeTrailingComments(stsCatchClause);
        return null;
    }

    @Override
    public Void visitExceptionParameter(ExceptionParameterContext stsExceptionParam) {
        writeLeadingComments(stsExceptionParam);

        sb.append('(').append(stsExceptionParam.Identifier().getText()).append(' ');
        visitTypeAnnotation(stsExceptionParam.typeAnnotation());
        sb.append(") ");

        writeTrailingComments(stsExceptionParam);
        return null;
    }

    @Override
    public Void visitDefaultCatch(DefaultCatchContext stsDefaultCatch) {
        doNeededIndent();
        writeLeadingComments(stsDefaultCatch);

        String stsCatchKeyword = stsDefaultCatch.Identifier(0).getText();
        if (!StaticTSParser.CATCH.equals(stsCatchKeyword)) {
            reportError("Unexpected keyword " + stsCatchKeyword + " in default catch clause", stsDefaultCatch);
            stsCatchKeyword = StaticTSParser.CATCH;
        }
        sb.append(stsCatchKeyword).append(' ');

        if (stsDefaultCatch.Identifier().size() > 1)
            sb.append('(').append(stsDefaultCatch.Identifier(1).getText()).append(") ");

        visitBlock(stsDefaultCatch.block());

        writeTrailingComments(stsDefaultCatch);
        return null;
    }

    // functionDeclaration: Function Identifier signature block
    @Override
    public Void visitFunctionDeclaration(FunctionDeclarationContext stsFunctionDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsFunctionDeclaration);

        TerminalNode stsAsyncTerm = stsFunctionDeclaration.Async();
        if (stsAsyncTerm != null) sb.append(stsAsyncTerm.getText()).append(' ');
        
        sb.append(stsFunctionDeclaration.Function().getText()).append(' ');
        sb.append(stsFunctionDeclaration.Identifier().getText());

        visitSignature(stsFunctionDeclaration.signature());

        visitBlock(stsFunctionDeclaration.block());

        writeTrailingComments(stsFunctionDeclaration);
        return null;
    }

    private void modifierWriteSafe(TerminalNode term) {
        if (term != null)
            sb.append(term.getText()).append(' ');
    }

    // classDeclaration:
    //   (Static? (Abstract | Open) | (Abstract | Open) Static)?
    //      Class Identifier typeParameters? classExtendsClause? implementsClause? classBody
    @Override
    public Void visitClassDeclaration(ClassDeclarationContext stsClassDeclaration) {
        doNeededIndent();
        writeLeadingComments(stsClassDeclaration);

        modifierWriteSafe(stsClassDeclaration.Abstract());
        modifierWriteSafe(stsClassDeclaration.Inner());
        modifierWriteSafe(stsClassDeclaration.Open());

        sb.append(stsClassDeclaration.Class().getText()).append(' ');
        sb.append(stsClassDeclaration.Identifier().getText());

        TypeParametersContext stsTypeParameters = stsClassDeclaration.typeParameters();
        if (stsTypeParameters != null) visitTypeParameters(stsTypeParameters);

        sb.append(' ');

        ClassExtendsClauseContext stsClassExtends = stsClassDeclaration.classExtendsClause();
        if (stsClassExtends != null) {
            visitClassExtendsClause(stsClassExtends);
        }

        ImplementsClauseContext stsImplements = stsClassDeclaration.implementsClause();
        if (stsImplements != null) {
            visitImplementsClause(stsImplements);
        }

        visitClassBody(stsClassDeclaration.classBody());

        writeTrailingComments(stsClassDeclaration);
        return null;
    }

    // classBody:  '{' classElement* '}'
    @Override
    public Void visitClassBody(ClassBodyContext stsClassBody) {
        writeLeadingComments(stsClassBody);

        sb.append(" {\n");
        indentIncrement();

        visitChildren(stsClassBody);

        indentDecrement();
        sb.append(indentCurrent).append("}");

        // Don't start new line if this class body is a part of an object creation expression
        if (!(stsClassBody.getParent() instanceof NewClassInstanceExpressionContext) &&
            !(stsClassBody.getParent() instanceof NewInnerClassInstanceExpressionContext))
            sb.append("\n\n");

        writeTrailingComments(stsClassBody);
        return null;
    }

    // classInitializer
    @Override
    public Void visitClassInitializer(ClassInitializerContext stsClassInit) {
        doNeededIndent();
        writeLeadingComments(stsClassInit);

        modifierWriteSafe(stsClassInit.Static());

        BlockContext stsBlock = stsClassInit.block();
        assert(stsBlock != null);
        visitBlock(stsBlock);

        writeTrailingComments(stsClassInit);
        return null;
    }

    // classFieldDeclaration
    //     : Static? (variableDeclaration | {this.next(StaticTSParser.READONLY)}? Identifier constantDeclaration) SemiColon?
    //    | {this.next(StaticTSParser.READONLY)}? Identifier Static? constantDeclaration SemiColon?
    @Override
    public Void visitClassFieldDeclaration(ClassFieldDeclarationContext stsClassField) {
        doNeededIndent();
        writeLeadingComments(stsClassField);

        modifierWriteSafe(stsClassField.Static());

        VariableDeclarationContext stsVarDecl = stsClassField.variableDeclaration();
        if (stsVarDecl != null) {
            visitVariableDeclaration(stsVarDecl);
        }
        else {
            assert(stsClassField.Identifier() != null);
            sb.append(stsClassField.Identifier().getText()).append(' ');

            ConstantDeclarationContext stsConstDecl = stsClassField.constantDeclaration();
            assert(stsConstDecl != null);
            visitConstantDeclaration(stsConstDecl);
        }

        sb.append(";\n");

        writeTrailingComments(stsClassField);
        return null;
    }

    // : (Static | Override | Open)? Identifier signature block    #ClassMethodWithBody
    @Override
    public Void visitClassMethodWithBody(ClassMethodWithBodyContext stsClassMethodWithBody) {
        doNeededIndent();
        writeLeadingComments(stsClassMethodWithBody);

        modifierWriteSafe(stsClassMethodWithBody.Static());
        modifierWriteSafe(stsClassMethodWithBody.Override());
        modifierWriteSafe(stsClassMethodWithBody.Open());

        sb.append(stsClassMethodWithBody.Identifier().getText());
        visitSignature(stsClassMethodWithBody.signature());

        visitBlock(stsClassMethodWithBody.block());

        writeTrailingComments(stsClassMethodWithBody);
        return null;
    }

    // | (Abstract | Static? Native | Native Static) Identifier signature SemiColon                                   #AbstractClassMethod
    @Override
    public Void visitAbstractOrNativeClassMethod(AbstractOrNativeClassMethodContext stsAbstractMethod) {
        doNeededIndent();
        writeLeadingComments(stsAbstractMethod);

        modifierWriteSafe(stsAbstractMethod.Abstract());
        modifierWriteSafe(stsAbstractMethod.Static());
        modifierWriteSafe(stsAbstractMethod.Native());

        sb.append(stsAbstractMethod.Identifier().getText());
        visitSignature(stsAbstractMethod.signature());

        sb.append(";\n");

        writeTrailingComments(stsAbstractMethod);
        return null;
    }

    //classGetterDeclaration
    //    : (Static | Override | Open)? getterHeader block
    //    | Abstract getterHeader
    @Override
    public Void visitClassGetterDeclaration(ClassGetterDeclarationContext stsClassGetter) {
        doNeededIndent();
        writeLeadingComments(stsClassGetter);

        modifierWriteSafe(stsClassGetter.Abstract());
        modifierWriteSafe(stsClassGetter.Static());
        modifierWriteSafe(stsClassGetter.Override());
        modifierWriteSafe(stsClassGetter.Open());

        visitGetterHeader(stsClassGetter.getterHeader());

        if (stsClassGetter.block() != null)
            visitBlock(stsClassGetter.block());
        else
            sb.append(";\n");

        writeTrailingComments(stsClassGetter);
        return null;
    }

    // getterHeader
    //    : { this.next(StaticTSParser.GET) }? Identifier Identifier OpenParen CloseParen typeAnnotation
    @Override
    public Void visitGetterHeader(GetterHeaderContext stsGetterHeader) {
        writeLeadingComments(stsGetterHeader);

        assert(stsGetterHeader.Identifier().size() > 1);
        sb.append(stsGetterHeader.Identifier(0).getText()).append(' ');
        sb.append(stsGetterHeader.Identifier(1).getText()).append("()");

        visitTypeAnnotation(stsGetterHeader.typeAnnotation());

        writeTrailingComments(stsGetterHeader);
        return null;
    }

    // classSetterDeclaration
    //    : (Static | Override | Open)? setterHeader block
    //    | Abstract setterHeader
    @Override
    public Void visitClassSetterDeclaration(ClassSetterDeclarationContext stsClassSetter) {
        doNeededIndent();
        writeLeadingComments(stsClassSetter);

        modifierWriteSafe(stsClassSetter.Abstract());
        modifierWriteSafe(stsClassSetter.Static());
        modifierWriteSafe(stsClassSetter.Override());
        modifierWriteSafe(stsClassSetter.Open());

        visitSetterHeader(stsClassSetter.setterHeader());

        if (stsClassSetter.block() != null)
            visitBlock(stsClassSetter.block());
        else
            sb.append(";\n");

        writeTrailingComments(stsClassSetter);
        return null;
    }

    // setterHeader
    //    : { this.next(StaticTSParser.SET) }? Identifier Identifier OpenParen parameter CloseParen
    @Override
    public Void visitSetterHeader(SetterHeaderContext stsSetterHeader) {
        writeLeadingComments(stsSetterHeader);

        assert(stsSetterHeader.Identifier().size() > 1);
        sb.append(stsSetterHeader.Identifier(0).getText()).append(' ');
        sb.append(stsSetterHeader.Identifier(1).getText()).append('(');

        visitParameter(stsSetterHeader.parameter());
        sb.append(')');

        writeTrailingComments(stsSetterHeader);
        return null;
    }

    // classExtendsClause: Extends typeReference
    @Override
    public Void visitClassExtendsClause(ClassExtendsClauseContext stsClassExtendsClause) {
        writeLeadingComments(stsClassExtendsClause);

        String stsExtendsKeyword = stsClassExtendsClause.Identifier().getText();
        if (!StaticTSParser.EXTENDS.equals(stsExtendsKeyword)) {
            reportError("Unexpected keyword " + stsExtendsKeyword + " in class declaration", stsClassExtendsClause);
            stsExtendsKeyword = StaticTSParser.EXTENDS;
        }
        sb.append(stsExtendsKeyword).append(' ');

        visitTypeReference(stsClassExtendsClause.typeReference());
        sb.append(' ');

        writeTrailingComments(stsClassExtendsClause);
        return null;
    }

    // implementsClause: Implements classOrInterfaceTypeList
    @Override
    public Void visitImplementsClause(ImplementsClauseContext stsImplementsClause) {
        writeLeadingComments(stsImplementsClause);

        String stsImplementsKeyword = stsImplementsClause.Identifier().getText();
        if (!StaticTSParser.IMPLEMENTS.equals(stsImplementsKeyword)) {
            reportError("Unexpected keyword " + stsImplementsKeyword + " in class declaration", stsImplementsClause);
            stsImplementsKeyword = StaticTSParser.IMPLEMENTS;
        }
        sb.append(stsImplementsKeyword).append(' ');
        visitInterfaceTypeList(stsImplementsClause.interfaceTypeList());
        sb.append(' ');

        writeTrailingComments(stsImplementsClause);
        return null;
    }

    // parameterList
    //    : parameter (',' parameter)* (',' variadicParameter)?
    //    | variadicParameter
    @Override
    public Void visitParameterList(ParameterListContext stsParameterList) {
        writeLeadingComments(stsParameterList);
        List<ParameterContext> stsParameters = stsParameterList.parameter();

        int i = 0;
        if (stsParameters != null) {
            for (ParameterContext stsParameter : stsParameters) {
                if (i > 0) sb.append(", ");
                visitParameter(stsParameter);
                ++i;
            }
        }

        VariadicParameterContext stsVariadicParameter = stsParameterList.variadicParameter();
        if (stsVariadicParameter != null) {
            if (i > 0) sb.append(", ");
            visitVariadicParameter(stsVariadicParameter);
        }

        writeTrailingComments(stsParameterList);
        return null;
    }

    // parameter: Identifier typeAnnotation
    @Override
    public Void visitParameter(ParameterContext stsParameter) {
        writeLeadingComments(stsParameter);

        TerminalNode termIdentifier = stsParameter.Identifier();
        if (termIdentifier != null) {
            sb.append(termIdentifier.getText()).append(' ');
        }

        visitTypeAnnotation(stsParameter.typeAnnotation());

        InitializerContext stsInitializer = stsParameter.initializer();
        if (stsInitializer != null) {
            sb.append(' ');
            visitInitializer(stsInitializer);
        }

        writeTrailingComments(stsParameter);
        return null;
    }

    // variadicParameter: Ellipsis Identifier typeAnnotation
    @Override
    public Void visitVariadicParameter(VariadicParameterContext stsVariadicParameter) {
        writeLeadingComments(stsVariadicParameter);

        sb.append(stsVariadicParameter.Ellipsis().getText()).append(' ');
        sb.append(stsVariadicParameter.Identifier().getText());
        visitTypeAnnotation(stsVariadicParameter.typeAnnotation());

        writeTrailingComments(stsVariadicParameter);
        return null;
    }

    // | OpenBracket expressionSequence? CloseBracket  #ArrayLiterlaExpression
    @Override
    public Void visitArrayLiteralExpression(ArrayLiteralExpressionContext stsArrayLiteral) {
        writeLeadingComments(stsArrayLiteral);

        sb.append('[');

        ExpressionSequenceContext stsExpressions = stsArrayLiteral.expressionSequence();
        if (stsExpressions != null) visitExpressionSequence(stsExpressions);

        sb.append(']');

        writeTrailingComments(stsArrayLiteral);
        return null;
    }

    //     | primaryType '.' Class                                                  # ClassLiteralExpression
    @Override
    public Void visitClassLiteralExpression(ClassLiteralExpressionContext stsClassLiteral) {
        writeLeadingComments(stsClassLiteral);

        stsClassLiteral.primaryType().accept(this);
        sb.append(stsClassLiteral.Dot().getText()).append(stsClassLiteral.Class().getText());

        writeTrailingComments(stsClassLiteral);
        return null;
    }

    //    | OpenBrace nameValueSequence? CloseBrace                                # ClassCompositeExpression
    @Override
    public Void visitClassCompositeExpression(ClassCompositeExpressionContext stsClassComposite) {
        writeLeadingComments(stsClassComposite);
        sb.append('{');

        NameValueSequenceContext stsNameValueSeq = stsClassComposite.nameValueSequence();
        if (stsNameValueSeq != null) visitNameValueSequence(stsNameValueSeq);

        sb.append('}');
        writeTrailingComments(stsClassComposite);
        return null;
    }

    //    nameValueSequence : nameValuePair (Comma nameValuePair)* ;
    @Override
    public Void visitNameValueSequence(NameValueSequenceContext stsNameValueSeq) {
        writeLeadingComments(stsNameValueSeq);

        int i = 0;
        for (NameValuePairContext stsNameValuePair : stsNameValueSeq.nameValuePair()) {
            if (i > 0) sb.append(", ");

            visitNameValuePair(stsNameValuePair);
            ++i;
        }

        writeTrailingComments(stsNameValueSeq);
        return null;
    }

    //    nameValuePair : Identifier Colon singleExpression ;
    @Override
    public Void visitNameValuePair(NameValuePairContext stsNameValuePair) {
        writeLeadingComments(stsNameValuePair);

        sb.append(stsNameValuePair.Identifier().getText()).append(": ");
        stsNameValuePair.singleExpression().accept(this);

        writeTrailingComments(stsNameValuePair);
        return null;
    }

    //    | '(' singleExpression ')'                                             # ParenthesizedExpression
    @Override
    public Void visitParenthesizedExpression(ParenthesizedExpressionContext stsParenthesizedExpression) {
        writeLeadingComments(stsParenthesizedExpression);

        sb.append('(');
        stsParenthesizedExpression.singleExpression().accept(this);
        sb.append(')');

        writeTrailingComments(stsParenthesizedExpression);
        return null;
    }

    //    | singleExpression As asExpression                                       # CastAsExpression;
    @Override
    public Void visitCastExpression(CastExpressionContext stsCastExpression) {
        writeLeadingComments(stsCastExpression);

        stsCastExpression.singleExpression().accept(this);

        sb.append(' ').append(stsCastExpression.As().getText()).append(' ');

        IntersectionTypeContext stsIntersectionType = stsCastExpression.intersectionType();
        if (stsIntersectionType != null) {
            visitIntersectionType(stsIntersectionType);
        }
        else {
            PrimaryTypeContext stsPrimaryType = stsCastExpression.primaryType();
            assert stsPrimaryType != null;
            stsPrimaryType.accept(this);
        }

        writeTrailingComments(stsCastExpression);
        return null;
    }

    //  | Await singleExpression                                                 # AwaitExpression
    @Override
    public Void visitAwaitExpression(AwaitExpressionContext stsAwaitExpr) {
        writeLeadingComments(stsAwaitExpr);

        sb.append(stsAwaitExpr.Await().getText()).append(' ');
        stsAwaitExpr.singleExpression().accept(this);

        writeTrailingComments(stsAwaitExpr);
        return null;
    }

    // arguments: '(' argumentList? ')'
    @Override
    public Void visitArguments(ArgumentsContext stsArguments) {
        writeLeadingComments(stsArguments);

        sb.append('(');

        ExpressionSequenceContext stsArgumentList = stsArguments.expressionSequence();
        if (stsArgumentList != null) visitExpressionSequence(stsArgumentList);

        sb.append(')');

        writeTrailingComments(stsArguments);
        return null;
    }

    @Override
    public Void visitTerminal(TerminalNode stsTerminal) {
        int stsTerminalCode = stsTerminal.getSymbol().getType();
        if (stsTerminalCode == StaticTSLexer.MultiLineComment ||
            stsTerminalCode == StaticTSLexer.SingleLineComment) {
            sb.append(stsTerminal.getText());
        }

        return null;
    }

    //    | singleExpression Instanceof singleExpression                           # InstanceofExpression
    @Override
    public Void visitInstanceofExpression(InstanceofExpressionContext stsInstanceofExpression) {
        writeLeadingComments(stsInstanceofExpression);

        stsInstanceofExpression.singleExpression().accept(this);
        sb.append(' ').append(stsInstanceofExpression.Instanceof().getText()).append(' ');
        stsInstanceofExpression.primaryType().accept(this);

        writeTrailingComments(stsInstanceofExpression);
        return null;
    }

    private void preOperatorExpressionWrite(String op, SingleExpressionContext stsSingleExpression) {
        sb.append(op);
        stsSingleExpression.accept(this);
    }

    private void postOperatorExpressionWrite(String op, SingleExpressionContext stsSingleExpression) {
        stsSingleExpression.accept(this);
        sb.append(op);
    }

    private void binaryOperatorWrite(String op, List<SingleExpressionContext> operands) {
        operands.get(0).accept(this);
        sb.append(' ').append(op).append(' ');
        operands.get(1).accept(this);
    }

    // | singleExpression typeArguments? arguments #CallExpression
    @Override
    public Void visitCallExpression(CallExpressionContext stsCallExpression) {
        writeLeadingComments(stsCallExpression);

        stsCallExpression.singleExpression().accept(this);

        TypeArgumentsContext stsTypeArguments = stsCallExpression.typeArguments();
        if (stsTypeArguments != null) {
            visitTypeArguments(stsTypeArguments);
        }

        if (stsCallExpression.QuestionMark() != null) sb.append("?.");

        visitArguments(stsCallExpression.arguments());

        writeTrailingComments(stsCallExpression);
        return null;
    }

    // | New typeArguments? typeReference arguments? classBody? # NewClassInstanceExpression
    @Override
    public Void visitNewClassInstanceExpression(NewClassInstanceExpressionContext stsNewClassInstanceExpression) {
        writeLeadingComments(stsNewClassInstanceExpression);

        sb.append(stsNewClassInstanceExpression.New().getText()).append(' ');

        TypeArgumentsContext stsTypeArguments = stsNewClassInstanceExpression.typeArguments();
        if (stsTypeArguments != null) visitTypeArguments(stsTypeArguments);

        visitTypeReference(stsNewClassInstanceExpression.typeReference());

        ArgumentsContext stsArguments = stsNewClassInstanceExpression.arguments();
        if (stsArguments != null) {
            visitArguments(stsArguments);
        }

        ClassBodyContext stsClassBody = stsNewClassInstanceExpression.classBody();
        if (stsClassBody != null) {
            visitClassBody(stsClassBody);
        }

        writeTrailingComments(stsNewClassInstanceExpression);
        return null;
    }

    // | singleExpression Dot New typeArguments? typeReference arguments? classBody? # NewInnerClassInstanceExpression
    @Override
    public Void visitNewInnerClassInstanceExpression(NewInnerClassInstanceExpressionContext stsNewInnerClassInstanceExpression) {
        writeLeadingComments(stsNewInnerClassInstanceExpression);

        SingleExpressionContext stsOuterObject = stsNewInnerClassInstanceExpression.singleExpression();
        stsOuterObject.accept(this);

        sb.append('.').append(stsNewInnerClassInstanceExpression.New().getText()).append(' ');

        TypeArgumentsContext stsTypeArguments = stsNewInnerClassInstanceExpression.typeArguments();
        if (stsTypeArguments != null) visitTypeArguments(stsTypeArguments);

        visitTypeReference(stsNewInnerClassInstanceExpression.typeReference());

        ArgumentsContext stsArguments = stsNewInnerClassInstanceExpression.arguments();
        if (stsArguments != null) {
            visitArguments(stsArguments);
        }

        ClassBodyContext stsClassBody = stsNewInnerClassInstanceExpression.classBody();
        if (stsClassBody != null) {
            visitClassBody(stsClassBody);
        }

        writeTrailingComments(stsNewInnerClassInstanceExpression);
        return null;
    }

    // | New primaryType indexExpression+ (OpenBracket CloseBracket)* # NewArrayExpression
    @Override
    public Void visitNewArrayExpression(NewArrayExpressionContext stsNewArrayExpression) {
        writeLeadingComments(stsNewArrayExpression);

        TerminalNode stsTerm = stsNewArrayExpression.New();
        sb.append(stsTerm.getText()).append(' ');

        PrimaryTypeContext stsPrimaryType = stsNewArrayExpression.primaryType();
        visitPrimaryType(stsPrimaryType);

        List<IndexExpressionContext> stsIndexList = stsNewArrayExpression.indexExpression();
        assert(stsIndexList != null && !stsIndexList.isEmpty());
        for (IndexExpressionContext stsIndex : stsIndexList)
            visitIndexExpression(stsIndex);

        List<TerminalNode> emptyDims = stsNewArrayExpression.OpenBracket();
        if (emptyDims != null && !emptyDims.isEmpty()) {
            assert(stsNewArrayExpression.CloseBracket().size() == emptyDims.size());
            for (int i = 0; i < emptyDims.size(); ++i) {
                sb.append("[]");
            }
        }

        writeTrailingComments(stsNewArrayExpression);
        return null;
    }

    @Override
    public Void visitIndexExpression(IndexExpressionContext stsIndexExpression) {
        writeLeadingComments(stsIndexExpression);

        sb.append('[');

        SingleExpressionContext stsExpression = stsIndexExpression.singleExpression();
        assert(stsExpression != null);
        stsExpression.accept(this);

        sb.append(']');

        writeTrailingComments(stsIndexExpression);
        return null;
    }

    //  | singleExpression Dot Identifier   # MemberDotExpression
    @Override
    public Void visitMemberAccessExpression(MemberAccessExpressionContext stsMemberAccessExpression) {
        writeLeadingComments(stsMemberAccessExpression);

        stsMemberAccessExpression.singleExpression().accept(this);
        if (stsMemberAccessExpression.QuestionMark() != null) sb.append('?');
        sb.append('.').append(stsMemberAccessExpression.Identifier().getText());

        writeTrailingComments(stsMemberAccessExpression);
        return null;
    }

    //    | singleExpression {this.notLineTerminator()}? '--'                      # PostDecreaseExpression
    @Override
    public Void visitPostDecreaseExpression(PostDecreaseExpressionContext stsPostDecreaseExpression) {
        writeLeadingComments(stsPostDecreaseExpression);

        postOperatorExpressionWrite("--", stsPostDecreaseExpression.singleExpression());

        writeTrailingComments(stsPostDecreaseExpression);
        return null;
    }

    //    | singleExpression {this.notLineTerminator()}? '++'                      # PostIncrementExpression
    @Override
    public Void visitPostIncrementExpression(PostIncrementExpressionContext stsPostIncrementExpression) {
        writeLeadingComments(stsPostIncrementExpression);

        postOperatorExpressionWrite("++", stsPostIncrementExpression.singleExpression());

        writeTrailingComments(stsPostIncrementExpression);
        return null;
    }

    //  | singleExpression {this.notLineTerminator()}? Not                       # NonNullExpression
    @Override
    public Void visitNonNullExpression(NonNullExpressionContext stsNonNullExpression) {
        writeLeadingComments(stsNonNullExpression);

        postOperatorExpressionWrite("!", stsNonNullExpression.singleExpression());

        writeTrailingComments(stsNonNullExpression);
        return null;
    }

    //    | '++' singleExpression                                                  # PreIncrementExpression
    @Override
    public Void visitPreIncrementExpression(PreIncrementExpressionContext stsPreIncrementExpression) {
        writeLeadingComments(stsPreIncrementExpression);

        preOperatorExpressionWrite("++", stsPreIncrementExpression.singleExpression());

        writeTrailingComments(stsPreIncrementExpression);
        return null;
    }

    //    | '--' singleExpression                                                  # PreDecreaseExpression
    @Override
    public Void visitPreDecreaseExpression(PreDecreaseExpressionContext stsPreDecreaseExpression) {
        writeLeadingComments(stsPreDecreaseExpression);

        preOperatorExpressionWrite("--", stsPreDecreaseExpression.singleExpression());

        writeTrailingComments(stsPreDecreaseExpression);
        return null;
    }

    //    | '+' singleExpression                                                   # UnaryPlusExpression
    @Override
    public Void visitUnaryPlusExpression(UnaryPlusExpressionContext stsUnaryPlusExpression) {
        writeLeadingComments(stsUnaryPlusExpression);

        preOperatorExpressionWrite("+", stsUnaryPlusExpression.singleExpression());

        writeTrailingComments(stsUnaryPlusExpression);
        return null;
    }

    //    | '-' singleExpression                                                   # UnaryMinusExpression
    @Override
    public Void visitUnaryMinusExpression(UnaryMinusExpressionContext stsUnaryMinusExpression) {
        writeLeadingComments(stsUnaryMinusExpression);

        preOperatorExpressionWrite("-", stsUnaryMinusExpression.singleExpression());

        writeTrailingComments(stsUnaryMinusExpression);
        return null;
    }

    //    | '~' singleExpression                                                   # BitNotExpression
    @Override
    public Void visitBitNotExpression(BitNotExpressionContext stsBitNotExpression) {
        writeLeadingComments(stsBitNotExpression);

        preOperatorExpressionWrite("~", stsBitNotExpression.singleExpression());

        writeTrailingComments(stsBitNotExpression);
        return null;
    }

    //    | '!' singleExpression                                                   # NotExpression
    @Override
    public Void visitNotExpression(NotExpressionContext stsNotExpression) {
        writeLeadingComments(stsNotExpression);

        preOperatorExpressionWrite("!", stsNotExpression.singleExpression());

        writeTrailingComments(stsNotExpression);
        return null;
    }

    //    | singleExpression ('*' | '/' | '%') singleExpression                    # MultiplicativeExpression
    @Override
    public Void visitMultiplicativeExpression(MultiplicativeExpressionContext stsMultiplicativeExpression) {
        writeLeadingComments(stsMultiplicativeExpression);

        String op = stsMultiplicativeExpression.getChild(1).getText();
        binaryOperatorWrite(op, stsMultiplicativeExpression.singleExpression());

        writeTrailingComments(stsMultiplicativeExpression);
        return null;
    }

    //    | singleExpression ('+' | '-') singleExpression                          # AdditiveExpression
    @Override
    public Void visitAdditiveExpression(AdditiveExpressionContext stsAdditiveExpression) {
        writeLeadingComments(stsAdditiveExpression);

        String op = stsAdditiveExpression.getChild(1).getText();
        binaryOperatorWrite(op, stsAdditiveExpression.singleExpression());

        writeTrailingComments(stsAdditiveExpression);
        return null;
    }

    //    | singleExpression ('<' '<' | '>' '>' | '>' '>' '>') singleExpression                # BitShiftExpression
    @Override
    public Void visitBitShiftExpression(BitShiftExpressionContext stsBitShiftExpression) {
        writeLeadingComments(stsBitShiftExpression);

        String op = stsBitShiftExpression.shiftOperator().getText();
        binaryOperatorWrite(op, stsBitShiftExpression.singleExpression());

        writeTrailingComments(stsBitShiftExpression);
        return null;
    }

    //    | singleExpression ('<' | '>' | '<=' | '>=') singleExpression            # RelationalExpression
    @Override
    public Void visitRelationalExpression(RelationalExpressionContext stsRelationalExpression) {
        writeLeadingComments(stsRelationalExpression);

        String op = stsRelationalExpression.getChild(1).getText();
        binaryOperatorWrite(op, stsRelationalExpression.singleExpression());

        writeTrailingComments(stsRelationalExpression);
        return null;
    }

    // | singleExpression ('==' | '!=') singleExpression                        # EqualityExpression
    @Override
    public Void visitEqualityExpression(EqualityExpressionContext stsEqualityExpression) {
        writeLeadingComments(stsEqualityExpression);

        String op = stsEqualityExpression.getChild(1).getText();
        binaryOperatorWrite(op, stsEqualityExpression.singleExpression());

        writeTrailingComments(stsEqualityExpression);
        return null;
    }

    //    | singleExpression '&' singleExpression                                  # BitAndExpression
    @Override
    public Void visitBitAndExpression(BitAndExpressionContext stsBitAndExpression) {
        writeLeadingComments(stsBitAndExpression);

        binaryOperatorWrite(stsBitAndExpression.BitAnd().getText(), stsBitAndExpression.singleExpression());

        writeTrailingComments(stsBitAndExpression);
        return null;
    }

    //    | singleExpression '^' singleExpression                                  # BitXorExpression
    @Override
    public Void visitBitXOrExpression(BitXOrExpressionContext stsBitXOrExpression) {
        writeLeadingComments(stsBitXOrExpression);

        binaryOperatorWrite(stsBitXOrExpression.BitXor().getText(), stsBitXOrExpression.singleExpression());

        writeTrailingComments(stsBitXOrExpression);
        return null;
    }

    //    | singleExpression '|' singleExpression                                  # BitOrExpression
    @Override
    public Void visitBitOrExpression(BitOrExpressionContext stsBitOrExpression) {
        writeLeadingComments(stsBitOrExpression);

        binaryOperatorWrite(stsBitOrExpression.BitOr().getText(), stsBitOrExpression.singleExpression());

        writeTrailingComments(stsBitOrExpression);
        return null;
    }

    //    | singleExpression '&&' singleExpression                                 # LogicalAndExpression
    @Override
    public Void visitLogicalAndExpression(LogicalAndExpressionContext stsLogicalAndExpression) {
        writeLeadingComments(stsLogicalAndExpression);

        binaryOperatorWrite(stsLogicalAndExpression.And().getText(), stsLogicalAndExpression.singleExpression());

        writeTrailingComments(stsLogicalAndExpression);
        return null;
    }

    //    | singleExpression '||' singleExpression                                 # LogicalOrExpression
    @Override
    public Void visitLogicalOrExpression(LogicalOrExpressionContext stsLogicalOrExpression) {
        writeLeadingComments(stsLogicalOrExpression);

        binaryOperatorWrite(stsLogicalOrExpression.Or().getText(), stsLogicalOrExpression.singleExpression());

        writeTrailingComments(stsLogicalOrExpression);
        return null;
    }

    //    | singleExpression '?' singleExpression ':' singleExpression             # TernaryExpression
    @Override
    public Void visitTernaryExpression(TernaryExpressionContext stsTernaryExpression) {
        writeLeadingComments(stsTernaryExpression);

        List<SingleExpressionContext> stsExpressionList = stsTernaryExpression.singleExpression();

        stsExpressionList.get(0).accept(this);
        sb.append(" ? ");
        stsExpressionList.get(1).accept(this);
        sb.append(" : ");
        stsExpressionList.get(2).accept(this);

        writeTrailingComments(stsTernaryExpression);
        return null;
    }

    // | singleExpression QuestionMark QuestionMark singleExpression            # NullCoalescingExpression
    @Override
    public Void visitNullCoalescingExpression(NullCoalescingExpressionContext stsNullCoalescingExpr) {
        writeLeadingComments(stsNullCoalescingExpr);

        stsNullCoalescingExpr.singleExpression(0).accept(this);
        sb.append(" ?? ");
        stsNullCoalescingExpr.singleExpression(1).accept(this);

        writeTrailingComments(stsNullCoalescingExpr);
        return null;
    }

    //    | singleExpression '=' singleExpression                                  # AssignmentExpression
    @Override
    public Void visitAssignmentExpression(AssignmentExpressionContext stsAssignmentExpression) {
        writeLeadingComments(stsAssignmentExpression);

        binaryOperatorWrite(stsAssignmentExpression.Assign().getText(), stsAssignmentExpression.singleExpression());

        writeTrailingComments(stsAssignmentExpression);
        return null;
    }

    //    | singleExpression assignmentOperator singleExpression                   # AssignmentOperatorExpression
    @Override
    public Void visitAssignmentOperatorExpression(AssignmentOperatorExpressionContext stsAssignmentOperatorExpression) {
        writeLeadingComments(stsAssignmentOperatorExpression);

        String op = stsAssignmentOperatorExpression.assignmentOperator().getText();
        binaryOperatorWrite(op, stsAssignmentOperatorExpression.singleExpression());

        writeTrailingComments(stsAssignmentOperatorExpression);
        return null;
    }

        //    | singleExpression '[' indexExpression ']' # ArrayAccessExpression
    @Override
    public Void visitArrayAccessExpression(ArrayAccessExpressionContext stsArrayAccessExpression) {
        writeLeadingComments(stsArrayAccessExpression);

        stsArrayAccessExpression.singleExpression().accept(this);

        if (stsArrayAccessExpression.QuestionMark() != null) sb.append("?.");

        IndexExpressionContext stsIndexExpression = stsArrayAccessExpression.indexExpression();
        assert(stsIndexExpression != null);
        visitIndexExpression(stsIndexExpression);

        writeTrailingComments(stsArrayAccessExpression);
        return null;
    }

    // lambdaExpression: : '(' formalParameterList? ')' typeAnnotation Arrow lambdaBody           # LambdaExpression   // ECMAScript 6
    @Override
    public Void visitLambdaExpression(LambdaExpressionContext stsLambdaExpression) {
        writeLeadingComments(stsLambdaExpression);

        sb.append('(');
        ParameterListContext stsParameterList = stsLambdaExpression.parameterList();
        if (stsParameterList != null) {
            visitParameterList(stsParameterList);
        }
        sb.append(')');

        visitTypeAnnotation(stsLambdaExpression.typeAnnotation());

        ThrowsAnnotationContext stsThrowsAnno = stsLambdaExpression.throwsAnnotation();
        if (stsThrowsAnno != null) visitThrowsAnnotation(stsThrowsAnno);

        sb.append(stsLambdaExpression.Arrow().getText());

        visitLambdaBody(stsLambdaExpression.lambdaBody());

        writeTrailingComments(stsLambdaExpression);
        return null;
    }

    // lambdaBody
    //    : singleExpression
    //    | '{' functionBody '}'
    @Override
    public Void visitLambdaBody(LambdaBodyContext stsLambdaBody) {
        writeLeadingComments(stsLambdaBody);

        SingleExpressionContext stsSingleExpression = stsLambdaBody.singleExpression();
        if (stsSingleExpression != null) {
            sb.append(' ');
            stsSingleExpression.accept(this);
        }
        else {
            BlockContext stsBlock = stsLambdaBody.block();
            assert(stsBlock != null);

            if (!doNeededIndent()) {
                sb.append(' ');
            }

            visitBlock(stsBlock);
        }

        writeTrailingComments(stsLambdaBody);
        return null;
    }

    // literal:
    //    NullLiteral
    //  | BooleanLiteral
    //  | StringLiteral
    //  | numericLiteral
    @Override
    public Void visitLiteral(LiteralContext stsLiteral) {
        writeLeadingComments(stsLiteral);

        sb.append(stsLiteral.getText());

        writeTrailingComments(stsLiteral);
        return null;
    }

    // deferStatement: Defer statement;
    @Override
    public Void visitDeferStatement(DeferStatementContext stsDeferStatement) {
        doNeededIndent();
        writeLeadingComments(stsDeferStatement);

        sb.append(stsDeferStatement.Defer().getText()).append(' ');
        stsDeferStatement.statement().accept(this);

        writeTrailingComments(stsDeferStatement);
        return null;
    }

    // This is to emit comments that we attached to nodes for
    // which we don't have explicit visit function above.
    @Override
    public Void visitChildren(RuleNode node) {
        StaticTSContextBase stsNode = node instanceof StaticTSContextBase ?
                                      (StaticTSContextBase)node : null;
        writeLeadingComments(stsNode);

        super.visitChildren(node);

        writeTrailingComments(stsNode);
        return null;
    }
    public void visitDummyNode(StaticTSContextBase stsContextBase) {
        // Just dump comments on this node.
        writeLeadingComments(stsContextBase);
        writeTrailingComments(stsContextBase);
    }

    @Override
    public Void visitTypeAliasDeclaration(TypeAliasDeclarationContext stsTypeAliasDecl) {
        sb.append(stsTypeAliasDecl.Type().getText()).append(' ');
        sb.append(stsTypeAliasDecl.Identifier().getText());

        TypeParametersContext stsTypeParams = stsTypeAliasDecl.typeParameters();
        if (stsTypeParams != null) visitTypeParameters(stsTypeParams);

        sb.append(" = ");

        stsTypeAliasDecl.primaryType().accept(this);
        sb.append(";\n");

        return null;
    }
}
