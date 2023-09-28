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

package com.ohos.migrator.staticTS;

import com.ohos.migrator.staticTS.parser.DummyContext;
import com.ohos.migrator.staticTS.parser.StaticTSContextBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import org.antlr.v4.runtime.CommonToken;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Vocabulary;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.antlr.v4.runtime.tree.TerminalNodeImpl;

import java.util.ArrayList;
import java.util.List;

public class NodeBuilderBase {
    private static final Vocabulary vocabulary = StaticTSParser.VOCABULARY;
    protected static final String UNKNOWN_TYPE_NAME = "__UnknownType__";
    protected static final String UNTRANSLATED_EXPRESSION = "__untranslated_expression";
    protected static final String UNTRANSLATED_STATEMENT = "__untranslated_statement";

    public static TerminalNode terminalNode(int type) {
        return terminalNode(type, null);
    }

    public static TerminalNode terminalNode(int type, String value) {
        if (value == null || value.isEmpty()) value = stsName(type);

        // Add leading and/or terminating quotes if necessary
        if (type == StaticTSParser.StringLiteral) {
            if (!value.startsWith("\"")) value = "\"" + value;
            if (!value.endsWith("\"")) value += "\"";
        }
        else if (type == StaticTSParser.CharLiteral) {
            if (!value.startsWith("'")) value = "'" + value;
            if (!value.endsWith("'")) value += "'";
        }

        return new TerminalNodeImpl(new CommonToken(type, value));
    }
    public static String stsName(int type) {
        // Antlr store all literal names wrapped into single quotes. Like: "'&='", "'^='", "'|='", "'=>'", "'null'", null,
        // "'do'", "'instanceof'", "'typeof'", "'case'",
        // Some values are null (for some codes/types).
        String stsName = vocabulary.getLiteralName(type);
        if (stsName == null) {
            assert(false);
            stsName = " <null> ";
        }
        else {
            assert(stsName.length() > 2);
            stsName = stsName.substring(1, stsName.length()-1);
        }

        return stsName;
    }

    public static TerminalNode terminalIdentifier(String identifier) {
        return terminalNode(StaticTSParser.Identifier, identifier);
    }

    public static TerminalNode multiLineComment(String comment) {
        return terminalNode(StaticTSParser.MultiLineComment, comment);
    }

    public static TerminalNode singleLineComment(String comment) {
        return terminalNode(StaticTSParser.SingleLineComment, comment);
    }

    // The 'name' here is expected to be a dot-separated sequence of names: 'name' '.' 'name' '.' 'name' ...
    public static QualifiedNameContext qualifiedName(String fqname) {
        QualifiedNameContext stsQualifiedName = new QualifiedNameContext(null, 0);
        stsQualifiedName.addChild(terminalIdentifier(fqname)).setParent(stsQualifiedName);
        return stsQualifiedName;
    }

    private static String stsPredefinedTypeName(String typeName) {
        String stsTypeName = null;

        if ("boolean".equals(typeName))
            stsTypeName = StaticTSParser.BOOLEAN;
        else if ("byte".equals(typeName))
            stsTypeName = StaticTSParser.BYTE;
        else if ("char".equals(typeName))
            stsTypeName = StaticTSParser.CHAR;
        else if ("int".equals(typeName))
            stsTypeName = StaticTSParser.INT;
        else if ("double".equals(typeName))
            stsTypeName = StaticTSParser.DOUBLE;
        else if ("float".equals(typeName))
            stsTypeName = StaticTSParser.FLOAT;
        else if ("long".equals(typeName))
            stsTypeName = StaticTSParser.LONG;
        else if ("short".equals(typeName))
            stsTypeName = StaticTSParser.SHORT;
        else if ("ubyte".equals(typeName))
            stsTypeName = StaticTSParser.UBYTE;
        else if ("uint".equals(typeName))
            stsTypeName = StaticTSParser.UINT;
        else if ("ulong".equals(typeName))
            stsTypeName = StaticTSParser.ULONG;
        else if ("ushort".equals(typeName))
            stsTypeName = StaticTSParser.USHORT;
        else if ("void".equals(typeName))
            stsTypeName = StaticTSParser.VOID;

        return stsTypeName;
    }

    public static StaticTSContextBase predefinedType(String typeName) {
        // predefinedType -> TerminalNode<TypeName>
        String stsTypeName = stsPredefinedTypeName(typeName);
        if (stsTypeName == null) return unknownTypeReference("/* " + typeName + " */");

        PredefinedTypeContext stsPredefinedType = new PredefinedTypeContext(null, 0);
        stsPredefinedType.addChild(terminalIdentifier(stsTypeName));
        return stsPredefinedType;
    }

    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: Null
    public static SingleExpressionContext nullLiteral() {
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        LiteralContext stsLiteral = new LiteralContext(stsExpression, 0);
        stsLiteral.addChild(terminalNode(StaticTSParser.Null));
        stsExpression.addChild(stsLiteral).setParent(stsExpression);

        return stsExpression;
    }

    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | True | False
    public static SingleExpressionContext boolLiteral(Boolean value) {
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        LiteralContext stsLiteral = new LiteralContext(null, 0);
        stsLiteral.addChild(terminalNode(value ? StaticTSParser.True : StaticTSParser.False));
        stsExpression.addChild(stsLiteral).setParent(stsExpression);
        return stsExpression;
    }

    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | CharLiteral
    public static SingleExpressionContext charLiteral(String value) {
        // Add leading and/or terminating quotes if missing
        if (!value.startsWith("'")) value = "'" + value;
        if (!value.endsWith("'")) value += "'";

        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        LiteralContext stsLiteral = new LiteralContext(null, 0);
        stsLiteral.addChild(new TerminalNodeImpl(new CommonToken(StaticTSParser.CharLiteral, value)));
        stsExpression.addChild(stsLiteral).setParent(stsExpression);

        return stsExpression;
    }

    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | StringLiteral
    public static SingleExpressionContext stringLiteral(String value) {
        // TODO: Escape all unescaped characters
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        LiteralContext stsLiteral = new LiteralContext(null, 0);
        stsLiteral.addChild(terminalNode(StaticTSParser.StringLiteral, value));
        stsExpression.addChild(stsLiteral).setParent(stsExpression);

        return stsExpression;
    }

    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | numericLiteral
    //      numericLiteral:
    //              : DecimalLiteral
    //              | HexIntegerLiteral
    //              | OctalIntegerLiteral
    //              | BinaryIntegerLiteral
    public static SingleExpressionContext numericLiteral(String value) {
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        LiteralContext stsLiteral = new LiteralContext(null, 0);

        CommonToken token;

        // parse string representation to create appropriate token
        // Ignore d and l suffices that Java allows for numeric literals
        // NOTE: The f suffix that Java also allows will be dealt with
        // later, as it might conflict with hexadecimal literals.
        if (value.endsWith("d") || value.endsWith("D") ||
            value.endsWith("l") || value.endsWith("L")) {
            value = value.substring(0, value.length() - 1);
        }

        if (value.startsWith("0b") || value.startsWith("0B")) {
            token = new CommonToken(StaticTSParser.BinaryIntegerLiteral, value);
        }
        else if (value.startsWith("0x") || value.startsWith("0X")) {
            token = new CommonToken(StaticTSParser.HexIntegerLiteral, value);
        }
        else if (value.startsWith("0") && value.length() > 1 &&
                !value.contains("89") && !value.contains(".")) {
            // STS octal literals start with 0o
            value = "0o" + value.substring(1);
            token = new CommonToken(StaticTSParser.OctalIntegerLiteral, value);
        }
        else {
            if (value.endsWith("f") || value.endsWith("F")) {
                value = value.substring(0, value.length() - 1);
            }
            token = new CommonToken(StaticTSParser.DecimalLiteral, value);
        }

        stsLiteral.addChild(new TerminalNodeImpl(token));
        stsExpression.addChild(stsLiteral).setParent(stsExpression);

        return stsExpression;
    }

    // STS:
    //   typeReference: typeReferencePart ('.' typeReferencePart)*
    //   typeReferencePart: qualifiedName typeArguments?
    public static TypeReferenceContext typeReference(String typeName) {
        TypeReferenceContext stsTypeReference = new TypeReferenceContext(null, 0);
        TypeReferencePartContext stsTypeRefPart = typeReferencePart(typeName);
        stsTypeReference.addChild(stsTypeRefPart).setParent(stsTypeReference);
        return stsTypeReference;
    }

    // STS:
    //   typeReferencePart: qualifiedName typeArguments?
    public static TypeReferencePartContext typeReferencePart(String typeName) {
        TypeReferencePartContext stsTypeRefPart = new TypeReferencePartContext(null, 0);
        stsTypeRefPart.addChild(qualifiedName(typeName)).setParent(stsTypeRefPart);
        return stsTypeRefPart;
    }

    public static TypeReferenceContext unknownTypeReference(String comment) {
        TypeReferenceContext stsTypeRef = typeReference(UNKNOWN_TYPE_NAME);
        if (comment != null) {
            TerminalNode stsComment = multiLineComment("/* " + comment + " */");
            stsTypeRef.addTrailingComment(stsComment);
        }

        return stsTypeRef;
    }

    // STS tree:
    //     singleExpression: | Identifier # IdentifierExpression
    public static SingleExpressionContext identifierExpression(String name) {
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        IdentifierExpressionContext stsIdentifier = new IdentifierExpressionContext(stsExpression);
        stsIdentifier.addChild(terminalIdentifier(name));
        stsExpression.addChild(stsIdentifier).setParent(stsExpression);

        return stsExpression;
    }

    public static ArrayTypeContext arrayType(String elementTypeName, int dimensions) {
        return arrayType(typeReference(elementTypeName), dimensions);
    }

    public static ArrayTypeContext arrayType(ParserRuleContext elementType, int dimensions) {
        ArrayTypeContext stsArrayType = new ArrayTypeContext(null, 0);
        stsArrayType.addChild(elementType).setParent(stsArrayType);
        for (int i = 0; i < dimensions; ++i) {
            stsArrayType.addChild(terminalNode(StaticTSParser.OpenBracket));
            stsArrayType.addChild(terminalNode(StaticTSParser.CloseBracket));
        }
        return stsArrayType;
    }

    public static TypeAnnotationContext typeAnnotation(ParserRuleContext stsType) {
        if (stsType.getRuleIndex() != StaticTSParser.RULE_predefinedType &&
                stsType.getRuleIndex() != StaticTSParser.RULE_arrayType &&
                stsType.getRuleIndex() != StaticTSParser.RULE_typeReference) {
            // Sanity check. Shouldn't even get here.
            return unknownTypeAnnotation();
        }

        TypeAnnotationContext stsTypeAnno = new TypeAnnotationContext(null, 0);
        PrimaryTypeContext stsPrimaryType = new PrimaryTypeContext(stsTypeAnno, 0);
        stsPrimaryType.addChild(stsType).setParent(stsPrimaryType);
        stsTypeAnno.addChild(stsPrimaryType).setParent(stsTypeAnno);
        return stsTypeAnno;
    }
    public static TypeAnnotationContext typeAnnotation(String stsTypeName) {
        TypeReferenceContext stsTypeRef = typeReference(stsTypeName);
        return typeAnnotation(stsTypeRef);
    }

    public static ThrowsAnnotationContext throwsAnnotation(boolean isThrows) {
        ThrowsAnnotationContext stsThrowsAnno = new ThrowsAnnotationContext(null, 0);
        stsThrowsAnno.addChild(terminalIdentifier(isThrows ? StaticTSParser.THROWS : StaticTSParser.RETHROWS));

        return stsThrowsAnno;
    }

    public static ParameterContext parameter(String stsParamName, String stsParamType) {
        ParameterContext stsParam = new ParameterContext(null, 0);
        stsParam.addChild(terminalIdentifier(stsParamName));
        stsParam.addChild(typeAnnotation(stsParamType)).setParent(stsParam);
        return stsParam;
    }

    public static ParameterContext parameter(String stsParamName, ParserRuleContext stsParamType) {
        ParameterContext stsParam = new ParameterContext(null, 0);
        stsParam.addChild(terminalIdentifier(stsParamName));
        stsParam.addChild(typeAnnotation(stsParamType)).setParent(stsParam);
        return stsParam;
    }
    public static ConstructorCallContext ctorCall(boolean isSuperCall, String... stsArgNames) {
        List<SingleExpressionContext> stsArgs = new ArrayList<>();
        for (String stsArgName : stsArgNames) {
            stsArgs.add(identifierExpression(stsArgName));
        }

        return ctorCall(isSuperCall, false, stsArgs.toArray(new SingleExpressionContext[0]));
    }

    public static ConstructorCallContext ctorCall(boolean isSuperCall, boolean hasOuterObj,
                                                  SingleExpressionContext... stsArgs) {
        ConstructorCallContext stsSuperCtorCall = new ConstructorCallContext(null, 0);

        int argStartIndex = 0;
        if (isSuperCall) {
            if (hasOuterObj && stsArgs.length > 0) {
                stsSuperCtorCall.addChild(stsArgs[0]).setParent(stsSuperCtorCall);
                argStartIndex = 1;
            }

            stsSuperCtorCall.addChild(terminalNode(StaticTSParser.Super));
        }
        else
            stsSuperCtorCall.addChild(terminalNode(StaticTSParser.This));

        ArgumentsContext stsSuperCtorCallArgs = new ArgumentsContext(stsSuperCtorCall, 0);
        stsSuperCtorCall.addChild(stsSuperCtorCallArgs).setParent(stsSuperCtorCall);

        ExpressionSequenceContext stsExprSeq = new ExpressionSequenceContext(stsSuperCtorCallArgs, 0);
        stsSuperCtorCallArgs.addChild(stsExprSeq).setParent(stsSuperCtorCallArgs);

        for (int i = argStartIndex; i < stsArgs.length; ++i) {
            stsExprSeq.addChild(stsArgs[i]).setParent(stsExprSeq);
        }

        return stsSuperCtorCall;
    }
    public static TypeAnnotationContext unknownTypeAnnotation() {
        return typeAnnotation(UNKNOWN_TYPE_NAME);
    }

    protected static SingleExpressionContext dummyCall(String callName, String comment) {
        SingleExpressionContext stsExpression = new SingleExpressionContext(null, 0);
        CallExpressionContext stsCallExpression = new CallExpressionContext(stsExpression);
        stsExpression.addChild(stsCallExpression).setParent(stsExpression);

        SingleExpressionContext stsIdentifier = identifierExpression(callName);
        stsCallExpression.addChild(stsIdentifier).setParent(stsCallExpression);

        ArgumentsContext stsArguments = new ArgumentsContext(stsCallExpression, 0);
        stsCallExpression.addChild(stsArguments).setParent(stsCallExpression);

        // Create empty argument list and add trailing comment to it to make sure the comment
        // appears inside parentheses (see StaticTSWriter.visitArguments for details)
        ExpressionSequenceContext stsArgList = new ExpressionSequenceContext(stsArguments, 0);
        stsArguments.addChild(stsArgList).setParent(stsArguments);

        stsArgList.addTrailingComment(multiLineComment("/* " + comment + " */"));

        return stsExpression;
    }

    public static DummyContext dummyNode(String comment) {
        DummyContext stsDummyContext = new DummyContext(null, 0);
        stsDummyContext.addLeadingComment(multiLineComment("/* " + comment + " */"));
        return stsDummyContext;
    }
    public static boolean needStatementOrLocalDeclaration(ParserRuleContext stsContext) {
        return stsContext.getRuleIndex() == StaticTSParser.RULE_block
                || stsContext.getRuleIndex() == StaticTSParser.RULE_constructorBody;
    }

    public static void addArgument(CallExpressionContext stsCallExpr, SingleExpressionContext stsArg) {
        ArgumentsContext stsArgs = stsCallExpr.arguments();

        if (stsArgs != null) {
            ExpressionSequenceContext stsExprSeq = stsArgs.expressionSequence();
            if (stsExprSeq != null) {
                stsExprSeq.addChild(stsArg).setParent(stsExprSeq);
            }
        }
    }

    public static SingleExpressionContext thisExpression(TypeReferenceContext stsTypeRef) {
        SingleExpressionContext stsSingleExpr = new SingleExpressionContext(null, 0);
        ThisExpressionContext stsThisExpression = new ThisExpressionContext(stsSingleExpr);
        stsSingleExpr.addChild(stsThisExpression).setParent(stsSingleExpr);

        if (stsTypeRef != null) {
            stsThisExpression.addChild(stsTypeRef).setParent(stsThisExpression);
        }

        stsThisExpression.addChild(terminalNode(StaticTSParser.This));

        return stsSingleExpr;
    }

    public static SingleExpressionContext superExpression(TypeReferenceContext stsTypeRef) {
        SingleExpressionContext stsSingleExpr = new SingleExpressionContext(null, 0);
        SuperExpressionContext stsThisExpression = new SuperExpressionContext(stsSingleExpr);
        stsSingleExpr.addChild(stsThisExpression).setParent(stsSingleExpr);

        if (stsTypeRef != null) {
            stsThisExpression.addChild(stsTypeRef).setParent(stsThisExpression);
        }

        stsThisExpression.addChild(terminalNode(StaticTSParser.This));

        return stsSingleExpr;
    }

    public static SingleExpressionContext classLiteral(String className) {
        // Sanity check
        if (className == null) return null;

        SingleExpressionContext stsSingleExpr = new SingleExpressionContext(null, 0);
        ClassLiteralExpressionContext stsClassLiteral = new ClassLiteralExpressionContext(stsSingleExpr);
        stsSingleExpr.addChild(stsClassLiteral).setParent(stsSingleExpr);

        // NOTE: Class literal requires PrimaryTypeContext!
        //     | primaryType Dot Class      # ClassLiteralExpression
        PrimaryTypeContext stsPrimaryType = new PrimaryTypeContext(stsClassLiteral, 0);
        stsPrimaryType.addChild(typeReference(className)).setParent(stsPrimaryType);
        stsClassLiteral.addChild(stsPrimaryType).setParent(stsClassLiteral);

        stsClassLiteral.addChild(terminalNode(StaticTSParser.Dot));
        stsClassLiteral.addChild(terminalNode(StaticTSParser.Class));

        return stsSingleExpr;
    }

    public static boolean isTypeArgument(ParserRuleContext stsType) {
        return stsType.getRuleIndex() == StaticTSParser.RULE_arrayType ||
               stsType.getRuleIndex() == StaticTSParser.RULE_typeReference ||
               stsType.getRuleIndex() == StaticTSParser.RULE_wildcardType;
    }

    public static StatementContext expressionStatement(SingleExpressionContext stsSingleExpr) {
        ExpressionStatementContext stsExprStmt = new ExpressionStatementContext(null, 0);
        stsExprStmt.addChild(stsSingleExpr).setParent(stsExprStmt);
        StatementContext stsStmt = new StatementContext(null, 0);
        stsStmt.addChild(stsExprStmt).setParent(stsStmt);

        return stsStmt;
    }
}
