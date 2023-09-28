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

package com.ohos.migrator.java;

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.staticTS.NodeBuilderBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.eclipse.jdt.core.dom.*;

import java.util.List;

public class NodeBuilder extends NodeBuilderBase {
    private static final String UNTRANSLATED_TRY_RESOURCE = "__untranslated_try_resource";

    public static TerminalNode terminalIdentifier(SimpleName name) {
        return terminalIdentifier(name.getIdentifier());
    }

    public static QualifiedNameContext qualifiedName(Name javaName) {
        return qualifiedName(javaName.getFullyQualifiedName());
    }

    private static String stsPredefinedTypeName(PrimitiveType.Code javaPrimitiveTypeCode) {
        String stsTypeName = null;

        if (javaPrimitiveTypeCode == PrimitiveType.BOOLEAN)
            stsTypeName = StaticTSParser.BOOLEAN;
        else if (javaPrimitiveTypeCode == PrimitiveType.BYTE)
            stsTypeName = StaticTSParser.BYTE;
        else if (javaPrimitiveTypeCode == PrimitiveType.CHAR)
            stsTypeName = StaticTSParser.CHAR;
        else if (javaPrimitiveTypeCode == PrimitiveType.INT)
            stsTypeName = StaticTSParser.INT;
        else if (javaPrimitiveTypeCode == PrimitiveType.DOUBLE)
            stsTypeName = StaticTSParser.DOUBLE;
        else if (javaPrimitiveTypeCode == PrimitiveType.FLOAT)
            stsTypeName = StaticTSParser.FLOAT;
        else if (javaPrimitiveTypeCode == PrimitiveType.LONG)
            stsTypeName = StaticTSParser.LONG;
        else if (javaPrimitiveTypeCode == PrimitiveType.SHORT)
            stsTypeName = StaticTSParser.SHORT;
        else if (javaPrimitiveTypeCode == PrimitiveType.VOID)
            stsTypeName = StaticTSParser.VOID;

        return stsTypeName;
    }

    public static PredefinedTypeContext predefinedType(PrimitiveType.Code javaPrimitiveTypeCode) {
        // predefinedType -> TerminalNode<TypeName>
        String stsTypeName = stsPredefinedTypeName(javaPrimitiveTypeCode);
        if (stsTypeName == null) return null; // The caller is responsible for handling this properly.

        PredefinedTypeContext stsPredefinedType = new PredefinedTypeContext(null, 0);
        stsPredefinedType.addChild(terminalIdentifier(stsTypeName));
        return stsPredefinedType;
    }

    public static AccessibilityModifierContext accessibilityModifier(int javaModifiers) {
        int stsModifierCode = -1;
        if ((javaModifiers & Modifier.PRIVATE) != 0)
            stsModifierCode = StaticTSParser.Private;
        else if ((javaModifiers & Modifier.PROTECTED) != 0)
            stsModifierCode = StaticTSParser.Protected;
        else if ((javaModifiers & Modifier.PUBLIC) != 0)
            stsModifierCode = StaticTSParser.Public;

        if (stsModifierCode == -1) return null;

        AccessibilityModifierContext stsAccessMod = new AccessibilityModifierContext(null, 0);
        stsAccessMod.addChild(terminalNode(stsModifierCode));
        return stsAccessMod;
    }

    // Java:
    //   QualifiedType: Type . { Annotation } SimpleName
    //   SimpleType: { Annotation } TypeName
    // STS:
    //   typeReference: typeReferencePart ('.' typeReferencePart)*
    //   typeReferencePart: qualifiedName typeArguments?
    /*
    public static TypeReferenceContext typeReference(PrimitiveType javaPrimitiveType) {
        PrimitiveType.Code javaPrimitiveTypeCode = javaPrimitiveType.getPrimitiveTypeCode();
        TypeReferenceContext stsTypeReference = new TypeReferenceContext(null, 0);
        stsTypeReference.addChild(qualifiedName(stsName(stsPredefinedTypeName(javaPrimitiveTypeCode)))).setParent(stsTypeReference);
        return stsTypeReference;
    }
    public static TypeReferenceContext typeReference(String stsQualifierText, Name javaName) {
        String typeFQN = stsQualifierText + '.' + javaName.getFullyQualifiedName();

        TypeReferenceContext stsTypeReference = new TypeReferenceContext(null, 0);
        stsTypeReference.addChild(qualifiedName(typeFQN)).setParent(stsTypeReference);
        return stsTypeReference;
    }
     */
    public static AssignmentOperatorContext assignmentOperator(Assignment.Operator javaAssignOp) {
        int stsOperatorCode = -1;

        if (javaAssignOp == Assignment.Operator.PLUS_ASSIGN)
            stsOperatorCode = StaticTSParser.PlusAssign;
        else if (javaAssignOp == Assignment.Operator.MINUS_ASSIGN)
            stsOperatorCode = StaticTSParser.MinusAssign;
        else if (javaAssignOp == Assignment.Operator.TIMES_ASSIGN)
            stsOperatorCode = StaticTSParser.MultiplyAssign;
        else if (javaAssignOp == Assignment.Operator.DIVIDE_ASSIGN)
            stsOperatorCode = StaticTSParser.DivideAssign;
        else if (javaAssignOp == Assignment.Operator.BIT_AND_ASSIGN)
            stsOperatorCode = StaticTSParser.BitAndAssign;
        else if (javaAssignOp == Assignment.Operator.BIT_OR_ASSIGN)
            stsOperatorCode = StaticTSParser.BitOrAssign;
        else if (javaAssignOp == Assignment.Operator.BIT_XOR_ASSIGN)
            stsOperatorCode = StaticTSParser.BitXorAssign;
        else if (javaAssignOp == Assignment.Operator.REMAINDER_ASSIGN)
            stsOperatorCode = StaticTSParser.ModulusAssign;
        else if (javaAssignOp == Assignment.Operator.LEFT_SHIFT_ASSIGN)
            stsOperatorCode = StaticTSParser.LeftShiftArithmeticAssign;
        else if (javaAssignOp == Assignment.Operator.RIGHT_SHIFT_SIGNED_ASSIGN)
            stsOperatorCode = StaticTSParser.RightShiftArithmeticAssign;
        else if (javaAssignOp == Assignment.Operator.RIGHT_SHIFT_UNSIGNED_ASSIGN)
            stsOperatorCode = StaticTSParser.RightShiftLogicalAssign;

        if (stsOperatorCode == -1) return null;

        AssignmentOperatorContext stsAssignOp = new AssignmentOperatorContext(null, 0);
        stsAssignOp.addChild(terminalNode(stsOperatorCode));
        return stsAssignOp;
    }

    public static void addExtraDimensions(ParserRuleContext stsCurrent, int extraDims) {
        assert(stsCurrent instanceof TypeAnnotationContext && extraDims > 0);

        PrimaryTypeContext stsPrimaryType = ((TypeAnnotationContext)stsCurrent).primaryType();
        ArrayTypeContext stsArrayType = stsPrimaryType.arrayType();
        if (stsArrayType == null) {
            // Should be either a type reference or predefined type.
            ParserRuleContext stsType = stsPrimaryType.typeReference();
            if (stsType == null) stsType = stsPrimaryType.predefinedType();
            assert(stsType != null);

            // Drop the type which we just extracted above.
            stsPrimaryType.removeLastChild();

            // Construct new ArrayTypeContext and link it up to PrimaryTypeContext.
            stsArrayType = new ArrayTypeContext(stsPrimaryType, 0);
            stsArrayType.addChild(stsType).setParent(stsArrayType);
            stsPrimaryType.addChild(stsArrayType);
        }

        for (int i = 0; i < extraDims; ++i) {
            stsArrayType.addChild(terminalNode(StaticTSParser.OpenBracket));
            stsArrayType.addChild(terminalNode(StaticTSParser.CloseBracket));
        }
    }

    public static ParameterContext parameter(String stsParamName, PrimitiveType.Code javaPrimitiveTypeCode) {
        ParameterContext stsParam = new ParameterContext(null, 0);
        stsParam.addChild(terminalIdentifier(stsParamName));

        ParserRuleContext stsParamType = predefinedType(javaPrimitiveTypeCode);
        if (stsParamType == null) stsParamType = unknownTypeReference("/* " + javaPrimitiveTypeCode.toString() + " */");

        stsParam.addChild(typeAnnotation(stsParamType)).setParent(stsParam);
        return stsParam;
    }

    public static TypeAnnotationContext unknownTypeAnnotation(Type javaType) {
        TypeAnnotationContext stsTypeAnnotation = unknownTypeAnnotation();

        if (javaType != null) {
            stsTypeAnnotation.addTrailingComment(multiLineComment("/* " + javaType.toString() + " */"));
        }

        return stsTypeAnnotation;
    }

    public static TypeAnnotationContext unknownTypeAnnotation(ITypeBinding javaTypeBinding) {
        TypeAnnotationContext stsTypeAnnotation = unknownTypeAnnotation();

        if (javaTypeBinding != null) {
            stsTypeAnnotation.addTrailingComment(multiLineComment("/* " + javaTypeBinding.getName() + " */"));
        }

        return stsTypeAnnotation;
    }

    public static SingleExpressionContext untranslatedExpression(ASTNode node) {
        return dummyCall(UNTRANSLATED_EXPRESSION, node.toString());
    }

    public static ParserRuleContext untranslatedStatement(ASTNode node, ParserRuleContext stsContext) {
        StatementContext stsStatement = new StatementContext(null, 0);
        ExpressionStatementContext stsExprStatement = new ExpressionStatementContext(stsStatement, 0);
        stsStatement.addChild(stsExprStatement);
        stsExprStatement.addChild(dummyCall(UNTRANSLATED_STATEMENT, node.toString())).setParent(stsExprStatement);

        if (needStatementOrLocalDeclaration(stsContext)) {
            StatementOrLocalDeclarationContext stsStmtOrLocalDecl = new StatementOrLocalDeclarationContext(null, 0);
            stsStmtOrLocalDecl.addChild(stsStatement).setParent(stsStmtOrLocalDecl);
            return stsStmtOrLocalDecl;
        }

        return stsStatement;
    }

    public static ParserRuleContext untranslatedTryResource(ASTNode node, ParserRuleContext stsContext) {
        StatementContext stsStatement = new StatementContext(null, 0);
        ExpressionStatementContext stsExprStatement = new ExpressionStatementContext(stsStatement, 0);
        stsStatement.addChild(stsExprStatement);
        stsExprStatement.addChild(dummyCall(UNTRANSLATED_TRY_RESOURCE, node.toString())).setParent(stsExprStatement);

        if (needStatementOrLocalDeclaration(stsContext)) {
            StatementOrLocalDeclarationContext stsStmtOrLocalDecl = new StatementOrLocalDeclarationContext(null, 0);
            stsStmtOrLocalDecl.addChild(stsStatement).setParent(stsStmtOrLocalDecl);
            return stsStmtOrLocalDecl;
        }

        return stsStatement;
    }

    public static ShiftOperatorContext shiftOperator(InfixExpression.Operator javaOp) {
        ShiftOperatorContext stsShiftOp = new ShiftOperatorContext(null, 0);

        if (javaOp == InfixExpression.Operator.LEFT_SHIFT) {
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.LessThan));
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.LessThan));
        }
        else if (javaOp == InfixExpression.Operator.RIGHT_SHIFT_SIGNED) {
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
        }
        else if (javaOp == InfixExpression.Operator.RIGHT_SHIFT_UNSIGNED) {
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            stsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
        }

        return stsShiftOp;
    }

    public static ParserRuleContext translateTypeBinding(ITypeBinding javaTypeBinding) {
        if (javaTypeBinding.isPrimitive()) {
            String javaTypeName = javaTypeBinding.getName();
            return predefinedType(javaTypeName);
        }

        if (javaTypeBinding.isArray()) {
            ITypeBinding javaArrayElemType = javaTypeBinding.getElementType();
            ParserRuleContext stsArrayElemType = translateTypeBinding(javaArrayElemType);
            return arrayType(stsArrayElemType, javaTypeBinding.getDimensions());
        }

        if (javaTypeBinding.isParameterizedType()) {
            ITypeBinding javaErasedType = javaTypeBinding.getErasure();
            ParserRuleContext stsType = translateTypeBinding(javaErasedType);
            if (stsType.getRuleIndex() != StaticTSParser.RULE_typeReference) {
                stsType = unknownTypeReference(javaErasedType.getQualifiedName());
            }

            // Translate type arguments and inject them into last child of TypeReferenceContext node
            TypeReferencePartContext stsLastTypePart = (TypeReferencePartContext)stsType.getChild(stsType.getChildCount()-1);
            TypeArgumentsContext stsTypeArgs = translateTypeArguments(javaTypeBinding.getTypeArguments());
            stsLastTypePart.addChild(stsTypeArgs).setParent(stsLastTypePart);
            return stsType;
        }

        if (javaTypeBinding.isWildcardType()) {
            WildcardTypeContext stsWildCardType = new WildcardTypeContext(null, 0);
            ITypeBinding javaBoundType = javaTypeBinding.getBound();
            if (javaBoundType != null) {
                String stsInOrOutKeyword = javaTypeBinding.isUpperbound() ? StaticTSParser.OUT : StaticTSParser.IN;
                stsWildCardType.addChild(terminalIdentifier(stsInOrOutKeyword));
                ParserRuleContext stsBoundType = translateTypeBinding(javaBoundType);
                stsWildCardType.addChild(stsBoundType).setParent(stsWildCardType);
            }
            else {
                stsWildCardType.addChild(terminalIdentifier(StaticTSParser.OUT));
            }
            return stsWildCardType;
        }

        if (javaTypeBinding.isIntersectionType()) {
            IntersectionTypeContext stsIntersectionType = new IntersectionTypeContext(null, 0);
            for (ITypeBinding javaIntersectedType : javaTypeBinding.getTypeBounds()) {
                ParserRuleContext stsIntersectedType = translateTypeBinding(javaIntersectedType);
                stsIntersectionType.addChild(stsIntersectedType).setParent(stsIntersectionType);
            }

            return stsIntersectionType;
        }

        // All other types should be named - just emit TypeReferenceContext
        String javaTypeName = javaTypeBinding.getQualifiedName();
        String javaFQType = javaTypeName;
        if (javaTypeName.startsWith("java.lang.")) {
            javaTypeName = javaTypeName.substring("java.lang.".length());
        }

        TypeReferenceContext stsTypeRef = typeReference(javaTypeName);
        addEmptyTypeArgumentsToRawType(stsTypeRef, javaTypeBinding);
        fillMapperMatchAtributs(stsTypeRef, javaTypeBinding);

        return stsTypeRef;
    }

    private static void addEmptyTypeArgumentsToRawType(TypeReferenceContext stsTypeRef, ITypeBinding javaTypeBinding) {
        if (javaTypeBinding != null && javaTypeBinding.isRawType()) {
            TypeReferencePartContext stsLastTypePart = (TypeReferencePartContext) stsTypeRef.getChild(stsTypeRef.getChildCount() - 1);
            stsLastTypePart.addChild(new TypeArgumentsContext(stsLastTypePart, 0)).setParent(stsLastTypePart);
        }
    }

    public static void addEmptyTypeArgumentsToRawType(TypeReferenceContext stsTypeRef, Type javaType) {
        ITypeBinding javaTypeBinding = getTypeBinding(javaType);
        addEmptyTypeArgumentsToRawType(stsTypeRef, javaTypeBinding);
    }

    public static TypeArgumentsContext translateTypeArguments(ITypeBinding[] javaTypeArgs) {
        TypeArgumentsContext stsTypeArgs = new TypeArgumentsContext(null, 0);

        if (javaTypeArgs != null) {
            TypeArgumentListContext stsTypeArgList = new TypeArgumentListContext(stsTypeArgs, 0);
            stsTypeArgs.addChild(stsTypeArgList).setParent(stsTypeArgs);

            for (ITypeBinding javaTypeArg : javaTypeArgs) {
                ParserRuleContext stsTypeArg = translateTypeBinding(javaTypeArg);
                if (!isTypeArgument(stsTypeArg)) stsTypeArg = unknownTypeReference(null);

                TypeArgumentContext stsTypeArgNode = new TypeArgumentContext(stsTypeArgList, 0);
                stsTypeArgNode.addChild(stsTypeArg).setParent(stsTypeArgNode);
                stsTypeArgList.addChild(stsTypeArgNode).setParent(stsTypeArgList);
            }
        }

        return stsTypeArgs;
    }

    public static boolean isTypeArgument(Type javaType) {
        return isTypeReference(javaType) || javaType.isArrayType() || javaType.isWildcardType();
    }

    public static boolean isTypeReference(Type javaType) {
        return javaType.isSimpleType() || javaType.isQualifiedType() ||
               javaType.isNameQualifiedType() || javaType.isParameterizedType();
    }

    public static ITypeBinding getTypeBinding(Type javaType) {
        // Type.resolveBinding() can throw exceptions, so let's catch them
        ITypeBinding javaTypeBinding;
        try {
            javaTypeBinding = javaType.resolveBinding();
        }
        catch (Exception e) {
            javaTypeBinding = null;
        }

        return javaTypeBinding;
    }

    private static StringBuilder sbForApiMapper = new StringBuilder();

    public static void fillMapperMatchAtributs(TypeReferenceContext stsTypeRef, ITypeBinding javaTypeBinding) {
        if (javaTypeBinding != null) {
            // getQualifiedName() method returns the name with type argument names. So use getBinaryName to get the name
            // without type arguments names.
            //stsTypeRef.javaType     = javaTypeBinding.getQualifiedName();
            stsTypeRef.javaType     = javaTypeBinding.getBinaryName();
            stsTypeRef.javaTypeArgs = buildTypeArgsSignature(javaTypeBinding.getTypeArguments());
        }
    }

    public static TypeReferenceContext typeReference(String typeName, ITypeBinding javaTypeBinding) {
        TypeReferenceContext stsTypeRef = NodeBuilderBase.typeReference(typeName);
        fillMapperMatchAtributs(stsTypeRef, javaTypeBinding);
        addEmptyTypeArgumentsToRawType(stsTypeRef, javaTypeBinding);
        return stsTypeRef;
    }

    public static String buildTypeArgsSignature(ITypeBinding typeArguments[]) {
        if (typeArguments != null) {
            sbForApiMapper.setLength(0);

            for (ITypeBinding typeArgument : typeArguments) {
                sbForApiMapper.append(typeArgument.getQualifiedName()).append(',');
            }

            if (sbForApiMapper.length() > 0) {
                return sbForApiMapper.substring(0, sbForApiMapper.length() - 1); // Remove the ending extra comma.
            }
        }

        return null;
    }

    public static String buildTypeArgsSignature(List<Type> javaTypeArgs, String srcFilePath) {
        if (javaTypeArgs != null && !javaTypeArgs.isEmpty()) {
            sbForApiMapper.setLength(0); // Clear the string builder.

            for (Type javaTypeArg : javaTypeArgs) {
                ITypeBinding javaTypeBinding = javaTypeArg.resolveBinding();

                if (javaTypeBinding != null) {
                    sbForApiMapper.append(javaTypeBinding.getQualifiedName());
                }
                else {
                    ASTNode javaRoot = javaTypeArg.getRoot();
                    if (javaRoot instanceof CompilationUnit) {
                        CompilationUnit javaCU = (CompilationUnit)javaRoot;

                        String loc = srcFilePath + ":" + javaCU.getLineNumber(javaTypeArg.getStartPosition());
                        Main.addError(ResultCode.TranspileError, "Fail to resolve type at " + loc);
                    }
                }

                sbForApiMapper.append(',');
            }

            if (sbForApiMapper.length() > 1) {
                return sbForApiMapper.substring(0, sbForApiMapper.length() - 1); // Remove the ending extra comma.
            }
        }

        return null;
    }
}
