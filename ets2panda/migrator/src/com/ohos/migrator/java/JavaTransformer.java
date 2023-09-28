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
import com.ohos.migrator.Transformer;
import com.ohos.migrator.staticTS.NodeBuilderBase;
import com.ohos.migrator.staticTS.parser.StaticTSContextBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.eclipse.jdt.core.dom.*;

import java.io.File;
import java.util.*;

/**
 * Performs transformation of the Java AST (Eclipse JDT AST) into StaticTS AST.
 */
public class JavaTransformer extends ASTVisitor implements Transformer {
    private final CompilationUnit javaCU;

    private final char[] javaSource;
    private CompilationUnitContext stsCU;
    private final File srcFile;
    private ParserRuleContext stsCurrent;

    private LinkedList<Comment> javaComments = new LinkedList<>();
    private final Stack<ParserRuleContext> stsSaved = new Stack<>();
    private final Stack<TryStatementContext> stsCurrentTryStatement = new Stack<>();

    // 'nested' methods may be declared through the local classes,
    // so the list of collected exceptions for the 'outer' method might get mixed
    // with exceptions of the method of 'nested' class so use stack
    private final Stack<Set<ITypeBinding>> javaThrownExceptions = new Stack<>();
    private final String INIT_THROWN_EXEPTIONS = "INIT_THROWN_EXCEPTIONS";
    private final String INSTANCE_INITIALIZER = "INSTANCE_INITIALIZER";
    private final String USED_IN_ANOTHER_CASE_CLAUSE = "USED_IN_ANOTHER_CASE_CLAUSE";
    private final String ENUM_TYPE_NAME = "ENUM_TYPE_NAME";
    private final String ENUM_CONST_ORDINAL = "ENUM_CONST_ORDINAL";
    private final String OUTER_OBJECT = "OUTER_OBJECT";
    private final String CTOR_ARGUMENTS = "CTOR_ARGUMENTS";

    private final String LEADING_COMMENTS = "LEADING_COMMENTS";
    private final String TRAILING_COMMENT = "TRAILING_COMMENT";
    private final String RUNTIME_EXCEPTION_TYPE_NAME = "java.lang.RuntimeException";
    private final String THROWABLE_TYPE_NAME = "java.lang.Throwable";
    private final String METHOD_REF_PARAM_PREFIX = "__migrator_lambda_param_";

    private final ITypeBinding RUNTIME_EXCEPTION_TYPE;
    private final ITypeBinding THROWABLE_TYPE;

    private static int countStmtTotal = 0;
    private static int countExprTotal = 0;
    private static int countDeclTotal = 0;
    private static int countTypeTotal = 0;
    private static int countStmtTransformed = 0;
    private static int countExprTransformed = 0;
    private static int countDeclTransformed = 0;
    private static int countTypeTransformed = 0;

    private final Set<ASTNode> exprTransformed = new HashSet<>();
    private final Set<ASTNode> stmtTransformed = new HashSet<>();
    private final Set<ASTNode> declTransformed = new HashSet<>();

    private final Set<ASTNode> typeTransformed = new HashSet<>();

    private final Map<String, String> importAliasMap = new HashMap<>();
    public static double getTransformationRate() {
        if (Main.isVerboseMode()) {
            System.out.println("Statements: " + countStmtTransformed + " out of " + countStmtTotal +
            " (" + String.format("%.1f", countStmtTransformed / (double)countStmtTotal * 100) + "%)");
            System.out.println("Expressions: " + countExprTransformed + " out of " + countExprTotal +
            " (" + String.format("%.1f", countExprTransformed / (double)countExprTotal * 100) + "%)");
            System.out.println("Declarations: " + countDeclTransformed + " out of " + countDeclTotal +
            " (" + String.format("%.1f", countDeclTransformed / (double)countDeclTotal * 100) + "%)");
            System.out.println("Types: " + countTypeTransformed + " out of " + countTypeTotal +
            " (" + String.format("%.1f", countTypeTransformed / (double)countTypeTotal * 100) + "%)");

        }

        int countTotal = countStmtTotal + countExprTotal + countDeclTotal + countTypeTotal;
        int countTransformed = countStmtTransformed + countExprTransformed + countDeclTransformed + countTypeTransformed;
        return countTransformed / (double)countTotal;
    }

    private TryStatementContext getCurrentTry() { return stsCurrentTryStatement.isEmpty() ? null : stsCurrentTryStatement.peek(); }

    /**
     * Push node onto stack and add it to the children of
     * the current top node.
     */
    private void pushCurrent(ParserRuleContext stsNewCurrent) {
        pushCurrent(stsNewCurrent, true);
    }

    /**
     * Push node onto stack and optionally add it to the children
     * of the current top node.
     * @param addToChildren indicates whether to add a node as a child
     *                      of current top node.
     */
    private void pushCurrent(ParserRuleContext stsNewCurrent, boolean addToChildren) {
        stsSaved.push(stsCurrent);

        if (stsCurrent != null && addToChildren)
            stsCurrent.addChild(stsNewCurrent).setParent(stsCurrent);

        stsCurrent = stsNewCurrent;
    }

    private void popCurrent() {
        assert (!stsSaved.empty());
        stsCurrent = stsSaved.pop();
    }

    // Entering each method create set of exceptions this method may throw
    // If exception is caught inside method remove it from set
    private void pushExceptionSet() {
        Set<ITypeBinding> excpSet = new HashSet<>();
        javaThrownExceptions.push( excpSet );
    }

    private void popExceptionSet() {
        javaThrownExceptions.pop();
    }

    private boolean checkThrownExceptionSet(ASTNode javaNode) {
        if( javaThrownExceptions.isEmpty()) {
            reportError("Not initialized exception set", javaNode);
            return false;
        }
        return true;
    }
    private Set<ITypeBinding> currentExceptionsSet(ASTNode javaNode) {
        if( checkThrownExceptionSet(javaNode))
            return javaThrownExceptions.peek();
        else
            return new HashSet<ITypeBinding>();
    }
    private void addThrownException(ITypeBinding e) {
        // java runtime exceptions transform into STS panics not exceptions
        // so exclude them
        if( (e != null) && !isRuntimeExceptionType(e) )
            javaThrownExceptions.peek().add(e);
    }

    private void addMultipleThrownExceptions( ITypeBinding[] e) {
        for( ITypeBinding excp : e)
            addThrownException(excp);
    }

    private void removeThrownException(ITypeBinding e) {
        Set<ITypeBinding> javaExceptionSet =  javaThrownExceptions.peek();
        // use Iterator due to bad design of Java collections!
        Iterator iterator = javaThrownExceptions.peek().iterator();
        while( iterator.hasNext()) {
            // check if catch superclass for exception
            ITypeBinding exception = (ITypeBinding) iterator.next();
            if( exception.isSubTypeCompatible(e))
                iterator.remove();
        }
        javaThrownExceptions.peek().remove(e);
    }

    private void pushStatement(ParserRuleContext stsStatement) {
        if (NodeBuilder.needStatementOrLocalDeclaration(stsCurrent))
            pushCurrent(new StatementOrLocalDeclarationContext(stsCurrent, 0));

        pushCurrent(new StatementContext(stsCurrent, 0));
        pushCurrent(stsStatement);
    }

    private void popStatement() {
        popCurrent(); // real statement.
        popCurrent(); // StatementContext

        if (stsCurrent.getRuleIndex() == StaticTSParser.RULE_statementOrLocalDeclaration)
            popCurrent(); // StatementOrLocalDeclarationContext
    }

    private SingleExpressionContext pushSingleExpression() {
        SingleExpressionContext stsSingleExpression = new SingleExpressionContext();
        pushCurrent(stsSingleExpression);
        return stsSingleExpression;
    }

    private void popSingleExpression() {
        popCurrent(); // real expression node
        popCurrent(); // SingleExpressionContext - a wrapper of the real expression node.
    }

    private IterationStatementContext pushIterationStatement() {
        IterationStatementContext stsIterStmt = new IterationStatementContext(stsCurrent, 0);
        pushStatement(stsIterStmt);
        return stsIterStmt;
    }

    private void popIterationStatement() {
        popCurrent(); // Real loop statement
        popStatement(); // IterationStatement, StatementContext
    }

    public JavaTransformer(CompilationUnit javaCU, char[] javaSource, File srcFile) {
        this.javaCU = javaCU;
        this.srcFile = srcFile;
        this.javaSource = javaSource;
        AST javaAST = this.javaCU.getAST();
        RUNTIME_EXCEPTION_TYPE = javaAST.resolveWellKnownType(RUNTIME_EXCEPTION_TYPE_NAME);
        THROWABLE_TYPE = javaAST.resolveWellKnownType(THROWABLE_TYPE_NAME);
    }

    public CompilationUnitContext transform() {
        if (Main.isConvRateMode()) {
            // Compute total counts of statements, expressions, declarations
            // and types in Java AST that we expect to transform. This is used
            // in conversion rate computation.
            javaCU.accept(new ASTVisitor() {
                @Override
                public void postVisit(ASTNode node) {
                    if (node instanceof Expression &&
                            !(node instanceof Annotation) &&
                            // names are translated manually by and large,
                            // almost never by accept, so it's hard to count
                            // them properly. Assume we handle them all and ignore.
                            !(node instanceof Name) &&
                            // if array creation node has array initializer,
                            // we translate only the latter.
                            (node.getNodeType() != ASTNode.ARRAY_CREATION ||
                                ((ArrayCreation)node).getInitializer() == null) &&
                            node.getNodeType() != ASTNode.SWITCH_EXPRESSION &&
                            node.getNodeType() != ASTNode.TEXT_BLOCK)
                        ++countExprTotal;
                    else if (node instanceof Statement &&
                            node.getNodeType() != ASTNode.YIELD_STATEMENT)
                        ++countStmtTotal;
                    else if ((node instanceof BodyDeclaration
                                && node.getNodeType() != ASTNode.ANNOTATION_TYPE_DECLARATION
                                && node.getNodeType() != ASTNode.ANNOTATION_TYPE_MEMBER_DECLARATION)
                            || node instanceof VariableDeclaration
                            || node.getNodeType() == ASTNode.ANONYMOUS_CLASS_DECLARATION
                            || node.getNodeType() == ASTNode.IMPORT_DECLARATION
                            || node.getNodeType() == ASTNode.PACKAGE_DECLARATION)
                        ++countDeclTotal;
                    else if (node instanceof Type && node.getNodeType() != ASTNode.UNION_TYPE)
                        ++countTypeTotal;
                }

                // NOTE: The following AST nodes are not intended to be visited at the moment!
                @Override
                public boolean visit(MarkerAnnotation node) {
                    return false;
                }

                @Override
                public boolean visit(NormalAnnotation node) {
                    return false;
                }

                @Override
                public boolean visit(SingleMemberAnnotation node) {
                    return false;
                }

                @Override
                public boolean visit(SwitchExpression node) {
                    return false;
                }

                @Override
                public boolean visit(TextBlock node) {
                    return false;
                }

                @Override
                public boolean visit(YieldStatement node) {
                    return false;
                }

                @Override
                public boolean visit(AnnotationTypeDeclaration node) {
                    return false;
                }

                @Override
                public boolean visit(AnnotationTypeMemberDeclaration node) {
                    return false;
                }

                @Override
                public boolean visit(UnionType node) {
                    return false;
                }

                // NOTE: The following AST nodes are being visited by JavaTransformer
                // but need special treatment.
                @Override
                public boolean visit(ArrayCreation node) {
                    // If initializer is present, it's the only child node that gets visited.
                    ArrayInitializer initializer = node.getInitializer();
                    if (initializer != null) {
                        initializer.accept(this);
                        return false;
                    }

                    // We don't visit ArrayType inside ArrayCreation node.
                    node.getType().getElementType().accept(this);

                    List<Expression> indices = node.dimensions();
                    for (Expression index : indices)
                        index.accept(this);

                    return false;
                }

                @Override
                public boolean visit(MethodDeclaration node) {
                    // We don't visit list of exceptions thrown.
                    Type rt = node.getReturnType2();
                    if (rt != null) rt.accept(this);

                    List<TypeParameter> typeParams = node.typeParameters();
                    for (TypeParameter typeParam : typeParams)
                        typeParam.accept(this);

                    List<SingleVariableDeclaration> params = node.parameters();
                    for (SingleVariableDeclaration param : params)
                        param.accept(this);

                    // We don't visit the block itself, only statements inside it.
                    visitBodyStatements(node.getBody());

                    return false;
                }

                private void visitBodyStatements(Block body) {
                    if (body != null) {
                        List<Statement> stmts = body.statements();
                        for (Statement stmt : stmts)
                            stmt.accept(this);
                    }
                }

                @Override
                public boolean visit(TryStatement node) {
                    // We don't visit the block itself, only statements inside it.
                    visitBodyStatements(node.getBody());

                    Block finallyBody = node.getFinally();
                    if (finallyBody != null) finallyBody.accept(this);

                    List<CatchClause> catches = node.catchClauses();
                    for (CatchClause catchClause : catches)
                        catchClause.accept(this);

                    List<Expression> resources = node.resources();
                    for (Expression resource : resources)
                        resource.accept(this);

                    return false;
                }

                @Override
                public boolean visit(CatchClause node) {
                    // We visit only exception type, and if it's a union type,
                    // we visit only its component types.
                    SingleVariableDeclaration exception = node.getException();
                    Type excType = exception.getType();
                    if (excType.isUnionType()) {
                        List<Type> componentTypes = ((UnionType)excType).types();
                        for (Type componentType : componentTypes)
                            componentType.accept(this);
                    }
                    else
                        excType.accept(this);

                    // We don't visit the block itself, only statements inside it.
                    visitBodyStatements(node.getBody());

                    return false;
                }

                @Override
                public boolean visit(LambdaExpression node) {
                    List<VariableDeclaration> params = node.parameters();
                    for (VariableDeclaration param : params)
                        param.accept(this);

                    ASTNode body = node.getBody();
                    if (body != null) {
                        // We don't visit the block itself, only statements inside it.
                        if (body.getNodeType() == ASTNode.BLOCK)
                            visitBodyStatements((Block)body);
                        else if (body instanceof Expression)
                            body.accept(this);
                    }

                    return false;
                }

                @Override
                public boolean visit(Initializer node) {
                    // We don't visit the block itself, only statements inside it.
                    visitBodyStatements(node.getBody());

                    return false;
                }

                @Override
                public boolean visit(SynchronizedStatement node) {
                    node.getExpression().accept(this);

                    // We don't visit the block itself, only statements inside it.
                    visitBodyStatements(node.getBody());

                    return false;
                }
            });
        }

        // Visit Java AST and construct StaticTS AST.
        javaCU.accept(this);

        if (Main.isConvRateMode()) {
            // Update transformed AST node counts.
            countStmtTransformed += stmtTransformed.size();
            countExprTransformed += exprTransformed.size();
            countDeclTransformed += declTransformed.size();
            countTypeTransformed += typeTransformed.size();
        }

        // If any unprocessed comments remain to this point
        // (which should only happen for empty source file),
        // add them to compilation unit before returning it.
        for (Comment javaComment: javaComments)
            stsCU.addLeadingComment(createCommentNode(javaComment));

        return stsCU;
    }

    @Override
    public void preVisit(ASTNode javaNode) {
        // Skip compilation unit - it starts at 0, anyway,
        // so no comments can be ahead of it.
        if (javaNode.getNodeType() == ASTNode.COMPILATION_UNIT)
            return;

        // Pick up all comments that we haven't processed yet
        // which are in front of the current AST node.
        int javaNodeStart = javaNode.getStartPosition();
        List<TerminalNode> stsLeadingComments = new LinkedList<>();
        while (!javaComments.isEmpty()) {
            Comment javaComment = javaComments.get(0);
            int javaCommentStart = javaComment.getStartPosition();

            if (javaCommentStart < javaNodeStart) {
                stsLeadingComments.add(createCommentNode(javaComment));
                javaComments.removeFirst();
            }
            else break;
        }

        // Hoist list of leading comments onto Java AST node for the moment.
        // We'll transfer it to STS AST node when we've created it.
        if (!stsLeadingComments.isEmpty())
            javaNode.setProperty(LEADING_COMMENTS, stsLeadingComments);

        // Skip comments inside current AST node.
        int i = 0;
        int javaNodeEnd = javaNodeStart + javaNode.getLength();
        while (i < javaComments.size()) {
            int javaCommentStart = javaComments.get(i).getStartPosition();
            if (javaCommentStart < javaNodeEnd)
                ++i;
            else break;
        }

        // Pick up the comment immediately after the current AST node if
        // intervening characters are all whitespace except line terminator.
        // If such comment exists, hoist it onto the Java AST node as well.
        if (i < javaComments.size()) {
            Comment javaComment = javaComments.get(i);
            int javaCommentStart = javaComment.getStartPosition();

            String space = new String(javaSource, javaNodeEnd, javaCommentStart - javaNodeEnd);
            if (space.isBlank() && !space.contains("\n")) {
                javaNode.setProperty(TRAILING_COMMENT, createCommentNode(javaComment));
                javaComments.remove(javaComment);
            }
        }
    }
    private TerminalNode createCommentNode(Comment javaComment) {
        int javaCommentLen = javaComment.getLength();
        int javaCommentStart = javaComment.getStartPosition();
        String javaCommentText = new String(javaSource, javaCommentStart, javaCommentLen);

        if (javaComment.isLineComment())
            return NodeBuilder.singleLineComment(javaCommentText);

        // Use multiline comment for JavaDoc comments, too
        return NodeBuilder.multiLineComment(javaCommentText);
    }

    private void transferComments(ASTNode javaNode, StaticTSContextBase stsNode) {
        // Transfer comments from Java AST node (if any) to
        // STS AST node, removing them from the former.
        Object propObject = javaNode.getProperty(LEADING_COMMENTS);
        if (propObject != null) {
            stsNode.setLeadingComments((List<TerminalNode>)propObject);
            javaNode.setProperty(LEADING_COMMENTS, null);
        }
        propObject = javaNode.getProperty(TRAILING_COMMENT);
        if (propObject != null) {
            stsNode.addTrailingComment((TerminalNode)propObject);
            javaNode.setProperty(TRAILING_COMMENT, null);
        }
    }
    @Override
    public void postVisit(ASTNode javaNode) {
        // Sanity check.
        ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount()-1);
        if (lastChild == null || !(lastChild instanceof StaticTSContextBase)) return;

        // Transfer leading (if any) from Java AST node to the STS AST node we just added
        StaticTSContextBase stsLastChild = (StaticTSContextBase)lastChild;
        Object propObj = javaNode.getProperty(LEADING_COMMENTS);
        if (propObj != null)
            stsLastChild.setLeadingComments((List<TerminalNode>)propObj);

        // Pick up all comments inside the current AST node that haven't been
        // picked up by its child nodes. Hopefully, this won't happen too often.
        int javaNodeEnd = javaNode.getStartPosition() + javaNode.getLength();
        while (!javaComments.isEmpty()) {
            Comment javaComment = javaComments.get(0);
            int javaCommentStart = javaComment.getStartPosition();

            if (javaCommentStart < javaNodeEnd) {
                stsLastChild.addTrailingComment(createCommentNode(javaComment));
                javaComments.removeFirst();
            }
            else break;
        }

        // Transfer trailing comment (if any).
        propObj = javaNode.getProperty(TRAILING_COMMENT);
        if (propObj != null)
            stsLastChild.addTrailingComment((TerminalNode)propObj);
    }

    @Override
    public boolean visit(CompilationUnit javaCU) {
        javaComments.addAll(javaCU.getCommentList());
        pushCurrent(stsCU = new CompilationUnitContext(null, 0));
        return true;
    }

    // Java src:
    //    PackageDeclaration
    //       TerminalNode <package>
    //       QualifiedName <com.ohos.migrator.tests.java>
    //           QualifiedName <com.ohos.migrator.tests>
    //              QualifiedName <com.ohos.migrator>
    //                  ...
    //              SimpleName <tests>
    //           SimpleName <java>
    //       TerminalNode <;>
    //
    // STS tree:
    //    PackageDeclarationContext
    //       TerminalNode <package>
    //       QualifiedNameContext
    //           TerminalNodes <com . ohos . migrator . tests . java>
    //       TerminalNode <;>
    @Override
    public boolean visit(PackageDeclaration javaPackageDeclaration) {
        pushCurrent(new PackageDeclarationContext(stsCU, 0));

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Package));
        stsCurrent.addChild(NodeBuilder.qualifiedName(javaPackageDeclaration.getName())).setParent(stsCurrent);

        popCurrent(); // PackageDeclarationContext

        declTransformed.add(javaPackageDeclaration);
        return false;
    }

    private void translateNonAccessModifiers(TypeDeclaration javaTypeDeclaration) {
        int javaModifiers = javaTypeDeclaration.getModifiers();

        // Abstract implies Open --> both modifiers are not permitted for a class.
        if ((javaModifiers & Modifier.ABSTRACT) != 0)
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Abstract));
        else if ((javaModifiers & Modifier.FINAL) == 0)
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Open));

        if ((javaModifiers & Modifier.STATIC) == 0 && javaTypeDeclaration.isMemberTypeDeclaration())
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Inner));
    }

    private boolean doesOverride(ITypeBinding javaClassBinding, IMethodBinding javaCheckedMethod) {
        if (javaClassBinding != null) {
            if (!javaClassBinding.isEqualTo(javaCheckedMethod.getDeclaringClass())) {
                for (IMethodBinding javaMethod : javaClassBinding.getDeclaredMethods()) {
                    if (javaCheckedMethod.overrides(javaMethod))
                        return true;
                }
            }

            for (ITypeBinding javaInterface : javaClassBinding.getInterfaces()) {
                if (doesOverride(javaInterface, javaCheckedMethod))
                    return true;
            }

            ITypeBinding javaSuperClassBinding = javaClassBinding.getSuperclass();
            if (javaSuperClassBinding != null)
                return doesOverride(javaSuperClassBinding, javaCheckedMethod);
        }

        return false;
    }

    private void translateNonAccessModifiers(MethodDeclaration javaMethodDeclaration, boolean isInClassContext) {
        int javaModifiers = javaMethodDeclaration.getModifiers();

        // A method may not have both Abstract and Open modifiers.
        if ((javaModifiers & Modifier.ABSTRACT) != 0)
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Abstract));
        else if ((javaModifiers & Modifier.FINAL) == 0) {
            // If the input (java) method is not final then output (STS) method has to be either Open or Override
            IMethodBinding javaMethodBinding = javaMethodDeclaration.resolveBinding();
            if (javaMethodBinding != null && doesOverride(javaMethodBinding.getDeclaringClass(), javaMethodBinding))
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Override));
            else if ((javaModifiers & Modifier.STATIC) == 0 && (javaModifiers & Modifier.PRIVATE) == 0 && isInClassContext)
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Open));
        }

        if ((javaModifiers & Modifier.STATIC) != 0) stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));
        if ((javaModifiers & Modifier.NATIVE) != 0) stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Native));
    }

    // Java tree:
    // TypeDeclaration: // A type declaration is the union of a class declaration and an interface declaration.
    //                ClassDeclaration
    //                InterfaceDeclaration
    // ClassDeclaration:
    //      [ Javadoc ] { ExtendedModifier } class Identifier
    //                        [ < TypeParameter { , TypeParameter } > ]
    //                        [ extends Type ]
    //                        [ implements Type { , Type } ]
    //                        [ permits Type { , Type } ]
    //                        { { ClassBodyDeclaration | ; } }
    // InterfaceDeclaration:
    //      [ Javadoc ] { ExtendedModifier } interface Identifier
    //                        [ < TypeParameter { , TypeParameter } > ]
    //                        [ extends Type { , Type } ]
    //                        [ permits Type { , Type } ]
    //                        { { InterfaceBodyDeclaration | ; } }
    //
    // STS tree for class declaration:
    //    topDeclarationContext
    //       Export?
    //       ClassDeclarationContext
    //          TerminalNode <(static? (abstract | open) | (abstract | open)? static)?> ?
    //          TerminalNode <class>
    //          TerminalNode <identifier>
    //          TypeParametersContext ?
    //          ClassExtendsClauseContext ?
    //          ImplementsClauseContext ?
    //          ClassBodyContext
    //              TerminalNode <{>
    //                  ClassMemberContext *
    //                  clinit = ClassInitializerContext ?
    //                  ClassMemberContext *
    //              TerminalNode <}>
    // STS tree for interface declaration:
    //    topDeclarationContext
    //       Export?
    //       InterfaceDeclarationContext
    //          TerminalNode <static> ?
    //          TerminalNode <interface>
    //          TerminalNode <identifier>
    //          TypeParametersContext ?
    //          InterfaceExtendsClauseContext ?
    //          TerminalNode <{>
    //             InterfaceBodyContext
    //                null
    //          TerminalNode <}>
    //
    @Override
    public boolean visit(TypeDeclaration javaTypeDeclaration) {
        // Create appropriate member context to put declaration into.
        int javaMods = javaTypeDeclaration.getModifiers();
        pushCurrent(createDeclarationOrMemberContextWithAccessModifier(javaMods));

        // Create class or interface declaration context and select appropriate keyword.
        int terminalCode = StaticTSParser.Class;

        if (javaTypeDeclaration.isInterface()) {
            pushCurrent(new InterfaceDeclarationContext(stsCurrent, 0));
            terminalCode = StaticTSParser.Interface;
        }
        else {
            pushCurrent(new ClassDeclarationContext(stsCurrent, 0));
        }

        // Add remaining (non-access modifiers) and class/interface keyword.
        translateNonAccessModifiers(javaTypeDeclaration);
        stsCurrent.addChild(NodeBuilder.terminalNode(terminalCode));

        // The name of the type declared in this type declaration.
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaTypeDeclaration.getName()));

        translateTypeParameters(javaTypeDeclaration.typeParameters());
        translateSuperclassType(javaTypeDeclaration.getSuperclassType());        // extends (not present for interface)
        translateSuperInterfaceTypes(javaTypeDeclaration.superInterfaceTypes()); // implements (extends for interface)

        if (javaTypeDeclaration.isInterface()) {
            pushCurrent(new InterfaceBodyContext(stsCurrent, 0));
        }
        else {
            pushCurrent(new ClassBodyContext(stsCurrent, 0));
        }

        // All type members are represented as body declarations.
        List<BodyDeclaration> javaBodyDeclarations = javaTypeDeclaration.bodyDeclarations();
        for (BodyDeclaration javaBodyDecl : javaBodyDeclarations) {
            javaBodyDecl.accept(this);
        }

        addInstanceInitializersToCtors(javaTypeDeclaration);

        popCurrent(); // InterfaceBodyContext or ClassBodyContext
        popCurrent(); // Interface/ClassDeclarationContext
        popCurrent(); // DeclarationOrMemberContext

        declTransformed.add(javaTypeDeclaration);
        return false;
    }

    private void translateSuperclassType(Type javaSuperClass) {
        if (javaSuperClass == null) return;

        // ClassExtendsClauseContext
        //    TerminalNode <extends>
        //    TypeReferenceContext
        //        QualifiedNameContext
        //            TerminalNode <ClassName>
        pushCurrent(new ClassExtendsClauseContext(stsCurrent, 0));

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.EXTENDS));
        javaSuperClass.accept(this);

        popCurrent(); // ClassExtendsClauseContext
    }

    private void translateSuperInterfaceTypes(List<Type> javaSuperInterfaceTypes) {
        if ((javaSuperInterfaceTypes == null) || javaSuperInterfaceTypes.isEmpty()) return;

        // ImplementsClauseContext
        //     TerminalNode <implements>
        //     InterfaceTypeListContext
        //         TypeReferenceContext
        //             QualifiedNameContext
        //                TerminalNode <ClassName>
        //         TerminalNode <,>
        //         TypeReferenceContext
        //             QualifiedNameContext
        //                TerminalNode <ClassName>
        if( stsCurrent instanceof InterfaceDeclarationContext) {
            pushCurrent(new InterfaceExtendsClauseContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.EXTENDS));
        }
        else {
            pushCurrent(new ImplementsClauseContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.IMPLEMENTS));
        }

        pushCurrent(new InterfaceTypeListContext(stsCurrent, 0));

        for (Type javaSuperInterfaceType : javaSuperInterfaceTypes) {
            javaSuperInterfaceType.accept(this);
        }

        popCurrent(); // InterfaceTypeListContext
        popCurrent(); // ImplementsClauseContext
    }

    private void translateTypeParameters(List<TypeParameter> javaTypeParameters) {
        if (javaTypeParameters == null || javaTypeParameters.isEmpty()) return;

        pushCurrent(new TypeParametersContext(stsCurrent, 0));
        pushCurrent(new TypeParameterListContext(stsCurrent, 0));

        for (TypeParameter javaTypeParam : javaTypeParameters) {
            javaTypeParam.accept(this);
        }

        popCurrent(); // TypeParameterListContext
        popCurrent(); // TypeParametersContext
    }

    // Java tree:
    //      TypeParameter:  { ExtendedModifier } Identifier [ extends Type { & Type } ]
    // STS tree:
    //      typeParameter: Identifier constraint?;
    //      constraint: Extends (typeReference | intersectionType);
    //      typeReference: typeReferencePart (Dot typeReferencePart)*
    //          typeReferencePart: qualifiedName typeArguments?
    //          typeArguments: LessThan typeArgumentList? MoreThan
    //      intersectionType: OpenParen typeReference (BitAnd typeReference)+ CloseParen
    @Override
    public boolean visit(TypeParameter javaTypeParameter) {
        pushCurrent(new TypeParameterContext(stsCurrent, 0));

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaTypeParameter.getName()));

        // ExtendedModifiers are ignored at the moment.

        List<Type> javaTypeBounds = javaTypeParameter.typeBounds();

        if (!javaTypeBounds.isEmpty()) {
            pushCurrent(new ConstraintContext(stsCurrent, 0));

            stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.EXTENDS));

            boolean isIntersectionTypeBound = javaTypeBounds.size() > 1;
            if (isIntersectionTypeBound) pushCurrent(new IntersectionTypeContext(stsCurrent, 0));

            for (Type javaTypeBound : javaTypeBounds) {
                if (NodeBuilder.isTypeReference(javaTypeBound)) {
                    javaTypeBound.accept(this);
                }
                else {
                    // Only type references are allowed as type parameter bounds
                    // (or as intersection type components) in STS.
                    // Warn and emit __UnknownType__ with original source code as comment.
                    String boundTypeName = javaTypeBound.toString();
                    reportError("Invalid type " + boundTypeName + " in type parameter bound", javaTypeBound);
                    stsCurrent.addChild(NodeBuilder.unknownTypeReference(boundTypeName)).setParent(stsCurrent);
                }
            }

            if (isIntersectionTypeBound) popCurrent(); // IntersectionTypeContext
            popCurrent(); // ConstraintContext
        }

        popCurrent(); // TypeParameterContext
        return false;
    }
    private ParserRuleContext createDeclarationOrMemberContextWithAccessModifier(int javaMods) {
        boolean isInClassContext = stsCurrent instanceof ClassBodyContext;
        boolean isInInterfaceContext = stsCurrent instanceof InterfaceBodyContext;

        ParserRuleContext stsMemberContext;
        if (isInClassContext)
            stsMemberContext = new ClassMemberContext(stsCurrent, 0);
        else if (isInInterfaceContext)
            stsMemberContext = new InterfaceMemberContext(stsCurrent, 0);
        else if (stsCurrent instanceof BlockContext || stsCurrent instanceof ConstructorBodyContext)
            stsMemberContext = new StatementOrLocalDeclarationContext(stsCurrent, 0);
        else
            stsMemberContext = new TopDeclarationContext(stsCurrent, 0);

        // Process access modifier. In top-level context, public translates to export,
        // everything else to none. In all other contexts, emit AccessibilityModifierContext.
        if (isInClassContext) {
            AccessibilityModifierContext stsAccessMod = NodeBuilder.accessibilityModifier(javaMods);
            if (stsAccessMod != null) stsMemberContext.addChild(stsAccessMod).setParent(stsMemberContext);
        }
        else if (isInInterfaceContext) {
            // Note: 'public' modifier is not permitted for interface's members.
            AccessibilityModifierContext stsAccessMod = NodeBuilder.accessibilityModifier(javaMods & ~Modifier.PUBLIC);
            if (stsAccessMod != null) stsMemberContext.addChild(stsAccessMod).setParent(stsMemberContext);
        }
        else if ((javaMods & Modifier.PUBLIC) != 0)
            stsMemberContext.addChild(NodeBuilder.terminalNode(StaticTSParser.Export));

        return stsMemberContext;
    }

    private ConstructorDeclarationContext addInstanceInitializersToCtors(ASTNode javaTypeDeclaration) {
        // Put statements from instance initializers into constructors which don't call
        // another constructor (i.e. don't have 'this()' call).
        List<StatementOrLocalDeclarationContext> stsInitStmts = (List<StatementOrLocalDeclarationContext>)javaTypeDeclaration.getProperty(INSTANCE_INITIALIZER);
        Set<ITypeBinding> stsInitThrownExceptions = (Set<ITypeBinding>)javaTypeDeclaration.getProperty(INIT_THROWN_EXEPTIONS);
        if (stsCurrent instanceof ClassBodyContext && stsInitStmts != null && !stsInitStmts.isEmpty()) {
            ClassBodyContext stsClassBody = (ClassBodyContext) stsCurrent;

            boolean needDefaultCtor = true;
            for (ClassMemberContext stsMember : stsClassBody.classMember()) {
                ConstructorDeclarationContext stsCtorDecl = stsMember.constructorDeclaration();
                if (stsCtorDecl != null) {
                    addInstanceInitializersToCtor(stsCtorDecl, stsInitStmts);
                    needDefaultCtor = false;

                    // if constructor already has 'throws' clause - do nothing
                    // else check thrown exceptions set for init blocks
                    if ((stsCtorDecl.throwsAnnotation() == null) && !stsInitThrownExceptions.isEmpty())
                        stsCtorDecl.addChild(NodeBuilder.throwsAnnotation(true));
                }
            }

            if (needDefaultCtor) {
                // Create default ctor and add initializer statements to it
                pushCurrent(new ClassMemberContext(stsCurrent, 0));
                stsCurrent.addChild(NodeBuilder.accessibilityModifier(Modifier.PUBLIC)).setParent(stsCurrent);

                ConstructorDeclarationContext stsDefaultCtor = new ConstructorDeclarationContext(stsCurrent, 0);
                pushCurrent(stsDefaultCtor);

                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Constructor));
                stsCurrent.addChild(new ConstructorBodyContext(stsCurrent, 0)).setParent(stsCurrent);

                if( !stsInitThrownExceptions.isEmpty() )
                    stsCurrent.addChild(NodeBuilder.throwsAnnotation(true));

                popCurrent(); // stsDefaultCtor
                popCurrent(); // ClassMemberContext

                addInstanceInitializersToCtor(stsDefaultCtor, stsInitStmts);
                return stsDefaultCtor;
            }
        }
        return null;
    }
    private void addInstanceInitializersToCtor(ConstructorDeclarationContext stsCtorDecl, List<StatementOrLocalDeclarationContext> stsInitStmts) {
        // Sanity check.
        if (stsCtorDecl == null) return;

        ConstructorBodyContext stsCtorBody = stsCtorDecl.constructorBody();
        ConstructorCallContext stsCtorCall = stsCtorBody.constructorCall();

        if (stsCtorCall == null || stsCtorCall.Super() != null) {
            // The children list may not be initialized if the ctor body is empty.
            // In such case, initialize the list manually.
            if (stsCtorBody.children == null) {
                stsCtorBody.children = new ArrayList<>();
            }

            // If super() ctor call is present, insert statements after it.
            boolean hasSuperCall = stsCtorCall != null && stsCtorCall.Super() != null;
            int addIndex = hasSuperCall ? 1 : 0;
            stsCtorBody.children.addAll(addIndex, stsInitStmts);
        }
    }

    // Java tree:
    //  FieldDeclaration: [Javadoc] { ExtendedModifier } Type VariableDeclarationFragment { , VariableDeclarationFragment } ;
    //  VariableDeclarationFragment: Identifier { Dimension } [ = Expression ]
    // STS tree:
    //  classMember:
    //      | classFieldDeclaration
    // or
    //  interfaceMember:
    //      | ({this.next(StaticTSParser.READONLY)}? Identifier)?
    //        variableDeclaration SemiColon?                  #InterfaceField
    //  classFieldDeclaration
    //    : Static? (variableDeclaration | {this.next(StaticTSParser.READONLY)}? Identifier constantDeclaration) SemiColon
    //    | {this.next(StaticTSParser.READONLY)}? Identifier Static? constantDeclaration SemiColon
    //  variableDeclaration: Identifier typeAnnotation initializer? | Identifier initializer
    //  constantDeclaration: Identifier typeAnnotation? initializer
    @Override
    public boolean visit(FieldDeclaration javaFieldDecl) {
        boolean isInClassContext = stsCurrent instanceof ClassBodyContext;
        assert(isInClassContext || (stsCurrent instanceof InterfaceBodyContext));

        int javaMods = javaFieldDecl.getModifiers();
        List<VariableDeclarationFragment> javaVarDeclFragments = javaFieldDecl.fragments();

        for (VariableDeclarationFragment javaVarDeclFragment : javaVarDeclFragments) {
            pushCurrent(createDeclarationOrMemberContextWithAccessModifier(javaMods));
            ParserRuleContext stsClassOrInterField = isInClassContext ?
                              new ClassFieldDeclarationContext(stsCurrent, 0)
                            : new InterfaceFieldContext((InterfaceMemberContext)stsCurrent);

            pushCurrent(stsClassOrInterField);

            // Non-access modifiers
            if ((javaMods & Modifier.STATIC) != 0)
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));

            // Note: Java allows final fields declared without initializer (to be initialized in ctor).
            // STS doesn't allow constant fields without initializer, therefore the fields above will
            // be translated without const modifier.
            ParserRuleContext stsVarOrConstDecl;
            Expression javaFragmentInit = javaVarDeclFragment.getInitializer();
            if (((javaMods & Modifier.FINAL) != 0 && javaFragmentInit != null) || !isInClassContext) {
                stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.READONLY));
                stsVarOrConstDecl = isInClassContext ?
                                    new ConstantDeclarationContext(stsCurrent, 0) :
                                    new VariableDeclarationContext(stsCurrent, 0);
            }
            else
                stsVarOrConstDecl = new VariableDeclarationContext(stsCurrent, 0);

            // Field name
            pushCurrent(stsVarOrConstDecl);
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaVarDeclFragment.getName()));

            // Field type
            pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Colon));
            javaFieldDecl.getType().accept(this);

            int extraDims = javaVarDeclFragment.getExtraDimensions();
            if (extraDims > 0) NodeBuilder.addExtraDimensions(stsCurrent, extraDims);

            popCurrent(); // TypeAnnotationContext

            // Field initializer, if any
            if (javaFragmentInit != null)  {
                pushCurrent(new InitializerContext(stsCurrent, 0));
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
                javaFragmentInit.accept(this);
                popCurrent(); // InitializerContext
            }

            popCurrent(); // stsVarOrConstDecl
            popCurrent(); // stsClassOrInterField
            popCurrent(); // stsClassOrInterMember

            // Each VariableDeclarationFragment is a separate declaration construct!
            declTransformed.add(javaVarDeclFragment);
        }

        declTransformed.add(javaFieldDecl);
        return false;
    }

    // Java tree:
    // ImportDeclaration:
    //    import [ static ] Name [ . * ] ;
    //
    // STS tree:
    // importDeclaration
    //    : Import (asteriskBinding | simpleBinding) From StringLiteral SemiColon?
    @Override
    public boolean visit(ImportDeclaration javaImportDeclaration) {
        String javaImportName = javaImportDeclaration.getName().getFullyQualifiedName();
        String stsImportFromPath = javaImportName;

        IBinding javaImportBinding = javaImportDeclaration.resolveBinding();
        if (javaImportBinding != null && !javaImportBinding.isRecovered()) {
            if (javaImportBinding.getKind() == IBinding.TYPE) {
                stsImportFromPath = ((ITypeBinding) javaImportBinding).getPackage().getName();
            }
            else if (javaImportBinding.getKind() == IBinding.METHOD) {
                stsImportFromPath = ((IMethodBinding) javaImportBinding).getDeclaringClass().getPackage().getName();
            }
            else if (javaImportBinding.getKind() == IBinding.VARIABLE) {
                IVariableBinding javaVarBinding = (IVariableBinding)javaImportBinding;
                if (javaVarBinding.isField() || javaVarBinding.isEnumConstant())
                    stsImportFromPath = javaVarBinding.getDeclaringClass().getPackage().getName();
            }
        }
        else
            reportError("Failed to resolve import declaration", javaImportDeclaration);

        // Check for validity - regular (not on-demand) import should always use a qualified name.
        // If invalid, warn and emit original import syntax in a comment.
        if (!javaImportDeclaration.isOnDemand() && javaImportName.lastIndexOf('.') == -1) {
            reportError("Invalid import declaration", javaImportDeclaration);
            TerminalNode stsComment = NodeBuilder.multiLineComment("/* Untranslated import declaration: " +
                                                                    javaImportDeclaration.toString() + " */");
            if (stsCU.getChildCount() > 0) {
                StaticTSContextBase lastChild = (StaticTSContextBase)stsCU.getChild(stsCU.getChildCount()-1);
                lastChild.addTrailingComment(stsComment);
            }
            else
                stsCU.addLeadingComment(stsComment);

            return false; // Bail out as we don't need to do anything further here.
        }

        ImportDeclarationContext stsImportDeclaration = new ImportDeclarationContext(stsCurrent, 0);
        pushCurrent(stsImportDeclaration);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Import));

        pushCurrent(new ImportBindingContext(stsCurrent, 0));

        stsImportDeclaration.javaImport = javaImportName;

        if (javaImportDeclaration.isOnDemand()) {
            // If stsImportFromPath is a prefix of javaImportName, we must be importing from a type.
            // Extract the type name and use it as qualifier for the asterisk.
            if (javaImportName.startsWith(stsImportFromPath) && !javaImportName.equals(stsImportFromPath)) {
                String stsImportName = javaImportName.substring(stsImportFromPath.length()+1);
                stsCurrent.addChild(NodeBuilder.qualifiedName(stsImportName)).setParent(stsCurrent);
            }

            // Need this terminal now to identify on-demand import from a type.
            // See StaticTSWriter.visitImportBinding for details.
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Multiply));
            stsImportDeclaration.javaImport += ".*";
        }
        else {
            // If we couldn't resolve this import, assume we're importing
            // the last element of javaImportName
            if (javaImportName.equals(stsImportFromPath)) {
                int lastDotPos = javaImportName.lastIndexOf('.');
                stsImportFromPath = javaImportName.substring(0, lastDotPos);
            }

            String stsImportName = javaImportName.substring(stsImportFromPath.length()+1);
            stsCurrent.addChild(NodeBuilder.qualifiedName(stsImportName)).setParent(stsCurrent);

            // If we're importing from a type (i.e., stsImportName contains dots),
            // add alias to make sure imported entities as available by simple names.
            int lastDotPos = stsImportName.lastIndexOf('.');
            if (lastDotPos != -1) {
                String stsAliasName = stsImportName.substring(lastDotPos+1);
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.As));
                stsCurrent.addChild(NodeBuilder.terminalIdentifier(stsAliasName));
            }
        }

        popCurrent(); // ImportBindingContext

        // Replace dots with slashes to get the path.
        stsImportFromPath = stsImportFromPath.replace('.', '/');

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.FROM));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.StringLiteral, stsImportFromPath));

        popCurrent(); // stsImportDeclaration

        declTransformed.add(javaImportDeclaration);
        return false;
    }

    // Java tree:
    //  Type:
    //    AnnotatableType:
    //       PrimitiveType
    //       SimpleType
    //       QualifiedType
    //       NameQualifiedType
    //       WildcardType
    //    ArrayType
    //    ParameterizedType
    //    UnionType
    //    IntersectionType
    // STS tree:

    // Java tree:
    //  PrimitiveType:
    //    { Annotation } byte
    //    { Annotation } short
    //    { Annotation } char
    //    { Annotation } int
    //    { Annotation } long
    //    { Annotation } float
    //    { Annotation } double
    //    { Annotation } boolean
    //    { Annotation } void
    // STS tree:
    //  primaryType:
    //      : predefinedType  #PredefinedPrimType
    // or
    //  typeReference
    //      : qualifiedName
    @Override
    public boolean visit(PrimitiveType javaPrimitiveType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        StaticTSContextBase stsType = NodeBuilder.predefinedType(javaPrimitiveType.getPrimitiveTypeCode());
        if (stsType == null) {
            reportError("Failed to translate primitive type", javaPrimitiveType);
            stsType = NodeBuilder.unknownTypeReference("/* " + javaPrimitiveType.toString() + " */");
        }
        stsCurrent.addChild(stsType).setParent(stsCurrent);

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaPrimitiveType);
        return false;
    }

    // Java tree:
    //    SimpleType:  { Annotation } TypeName
    //
    // STS tree:
    //    typeReference or
    //    primaryType: typeReference (depending on context),
    //    where typeReference: typeReferencePart ('.' typeReferencePart)*
    //    and typeReferencePart: qualifiedName typeArguments?
    @Override
    public boolean visit(SimpleType javaSimpleType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        // Get fully qualified name of the type (prefer resolved version).
        ITypeBinding javaTypeBinding = javaSimpleType.resolveBinding();
        String origTypeFQName = javaSimpleType.getName().getFullyQualifiedName();
        String typeFQName = (javaTypeBinding != null && !javaTypeBinding.isLocal()) ?
                         javaTypeBinding.getQualifiedName() : origTypeFQName;

        String javaFQType = typeFQName;
        int index = javaFQType.lastIndexOf("<");
        if (index > 0) {
            javaFQType = javaFQType.substring(0, index); // Cut off the argument types for generic types.
        }

        // If typeFQN is a qualified name, replace
        // qualifier with its import alias (if any).
        int lastDotPos = typeFQName.lastIndexOf('.');
        if (lastDotPos != -1) {
            String qualifier = typeFQName.substring(0, lastDotPos);
            if (importAliasMap.containsKey(qualifier)) {
                String typeName = typeFQName.substring(lastDotPos + 1);
                typeFQName = importAliasMap.get(qualifier) + "." + typeName;
            }
            else {
                // Revert to original type name from source.
                typeFQName = origTypeFQName;
            }
        }

        stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaSimpleType);
        return false;
    }

    private boolean isInPrimaryTypeContext() {
        return stsCurrent.getRuleIndex() == StaticTSParser.RULE_typeAnnotation
                || stsCurrent instanceof NewArrayExpressionContext
                || stsCurrent instanceof InstanceofExpressionContext
                || stsCurrent instanceof ClassLiteralExpressionContext
                || stsCurrent instanceof CastExpressionContext;
    }

    // Java tree:
    //    QualifiedType: Type . { Annotation } SimpleName
    //
    // STS tree:
    //    primaryType: typeReference or plain typeReference (depending on context)
    //    typeReference: typeReferencePart ('.' typeReferencePart)*
    //    where typeReferencePart: qualifiedName typeArguments?
    @Override
    public boolean visit(QualifiedType javaQualifiedType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        // Translate qualifier type and remove translation result from stsCurrent
        javaQualifiedType.getQualifier().accept(this);
        ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(lastChild instanceof TypeReferenceContext); // qualifier type should never be wrapped in PrimaryTypeContext!

        // Add new TypeReferencePart node to existing TypeReference context.
        TypeReferenceContext stsTypeRef = (TypeReferenceContext)lastChild;
        String typeName = javaQualifiedType.getName().getFullyQualifiedName();
        stsTypeRef.addChild(NodeBuilder.typeReferencePart(typeName)).setParent(stsTypeRef);

        NodeBuilder.fillMapperMatchAtributs(stsTypeRef, javaQualifiedType.resolveBinding());

        // Add empty type arguments list if this is a raw type
        NodeBuilder.addEmptyTypeArgumentsToRawType(stsTypeRef, javaQualifiedType);

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaQualifiedType);
        return false;
    }

    // Java tree:
    //    NameQualifiedType: Name . { Annotation } SimpleName
    //
    // STS tree:
    //    primaryType: typeReference or plain typeReference (depending on context)
    //    typeReference: typeReferencePart ('.' typeReferencePart)*
    //    where typeReferencePart: qualifiedName typeArguments?
    @Override
    public boolean visit(NameQualifiedType javaNameQualifiedType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        // Construct TypeReferenceContext from qualifier name and type name.
        String javaQualifierText = javaNameQualifiedType.getQualifier().getFullyQualifiedName();
        String typeFQName = javaQualifierText + '.' + javaNameQualifiedType.getName().getFullyQualifiedName();
        ITypeBinding javaTypeBinding = javaNameQualifiedType.resolveBinding();

        stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaNameQualifiedType);
        return false;
    }

    @Override
    public boolean visit(ParameterizedType javaParametrizedType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        // Translate the type part of parameterized type.
        // This should create TypeReference context with
        // one or several TypeReferencePart nodes under it.
        Type javaGenericType = javaParametrizedType.getType();
        if (NodeBuilder.isTypeReference(javaGenericType)) {
            javaGenericType.accept(this);
        }
        else {
            String javaGenericTypeName = javaGenericType.toString();
            reportError("Invalid generic type " +  javaGenericTypeName + " in parametrized type", javaParametrizedType);
            stsCurrent.addChild(NodeBuilder.unknownTypeReference(javaGenericTypeName)).setParent(stsCurrent);
        }

        // Get last TypeReferencePartContext node of the
        // TypeReferenceContext node we just constructed above
        ParseTree stsLastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        stsLastChild = stsLastChild.getChild(stsLastChild.getChildCount() - 1);

        // Translate and add type arguments to last TypeReferencePartContext node
        pushCurrent((TypeReferencePartContext)stsLastChild, false);
        List<Type> javaTypeArgs = javaParametrizedType.typeArguments();

        if (javaTypeArgs != null && !javaTypeArgs.isEmpty()) {
            translateTypeArguments(javaTypeArgs);
        }
        else {
            // Handle the case of Java "diamond" syntax, e.g. new HashSet<>()
            ITypeBinding javaTypeBinding = NodeBuilder.getTypeBinding(javaParametrizedType);
            if (javaTypeBinding != null && !javaTypeBinding.isRecovered()) {
                ITypeBinding[] javaTypeArgBindings = javaTypeBinding.getTypeArguments();
                TypeArgumentsContext stsTypeArgs = NodeBuilder.translateTypeArguments(javaTypeArgBindings);
                stsCurrent.addChild(stsTypeArgs).setParent(stsCurrent);
            }
        }

        popCurrent(); // (TypeReferencePartContext)stsLastChild

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaParametrizedType);
        return false;
    }

    @Override
    public boolean visit(WildcardType javaWildcardType) {
        pushCurrent(new WildcardTypeContext(stsCurrent, 0));

        Type javaBound = javaWildcardType.getBound();
        if (javaBound != null) {
            // Add corresponding keyword and bounding type
            String stsInOrOutKeyword = javaWildcardType.isUpperBound() ? StaticTSParser.OUT : StaticTSParser.IN;
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(stsInOrOutKeyword));

            if (NodeBuilder.isTypeReference(javaBound)) {
                javaBound.accept(this);
            }
            else {
                // Only type references are allowed as wildcard bounds in STS.
                // Warn and emit __UnknownType__ with original source code as a comment.
                String boundTypeName = javaBound.toString();
                reportError("Invalid bound type " + boundTypeName + " in wildcard type", javaBound);
                stsCurrent.addChild(NodeBuilder.unknownTypeReference(boundTypeName)).setParent(stsCurrent);
            }
        }
        else {
            // No wildcard bound, i.e. '?' in Java translates to 'out' in STS
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.OUT));
        }

        popCurrent(); // WildcardTypeContext

        typeTransformed.add(javaWildcardType);
        return false;
    }

    @Override
    public boolean visit(ArrayType javaArrayType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        pushCurrent(new ArrayTypeContext(stsCurrent, 0));
        javaArrayType.getElementType().accept(this);

        int numDims = javaArrayType.getDimensions();
        for (int i = 0; i < numDims; ++i) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.OpenBracket));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.CloseBracket));
        }

        popCurrent(); // ArrayTypeContext

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaArrayType);
        return false;
    }

    @Override
    public boolean visit(IntersectionType javaIntersectionType) {
        boolean needPrimaryType = isInPrimaryTypeContext();
        if (needPrimaryType) pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        pushCurrent(new IntersectionTypeContext(stsCurrent, 0));

        List<Type> javaTypeList = javaIntersectionType.types();
        for (Type javaType : javaTypeList)
            javaType.accept(this);

        popCurrent(); // IntersectionTypeContext

        if (needPrimaryType) popCurrent(); // PrimaryTypeContext

        typeTransformed.add(javaIntersectionType);
        return false;
    }

    private void translateTypeBinding(ITypeBinding javaTypeBinding, ASTNode javaNode) {
        if (javaTypeBinding == null || javaTypeBinding.isRecovered()) {
            // Warn and emit __UnknownType__ as result type
            String typeName = javaTypeBinding != null ? javaTypeBinding.getName() : "";
            reportError("Failed to resolve type " + typeName, javaNode);
            stsCurrent.addChild(NodeBuilder.unknownTypeAnnotation(javaTypeBinding)).setParent(stsCurrent);
            return;
        }

        pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
        pushCurrent(new PrimaryTypeContext(stsCurrent, 0));

        stsCurrent.addChild(NodeBuilder.translateTypeBinding(javaTypeBinding)).setParent(stsCurrent);

        popCurrent(); // PrimaryTypeContext
        popCurrent(); // TypeAnnotationContext
    }

    // Java tree:
    //      Expression: NullLiteral
    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: NullLiteral
    @Override
    public boolean visit(NullLiteral javaLiteral) {
        stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
        exprTransformed.add(javaLiteral);
        return false;
    }

    // Java tree:
    //      Expression: BooleanLiteral
    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | BooleanLiteral
    @Override
    public boolean visit(BooleanLiteral javaLiteral) {
        stsCurrent.addChild(NodeBuilder.boolLiteral(javaLiteral.booleanValue())).setParent(stsCurrent);
        exprTransformed.add(javaLiteral);
        return false;
    }

    // Java tree:
    //      Expression: CharacterLiteral
    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | CharLiteral
    @Override
    public boolean visit(CharacterLiteral javaLiteral) {
        stsCurrent.addChild(NodeBuilder.charLiteral(javaLiteral.getEscapedValue())).setParent(stsCurrent);
        exprTransformed.add(javaLiteral);
        return false;
    }

    // Java tree:
    //      Expression: StringLiteral
    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | StringLiteral
    @Override
    public boolean visit(StringLiteral javaLiteral) {
        stsCurrent.addChild(NodeBuilder.stringLiteral(javaLiteral.getEscapedValue())).setParent(stsCurrent);
        exprTransformed.add(javaLiteral);
        return false;
    }

    // Java tree:
    //      Expression: NumberLiteral
    // STS tree:
    //      singleExpression: | literal  # LiteralExpression
    //      literal: | numericLiteral
    //      numericLiteral:
    //              : DecimalLiteral
    //              | HexIntegerLiteral
    //              | OctalIntegerLiteral
    //              | BinaryIntegerLiteral
    @Override
    public boolean visit(NumberLiteral javaLiteral) {
        stsCurrent.addChild(NodeBuilder.numericLiteral(javaLiteral.getToken())).setParent(stsCurrent);
        exprTransformed.add(javaLiteral);
        return false;
    }

    // Java tree:
    //      Expression: Name
    //      Name: SimpleName
    // STS tree:
    //      singleExpression: | Identifier # IdentifierExpression
    @Override
    public boolean visit(SimpleName javaSimpleName) {
        String name = javaSimpleName.getIdentifier();
        stsCurrent.addChild(NodeBuilder.identifierExpression(name)).setParent(stsCurrent);
        // Don't count names as transformed as most of them are transformed manually.
        return false;
    }

    // Java tree:
    //      Expression: Name
    //      Name: QualifiedName
    // STS tree:
    //      singleExpression: | Identifier # IdentifierExpression
    @Override
    public boolean visit(QualifiedName javaQualifiedName) {
        // TODO: Check if this javaQualifiedName referes to a calss static field access. Like: Character.MAX_HIGH_SURROGATE.
        //       In this case it has to be translated to a MemberAccessExpression and not to a simple Identifier.
        //       It's needed to let the ApiMapper to apply corresponding MemberAccessExpressionRule.
        //       See #272
//        Name javaQualifier = javaQualifiedName.getQualifier();
//        if (javaQualifier != null) {
//            String typeFQName = javaQualifier.getFullyQualifiedName();
//            ITypeBinding javaTypeBinding = javaQualifier.resolveTypeBinding();
//            if (javaTypeBinding != null) {
//                MemberAccessExpressionContext stsMemberAccessExpr = new MemberAccessExpressionContext(pushSingleExpression());
//                pushCurrent(stsMemberAccessExpr);
//
//                //Expression javaObjectExpr = javaFieldAccess.getExpression();
//                SimpleName javaFieldName = javaQualifiedName.getName();
//                String javaTypeName = javaTypeBinding.getQualifiedName();
//
//                // Fill the rules match attributes.
//                stsMemberAccessExpr.javaName = javaFieldName.getIdentifier();
//                stsMemberAccessExpr.javaType = javaTypeName;
//
//                //javaObjectExpr.accept(this);
//                stsMemberAccessExpr.addChild(NodeBuilder.typeReference(javaTypeName)).setParent(stsMemberAccessExpr);
//                stsMemberAccessExpr.addChild(NodeBuilder.terminalIdentifier(javaFieldName));
//                stsMemberAccessExpr.addChild(NodeBuilder.terminalIdentifier(javaFieldName));
//
//                popSingleExpression(); // MemberAccessExpressionContext
//
//                return false;
//            }
//        }

        String name = javaQualifiedName.getFullyQualifiedName();
        stsCurrent.addChild(NodeBuilder.identifierExpression(name)).setParent(stsCurrent);
        // Don't count names as transformed as most of them are transformed manually.
        return false;
    }

    private int stsOperatorType(InfixExpression.Operator javaOp) {
        int stsOperator = -1;

        if (javaOp == InfixExpression.Operator.TIMES) stsOperator = StaticTSParser.Multiply;
        else if (javaOp == InfixExpression.Operator.DIVIDE) stsOperator = StaticTSParser.Divide;
        else if (javaOp == InfixExpression.Operator.REMAINDER) stsOperator = StaticTSParser.Modulus;
        else if (javaOp == InfixExpression.Operator.PLUS) stsOperator = StaticTSParser.Plus;
        else if (javaOp == InfixExpression.Operator.MINUS) stsOperator = StaticTSParser.Minus;
        else if (javaOp == InfixExpression.Operator.LESS) stsOperator = StaticTSParser.LessThan;
        else if (javaOp == InfixExpression.Operator.GREATER) stsOperator = StaticTSParser.MoreThan;
        else if (javaOp == InfixExpression.Operator.LESS_EQUALS) stsOperator = StaticTSParser.LessThanEquals;
        else if (javaOp == InfixExpression.Operator.GREATER_EQUALS) stsOperator = StaticTSParser.GreaterThanEquals;
        else if (javaOp == InfixExpression.Operator.EQUALS) stsOperator = StaticTSParser.Equals;
        else if (javaOp == InfixExpression.Operator.NOT_EQUALS) stsOperator = StaticTSParser.NotEquals;
        else if (javaOp == InfixExpression.Operator.AND) stsOperator = StaticTSParser.BitAnd;
        else if (javaOp == InfixExpression.Operator.XOR) stsOperator = StaticTSParser.BitXor;
        else if (javaOp == InfixExpression.Operator.OR) stsOperator = StaticTSParser.BitOr;
        else if (javaOp == InfixExpression.Operator.CONDITIONAL_AND) stsOperator = StaticTSParser.And;
        else if (javaOp == InfixExpression.Operator.CONDITIONAL_OR) stsOperator = StaticTSParser.Or;

        assert(stsOperator != -1);

        return stsOperator;
    }

    private ParseTree createStsInfixOperator(InfixExpression.Operator javaOp) {
        if (isShiftOperator(javaOp))
            return NodeBuilder.shiftOperator(javaOp);
        else
            return NodeBuilder.terminalNode(stsOperatorType(javaOp));
    }

    private boolean isShiftOperator(InfixExpression.Operator javaInfixOp) {
        return javaInfixOp == InfixExpression.Operator.LEFT_SHIFT
                || javaInfixOp == InfixExpression.Operator.RIGHT_SHIFT_SIGNED
                || javaInfixOp == InfixExpression.Operator.RIGHT_SHIFT_UNSIGNED;
    }

    private ParserRuleContext createStsInfixExpression(SingleExpressionContext stsSingleExpression, InfixExpression javaInfixExpression) {
        InfixExpression.Operator javaOp = javaInfixExpression.getOperator();

        if (javaOp == InfixExpression.Operator.TIMES || javaOp == InfixExpression.Operator.DIVIDE || javaOp == InfixExpression.Operator.REMAINDER)
            return new MultiplicativeExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.PLUS || javaOp == InfixExpression.Operator.MINUS)
            return new AdditiveExpressionContext(stsSingleExpression);
        else if (isShiftOperator(javaOp))
            return new BitShiftExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.LESS || javaOp == InfixExpression.Operator.GREATER || javaOp == InfixExpression.Operator.LESS_EQUALS || javaOp == InfixExpression.Operator.GREATER_EQUALS)
            return new RelationalExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.EQUALS || javaOp == InfixExpression.Operator.NOT_EQUALS)
            return new EqualityExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.AND)
            return new BitAndExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.XOR)
            return new BitXOrExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.OR)
            return new BitOrExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.CONDITIONAL_AND)
            return new LogicalAndExpressionContext(stsSingleExpression);
        else if (javaOp == InfixExpression.Operator.CONDITIONAL_OR)
            return new LogicalOrExpressionContext(stsSingleExpression);
        else
            assert (false);

        return null;
    }

    // Java tree:
    //      Expression: InfixExpression
    //      InfixExpression: Expression InfixOperator Expression { InfixOperator Expression }
    // STS tree:
    //     singleExpression:
    //       | singleExpression (Multiply | Divide | Modulus) singleExpression        # MultiplicativeExpression
    //       | singleExpression (Plus | Minus) singleExpression                       # AdditiveExpression
    //       | singleExpression (LeftShiftArithmetic | RightShiftArithmetic | RightShiftLogical) singleExpression  # BitShiftExpression
    //       | singleExpression (LessThan | MoreThan | LessThanEquals | GreaterThanEquals) singleExpression        # RelationalExpression
    //       | singleExpression (Equals | NotEquals) singleExpression                 # EqualityExpression
    //       | singleExpression BitAnd singleExpression                               # BitAndExpression
    //       | singleExpression BitXor singleExpression                               # BitXOrExpression
    //       | singleExpression BitOr singleExpression                                # BitOrExpression
    //       | singleExpression And singleExpression                                  # LogicalAndExpression
    //       | singleExpression Or singleExpression                                   # LogicalOrExpression
    @Override
    public boolean visit(InfixExpression javaInfixExpression) {
        pushCurrent(createStsInfixExpression(pushSingleExpression(), javaInfixExpression));
        InfixExpression.Operator javaOp = javaInfixExpression.getOperator();

        javaInfixExpression.getLeftOperand().accept(this);
        stsCurrent.addAnyChild(createStsInfixOperator(javaOp)).setParent(stsCurrent);
        javaInfixExpression.getRightOperand().accept(this);

        popSingleExpression(); // InfixExpression

        List<Expression> javaExtendedOperands = javaInfixExpression.extendedOperands();
        for (Expression javaRightExpression : javaExtendedOperands) {
            // The last child of current node is a SingleExpression which represents current binary operation.
            // It will be the left side operand of the new binary operation.
            ParserRuleContext stsLeftOperand = (ParserRuleContext)stsCurrent.getChild(stsCurrent.getChildCount() - 1);
            stsCurrent.removeLastChild();

            pushCurrent(createStsInfixExpression(pushSingleExpression(), javaInfixExpression));

            stsCurrent.addChild(stsLeftOperand).setParent(stsCurrent);
            stsCurrent.addAnyChild(createStsInfixOperator(javaOp)).setParent(stsCurrent);
            javaRightExpression.accept(this);

            popSingleExpression(); // InfixExpression
        }

        exprTransformed.add(javaInfixExpression);
        return false;
    }

    private int stsOperatorType(PostfixExpression javaPostfixExpression) {
        int stsOpType;
        PostfixExpression.Operator javaOp = javaPostfixExpression.getOperator();

        if (javaOp == PostfixExpression.Operator.INCREMENT) {
            stsOpType = StaticTSParser.PlusPlus;
        }
        else {
            assert (javaOp == PostfixExpression.Operator.DECREMENT);
            stsOpType = StaticTSParser.MinusMinus;
        }

        return stsOpType;
    }

    private ParserRuleContext createStsPostfixExpression(SingleExpressionContext stsSingleExpression, PostfixExpression javaPostfixExpression) {
        PostfixExpression.Operator javaOp = javaPostfixExpression.getOperator();
        if (javaOp == PostfixExpression.Operator.INCREMENT) {
            return new PostIncrementExpressionContext(stsSingleExpression);
        }

        assert (javaPostfixExpression.getOperator() == PostfixExpression.Operator.DECREMENT);
        return new PostDecreaseExpressionContext(stsSingleExpression);
    }

    // Java tree:
    //      Expression: PostfixExpression
    //      PostfixExpression: Expression PostfixOperator
    // STS tree:
    //      singleExpression:
    //          | singleExpression PlusPlus     # PostIncrementExpression
    //          | singleExpression MinusMinus   # PostDecreaseExpression
    @Override
    public  boolean visit(PostfixExpression javaPostfixExpression) {
        pushCurrent(createStsPostfixExpression(pushSingleExpression(), javaPostfixExpression));

        javaPostfixExpression.getOperand().accept(this);
        stsCurrent.addChild(NodeBuilder.terminalNode(stsOperatorType(javaPostfixExpression))).setParent(stsCurrent);

        popSingleExpression();

        exprTransformed.add(javaPostfixExpression);
        return false;
    }

    private int stsOperatorType(PrefixExpression javaPrefixExpression) {
        int stsOpType = -1;

        PrefixExpression.Operator javaOp = javaPrefixExpression.getOperator();

        if (javaOp == PrefixExpression.Operator.INCREMENT)
            stsOpType = StaticTSParser.PlusPlus;
        else if (javaOp == PrefixExpression.Operator.DECREMENT)
            stsOpType = StaticTSParser.MinusMinus;
        else if (javaOp == PrefixExpression.Operator.PLUS)
            stsOpType = StaticTSParser.Plus;
        else if (javaOp == PrefixExpression.Operator.MINUS)
            stsOpType = StaticTSParser.Minus;
        else if (javaOp == PrefixExpression.Operator.COMPLEMENT)
            stsOpType = StaticTSParser.BitNot;
        else if (javaOp == PrefixExpression.Operator.NOT)
            stsOpType = StaticTSParser.Not;

        assert (stsOpType != -1);
        return stsOpType;
    }

    private ParserRuleContext createStsPrefixExpression(SingleExpressionContext stsSingleExpression, PrefixExpression javaPrefixExpression) {
        PrefixExpression.Operator javaOp = javaPrefixExpression.getOperator();

        if (javaOp == PrefixExpression.Operator.INCREMENT)
            return new PreIncrementExpressionContext(stsSingleExpression);
        else if (javaOp == PrefixExpression.Operator.DECREMENT)
            return new PreDecreaseExpressionContext(stsSingleExpression);
        else if (javaOp == PrefixExpression.Operator.PLUS)
            return new UnaryPlusExpressionContext(stsSingleExpression);
        else if (javaOp == PrefixExpression.Operator.MINUS)
            return new UnaryMinusExpressionContext(stsSingleExpression);
        else if (javaOp == PrefixExpression.Operator.COMPLEMENT)
            return new BitNotExpressionContext(stsSingleExpression);

        assert (javaOp == PrefixExpression.Operator.NOT);
        return new NotExpressionContext(stsSingleExpression);
    }

    // Java tree:
    //      Expression: PrefixExpression
    //      PrefixExpression: PrefixOperator Expression
    // STS tree:
    //      singleExpression:
    //          | PlusPlus singleExpression        # PreIncrementExpression
    //          | MinusMinus singleExpression      # PreDecreaseExpression
    //          | Plus singleExpression            # UnaryPlusExpression
    //          | Minus singleExpression           # UnaryMinusExpression
    //          | BitNot singleExpression          # BitNotExpression
    //          | Not singleExpression             # NotExpression
    @Override
    public boolean visit(PrefixExpression javaPrefixExpression) {
        pushCurrent(createStsPrefixExpression(pushSingleExpression(), javaPrefixExpression));

        stsCurrent.addChild(NodeBuilder.terminalNode(stsOperatorType(javaPrefixExpression))).setParent(stsCurrent);
        javaPrefixExpression.getOperand().accept(this);

        popSingleExpression();

        exprTransformed.add(javaPrefixExpression);
        return false;
    }

    // Java tree:
    //  Expression:
    //     | ParenthesizedExpression
    //  ParenthesizedExpression: '(' Expression ')'
    // STS tree:
    //  singleExpression:
    //      | OpenParen singleExpression CloseParen   # ParenthesizedExpression
    //
    @Override
    public boolean visit(ParenthesizedExpression javaParenthesizedExpression) {
        pushCurrent(new ParenthesizedExpressionContext(pushSingleExpression()));

        javaParenthesizedExpression.getExpression().accept(this);

        popSingleExpression();

        exprTransformed.add(javaParenthesizedExpression);
        return false;
    }

    // STS tree:
    //    typeParameters: LessThan typeParameterList? MoreThan
    //    typeParameterList: typeParameter (Comma typeParameter)*
    private void createStsTypeParameters(List<TypeParameter> javaTypeParameters) {
        assert(javaTypeParameters != null);

        if (!javaTypeParameters.isEmpty()) {
            pushCurrent(new TypeParametersContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.LessThan)).setParent(stsCurrent);

            // typeParameterList: typeParameter (Comma typeParameter)*
            pushCurrent(new TypeParameterListContext(stsCurrent, 0));

            for (TypeParameter javaTypeParam : javaTypeParameters) {
                javaTypeParam.accept(this);
                // Note: TerminalToken (Comma) is not added to the tree. Check if it works OK.
            }

            popCurrent(); // TypeParameterListContext
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan)).setParent(stsCurrent);
            popCurrent(); // TypeParametersContext;
        }
    }

    private StringBuilder sbForApiMapper = new StringBuilder();

    // STS Tree:
    //    typeArguments: LessThan typeArgumentList? MoreThan
    //    typeArgumentList: typeArgument (Comma typeArgument)*
    //    typeArgument: typeReference | arrayType | wildcardType
    private void translateTypeArguments(List<Type> javaTypeArgs) {
        if (javaTypeArgs != null && !javaTypeArgs.isEmpty()) {
            sbForApiMapper.setLength(0); // Clear the string builder.

            pushCurrent(new TypeArgumentsContext(stsCurrent, 0));

            // typeArgumentList: typeArgument (Comma typeArgument)*
            pushCurrent(new TypeArgumentListContext(stsCurrent, 0));

            for (Type javaTypeArg : javaTypeArgs) {
                pushCurrent(new TypeArgumentContext(stsCurrent, 0));

                if (NodeBuilder.isTypeArgument(javaTypeArg)) {
                    javaTypeArg.accept(this);
                } else {
                    String javaTypeArgName = javaTypeArg.toString();
                    reportError("Invalid type argument " + javaTypeArgName, javaTypeArg);
                    TypeReferenceContext stsTypeArg = NodeBuilder.unknownTypeReference(javaTypeArgName);
                    stsCurrent.addChild(stsTypeArg).setParent(stsCurrent);
                }

                popCurrent(); // TypeArgumentContext

                ITypeBinding javaTypeBinding = javaTypeArg.resolveBinding();

                if (javaTypeBinding != null) {
                    sbForApiMapper.append(javaTypeBinding.getQualifiedName());
                }
                else {
                    reportError("Fail to resolve type argument", javaTypeArg);
                }

                sbForApiMapper.append(',');
            }

            if (sbForApiMapper.length() > 1) {
                sbForApiMapper.setLength(sbForApiMapper.length() - 1); // Remove the ending extra comma.
            }

            popCurrent(); // TypeArgumentListContext
            popCurrent(); // TypeArgumentsContext
        }
    }

    // STS tree:
    //    OpenParen parameterList? CloseParen
    //    parameterList: parameter (Comma parameter)* (Comma variadicParameter)? | variadicParameter
    private void createStsParameterList(List<VariableDeclaration> javaParameters) {
        // OpenParen parameterList? CloseParen
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.OpenParen)).setParent(stsCurrent);

        assert(javaParameters != null);
        if (!javaParameters.isEmpty()) {
            pushCurrent(new ParameterListContext(stsCurrent, 0));

            for (VariableDeclaration javaVariableDeclaration : javaParameters) {
                javaVariableDeclaration.accept(this);
            }

            popCurrent(); // ParameterListContext
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.CloseParen)).setParent(stsCurrent);
    }

    // Java tree:
    //  MethodDeclaration:
    //    [ Javadoc ] { ExtendedModifier } [ < TypeParameter { , TypeParameter } > ] ( Type | void )
    //        Identifier (
    //            [ ReceiverParameter , ] [ FormalParameter { , FormalParameter } ]
    //        ) { Dimension }
    //        [ throws Type { , Type } ]
    //        ( Block | ; )
    // ConstructorDeclaration:
    //    [ Javadoc ] { ExtendedModifier } [ < TypeParameter { , TypeParameter } > ]
    //        Identifier (
    //            [ ReceiverParameter , ] [ FormalParameter { , FormalParameter } ]
    //        ) { Dimension }
    //        [ throws Type { , Type } ]
    //        ( Block | ; )
    // CompactConstructorDeclaration:
    //    [ Javadoc ] ExtendedModifier { ExtendedModifier}
    //        Identifier
    //        ( Block | ; )
    // STS tree:
    // interfaceMember: methodSignature SemiColon                                              #InterfaceMethod
    // classMember:
    //    accessibilityModifier?
    //    (
    //         constructorDeclaration
    //       | classMethodDeclaration
    //       | other alternatives are not relevant for this visitor.
    //    )
    // constructorDeclaration: Constructor OpenParen parameterList? CloseParen constructorBody
    // constructorBody: OpenBrace constructorCall? statementOrLocalDeclaration* CloseBrace
    // classMethodDeclaration
    //    : (Static | Override | Open)? Identifier signature block      #ClassMethodWithBody
    //    | (Abstract | Static? Native | Native Static)? Identifier signature SemiColon      #AbstractOrNativeClassMethod
    // signature: typeParameters? OpenParen parameterList? CloseParen typeAnnotation
    @Override
    public boolean visit(MethodDeclaration javaMethodDeclaration) {
        SignatureContext stsSignature = null;
        ConstructorDeclarationContext stsConstructor = null;
        boolean isInClassContext = stsCurrent instanceof ClassBodyContext;
        assert(isInClassContext || (stsCurrent instanceof InterfaceBodyContext));
        boolean methodHasThrowsClause = false;
        Set<ITypeBinding> javaMethodExceptionSet = new HashSet<>();

        // Sanity check: Constructors cannot be body-less and methods cannot be without return type
        Block javaBlock = javaMethodDeclaration.getBody();
        if (javaMethodDeclaration.isConstructor() && javaBlock == null) {
            // Warn and emit a comment with original source code of the constructor.
            reportError("Invalid constructor declaration without a body", javaMethodDeclaration);
            stsCurrent.addChild(NodeBuilder.dummyNode("Untranslated constructor declaration:\n" +
                                                            javaMethodDeclaration.toString()));
            return false;
        }
        else if (!javaMethodDeclaration.isConstructor() && javaMethodDeclaration.getReturnType2() == null) {
            reportError("Invalid method declaration without return type", javaMethodDeclaration);
            stsCurrent.addChild(NodeBuilder.dummyNode("Untranslated method declaration:\n" +
                                                            javaMethodDeclaration.toString()));
            return false;
        }
        // create thrown exception set for current method
        pushExceptionSet();

        // Get current enclosing context - we'll need it later if
        // current method is synchronized (see below). Also store
        // modifiers of the current method for the same reason.
        // NOTE: This has to happen BEFORE any further pushCurrent
        // or a similar call that changes the value of stsCurrent!
        ParserRuleContext enclosingContext = stsCurrent.getParent();
        int javaMods = javaMethodDeclaration.getModifiers();

        pushCurrent(createDeclarationOrMemberContextWithAccessModifier(javaMods));

        if (javaMethodDeclaration.isConstructor()) {
            stsConstructor = new ConstructorDeclarationContext(stsCurrent, 0);
            pushCurrent(stsConstructor);
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Constructor));

            // STS: typeParameters: LessThan typeParameterList? MoreThan
            createStsTypeParameters(javaMethodDeclaration.typeParameters());

            // STS: OpenParen parameterList? CloseParen
            createStsParameterList(javaMethodDeclaration.parameters());
        }
        else { // A regular method (not a constructor).
            // ClassMethodDeclarationContext object is needed for constructors of AbstractClassMethodContext and ClassMethodWithBodyContext.
            ClassMethodDeclarationContext stsClassMethodDeclaration = new ClassMethodDeclarationContext();
            pushCurrent(stsClassMethodDeclaration);

            if (javaBlock == null) { // Abstract method.
                pushCurrent(new AbstractOrNativeClassMethodContext(stsClassMethodDeclaration));
            } else { // not abstract method
                pushCurrent(new ClassMethodWithBodyContext(stsClassMethodDeclaration));
            }

            stsSignature = translateMethodHeader(javaMethodDeclaration, isInClassContext);
        }

        // process method thrown exceptions
        List<Type> javaExceptions = javaMethodDeclaration.thrownExceptionTypes();
        methodHasThrowsClause = ! javaExceptions.isEmpty();
        for (Type javaExcp : javaExceptions) {
            ITypeBinding javaExcpType = javaExcp.resolveBinding();
            if( !isRuntimeExceptionType(javaExcpType) )
                javaMethodExceptionSet.add(javaExcpType);
        }

        if (javaBlock != null) {
            if (javaMethodDeclaration.isConstructor()) {
                // For ctors, we need ConstructorBodyContext rather than BlockContext
                pushCurrent(new ConstructorBodyContext(stsCurrent, 0));
            } else {
                // Better this than calling javaBlock.accept(this) here
                // as visit(Block) will call pushStatement() which will
                // add StatementContext node which isn't needed here.
                pushCurrent(new BlockContext(stsCurrent, 0));
            }

            // For synchronized methods, inject MonitorEnter and deferred MonitorExit calls
            // in front of all other statements in the method body. The argument of both calls
            // is 'this' for non-static methods and class literal of the enclosing class otherwise.
            if ((javaMods & Modifier.SYNCHRONIZED) != 0) {
                // Figure out enclosing class or interface name. In case we're in anonymous class
                // instance creation context, leave it null - we won't need it as this context
                // doesn't allow static methods for which we need the class or interface name.
                String enclosingTypeName = null;
                if (enclosingContext.getRuleIndex() == StaticTSParser.RULE_classDeclaration)
                    enclosingTypeName = ((ClassDeclarationContext)enclosingContext).Identifier().getText();
                else if (enclosingContext.getRuleIndex() == StaticTSParser.RULE_interfaceDeclaration)
                    enclosingTypeName = ((InterfaceDeclarationContext)enclosingContext).Identifier().getText();

                // Add MonitorEnter call
                // NOTE: The argument has to be added manually as we don't have it in Java AST.
                CallExpressionContext stsMonitorEnterCall = createIntrinsicCall("MonitorEnter");
                SingleExpressionContext stsMonitorEnterCallArg = (javaMods & Modifier.STATIC) == 0
                                                        ? NodeBuilder.thisExpression(null)
                                                        : NodeBuilder.classLiteral(enclosingTypeName);
                NodeBuilder.addArgument(stsMonitorEnterCall, stsMonitorEnterCallArg);

                // Add deferred MonitorExit call
                // NOTE: The argument has to be created again to keep STS AST structure valid
                // and added manually as above.
                pushStatement(new DeferStatementContext(stsCurrent, 0));
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Defer));

                CallExpressionContext stsMonitorExitCall = createIntrinsicCall("MonitorExit");
                SingleExpressionContext stsMonitorExitCallArg = (javaMods & Modifier.STATIC) == 0
                                                        ? NodeBuilder.thisExpression(null)
                                                        : NodeBuilder.classLiteral(enclosingTypeName);
                NodeBuilder.addArgument(stsMonitorExitCall, stsMonitorExitCallArg);

                popStatement(); // DeferStatementContext
            }

            List<Statement> javaBlockStmts = javaBlock.statements();
            for (Statement javaStmt : javaBlockStmts) {
                javaStmt.accept(this);
            }

            popCurrent(); // ConstructorBodyContext or BlockContext
        }

        // If method has 'throws' clause with exceptions which are not panics - add 'throws' in STS
        // else emit message that only panics present
        // If there is no 'throws' - get results from analysis
        if( methodHasThrowsClause && javaMethodExceptionSet.isEmpty()) {
            String message = String.format("Java method '%s' throws only panics", javaMethodDeclaration.getName());
            reportError(message, javaMethodDeclaration);
        }
        if( !javaMethodExceptionSet.isEmpty() || !currentExceptionsSet(javaMethodDeclaration).isEmpty()) {
            if( javaMethodDeclaration.isConstructor() )
                stsConstructor.addChild(NodeBuilder.throwsAnnotation(true)).setParent(stsConstructor);
            else if (stsSignature != null)
                stsSignature.addChild(NodeBuilder.throwsAnnotation(true)).setParent(stsSignature);
        }
        popExceptionSet(); // remove thrown exception set for current method

        if (javaMethodDeclaration.isConstructor()) {
            popCurrent(); // ConstructorDeclarationContext
        } else {
            popCurrent(); // AbstractClassMethodContext or ClassMethodWithBodyContext
            popCurrent(); // ClassMethodDeclarationContext
        }

        popCurrent(); // ClassMemberContext or InterfaceMemberContext

        declTransformed.add(javaMethodDeclaration);
        return false;
    }

    private SignatureContext translateMethodHeader(MethodDeclaration javaMethodDeclaration, boolean isInClassContext) {
        // Non-access modifiers.
        translateNonAccessModifiers(javaMethodDeclaration, isInClassContext);

        // STS: signature: typeParameters? OpenParen parameterList? CloseParen typeAnnotation
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaMethodDeclaration.getName()));
        SignatureContext stsSignature = new SignatureContext(stsCurrent, 0);
        pushCurrent(stsSignature);

        // STS: typeParameters: LessThan typeParameterList? MoreThan
        createStsTypeParameters(javaMethodDeclaration.typeParameters());

        // STS: OpenParen parameterList? CloseParen
        createStsParameterList(javaMethodDeclaration.parameters());

        // typeAnnotation
        if(javaMethodDeclaration.getReturnType2() != null) {
            pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
            javaMethodDeclaration.getReturnType2().accept(this);
        }
        else {
            // Warn and emit __UnknownType__ as variable type
            reportError("Failed to resolve method returned type", javaMethodDeclaration);
            stsCurrent.addChild(NodeBuilder.unknownTypeAnnotation()).setParent(stsCurrent);
        }

        int javaExtraDims = javaMethodDeclaration.getExtraDimensions();
        if (javaExtraDims > 0) NodeBuilder.addExtraDimensions(stsCurrent, javaExtraDims);

        popCurrent(); // TypeAnnotationContext
        popCurrent(); // SignatureContext
        return stsSignature;
    }

    // Java tree:
    //     SingleVariableDeclaration: { ExtendedModifier } Type {Annotation} [ ... ] Identifier { Dimension } [ = Expression ]
    // STS tree for formal parameter:
    //    parameter: Identifier typeAnnotation
    // or
    //    variadicParameter: Ellipsis Identifier typeAnnotation
    @Override
    public boolean visit(SingleVariableDeclaration javaSingleVariableDeclaration) {
        if (javaSingleVariableDeclaration.isVarargs()) {
            pushCurrent(new VariadicParameterContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Ellipsis));
        }
        else {
            pushCurrent(new ParameterContext(stsCurrent, 0));
        }

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaSingleVariableDeclaration.getName()));

        // Parameter type
        pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
        javaSingleVariableDeclaration.getType().accept(this);

        int extraDims = javaSingleVariableDeclaration.getExtraDimensions();
        if (extraDims > 0) NodeBuilder.addExtraDimensions(stsCurrent, extraDims);

        popCurrent(); // TypeAnnotationContext
        popCurrent(); // ParameterContext | VariadicParameterContext

        declTransformed.add(javaSingleVariableDeclaration);
        return false;
    }

    // Java tree:
    //    VariableDeclarationFragment:
    //       Identifier { Dimension } [ = Expression ]
    // STS tree for formal parameter:
    //    parameter:
    //       Identifier typeAnnotation
    @Override
    public boolean visit(VariableDeclarationFragment javaVariableDeclarationFragment) {
        // Here, VariableDeclarationFragment node represents lambda's parameter
        // with omitted parameter type.

        pushCurrent(new ParameterContext(stsCurrent, 0));

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaVariableDeclarationFragment.getName()));

        IVariableBinding variableBinding = javaVariableDeclarationFragment.resolveBinding();

        if (variableBinding != null) {
            translateTypeBinding(variableBinding.getType(), javaVariableDeclarationFragment);
        }
        else {
            // Warn and emit __UnknownType__ as variable type
            reportError("Failed to resolve lambda parameter", javaVariableDeclarationFragment);
            stsCurrent.addChild(NodeBuilder.unknownTypeAnnotation()).setParent(stsCurrent);
        }

        // Note: no need to process the "{ Dimension }" part, as the extra dimensions
        // of the declaration are covered by "translateType(ITypeBinding)" call.

        popCurrent(); // ParameterContext

        declTransformed.add(javaVariableDeclarationFragment);
        return false;
    }

    // NOTE: All Java enums are translated into STS classes because of
    // built-in methods values() and valueOf() available to the former!
    //
    // Java tree:
    // EnumDeclaration:
    //     [ Javadoc ] { ExtendedModifier } enum Identifier
    //         [ implements Type { , Type } ]
    //         {
    //         [ EnumConstantDeclaration { , EnumConstantDeclaration } ] [ , ]
    //         [ ; { ClassBodyDeclaration | ; } ]
    //         }
    //
    // STS tree:
    // TopDeclarationContext | ClassMemberContext | InterfaceMemberContext
    //      TerminalNode <export>? (for TopDeclarationContext)
    //    | AccessibilityModifierContext? (for ClassMemberContext or InterfaceMemberContext)
    //    ClassDeclarationContext
    //       TerminalNode <class>
    //       Identifier
    //       ClassExtendsClauseContext
    //           TerminalNode <extends>
    //           TypeReferenceContext
    //               QualifiedNameContext
    //                   TerminalNode <Enum>
    //      ImplementsClauseContext
    //          TerminalNode <implements>
    //          InterfaceTypeListContext
    //              TypeReferenceContext
    //                  QualifiedNameContext
    //                      TerminalNode <ClassName>
    //              TerminalNode <,>
    //              TypeReferenceContext
    //                  QualifiedNameContext
    //                      TerminalNode <ClassName>
    //       ClassBodyContext
    @Override
    public boolean visit(EnumDeclaration javaEnumDeclaration) {
        // Create appropriate member context to put declaration into.
        int javaEnumMods = javaEnumDeclaration.getModifiers();
        pushCurrent(createDeclarationOrMemberContextWithAccessModifier(javaEnumMods));

        // Create class declaration context
        ClassDeclarationContext stsClassDecl = new ClassDeclarationContext(stsCurrent, 0);
        pushCurrent(stsClassDecl);

        // Set static modifier as necessary.
        if (stsCurrent.getParent().getRuleIndex() != StaticTSParser.RULE_topDeclaration) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));
        }

        // Add class keyword and enum name
        SimpleName javaEnumName = javaEnumDeclaration.getName();
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Class));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaEnumName));

        // Add extends clause.
        createEnumExtendsClause(javaEnumName.getIdentifier());

        // Add implements clause, if necessary
        translateSuperInterfaceTypes(javaEnumDeclaration.superInterfaceTypes());

        pushCurrent(new ClassBodyContext(stsCurrent, 0));

        // Translate enum constants.
        // If any of the constants contain anonymous class body (e.g., extend enum type),
        // add open modifier to the resulting class.
        boolean needOpen = false;
        int javaEnumConstOrdinal = 0;
        List<String> javaEnumConstNames = new ArrayList<>();
        List<EnumConstantDeclaration> javaEnumConstants = javaEnumDeclaration.enumConstants();
        for (EnumConstantDeclaration javaEnumConst : javaEnumConstants) {
            if (!needOpen) needOpen = javaEnumConst.getAnonymousClassDeclaration() != null;

            // Pass enum name and ordinal to enum constant node before visiting it
            // as we'll need it to create appropriate initializers.
            javaEnumConst.setProperty(ENUM_TYPE_NAME, javaEnumName.getIdentifier());
            javaEnumConst.setProperty(ENUM_CONST_ORDINAL, String.valueOf(javaEnumConstOrdinal));

            // Store enum constant name in a list - we'll need it later to generate
            // built-in values() method
            javaEnumConstNames.add(javaEnumConst.getName().getIdentifier());

            javaEnumConst.accept(this);
            ++javaEnumConstOrdinal;
        }
        if (needOpen) {
            stsClassDecl.children.add(0, NodeBuilder.terminalNode(StaticTSParser.Open));
        }

        // Translate body declarations (ctors, methods, nested types, and fields).
        boolean hasCtors = false;
        List<BodyDeclaration> javaEnumBodyDecls = javaEnumDeclaration.bodyDeclarations();
        for (BodyDeclaration javaEnumBodyDecl : javaEnumBodyDecls) {
            javaEnumBodyDecl.accept(this);
            if (!hasCtors) {
                if (javaEnumBodyDecl.getNodeType() == ASTNode.METHOD_DECLARATION) {
                    MethodDeclaration javaEnumMethodDecl = (MethodDeclaration) javaEnumBodyDecl;
                    hasCtors = javaEnumMethodDecl.isConstructor();
                }
            }
        }

        // Add values and valueOf built-in methods
        String javaEnumTypeName = javaEnumDeclaration.getName().getIdentifier();
        createEnumValuesMethod(javaEnumTypeName, javaEnumConstNames);
        createEnumValueOfMethod(javaEnumTypeName);

        // Add name and ordinal parameters to all ctors.
        if (!hasCtors) {
            // If no ctors present, generate default one with just the two parameters above,
            // and a single super(name, ordinal) call in the body.
            createEnumDefaultCtor();
        }
        else {
            // For all non-default ctors - if there is no call to another ctor in the body,
            // generate super(name, ordinal) call, otherwise pass name and ordinal to existing ctor call.
            ClassBodyContext stsEnumClassBody = (ClassBodyContext)stsCurrent;
            for (ClassMemberContext stsEnumClassMember : stsEnumClassBody.classMember()) {
                ConstructorDeclarationContext stsEnumCtor = stsEnumClassMember.constructorDeclaration();
                if (stsEnumCtor != null) {
                    modifyEnumCtor(stsEnumCtor);
                }
            }
        }

        // Process instance initializers, if any.
        // NOTE: This has to happen here, after default ctor is generated if necessary,
        // (see above), as default ctor of enum class is different from the one that
        // addInstanceInitializersToCtors can create.
        addInstanceInitializersToCtors(javaEnumDeclaration);

        popCurrent(); // ClassBodyContext
        popCurrent(); // stsClassDecl
        popCurrent(); // member context

        declTransformed.add(javaEnumDeclaration);
        return false;
    }

    private void createEnumDefaultCtor() {
        pushCurrent(new ClassMemberContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.accessibilityModifier(Modifier.PRIVATE)).setParent(stsCurrent);
        pushCurrent(new ConstructorDeclarationContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Constructor));
        pushCurrent(new ParameterListContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.parameter("name", "String")).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.parameter("ordinal", PrimitiveType.INT)).setParent(stsCurrent);
        popCurrent(); // ParameterListContext
        pushCurrent(new ConstructorBodyContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.ctorCall(true, "name", "ordinal")).setParent(stsCurrent);
        popCurrent(); // ConstructorBodyContext
        popCurrent(); // ConstructorDeclarationContext
        popCurrent(); // ClassMemberContext
    }

    private void modifyEnumCtor(ConstructorDeclarationContext stsEnumCtor) {
        // Get parameter list or create if there isn't one
        ParameterListContext stsEnumCtorParams = stsEnumCtor.parameterList();
        if (stsEnumCtorParams == null) {
            // ParameterListContext ctor doesn't initialize children field
            // which we use below, so initialize it explicitly.
            stsEnumCtorParams = new ParameterListContext(stsEnumCtor, 0);
            stsEnumCtorParams.children = new ArrayList<>();

            stsEnumCtor.addChild(stsEnumCtorParams).setParent(stsEnumCtor);
        }

        // Inject name and ordinal parameters
        ParameterContext stsEnumCtorParam = NodeBuilder.parameter("name", "String");
        stsEnumCtorParams.children.add(0, stsEnumCtorParam);
        stsEnumCtorParam.setParent(stsEnumCtorParams);
        stsEnumCtorParam = NodeBuilder.parameter("ordinal", PrimitiveType.INT);
        stsEnumCtorParams.children.add(1, stsEnumCtorParam);
        stsEnumCtorParam.setParent(stsEnumCtorParams);

        ConstructorBodyContext stsEnumCtorBody = stsEnumCtor.constructorBody();
        ConstructorCallContext stsEnumCtorCall = stsEnumCtorBody.getRuleContext(ConstructorCallContext.class, 0);
        if (stsEnumCtorCall == null) {
            // Create super(name, ordinal) call
            stsEnumCtorBody.addChild(NodeBuilder.ctorCall(true, "name", "ordinal")).setParent(stsEnumCtorBody);
        }
        else {
            // Pass name and ordinal parameters to ctor call
            ArgumentsContext stsEnumCtorCallArgs = stsEnumCtorCall.arguments();
            ExpressionSequenceContext stsExprSeq = stsEnumCtorCallArgs.expressionSequence();
            if (stsExprSeq == null) {
                // Create expression sequence node, if necessary
                // ExpressionSequenceContext ctor doesn't initialize children field
                // which we use below, so initialize it explicitly.
                stsExprSeq = new ExpressionSequenceContext(stsEnumCtorCallArgs, 0);
                stsExprSeq.children = new ArrayList<>();

                stsEnumCtorCallArgs.addChild(stsExprSeq).setParent(stsEnumCtorCallArgs);
            }

            SingleExpressionContext stsEnumCtorCallArg = NodeBuilder.identifierExpression("name");
            stsExprSeq.children.add(0, stsEnumCtorCallArg);
            stsEnumCtorCallArg.setParent(stsExprSeq);
            stsEnumCtorCallArg = NodeBuilder.identifierExpression("ordinal");
            stsExprSeq.children.add(1, stsEnumCtorCallArg);
            stsEnumCtorCallArg.setParent(stsExprSeq);
        }
    }

    private void createEnumExtendsClause(String javaEnumName) {
        // Note: A Java enum extends Enum<enum name> class.
        pushCurrent(new ClassExtendsClauseContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.EXTENDS));
        pushCurrent(NodeBuilderBase.typeReference("Enum"));
        ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount()-1);
        pushCurrent((TypeReferencePartContext)lastChild, false);
        pushCurrent(new TypeArgumentsContext(stsCurrent, 0));
        pushCurrent(new TypeArgumentListContext(stsCurrent, 0));
        pushCurrent(new TypeArgumentContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilderBase.typeReference(javaEnumName)).setParent(stsCurrent);
        popCurrent(); // TypeArgumentContext
        popCurrent(); // TypeArgumentListContext
        popCurrent(); // TypeArgumentsContext
        popCurrent(); // (TypeReferencePartContext)lastChild
        popCurrent(); // TypeReferenceContext
        popCurrent(); // ClassExtendsClauseContext
    }

    private void pushEnumBuiltinMethod() {
        // Create class member context and add public modifier
        pushCurrent(new ClassMemberContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.accessibilityModifier(Modifier.PUBLIC));

        // Create class method declaration context and add static modifier
        pushCurrent(new ClassMethodDeclarationContext(stsCurrent, 0));
        pushCurrent(new ClassMethodWithBodyContext((ClassMethodDeclarationContext)stsCurrent));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));
    }

    private void popEnumBuiltinMethod() {
        popCurrent(); // ClassMethodWithBodyContext
        popCurrent(); // ClassMethodDeclarationContext
        popCurrent(); // ClassMemberContext
    }

    // Generates the following method
    // public static values() : <enum type>[] {
    //     return [ <enum constant1>, <enum constant2>, ... ];
    // }
    private void createEnumValuesMethod(String javaEnumTypeName, List<String> javaEnumConstNames) {
        pushEnumBuiltinMethod();

        // Add method name and signature
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("values"));
        pushCurrent(new SignatureContext(stsCurrent, 0));
        ArrayTypeContext stsReturnType = NodeBuilder.arrayType(javaEnumTypeName, 1);
        stsCurrent.addChild(NodeBuilder.typeAnnotation(stsReturnType)).setParent(stsCurrent);
        popCurrent(); // SignatureContext

        // Add method body
        // return [ enum_constant1, enum_constant2, ... ];
        pushCurrent(new BlockContext(stsCurrent, 0));
        pushStatement(new ReturnStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Return));
        pushCurrent(new ArrayLiteralExpressionContext(pushSingleExpression()));
        pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));
        for (String javaEnumConstName : javaEnumConstNames) {
            stsCurrent.addChild(NodeBuilder.identifierExpression(javaEnumConstName)).setParent(stsCurrent);
        }
        popCurrent(); // ExpressionSequenceContext
        popSingleExpression(); // ArrayLiteralExpressionContext
        popStatement(); // ReturnStatementContext
        popCurrent(); // BlockContext

        popEnumBuiltinMethod();
    }

    // Generates the following method:
    // public static valueOf(String name) : <enum type> {
    //    for (let value : <enum type> of values()) {
    //        if (name == value.toString()) return value;
    //    }
    //    return null;
    // }
    private void createEnumValueOfMethod(String javaEnumTypeName) {
        pushEnumBuiltinMethod();

        // Add method name and signature
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("valueOf"));
        pushCurrent(new SignatureContext(stsCurrent, 0));
        pushCurrent(new ParameterListContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.parameter("name", "String")).setParent(stsCurrent);
        popCurrent(); // ParameterListContext
        stsCurrent.addChild(NodeBuilder.typeAnnotation(javaEnumTypeName)).setParent(stsCurrent);
        popCurrent(); // SignatureContext

        // Add method body
        // for (let value : <enum type> of values()) {
        pushCurrent(new BlockContext(stsCurrent, 0));
        pushCurrent(new ForOfStatementContext(pushIterationStatement()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.For));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Let));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("value"));
        stsCurrent.addChild(NodeBuilder.typeAnnotation(javaEnumTypeName)).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.OF));
        pushCurrent(new CallExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression("values")).setParent(stsCurrent);
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        popCurrent(); // ArgumentsContext
        popSingleExpression(); // CallExpressionContext
        pushStatement(new BlockContext(stsCurrent, 0));

        // if (name == value.toString()) return value;
        IfStatementContext stsIfStmt = new IfStatementContext(stsCurrent, 0);
        pushStatement(stsIfStmt);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.If));
        pushCurrent(new EqualityExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression("name")).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Equals));
        pushCurrent(new CallExpressionContext(pushSingleExpression()));
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression("value")).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("toString"));
        popSingleExpression(); // MemberAccessExpressionContext
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        popCurrent(); // ArgumentsContext
        popSingleExpression(); // CallExpressionContext
        popSingleExpression(); // EqualityExpressionContext
        pushStatement(new ReturnStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Return));
        stsCurrent.addChild(NodeBuilder.identifierExpression("value")).setParent(stsCurrent);
        popStatement(); // ReturnStatementContext
        ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(lastChild instanceof StatementContext);
        stsIfStmt.ifStmt = (StatementContext)lastChild;
        popStatement(); // IfStatementContext

        // close off for-of statement
        popStatement(); // BlockContext
        popIterationStatement(); // ForOfStatementContext

        // return null;
        pushStatement(new ReturnStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Return));
        stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
        popStatement(); // ReturnStatementContext

        // close off method body
        popCurrent(); // BlockContext

        popEnumBuiltinMethod();
    }

    @Override
    public boolean visit(EnumConstantDeclaration javaEnumConstant) {
        // Create class member context and add public modifier
        pushCurrent(new ClassMemberContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.accessibilityModifier(Modifier.PUBLIC));

        // Create class field declaration context and add static and const modifiers
        pushCurrent(new ClassFieldDeclarationContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.READONLY));

        // Create constant declaration context and add enum constant name and type
        pushCurrent(new ConstantDeclarationContext(stsCurrent, 0));
        String javaEnumConstName = javaEnumConstant.getName().getIdentifier();
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaEnumConstName));
        String javaEnumTypeName = (String)javaEnumConstant.getProperty(ENUM_TYPE_NAME);
        pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
        pushCurrent(new PrimaryTypeContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilderBase.typeReference(javaEnumTypeName)).setParent(stsCurrent);
        popCurrent(); // PrimaryTypeContext
        popCurrent(); // TypeAnnotation

        // Add initializer to constant declaration context
        pushCurrent(new InitializerContext(stsCurrent, 0));
        pushCurrent(new NewClassInstanceExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.New));
        stsCurrent.addChild(NodeBuilderBase.typeReference(javaEnumTypeName)).setParent(stsCurrent);

        // Process ctor arguments, if any.
        // NOTE: Always insert name and ordinal as first two ctor arguments!
        List<Expression> javaEnumConstArgs = javaEnumConstant.arguments();
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.stringLiteral(javaEnumConstName)).setParent(stsCurrent);
        String javaEnumConstOrdinal = (String)javaEnumConstant.getProperty(ENUM_CONST_ORDINAL);
        stsCurrent.addChild(NodeBuilder.numericLiteral(javaEnumConstOrdinal)).setParent(stsCurrent);
        if (javaEnumConstArgs != null && !javaEnumConstArgs.isEmpty()) {
            for (Expression javaEnumConstArg : javaEnumConstArgs) {
                javaEnumConstArg.accept(this);
            }
        }
        popCurrent(); // ExpressionSequenceContext
        popCurrent(); // ArgumentsContext

        // Process anonymous class body, if any
        AnonymousClassDeclaration javaEnumConstClassBody = javaEnumConstant.getAnonymousClassDeclaration();
        if (javaEnumConstClassBody != null) {
            javaEnumConstClassBody.accept(this);
        }

        popSingleExpression(); // NewClassInstanceExpressionContext
        popCurrent(); // InitializerContext

        popCurrent(); // ConstantDeclarationContext
        popCurrent(); // ClassFieldDeclarationContext
        popCurrent(); // ClassMemberContext

        declTransformed.add(javaEnumConstant);
        return false;
    }

    private void translateBlockStatements(Block javaBlock) {
        List<Statement> javaBlockStmts = javaBlock.statements();
        for(Statement javaStmt : javaBlockStmts) {
            javaStmt.accept(this);
        }
    }

    @Override
    public boolean visit(Block javaBlock) {
        pushStatement(new BlockContext(stsCurrent, 0));
        translateBlockStatements(javaBlock);
        popStatement(); // BlockContext

        stmtTransformed.add(javaBlock);
        return false;
    }

    // Drop empty statements if in block context,
    // replace by null literal if in labelled statement context,
    // otherwise replace with empty block.
    @Override
    public boolean visit(EmptyStatement javaEmptyStmnt) {
        if (stsCurrent.getRuleIndex() != StaticTSParser.RULE_block) {
            if (stsCurrent.getRuleIndex() == StaticTSParser.RULE_labelledStatement) {
                pushStatement(new ExpressionStatementContext(null, 0));
                stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
            } else {
                pushStatement(new BlockContext(stsCurrent, 0));
            }

            popStatement();
        }

        stmtTransformed.add(javaEmptyStmnt);
        return false;
    }

    // Statements translation:
    // every sts statement block should be enveloped by sts StatementContext node
    //
    @Override
    public boolean visit(LabeledStatement javaLabeledStmnt) {
        pushStatement(new LabelledStatementContext(null, 0));

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaLabeledStmnt.getLabel()));
        javaLabeledStmnt.getBody().accept(this);

        popStatement();

        stmtTransformed.add(javaLabeledStmnt);
        return false;
    }

    // STS tree:
    //    Let variableDeclarationList | Const constantDeclarationList
    private ParserRuleContext createVarOrConstDeclarationList(int javaModifiers) {
        if ((javaModifiers & Modifier.FINAL) != 0 ) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Const));
            return new ConstantDeclarationListContext(stsCurrent, 0);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Let));
        return new VariableDeclarationListContext(stsCurrent, 0);
    }

    private ParserRuleContext createVarOrConstDeclaration(int javaModifiers) {
        if ((javaModifiers & Modifier.FINAL) != 0 )
            return new ConstantDeclarationContext(stsCurrent, 0);

        return new VariableDeclarationContext(stsCurrent, 0);
    }

    private void createAndFillVarOrConstDeclarationList(int javaModifiers, List<VariableDeclarationFragment> javaVarDeclFragments, Type javaType) {
        createAndFillVarOrConstDeclarationList(javaModifiers, javaVarDeclFragments, javaType, true);
    }

    private void createAndFillVarOrConstDeclarationList(int javaModifiers, List<VariableDeclarationFragment> javaVarDeclFragments, Type javaType, boolean translateVarInitializers) {
        pushCurrent(createVarOrConstDeclarationList(javaModifiers));

        for (VariableDeclarationFragment javaVarDeclFragment : javaVarDeclFragments) {
            pushCurrent(createVarOrConstDeclaration(javaModifiers));

            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaVarDeclFragment.getName()));

            pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Colon));
            javaType.accept(this);
            popCurrent(); // TypeAnnotationContext

            if (translateVarInitializers) {
                Expression javaInitializer = javaVarDeclFragment.getInitializer();

                if (javaInitializer != null) {
                    pushCurrent(new InitializerContext(stsCurrent, 0));
                    stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
                    javaInitializer.accept(this);
                    popCurrent(); // InitializerContext
                }
            }

            popCurrent(); // VarOrConstDeclaration
            declTransformed.add(javaVarDeclFragment); // Each VariableDeclarationFragment is a separate declaration construct!
        }

        popCurrent(); // VarOrConstDeclarationList
    }

    // Java tree:
    //  Statement:
    //     | VariableDeclarationStatement
    //  VariableDeclarationStatement:  { ExtendedModifier } Type VariableDeclarationFragment { , VariableDeclarationFragment } ;
    // STS tree:
    //    topDeclaration: Export?
    //        | variableStatement
    //    variableStatement: ((Let variableDeclarationList) | (Const constantDeclarationList)) SemiColon
    //    variableDeclarationList:
    //        variableDeclaration (Comma variableDeclaration)*
    //    variableDeclaration: Identifier typeAnnotation initializer? | Identifier initializer
    //    constantDeclarationList:
    //        constantDeclaration (Comma constantDeclaration)*
    //    constantDeclaration: Identifier typeAnnotation? initializer
    @Override
    public boolean visit(VariableDeclarationStatement javaVarStmnt) {
        pushStatement(new VariableOrConstantDeclarationContext(null, 0));
        createAndFillVarOrConstDeclarationList(javaVarStmnt.getModifiers(), javaVarStmnt.fragments(), javaVarStmnt.getType());
        popStatement(); // VariableStatementContext

        stmtTransformed.add(javaVarStmnt);
        return false;
    }

    // Java tree:
    //  Expression:
    //     | VariableDeclarationExpression: { ExtendedModifier } Type VariableDeclarationFragment { , VariableDeclarationFragment }
    // STS tree:
    //    variableDeclarationList:
    //        variableDeclaration (Comma variableDeclaration)*
    @Override
    public boolean visit(VariableDeclarationExpression javaVarDeclExpr) {
        // Drop 'final' modifier if we're inside for statement, as
        // STS doesn't allow constant declarations in that context.
        int javaMods = javaVarDeclExpr.getModifiers();
        if (javaVarDeclExpr.getParent().getNodeType() == ASTNode.FOR_STATEMENT) {
            if (Modifier.isFinal(javaMods)) {
                javaMods = javaMods & ~Modifier.FINAL;
            }
        }

        createAndFillVarOrConstDeclarationList(javaMods, javaVarDeclExpr.fragments(), javaVarDeclExpr.getType());

        exprTransformed.add(javaVarDeclExpr);
        return false;
    }

    // Java tree:
    //   IfStatement:
    //     if ( Expression ) Statement [ else Statement ]
    // STS tree:
    //   ifStatement:
    //     If OpenParen singleExpression CloseParen ifStmt=statement (Else elseStmt=statement)?
    @Override
    public boolean visit(IfStatement javaIfStmt) {
        IfStatementContext stsIfStmt = new IfStatementContext(null, 0);
        pushStatement(stsIfStmt);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.If));
        javaIfStmt.getExpression().accept(this); // It has to add SingleExpression

        javaIfStmt.getThenStatement().accept(this);

        // Now the last child of stsCurrent has to be StatementContext.
        ParseTree stsIfThenStmt = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(stsIfThenStmt instanceof StatementContext);
        stsIfStmt.ifStmt = (StatementContext) stsIfThenStmt;

        Statement javaElseStmt = javaIfStmt.getElseStatement();
        if(javaElseStmt != null) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Else));
            javaElseStmt.accept(this);

            // Now the last child of stsCurrent has to be StatementContext.
            ParseTree stsElseStmt = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
            assert(stsElseStmt instanceof StatementContext);
            stsIfStmt.elseStmt = (StatementContext) stsElseStmt;
        }

        popStatement(); // IfStatementContext

        stmtTransformed.add(javaIfStmt);
        return false;
    }

    @Override
    public boolean visit(WhileStatement javaWhileStmt) {
        pushCurrent(new WhileStatementContext(pushIterationStatement()));

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.While));
        Expression javaExpr = javaWhileStmt.getExpression();
        assert(javaExpr != null);
        javaExpr.accept(this);

        Statement javaLoopBody = javaWhileStmt.getBody();
        assert(javaLoopBody != null);
        javaLoopBody.accept(this);

        popIterationStatement(); // WhileStatementContext

        stmtTransformed.add(javaWhileStmt);
        return false;
    }


    @Override
    public boolean visit(DoStatement javaDoStmt) {
        pushCurrent(new DoStatementContext(pushIterationStatement()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Do));

        Statement javaLoopBody = javaDoStmt.getBody();
        assert(javaLoopBody != null);
        javaLoopBody.accept(this);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.While));

        Expression javaExpr = javaDoStmt.getExpression();
        assert(javaExpr != null);
        javaExpr.accept(this);

        popIterationStatement(); // DoStatementContext

        stmtTransformed.add(javaDoStmt);
        return false;
    }


    // Java tree:
    //    Initializer:
    //       [ static ] Block
    // STS tree:
    //    classInitializer:
    //       static block
    @Override
    public boolean visit(Initializer javaInitializer) {
        // Sanity check: Initializers are allowed only in class body context.
        if (stsCurrent.getRuleIndex() != StaticTSParser.RULE_classBody) {
            // Warn and emit a comment with original source code of initializer
            reportError("Invalid context for initializer", javaInitializer);
            stsCurrent.addChild(NodeBuilder.dummyNode("Untranslated initializer:\n" +
                                                        javaInitializer.toString()));
            return false;
        }

        ASTNode javaInitParent = javaInitializer.getParent();
        Set<ITypeBinding> javaInitThrownExceptions = (Set<ITypeBinding>) javaInitParent.getProperty(INIT_THROWN_EXEPTIONS);
        if( javaInitThrownExceptions == null ) {
            javaInitThrownExceptions = new HashSet<ITypeBinding>();
            javaInitParent.setProperty(INIT_THROWN_EXEPTIONS, javaInitThrownExceptions);
        }

        boolean isStatic = Modifier.isStatic(javaInitializer.getModifiers());

        if (isStatic) {
            // StaticTS permits only one static initializer per class declaration.
            // Thus, we gather statements from all Java's static initializers
            // into one single static initializer block in StaticTS code.
            ClassBodyContext stsClassBody = (ClassBodyContext) stsCurrent;
            if (stsClassBody.clinit != null) {
                // Note: Class initializer is already added to parent context's children,
                // thus use the flag to prevent adding it again.
                pushCurrent(stsClassBody.clinit, false);
            } else {
                // Create new class initializer context and push into stack.
                stsClassBody.clinit = new ClassInitializerContext(stsCurrent, 0);
                pushCurrent(stsClassBody.clinit, true);

                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Static));
            }

            // If we translated class initializer earlier, add statements from this one
            // to its block. Otherwise, translate the body of this initializer as block.
            if (stsCurrent.getChildCount() > 1) {
                ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
                pushCurrent((ParserRuleContext) lastChild, false);
            }
            else {
                // Better this than calling javaBlock.accept(this) here as
                // it will add StatementContext node which we don't need here.
                pushCurrent(new BlockContext(stsCurrent, 0));
            }

            List<Statement> javaStmts = javaInitializer.getBody().statements();
            for (Statement javaStmt : javaStmts) {
                javaStmt.accept(this);
            }

            popCurrent(); // BlockContext or lastChild (which is also BlockContext)
            popCurrent(); // ClassInitializerContext
        } else {
            // StaticTS doesn't have syntax for separate instance initializer blocks.
            // We gather all statements from such blocks in class declaration and place
            // at the beginning of all constructor's bodies that don't call another constructor.
            List<StatementOrLocalDeclarationContext> stsInitStmts = (List<StatementOrLocalDeclarationContext>) javaInitParent.getProperty(INSTANCE_INITIALIZER);

            if (stsInitStmts == null) {
                stsInitStmts = new ArrayList<>();
                javaInitParent.setProperty(INSTANCE_INITIALIZER, stsInitStmts);
            }

            // Use dummy block here to gather translated statements. Do not
            // add this block to children of the current top node on stack.
            BlockContext stsBlock = new BlockContext(null, 0);
            pushCurrent(stsBlock, false);

            pushExceptionSet();

            List<Statement> javaStmts = javaInitializer.getBody().statements();
            for(Statement javaStmt : javaStmts) {
                javaStmt.accept(this);
            }

            javaInitThrownExceptions.addAll(currentExceptionsSet(javaInitializer));
            popExceptionSet();

            popCurrent(); // BlockContext

            stsInitStmts.addAll(stsBlock.statementOrLocalDeclaration());
        }

        declTransformed.add(javaInitializer);
        return false;
    }

    // Java AST:
    //    TypeName {[ ]} . class
    //    NumericType {[ ]} . class
    //    boolean {[ ]} . class
    //    void . class
    // STS AST:
    //    SingleExpressionContext
    //      ClassLiteralExpressionContext
    //          PrimaryTypeContext . class
    @Override
    public boolean visit(TypeLiteral javaTypeLiteral) {
        pushCurrent(new ClassLiteralExpressionContext(pushSingleExpression()));

        // Translate type
        javaTypeLiteral.getType().accept(this);

        // Add . and class tokens
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Dot));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Class));

        popSingleExpression(); // ClassLiteralExpressionContext

        exprTransformed.add(javaTypeLiteral);
        return false;
    }

    // Java tree:
    //    ExpressionStatement:
    //       Expression ;
    // STS tree:
    //    expressionStatement:
    //       singleExpression SemiColon?
    @Override
    public boolean visit(ExpressionStatement javaExprStmt) {
        pushStatement(new ExpressionStatementContext(null, 0));
        javaExprStmt.getExpression().accept(this);
        popStatement();

        stmtTransformed.add(javaExprStmt);
        return false;
    }

    private SingleExpressionContext createStsAssignmentExpression(Assignment javaAssignment) {
        if (javaAssignment.getOperator() == Assignment.Operator.ASSIGN) {
            return new AssignmentExpressionContext(pushSingleExpression());
        }

        return new AssignmentOperatorExpressionContext(pushSingleExpression());
    }

    // Java tree:
    //    Assignment:
    //       Expression AssignmentOperator Expression
    // STS tree:
    //    singleExpression:
    //       | singleExpression Assign singleExpression              # AssignmentExpression
    //       | singleExpression assignmentOperator singleExpression  # AssignmentOperatorExpression
    @Override
    public boolean visit(Assignment javaAssignment) {
        pushCurrent(createStsAssignmentExpression(javaAssignment));

        javaAssignment.getLeftHandSide().accept(this);

        if (javaAssignment.getOperator() == Assignment.Operator.ASSIGN) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
        } else {
            // Handle compound assignment operator.
            AssignmentOperatorContext stsAssignOp = NodeBuilder.assignmentOperator(javaAssignment.getOperator());
            stsCurrent.addChild(stsAssignOp).setParent(stsCurrent);
        }

        javaAssignment.getRightHandSide().accept(this);

        popSingleExpression(); // AssignmentExpressionContext or AssignmentOperatorExpressionContext

        exprTransformed.add(javaAssignment);
        return false;
    }

    // Java tree:
    //    AssertStatement:
    //       assert Expression [ : Expresion ] ;
    // STS tree:
    //    assertStatement:
    //       Assert condition=singleExpression (Colon message=singleExpression)? SemiColon
    @Override
    public boolean visit(AssertStatement javaAssertStmt) {
        AssertStatementContext stsAssertStmtContext = new AssertStatementContext(null, 0);
        pushStatement(stsAssertStmtContext);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assert));
        javaAssertStmt.getExpression().accept(this);
        ParseTree stsCondition = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(stsCondition instanceof SingleExpressionContext);
        stsAssertStmtContext.condition = (SingleExpressionContext) stsCondition;

        Expression message = javaAssertStmt.getMessage();
        if (message != null) {
            message.accept(this);
            ParseTree stsMessage = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
            assert(stsMessage instanceof SingleExpressionContext);
            stsAssertStmtContext.message = (SingleExpressionContext) stsMessage;
        }

        popStatement();

        stmtTransformed.add(javaAssertStmt);
        return false;
    }

    // Java tree:
    //    ConstructorInvocation:
    //       [ < Type { , Type } > ]
    //       this ( [ Expression { , Expression } ] ) ;
    // STS tree:
    //    constructorCall:
    //    Try?
    //    (
    //      This typeArguments? arguments
    //      | (singleExpression Dot)? Super typeArguments? arguments
    //    )
    @Override
    public boolean visit(ConstructorInvocation javaCtorInvocation) {
        translateCtorInvocation(NodeBuilder.terminalNode(StaticTSParser.This), javaCtorInvocation.typeArguments(),
                null, javaCtorInvocation.arguments(), javaCtorInvocation.resolveConstructorBinding(),
                javaCtorInvocation);

        return false;
    }

    // NOTE: If ctor called can throw exceptions, prepend 'try' keyword to result.
    private void translateCtorInvocation(TerminalNode stsThisOrSuper, List<Type> javaTypeArgs,
                                         Expression javaCtorExpr, List<Expression> javaArgs,
                                         IMethodBinding javaCtorBinding, ASTNode javaCtorInvocation) {
        boolean isThrowingCall = false;

        ConstructorCallContext stsConstructorCall = new ConstructorCallContext(stsCurrent, 0);


        ITypeBinding javaClassType = null;
        if (javaCtorExpr != null) {
            javaClassType = javaCtorExpr.resolveTypeBinding();
        }

        ITypeBinding[] javaParamsTypes = null;

        if (javaCtorBinding != null) {
            isThrowingCall = javaCtorBinding.getExceptionTypes().length > 0;
            if(isThrowingCall && checkThrownExceptionSet(javaCtorInvocation))
                addMultipleThrownExceptions(javaCtorBinding.getExceptionTypes());

            javaParamsTypes = javaCtorBinding.getParameterTypes();
            stsConstructorCall.javaMethodArgs = NodeBuilder.buildTypeArgsSignature(javaParamsTypes);

            if (javaCtorExpr == null) {
                javaClassType = javaCtorBinding.getDeclaringClass();
            }
        }
        else {
            reportError("Failed to resolve constructor call", javaCtorInvocation);
        }

        if (javaClassType != null) {
            stsConstructorCall.javaType = javaClassType.getQualifiedName();
            stsConstructorCall.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(javaClassType.getTypeArguments());
        }

        pushCurrent(stsConstructorCall);

        // Add 'try' keyword if this is a throwing call.
        if (isThrowingCall) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
        }

        if (javaCtorExpr != null) {
            javaCtorExpr.accept(this);
        }

        stsCurrent.addChild(stsThisOrSuper);

        translateTypeArguments(javaTypeArgs);
        stsConstructorCall.javaMethodTypeArgs = NodeBuilder.buildTypeArgsSignature(javaTypeArgs, srcFile.getPath());

        translateArguments(javaArgs, javaParamsTypes);

        popCurrent(); // ConstructorCallContext

        stmtTransformed.add(javaCtorInvocation);
    }

    private void reportError(String message, ASTNode node) {
        String loc = srcFile.getPath() + ":" + javaCU.getLineNumber(node.getStartPosition());
        Main.addError(ResultCode.TranspileError, message + " at " + loc);
    }

    // Java tree:
    //    SuperConstructorInvocation:
    //       [ Expression . ]
    //          [ < Type { , Type } > ]
    //          super ( [ Expression { , Expression } ] ) ;
    // STS tree:
    //    constructorCall:
    //       | (singleExpression . )? super typeArguments? arguments SemiColon
    @Override
    public boolean visit(SuperConstructorInvocation javaSuperCtorInvocation) {
        translateCtorInvocation(NodeBuilder.terminalNode(StaticTSParser.Super), javaSuperCtorInvocation.typeArguments(),
                javaSuperCtorInvocation.getExpression(), javaSuperCtorInvocation.arguments(),
                javaSuperCtorInvocation.resolveConstructorBinding(), javaSuperCtorInvocation);

        return false;
    }

    private List<SingleExpressionContext> translateArguments(List<Expression> javaArgs, ITypeBinding[] javaParamsTypes) {
        pushCurrent(new ArgumentsContext(stsCurrent, 0));

        List<SingleExpressionContext> result = null;
        if (javaArgs != null && !javaArgs.isEmpty()) {
            ExpressionSequenceContext stsExprSeq = new ExpressionSequenceContext(stsCurrent, 0);
            pushCurrent(stsExprSeq);

            for (Expression javaExpr : javaArgs) {
                ITypeBinding javaTypeBinding = javaExpr.resolveTypeBinding();

                if (javaTypeBinding != null) {
                    sbForApiMapper.append(javaTypeBinding.getQualifiedName());
                }
                else {
                    reportError("Fail to resolve argument", javaExpr);
                }

                sbForApiMapper.append(',');

                javaExpr.accept(this);
            }

            if (sbForApiMapper.length() > 1) {
                sbForApiMapper.setLength(sbForApiMapper.length() - 1); // Remove the ending extra comma.
            }

            popCurrent(); // ExpressionSequenceContext
            result = stsExprSeq.singleExpression();
        }

        popCurrent(); // ArgumentsContext
        return result;
    }

    // Java tree:
    //   Expression:
    //      | ArrayAccess
    //   ArrayAccess: Expression [ Expression ]
    // STS tree:
    //   singleExpression:
    //      | singleExpression indexExpression # ArrayAccessExpression
    // indexExpression: OpenBracket singleExpression CloseBracket
    @Override
    public boolean visit(ArrayAccess javaArrayAccess) {
        pushCurrent(new ArrayAccessExpressionContext(pushSingleExpression()));

        javaArrayAccess.getArray().accept(this); // singleExpression -- array name

        Expression javaIndexExpression = javaArrayAccess.getIndex();
        pushCurrent(new IndexExpressionContext(stsCurrent, 0));

        if (javaIndexExpression != null) // May be 'null' to create just an empty index expression: []
            javaIndexExpression.accept(this);

        popCurrent(); // IndexExpressionContext
        popSingleExpression(); // ArrayAccessExpression

        exprTransformed.add(javaArrayAccess);
        return false;
    }

    // Java tree:
    //   ArrayCreation:
    //     new PrimitiveType [ Expression ] { [ Expression ]+ } { [ ]+ }
    //     new TypeName [ < Type { , Type }* > ] [ Expression ] { [ Expression ]+ } { [ ]+ }
    // STS tree:
    //   singleExpression:
    //      | New primaryType indexExpression+ (OpenBracket CloseBracket)* # NewArrayExpression
    //
    // Java tree:
    //     new PrimitiveType [ ] { [ ]+ } ArrayInitializer
    //     new TypeName [ < Type { , Type }* > ] [ ] { [ ]+ } ArrayInitializer
    // STS tree:
    //  singleExpression:
    //    | OpenBracket expressionSequence? CloseBracket   # ArrayLiteralExpression
    @Override
    public boolean visit(ArrayCreation javaArrayCreation) {
        ArrayInitializer javaArrayInitializer = javaArrayCreation.getInitializer();
        if (javaArrayInitializer != null) {
            // For array creation expressions with array initializer,
            // emit ArrayLiteralExpressionContext node
            javaArrayInitializer.accept(this);
            return false;
        }

        // Otherwise, emit NewArrayExpressionContext node
        pushCurrent(new NewArrayExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.New));

        ArrayType javaArrayType = javaArrayCreation.getType();
        javaArrayType.getElementType().accept(this);

        List<Expression> javaIndexExpressions = javaArrayCreation.dimensions();
        for (Expression javaIndexExpression : javaIndexExpressions) {
            pushCurrent(new IndexExpressionContext(stsCurrent, 0));
            javaIndexExpression.accept(this);
            popCurrent(); // IndexExpressionContext
        }

        int javaNumIndexExpr = javaIndexExpressions.size();
        int javaArrayTypeDims = javaArrayType.dimensions().size();
        if (javaArrayTypeDims > javaNumIndexExpr) {
            // Dimensionality of array type can exceed the number of index expressions
            // in the case current new array creation expression ends with empty dimensions.
            // All we need to do here is to emit the same empty dimensions here.
            for (int i = javaNumIndexExpr; i < javaArrayTypeDims; ++i) {
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.OpenBracket));
                stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.CloseBracket));
            }
        }

        popSingleExpression(); // NewArrayExpressionContext

        exprTransformed.add(javaArrayCreation);
        return false;
    }

    // Java tree:
    //    ArrayInitializer: { [ Expression { , Expression} [ , ]] }
    // STS tree:
    //  singleExpression:
    //    | OpenBracket expressionSequence? CloseBracket   # ArrayLiteralExpression
    @Override
    public boolean visit(ArrayInitializer javaArrayInitializer) {
        List<Expression> javaExpressions = javaArrayInitializer.expressions();
        assert (!javaExpressions.isEmpty());

        pushCurrent(new ArrayLiteralExpressionContext(pushSingleExpression()));
        pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));

        for (Expression javaExpression : javaExpressions) {
            javaExpression.accept(this);
        }

        popCurrent(); // ExpressionSequenceContext
        popSingleExpression(); // ArrayLiteralContext

        exprTransformed.add(javaArrayInitializer);
        return false;
    }

    // Java tree:
    //    CastExpression: ( Type ) Expression
    // STS tree:
    //    singleExpression:
    //      | singleExpression As (intersectionType | primaryType) # CastExpression
    @Override
    public boolean visit(CastExpression javaCastExpression) {
        pushCurrent(new CastExpressionContext(pushSingleExpression()));

        javaCastExpression.getExpression().accept(this);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.As));
        javaCastExpression.getType().accept(this);

        popSingleExpression(); // CastExpressionContext

        exprTransformed.add(javaCastExpression);
        return false;
    }

    // Java tree:
    //    AnonymousClassDeclaration: { ClassBodyDeclaration }
    // STS tree:
    //    classBody: OpenBrace classMember* clinit=classInitializer? classMember* CloseBrace
    @Override
    public boolean visit(AnonymousClassDeclaration javaAnonClassDecl) {
        pushCurrent(new ClassBodyContext(stsCurrent, 0));

        List<BodyDeclaration> javaBodyDeclarations = javaAnonClassDecl.bodyDeclarations();
        if (javaBodyDeclarations != null && !javaBodyDeclarations.isEmpty()) {
            for (BodyDeclaration javaBodyDeclaration : javaBodyDeclarations) {
                javaBodyDeclaration.accept(this);
            }

            // If we saw an instance initializer, create ctor and put initializer statements into it.
            if (javaAnonClassDecl.getProperty(INSTANCE_INITIALIZER) != null) {
                ConstructorDeclarationContext stsCtor = addInstanceInitializersToCtors(javaAnonClassDecl);

                if (stsCtor != null) {
                    // Create superclass' ctor call and pass it ctor arguments and
                    // outer instance (if any) from the parent context.
                    List<SingleExpressionContext> stsCtorArgs = new ArrayList<>();
                    Object outerObjProp = javaAnonClassDecl.getProperty(OUTER_OBJECT);
                    if (outerObjProp != null) stsCtorArgs.add((SingleExpressionContext)outerObjProp);

                    Object ctorArgsProp = javaAnonClassDecl.getProperty(CTOR_ARGUMENTS);
                    if (ctorArgsProp != null) {
                        stsCtorArgs.addAll((List<SingleExpressionContext>)ctorArgsProp);
                    }

                    ConstructorCallContext stsSuperCtorCall =
                                        NodeBuilder.ctorCall(true,outerObjProp != null,
                                                        stsCtorArgs.toArray(new SingleExpressionContext[0]));

                    ConstructorBodyContext stsCtorBody = stsCtor.constructorBody();
                    stsCtorBody.children.add(0, stsSuperCtorCall);
                    stsSuperCtorCall.setParent(stsCtorBody);
                }
            }
        }

        popCurrent(); // ClassBodyContext

        declTransformed.add(javaAnonClassDecl);
        return false;
    }

    // Java tree:
    //   ClassInstanceCreation:
    //        [ Expression . ]
    //            new [ < Type { , Type } > ]
    //            Type ( [ Expression { , Expression } ] )
    //            [ AnonymousClassDeclaration ]
    //    AnonymousClassDeclaration: { ClassBodyDeclaration }
    // STS tree:
    //   singleExpression:
    //      | New typeArguments? typeReference arguments? classBody? # NewClassInstanceExpression
    //   arguments: OpenParen expressionSequence? CloseParen
    //   classBody: OpenBrace classMember* clinit=classInitializer? classMember* CloseBrace
    @Override
    public boolean visit(ClassInstanceCreation javaClassInstanceCreation) {
        IMethodBinding javaCtorBinding = javaClassInstanceCreation.resolveConstructorBinding();
        boolean ctorCanThrow = false;

        if (javaCtorBinding != null) {
            ctorCanThrow = javaCtorBinding.getExceptionTypes().length > 0;
        }
        else {
            reportError("Failed to resolve instance creation expression", javaClassInstanceCreation);
        }

        if (ctorCanThrow) {
            if(checkThrownExceptionSet(javaClassInstanceCreation))
                addMultipleThrownExceptions(javaCtorBinding.getExceptionTypes());
        }

        // Add outer class object, if any.
        Expression javaOuterObject = javaClassInstanceCreation.getExpression();
        SingleExpressionContext stsNewClassInstanceExpr;
        SingleExpressionContext stsOuterObject = null;

        if (javaOuterObject != null) {
            stsNewClassInstanceExpr = new NewInnerClassInstanceExpressionContext(pushSingleExpression());
            pushCurrent(stsNewClassInstanceExpr);
            javaOuterObject.accept(this);
            stsOuterObject = ((NewInnerClassInstanceExpressionContext)stsCurrent).singleExpression();
        }
        else {
            stsNewClassInstanceExpr = new NewClassInstanceExpressionContext(pushSingleExpression());
            pushCurrent(stsNewClassInstanceExpr);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.New)).setParent(stsCurrent);

        translateTypeArguments(javaClassInstanceCreation.typeArguments());
        stsNewClassInstanceExpr.javaMethodTypeArgs = NodeBuilder.buildTypeArgsSignature(javaClassInstanceCreation.typeArguments(), srcFile.getPath());

        Type javaClassType = javaClassInstanceCreation.getType();

        javaClassType.accept(this);

        try {
            ITypeBinding classTypeBinding = javaClassType.resolveBinding();
            ITypeBinding erasureTypeBinding = classTypeBinding.getErasure();
            stsNewClassInstanceExpr.javaType = (erasureTypeBinding != null) ? erasureTypeBinding.getQualifiedName() : classTypeBinding.getQualifiedName(); // Used by the API mapper.

            stsNewClassInstanceExpr.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(classTypeBinding.getTypeArguments());
        }
        catch (Exception e) {
            reportError("Fail to resolve class type", javaClassType);
        }

        ITypeBinding[] javaParamsTypes = null;

        if (javaCtorBinding != null) {
            javaParamsTypes = javaCtorBinding.getParameterTypes();
            stsNewClassInstanceExpr.javaMethodArgs = NodeBuilder.buildTypeArgsSignature(javaParamsTypes);
        }

        List<SingleExpressionContext> stsArgs = translateArguments(javaClassInstanceCreation.arguments(), javaParamsTypes);

        AnonymousClassDeclaration javaAnonymousClassDeclaration = javaClassInstanceCreation.getAnonymousClassDeclaration();

        if (javaAnonymousClassDeclaration != null) {
            // Store outer object and ctor arguments (if any) in javaAnonymousClassDeclaration.
            // We might need them if anonymous class contains instance initializer, see
            // visit(AnonymousClassDeclaration) for details.
            if (stsOuterObject != null)
                javaAnonymousClassDeclaration.setProperty(OUTER_OBJECT, stsOuterObject);

            if (stsArgs != null && !stsArgs.isEmpty())
                javaAnonymousClassDeclaration.setProperty(CTOR_ARGUMENTS, stsArgs);

            javaAnonymousClassDeclaration.accept(this);
        }

        popSingleExpression(); // NewInnerClassInstanceExpressionContext or NewClassInstanceExpressionContext

        exprTransformed.add(javaClassInstanceCreation);
        return false;
    }

    // Java tree:
    //    ForStatement:
    //       for (
    //           [ ForInit ] ;
    //           [ Expression] ;
    //           [ ForUpdate ] )
    //           Statement
    //    ForInit:
    //       Expression { , Expression }
    //    ForUpdate:
    //       Expression { , Expression }
    // STS tree:
    //    iterationStatement:
    //       | for ( forInit? ; singleExpression? ; expressionSequence? ) statement  # ForStatement
    //    forInit:
    //       expressionSequence | let variableDeclarationList
    @Override
    public boolean visit(ForStatement javaForStmt) {
        pushCurrent(new ForStatementContext(pushIterationStatement()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.For));

        List<Expression> javaInits = javaForStmt.initializers();
        if (javaInits != null && !javaInits.isEmpty()) {
            pushCurrent(new ForInitContext(stsCurrent, 0));

            // The list of initializers consists of either a list of statement expressions,
            // or a single VariableDeclarationExpression.
            Expression javaFirstExpr = javaInits.get(0);
            if (javaFirstExpr.getNodeType() == ASTNode.VARIABLE_DECLARATION_EXPRESSION) {
                javaFirstExpr.accept(this);
            } else {
                pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));
                for (Expression javaExpr : javaInits) {
                    javaExpr.accept(this);
                }
                popCurrent(); // ExpressionSequenceContext
            }

            popCurrent(); // ForInitContext
        }

        Expression javaCondition = javaForStmt.getExpression();
        if (javaCondition != null) {
            javaCondition.accept(this);
        }

        List<Expression> javaUpdaters = javaForStmt.updaters();
        if (javaUpdaters != null && !javaUpdaters.isEmpty()) {
            pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));
            for (Expression javaExpr : javaUpdaters) {
                javaExpr.accept(this);
            }
            popCurrent(); // ExpressionSequenceContext
        }

        javaForStmt.getBody().accept(this);

        popIterationStatement(); // IterationStatementContext + ForStatementContext

        stmtTransformed.add(javaForStmt);
        return false;
    }

    // Java tree:
    //    EnhancedForStatement:
    //       for ( FormalParameter : Expression ) Statement
    // STS tree:
    //    iterationStatement:
    //       | for ( let Identifier typeAnnotation? of singleExpression? ) statement  # ForOfStatement
    @Override
    public boolean visit(EnhancedForStatement javaEnhancedForStmt) {
        pushCurrent(new ForOfStatementContext(pushIterationStatement()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.For));

        SingleVariableDeclaration javaParam = javaEnhancedForStmt.getParameter();
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Let));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaParam.getName()));

        pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
        javaParam.getType().accept(this);
        popCurrent(); // TypeAnnotationContext
        declTransformed.add(javaParam); // Loop variable is a separate declaration construct!

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.OF));

        javaEnhancedForStmt.getExpression().accept(this);
        javaEnhancedForStmt.getBody().accept(this);

        popIterationStatement(); // IterationStatementContext + ForOfStatementContext

        stmtTransformed.add(javaEnhancedForStmt);
        return false;
    }

    // Java tree:
    //    BreakStatement:
    //       break [ Identifier ] ;
    // STS tree:
    //    breakStatement:
    //       break Identifier? SemiColon
    @Override
    public boolean visit(BreakStatement javaBreak) {
        pushStatement(new BreakStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Break));
        SimpleName javaLabel = javaBreak.getLabel();
        if (javaLabel != null) {
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaLabel));
        }
        popStatement(); // BreakStatementContext

        stmtTransformed.add(javaBreak);
        return false;
    }

    // Java tree:
    //    ContinueStatement:
    //       continue [ Identifier ] ;
    // STS tree:
    //    continueStatement:
    //       continue Identifier? SemiColon
    @Override
    public boolean visit(ContinueStatement javaContinue) {
        pushStatement(new ContinueStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Continue));
        SimpleName javaLabel = javaContinue.getLabel();
        if (javaLabel != null) {
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaLabel));
        }
        popStatement(); // ContinueStatementContext

        stmtTransformed.add(javaContinue);
        return false;
    }

    // Java tree:
    //    ReturnStatement:
    //       continue [ Expression ] ;
    // STS tree:
    //    returnStatement:
    //       return singleExpression? SemiColon
    @Override
    public boolean visit(ReturnStatement javaReturn) {
        pushStatement(new ReturnStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Return));

        Expression javaExpr = javaReturn.getExpression();
        if (javaExpr != null) {
            javaExpr.accept(this);
        }
        popStatement(); // ReturnStatementContext

        stmtTransformed.add(javaReturn);
        return false;
    }

    // Java tree:
    //    ConditionalExpression:
    //       Expression ? Expression : Expression
    // STS tree:
    //    singleExpression:
    //       | singleExpression ? singleExpression : singleExpression  # TernaryExpression
    @Override
    public boolean visit(ConditionalExpression javaConditionalExpr) {
        pushCurrent(new TernaryExpressionContext(pushSingleExpression()));

        javaConditionalExpr.getExpression().accept(this);
        javaConditionalExpr.getThenExpression().accept(this);
        javaConditionalExpr.getElseExpression().accept(this);

        popSingleExpression(); // TernaryExpressionContext

        exprTransformed.add(javaConditionalExpr);
        return false;
    }

    // Java tree:
    //    FieldAccess:
    //       Expression . Identifier
    // STS tree:
    //    singleExpression:
    //       | singleExpression Dot Identifier  # MemberAccessExpression
    @Override
    public boolean visit(FieldAccess javaFieldAccess) {
        MemberAccessExpressionContext stsMemberAccessExpr = new MemberAccessExpressionContext(pushSingleExpression());
        pushCurrent(stsMemberAccessExpr);

        Expression javaObjectExpr = javaFieldAccess.getExpression();
        SimpleName javaFieldName = javaFieldAccess.getName();

        ITypeBinding javaTypeBinding = javaObjectExpr.resolveTypeBinding();

        // Fill the rules match attributes.
        stsMemberAccessExpr.javaName = javaFieldName.getIdentifier();
        if (javaTypeBinding != null) stsMemberAccessExpr.javaType = javaTypeBinding.getQualifiedName();

        javaObjectExpr.accept(this);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Dot));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaFieldName));

        popSingleExpression(); // MemberAccessExpressionContext

        exprTransformed.add(javaFieldAccess);
        return false;
    }

    // Java tree:
    //    SuperFieldAccess:
    //       [ ClassName . ] super . Identifier
    // STS tree:
    //    singleExpression:
    //       | singleExpression Dot Identifier  # MemberAccessExpression
    //       where the next singleExpresion is
    //       | (typeReference Dot)? Super  # SuperExpression
    @Override
    public boolean visit(SuperFieldAccess javaSuperFieldAccess) {
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        pushCurrent(new SuperExpressionContext(pushSingleExpression()));

        Name javaQualifier = javaSuperFieldAccess.getQualifier();
        if (javaQualifier != null) {
            String typeFQName = javaQualifier.getFullyQualifiedName();
            ITypeBinding javaTypeBinding = javaQualifier.resolveTypeBinding();
            stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Super));
        popSingleExpression(); // SuperExpressionContext

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaSuperFieldAccess.getName()));
        popSingleExpression(); // MemberAccessExpressionContext

        exprTransformed.add(javaSuperFieldAccess);
        return false;
    }

    // Java tree:
    //    InstanceofExpression:
    //       Expression instanceof Type
    // STS tree:
    //    singleExpression:
    //       | singleExpression Instanceof primaryType  # instanceofExpression
    //       where the next singleExpresion is
    //       | (typeReference Dot)? Super  # SuperExpression
    @Override
    public boolean visit(InstanceofExpression javaInstanceofExpr) {
        pushCurrent(new InstanceofExpressionContext(pushSingleExpression()));

        javaInstanceofExpr.getLeftOperand().accept(this);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Instanceof));
        javaInstanceofExpr.getRightOperand().accept(this);

        popSingleExpression(); // InstanceofExpression

        exprTransformed.add(javaInstanceofExpr);
        return false;
    }

//    private static String buildSignature(ITypeBinding typeArguments[]) {
//        if (typeArguments != null) {
//            sbForApiMapper.setLength(0);
//
//            for (ITypeBinding typeArgument : typeArguments) {
//                sbForApiMapper.append(typeArgument.getQualifiedName()).append(',');
//            }
//
//            if (sbForApiMapper.length() > 0) {
//                return sbForApiMapper.substring(0, sbForApiMapper.length() - 1); // Remove the ending extra comma.
//            }
//        }
//
//        return null;
//    }
//
//    private static String buildSignature(List<Type> javaTypeArgs) {
//        if (javaTypeArgs != null && !javaTypeArgs.isEmpty()) {
//            sbForApiMapper.setLength(0); // Clear the string builder.
//
//            for (Type javaTypeArg : javaTypeArgs) {
//                ITypeBinding javaTypeBinding = javaTypeArg.resolveBinding();
//
//                if (javaTypeBinding != null) {
//                    sbForApiMapper.append(javaTypeBinding.getQualifiedName());
//                }
//                else {
//                    reportError("Fail to resolve type", javaTypeArg);
//                }
//
//                sbForApiMapper.append(',');
//            }
//
//            if (sbForApiMapper.length() > 1) {
//                return sbForApiMapper.substring(0, sbForApiMapper.length() - 1); // Remove the ending extra comma.
//            }
//        }
//
//        return null;
//    }


    // Java tree:
    //    MethodInvocation:
    //       [ Expression . ]
    //          [ < Type { , Type } > ]
    //          Identifier ( [ Expression { , Expression } ] )
    // STS tree:
    //    singleExpression:
    //       | singleExpression typeArguments? arguments  # CallExpression
    //    typeArguments: LessThan typeArgumentList? MoreThan
    //    typeArgumentList: typeArgument (Comma typeArgument)*
    //    typeArgument: typeReference | arrayType
    //    arguments: OpenParen expressionSequence? CloseParen
    //    expressionSequence: singleExpression (Comma singleExpression)*
    @Override
    public boolean visit(MethodInvocation javaMethodInvocation) {
        boolean isThrowingCall = false;
        // resolveMethodBinding() can throw exceptions, so let's catch them to make sure we proceed.
        IMethodBinding javaMethodBinding = null;
        try {
            javaMethodBinding = javaMethodInvocation.resolveMethodBinding();
            if (javaMethodBinding != null) {
                isThrowingCall = javaMethodBinding.getExceptionTypes().length > 0;
            }
        }
        catch (Exception e) {
            reportError("Failed to resolve method call", javaMethodInvocation);
        }

        if (isThrowingCall) {
            if(checkThrownExceptionSet(javaMethodInvocation))
                addMultipleThrownExceptions(javaMethodBinding.getExceptionTypes());
        }

        CallExpressionContext stsCallExpression = new CallExpressionContext(pushSingleExpression());
        pushCurrent(stsCallExpression);

        Expression javaObjectExpression = javaMethodInvocation.getExpression();
        String javaMethodName = javaMethodInvocation.getName().getIdentifier();
        stsCallExpression.javaName = javaMethodName; // Used by the API mapper.

        if (javaObjectExpression != null) {
            ITypeBinding objectTypeBinding = javaObjectExpression.resolveTypeBinding();
            if (objectTypeBinding != null) {
                // The API mapper needs name of fully qualified RAW type. So look for erasure.
                ITypeBinding erasureType = objectTypeBinding.getErasure();
                stsCallExpression.javaType = (erasureType != null) ? erasureType.getQualifiedName() : objectTypeBinding.getQualifiedName(); // Used by the API mapper.

                stsCallExpression.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(objectTypeBinding.getTypeArguments());
            }
            else {
                // TODO: If the type binding was not resolved then it's very probably the source code was invalid.
                //       Log the problem informatioin.
            }

            // | singleExpression Dot identifier  # MemberAccessExpression
            pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
            javaObjectExpression.accept(this);
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaMethodName));
            popSingleExpression(); // MemberAccessExpressionContext
        }
        else {
            pushCurrent(new IdentifierExpressionContext(pushSingleExpression()));
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaMethodName));
            popSingleExpression(); // IdentifierExpressionContext
        }

        translateTypeArguments(javaMethodInvocation.typeArguments());
        stsCallExpression.javaMethodTypeArgs = NodeBuilder.buildTypeArgsSignature(javaMethodInvocation.typeArguments(), srcFile.getPath());

        ITypeBinding[] javaParamsTypes = null;

        if (javaMethodBinding != null) {
            javaParamsTypes = javaMethodBinding.getParameterTypes();
            stsCallExpression.javaMethodArgs = NodeBuilder.buildTypeArgsSignature(javaParamsTypes);
        }

        translateArguments(javaMethodInvocation.arguments(), javaParamsTypes);

        popSingleExpression(); // CallExpressionContext

        exprTransformed.add(javaMethodInvocation);
        return false;
    }

    // Java tree:
    //    SuperMethodInvocation:
    //       [ ClassName . ] super
    //          [ < Type { , Type } > ]
    //          Identifier ( [ Expression { , Expression } ] )
    // STS tree:
    //    singleExpression:
    //       | singleExpression typeArguments? arguments  # CallExpression
    //    where the next singleExpression expands to:
    //       | singleExpression Dot Identifier  # MemberAccessExpression
    //       and here singleExpression expands to:
    //          | (typeReference Dot)? Super  # SuperExpression
    @Override
    public boolean visit(SuperMethodInvocation javaSuperMethodInvocation) {
        boolean isThrowingCall = false;
        // resolveMethodBinding() can throw exceptions, so let's catch them to make sure we proceed.
        IMethodBinding javaMethodBinding = null;
        try {
            javaMethodBinding = javaSuperMethodInvocation.resolveMethodBinding();
            if (javaMethodBinding != null) {
                isThrowingCall = javaMethodBinding.getExceptionTypes().length > 0;
            }
        }
        catch (Exception e) {
            reportError("Failed to resolve super method call", javaSuperMethodInvocation);
        }

        if (isThrowingCall) {
            if(checkThrownExceptionSet(javaSuperMethodInvocation))
                addMultipleThrownExceptions(javaMethodBinding.getExceptionTypes());
        }

        CallExpressionContext stsCallExpression = new CallExpressionContext(pushSingleExpression());
        pushCurrent(stsCallExpression);

        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        pushCurrent(new SuperExpressionContext(pushSingleExpression()));

        Name javaQualifier = javaSuperMethodInvocation.getQualifier();

        if (javaQualifier != null) {
            String typeFQName = javaQualifier.getFullyQualifiedName();
            ITypeBinding javaTypeBinding = javaQualifier.resolveTypeBinding();
            stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Super));
        popSingleExpression(); // SuperExpressionContext

        String javaMethodName = javaSuperMethodInvocation.getName().getFullyQualifiedName();

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaMethodName));
        popStatement(); // MemberAccessExpressionContext

        translateTypeArguments(javaSuperMethodInvocation.typeArguments());
        stsCallExpression.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(javaSuperMethodInvocation.typeArguments(), srcFile.getPath());

        ITypeBinding[] javaParamsTypes = null;

        if (javaMethodBinding != null) {
            javaParamsTypes = javaMethodBinding.getParameterTypes();
            stsCallExpression.javaMethodArgs = NodeBuilder.buildTypeArgsSignature(javaParamsTypes);
        }

        translateArguments(javaSuperMethodInvocation.arguments(), javaParamsTypes);

        popSingleExpression(); // CallExpressionContext

        exprTransformed.add(javaSuperMethodInvocation);
        return false;
    }

    // Java tree:
    //    ThisExpression:
    //       [ ClassName . ] this
    // STS tree:
    @Override
    public boolean visit(ThisExpression javaThisExpr) {
        pushCurrent(new ThisExpressionContext(pushSingleExpression()));

        Name javaQualifier = javaThisExpr.getQualifier();
        if (javaQualifier != null) {
            String typeFQName = javaQualifier.getFullyQualifiedName();
            ITypeBinding javaTypeBinding = javaQualifier.resolveTypeBinding();
            stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.This));
        popSingleExpression(); // ThisExpressionContext

        exprTransformed.add(javaThisExpr);
        return false;
    }

    // Java tree:
    //    TypeDeclarationStatement:
    //       TypeDeclaration
    //       EnumDeclaration
    // STS tree:
    //    statementOrLocalDeclaration:
    //       | classDeclaration
    //       | enumDeclaration
    @Override
    public boolean visit(TypeDeclarationStatement javaTypeDeclarationStmt) {
        javaTypeDeclarationStmt.getDeclaration().accept(this);

        stmtTransformed.add(javaTypeDeclarationStmt);
        return false;
    }

    // Java tree:
    //    switch ( Expression )
    //       { { SwitchCase | Statement } }
    //    SwitchCase:
    //       case Expression :
    //       default :
    // STS tree:
    //    switchStatement:
    //       switch OpenParen singleExpression CloseParen caseBlock
    //    caseBlock:
    //       OpenBrace leftCases=caseClauses? defaultClause? rightCases=caseClauses? CloseBrace
    //    caseClauses:
    //       caseClause+
    //    caseClause:
    //       case singleExpression ':' statement*
    //    defaultClause:
    //       default ':' statement*
    @Override
    public boolean visit(SwitchStatement javaSwitchStmt) {
        SwitchStatementContext stsSwitch = new SwitchStatementContext(stsCurrent, 0);
        pushStatement(stsSwitch);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Switch));

        javaSwitchStmt.getExpression().accept(this);

        CaseBlockContext stsCaseBlock = new CaseBlockContext(stsCurrent, 0);
        stsCaseBlock.leftCases = null;
        stsCaseBlock.rightCases = null;
        pushCurrent(stsCaseBlock);

        List<VariableDeclarationFragment> javaVariablesToMove = new ArrayList<>();
        SwitchCase javaCurrentSwitchCase = null;

        List<Statement> javaStmts = javaSwitchStmt.statements();
        for (Statement javaStmt : javaStmts) {
            if (javaStmt.getNodeType() == ASTNode.SWITCH_CASE) {
                javaCurrentSwitchCase = (SwitchCase) javaStmt;
            }
            else if (javaStmt.getNodeType() == ASTNode.TYPE_DECLARATION_STATEMENT) {
                wrapCaseClauseStatementsWithBlock();
            }
            else if (javaStmt.getNodeType() == ASTNode.VARIABLE_DECLARATION_STATEMENT) {
                // Call preVisit to collect comments that may be attached to this
                // statement. NOTE: We won't be visiting it so preVisit won't be
                // called automatically.
                preVisit(javaStmt);
                processSwitchCaseVariableDeclaration((VariableDeclarationStatement) javaStmt, javaCurrentSwitchCase,
                        javaSwitchStmt, javaVariablesToMove);

                // We've already processed variable declaration, proceed to the next statement.
                continue;
            }

            javaStmt.accept(this);
        }

        // Close the last case clause.
        popCaseClauseIfNeeded(); // CaseClauseContext | DefaultClauseContext

        // Create CaseClausesContext node and transfer all cases translated thus far to it.
        // If we've seen default node, initialize rightCases field of CaseBlockContext node;
        // otherwise, initialize leftCases field of CaseBlockContext node.
        CaseClausesContext stsCaseClauses = createAndFillCaseClausesContext(stsCaseBlock);
        if (stsCaseBlock.defaultClause() != null) {
            stsCaseBlock.rightCases = stsCaseClauses;
        }
        else {
            stsCaseBlock.leftCases = stsCaseClauses;
        }

        popCurrent(); // CaseBlockContext
        popStatement(); // SwitchStatementContext

        // Move variable declarations in front of switch statement, and enclose both
        // declarations and switch with additional block.
        if (javaVariablesToMove != null && !javaVariablesToMove.isEmpty()) {
            // Remove switch statement from current STS node.
            stsCurrent.removeLastChild();

            BlockContext stsBlock = new BlockContext(stsCurrent, 0);
            pushStatement(stsBlock);

            for (VariableDeclarationFragment javaVarFragment : javaVariablesToMove) {
                VariableDeclarationStatement javaVarDeclStmt = (VariableDeclarationStatement) javaVarFragment.getParent();

                VariableOrConstantDeclarationContext stsVarOrConstDecl = new VariableOrConstantDeclarationContext(null, 0);
                pushStatement(stsVarOrConstDecl);

                // Transfer comments from javaVarDeclStmt node (if any) to
                // STS VariableOrConstantDeclarationContext node.
                transferComments(javaVarDeclStmt, stsVarOrConstDecl);

                ArrayList<VariableDeclarationFragment> declFragmentList = new ArrayList<>();
                declFragmentList.add(javaVarFragment);

                createAndFillVarOrConstDeclarationList(javaVarDeclStmt.getModifiers(), declFragmentList, javaVarDeclStmt.getType(), false);
                popStatement(); // stsVarOrConstDecl
            }

            pushStatement(stsSwitch);
            popStatement(); // SwitchContext

            popStatement(); // BlockContext
        }

        stmtTransformed.add(javaSwitchStmt);
        return false;
    }

    @Override
    public boolean visit(SwitchCase javaSwitchCase) {
        // Close the last case clause.
        popCaseClauseIfNeeded(); // CaseClauseContext | DefaultClauseContext

        assert(stsCurrent.getRuleIndex() == StaticTSParser.RULE_caseBlock);
        CaseBlockContext stsCaseBlock = (CaseBlockContext)stsCurrent;

        if (javaSwitchCase.isDefault()) {
            // If any cases have been translated thus far, create CaseClauseContext node,
            // transfer those cases to it, and initialize leftCases field of CaseBlockContext node.
            stsCaseBlock.leftCases = createAndFillCaseClausesContext(stsCaseBlock);

            // Translate default clause
            pushCurrent(new DefaultClauseContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.DEFAULT));
        }
        else {
            pushCurrent(new CaseClauseContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Case));
            javaSwitchCase.getExpression().accept(this);
        }

        // SwitchCase is treated as Statement node, thus increment the count.
        stmtTransformed.add(javaSwitchCase);
        return false;
    }

    private CaseClausesContext createAndFillCaseClausesContext(CaseBlockContext stsCaseBlock) {
        List<CaseClauseContext> stsCaseList = stsCaseBlock.getRuleContexts(CaseClauseContext.class);
        CaseClausesContext stsCaseClauses = null;

        if (!stsCaseList.isEmpty()) {
            stsCaseClauses = new CaseClausesContext(stsCurrent, 0);
            for (CaseClauseContext stsCase : stsCaseList) {
                stsCaseClauses.addChild(stsCase).setParent(stsCaseClauses);
            }
            stsCaseBlock.children.removeAll(stsCaseList);

            // Add CaseClauseContext node to CaseBlockContext
            stsCaseBlock.addChild(stsCaseClauses).setParent(stsCaseBlock);
        }

        return stsCaseClauses;
    }
    private void popCaseClauseIfNeeded() {
        // Check if we need to pop additional block added as work around to add
        // local declarations to case clause (see wrapCaseClauseStatementsWithBlock()
        // method for details).
        if (stsCurrent.getRuleIndex() == StaticTSParser.RULE_block) {
            popStatement(); // BlockContext
        }

        if (stsCurrent.getRuleIndex() == StaticTSParser.RULE_caseClause
            || stsCurrent.getRuleIndex() == StaticTSParser.RULE_defaultClause) {
            popCurrent(); // CaseClauseContext | DefaultClauseContext
        }
    }

    private void wrapCaseClauseStatementsWithBlock() {
        // In StaticTS, CaseClause may contain only statements, and is not allowed to
        // have local declarations. In contrast, Java permits to have local declarations
        // in case clause scope, so when encounter one, wrap up all statements in case clause
        // with additional block as a workaround, (since block can have local declarations).

        // Check if already inserted additional block.
        if (stsCurrent.getRuleIndex() == StaticTSParser.RULE_block)
            return;

        assert stsCurrent.getRuleIndex() == StaticTSParser.RULE_caseClause ||
                stsCurrent.getRuleIndex() == StaticTSParser.RULE_defaultClause;

        List<StatementContext> stsCaseStmts = stsCurrent.getRuleContexts(StatementContext.class);
        stsCurrent.children.removeAll(stsCaseStmts);

        BlockContext stsBlock = new BlockContext(stsCurrent, 0);
        pushStatement(stsBlock);
        for (StatementContext stsStmt : stsCaseStmts) {
            StatementOrLocalDeclarationContext stsStmtOrLocalDecl = new StatementOrLocalDeclarationContext(stsBlock, 0);
            stsStmtOrLocalDecl.addChild(stsStmt).setParent(stsStmtOrLocalDecl);
            stsBlock.addChild(stsStmtOrLocalDecl).setParent(stsBlock);
        }
    }


    private void processSwitchCaseVariableDeclaration(VariableDeclarationStatement javaVarDeclStmt, SwitchCase javaCurrentSwitchCase,
                                                      SwitchStatement javaSwitchStmt, List<VariableDeclarationFragment> javaVariablesToMove) {
        // Java permits to declare local variables in switch scope. Such variables exist
        // in all following case clauses. In StaticTS, case clauses don't have a common
        // scope, and allow only statements, not declarations. To work around this, we
        // have to track whether a particular local variable has been referenced in another
        // case clause and, in such case, move declaration of that variable in front of
        // switch statement, additionally enclosing both variable declaration and switch
        // statement, so that variables are only visible in context of switch statement.
        List<VariableDeclarationFragment> javaVarFragments = javaVarDeclStmt.fragments();

        for (VariableDeclarationFragment javaVarFragment : javaVarFragments) {
            if (isUsedInAnotherCaseClause(javaVarFragment, javaCurrentSwitchCase, javaSwitchStmt)) {
                javaVariablesToMove.add(javaVarFragment);

                // Since evaluation of initializer expression can cause side effects,
                // in order to preserve the behaviour and result of program, all
                // expressions must evaluate in the same order as before. For that
                // purpose, we move the variable declaration without initializer part
                // and replace initialization with simple assignment.
                Expression javaInitExpr = javaVarFragment.getInitializer();
                if (javaInitExpr != null) {
                    pushStatement(new ExpressionStatementContext(stsCurrent, 0));
                    pushCurrent(new AssignmentExpressionContext(pushSingleExpression()));

                    javaVarFragment.getName().accept(this);
                    stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
                    javaInitExpr.accept(this);

                    popSingleExpression(); // AssignmentExpressionContext;
                    popStatement(); // ExpressionStatementContext
                }
            } else {
                wrapCaseClauseStatementsWithBlock();

                // For variables, that don't need to be moved, emit single variable
                // declaration here to preserve the correct order of evaluation of
                // initializer expressions (including assignments emitted for variables
                // that are moved).
                VariableOrConstantDeclarationContext stsVarOrConstDecl = new VariableOrConstantDeclarationContext(null, 0);
                pushStatement(stsVarOrConstDecl);

                // Transfer comments from javaVarDeclStmt node (if any) to
                // STS VariableOrConstantDeclarationContext node.
                transferComments(javaVarDeclStmt, stsVarOrConstDecl);

                ArrayList<VariableDeclarationFragment> declFragmentList = new ArrayList<>();
                declFragmentList.add(javaVarFragment);

                createAndFillVarOrConstDeclarationList(javaVarDeclStmt.getModifiers(), declFragmentList, javaVarDeclStmt.getType());
                popStatement(); // stsVarOrConstDecl
            }
        }

        stmtTransformed.add(javaVarDeclStmt);
    }

    private boolean isUsedInAnotherCaseClause(VariableDeclarationFragment javaVarDecl, SwitchCase javaSwitchCase,
                                              SwitchStatement javaSwitchStmt) {
        IVariableBinding javaVarBinding = javaVarDecl.resolveBinding();

        ASTVisitor localVarUsageLookupVisitor = new ASTVisitor() {
            boolean done = false;
            int nestedSwitchCount = 0;
            SwitchCase currentSwitchCase = null;

            @Override
            public boolean preVisit2(ASTNode javaNode) {
                // This line will prevent from visiting further AST nodes,
                // once we are done with the work.
                return !done;
            }

            @Override
            public boolean visit(SimpleName javaName) {
                IBinding binding = javaName.resolveBinding();

                if (binding != null && binding.isEqualTo(javaVarBinding) && javaSwitchCase != currentSwitchCase) {
                    javaVarDecl.setProperty(USED_IN_ANOTHER_CASE_CLAUSE, true);
                    done = true;
                }

                return false;
            }

            @Override
            public boolean visit(VariableDeclarationFragment javaVarDeclFragment) {
                // Do NOT visit declaration of the variable that we are looking up.
                return javaVarDeclFragment != javaVarDecl;
            }

            @Override
            public boolean visit(SwitchCase javaSwitchCase) {
                // Do not change currentSwitchCase when visiting nested switch statements.
                if (nestedSwitchCount == 0) {
                    currentSwitchCase = javaSwitchCase;
                }

                return false;
            }

            @Override
            public boolean visit(SwitchStatement javaSwitchStatement) {
                nestedSwitchCount++;
                return true;
            }

            @Override
            public void endVisit(SwitchStatement javaSwitchStatement) {
                nestedSwitchCount--;
            }
        };

        List<Statement> javaStmts = javaSwitchStmt.statements();
        for (Statement javaStmt : javaStmts) {
            javaStmt.accept(localVarUsageLookupVisitor);

            if (javaVarDecl.getProperty(USED_IN_ANOTHER_CASE_CLAUSE) != null)
                return true;
        }

        return false;
    }

    // AST nodes yet to be translated
    //

    // Java tree:
    //    LambdaExpression:
    //       Identifier -> Body
    //       ( [ Identifier { , Identifier } ] ) -> Body
    //       ( [ FormalParameter { , FormalParameter } ] ) -> Body
    //    Body:
    //       Expression
    //       Block
    // STS tree:
    //    singleExpression:
    //       OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody  # LambdaExpression
    //    lambdaBody
    //       : singleExpression
    //       | block
    @Override
    public boolean visit(LambdaExpression javaLambdaExpr) {
        pushCurrent(new LambdaExpressionContext(pushSingleExpression()));

        createStsParameterList(javaLambdaExpr.parameters());
        pushExceptionSet();

        // resolveMethodBinding() can throw exceptions,
        // so let's catch them to make sure we proceed.
        try {
            IMethodBinding lambdaMethod = javaLambdaExpr.resolveMethodBinding();
            translateTypeBinding(lambdaMethod.getReturnType(), javaLambdaExpr);
            if(checkThrownExceptionSet(javaLambdaExpr))
                addMultipleThrownExceptions(lambdaMethod.getExceptionTypes());
        }
        catch (Exception e) {
            reportError("Failed to resolve lambda expression", javaLambdaExpr);
            stsCurrent.addChild(NodeBuilder.unknownTypeAnnotation()).setParent(stsCurrent);
        }

        if (!currentExceptionsSet(javaLambdaExpr).isEmpty())
            stsCurrent.addChild(NodeBuilder.throwsAnnotation(true)).setParent(stsCurrent);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Arrow));

        pushCurrent(new LambdaBodyContext(stsCurrent, 0));
        ASTNode javaBody = javaLambdaExpr.getBody();

        if (javaBody instanceof Expression) {
            javaBody.accept(this);
        } else {
            // NOTE: Can't call javaBody.accept as that will emit
            // StatementContext which we don't need here
            pushCurrent(new BlockContext(stsCurrent, 0));
            translateBlockStatements((Block)javaBody);
            popCurrent(); // BlockContext
        }

        popExceptionSet();

        popCurrent(); // LambdaBodyContext
        popSingleExpression(); // LambdaExpressionContext

        exprTransformed.add(javaLambdaExpr);
        return false;
    }

    private void createMethodRefLambdaParam(ITypeBinding paramType, int lambdaParamIdx, MethodReference javaMethodRef) {
        pushCurrent(new ParameterContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(METHOD_REF_PARAM_PREFIX + lambdaParamIdx));
        translateTypeBinding(paramType, javaMethodRef);
        popCurrent(); // ParameterContext
    }

    private void wrapMethodRefCallWithLambda(IMethodBinding javaMethodBinding, ParserRuleContext stsMethodRefCall,
                                             MethodReference javaMethodRef, boolean needInstanceParam) {
        pushCurrent(new LambdaExpressionContext(pushSingleExpression()));

        // Create lambda parameters
        ITypeBinding[] javaParamTypes = javaMethodBinding.getParameterTypes();
        if (javaParamTypes.length > 0 || needInstanceParam) {
            pushCurrent(new ParameterListContext(stsCurrent, 0));
            int lambdaParamIdx = 1;

            if (needInstanceParam) {
                // Insert additional parameter representing the instance
                // of the referenced method.
                createMethodRefLambdaParam(javaMethodBinding.getDeclaringClass(), lambdaParamIdx++, javaMethodRef);
            }

            for (ITypeBinding paramType : javaParamTypes) {
                createMethodRefLambdaParam(paramType, lambdaParamIdx++, javaMethodRef);
            }
            popCurrent(); // ParameterListContext
        }

        // Create lambda return type
        ITypeBinding returnType = javaMethodBinding.isConstructor()
                ? javaMethodBinding.getDeclaringClass()
                : javaMethodBinding.getReturnType();
        translateTypeBinding(returnType, javaMethodRef);

        if (javaMethodBinding.getExceptionTypes().length > 0)
            stsCurrent.addChild(NodeBuilder.throwsAnnotation(true)).setParent(stsCurrent);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Arrow));

        // Create lambda body. It consists of the method reference call.
        pushCurrent(new LambdaBodyContext(stsCurrent, 0));
        stsCurrent.addChild(stsMethodRefCall).setParent(stsCurrent);
        popCurrent(); // LambdaBodyContext

        popSingleExpression(); // LambdaExpressionContext
    }

    // Java tree:
    //    CreationReference:
    //       Type ::
    //          [ < Type { , Type } > ]
    //          new
    // STS tree:
    //    singleExpression:
    //       OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody  # LambdaExpression
    //    where
    //       lambdaBody: singleExpression
    //       singleExpression: New typeArguments? typeReference arguments  # NewClassExpression
    @Override
    public boolean visit(CreationReference javaCreationRef) {
        if (javaCreationRef.getType().isArrayType())
            translateArrayCreationReference(javaCreationRef);
        else
            translateClassCreationReference(javaCreationRef);

        exprTransformed.add(javaCreationRef);
        return false;
    }

    private void translateArrayCreationReference(CreationReference javaCreationRef) {
        // The creation reference for an array type considers a single notional
        // method that performs an array creation. The method has single parameter
        // of type 'int' that specifies the size of array and returns the array type.
        // In case of multi-dimensional array, only first dimension will be specified.

        // Create lambda expression that wraps up the array creation expression.
        pushCurrent(new LambdaExpressionContext(pushSingleExpression()));

        // Lambda has single parameter specifying the size of array.
        pushCurrent(new ParameterListContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.parameter(METHOD_REF_PARAM_PREFIX + "1", PrimitiveType.INT)).setParent(stsCurrent);
        popCurrent(); // ParameterListContext

        // Lambda return type is an array type.
        pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
        ArrayType javaArrayType = (ArrayType) javaCreationRef.getType();
        javaArrayType.accept(this);
        popCurrent(); // TypeAnnotationContext

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Arrow));

        // Lambda body consists of an array creation expression.
        pushCurrent(new LambdaBodyContext(stsCurrent, 0));

        // Create new array expression.
        pushCurrent(new NewArrayExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.New)).setParent(stsCurrent);

        javaArrayType.getElementType().accept(this);

        // Specify first dimension of the new array with lambda's single parameter.
        pushCurrent(new IndexExpressionContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.identifierExpression(METHOD_REF_PARAM_PREFIX + "1")).setParent(stsCurrent);
        popCurrent(); // IndexExpressionContext

        // Emit empty dimensions for all other dimensions if array is multi-dimensional.
        for (int i = 1; i < javaArrayType.getDimensions(); i++) {
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.OpenBracket));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.CloseBracket));
        }

        popSingleExpression(); // NewArrayExpressionContext
        popCurrent(); // LambdaBodyContext
        popSingleExpression(); // LambdaExpressionContext
    }

    private void translateClassCreationReference(CreationReference javaCreationRef) {
        // resolveMethodBinding() can throw exceptions,
        // so let's catch them to make sure we proceed.
        IMethodBinding javaCtorBinding = null;
        try {
            javaCtorBinding = javaCreationRef.resolveMethodBinding();
        }
        catch (Exception e) {
            reportError("Failed to resolve CreationReference", javaCreationRef);
        }

        // Exclude recovered bindings as well here, as information we need
        // to extract from it below might not be available after recovery.
        if (javaCtorBinding == null || javaCtorBinding.isRecovered()) {
            // Warn and emit __untranslated_expression call with commented-out original syntax as argument.
            reportError("Failed to resolve creation reference", javaCreationRef);
            stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaCreationRef)).setParent(stsCurrent);
            return;
        }

        NewClassInstanceExpressionContext stsNewClassInstanceExpression = new NewClassInstanceExpressionContext(pushSingleExpression());
        pushCurrent(stsNewClassInstanceExpression);

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.New)).setParent(stsCurrent);

        translateTypeArguments(javaCreationRef.typeArguments());
        stsNewClassInstanceExpression.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(javaCreationRef.typeArguments(), srcFile.getPath());

        Type javaCreationType = javaCreationRef.getType();
        javaCreationType.accept(this);

        try {
            ITypeBinding javaTypeBinding = javaCreationType.resolveBinding();
            // TODO:
            //stsNewClassInstanceExpression.javaObjectType =
        }
        catch (Exception e) {
            reportError("Failed to resolve creation type", javaCreationType);
        }

        createMethodRefCallArgs(javaCtorBinding.getParameterTypes().length, 1);

        popSingleExpression(); // NewClassInstanceExpressionContext

        // The last child of current node is a SingleExpression which represents
        // the new class expression. It will be the body of the lambda expression.
        ParserRuleContext stsNewClassExpr = (ParserRuleContext)stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        stsCurrent.removeLastChild();

        wrapMethodRefCallWithLambda(javaCtorBinding, stsNewClassExpr, javaCreationRef, false);
    }

    private void createMethodRefCallArgs(int argsCount, int argIdx) {
        pushCurrent(new ArgumentsContext(stsCurrent, 0));

        if (argsCount > 0) {
            pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));

            for (int i = 0; i < argsCount; ++i) {
                stsCurrent.addChild(NodeBuilder.identifierExpression(METHOD_REF_PARAM_PREFIX + (argIdx++))).setParent(stsCurrent);
            }

            popCurrent(); // ExpressionSequenceContext
        }

        popCurrent(); // ArgumentsContext
    }

    // Java tree:
    //    SuperMethodReference:
    //       [ ClassName . ] super ::
    //          [ < Type { , Type } > ]
    //          Identifier
    // STS tree:
    //    singleExpression:
    //       OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody  # LambdaExpression
    //    where
    //       lambdaBody: singleExpression
    //       singleExpression: singleExpression typeArguments? arguments  # CallExpression
    @Override
    public boolean visit(SuperMethodReference javaSuperMethodRef) {
        // resolveMethodBinding() can throw exceptions,
        // so let's catch them to make sure we proceed.
        IMethodBinding javaMethodBinding;
        try {
            javaMethodBinding = javaSuperMethodRef.resolveMethodBinding();
        }
        catch (Exception e) {
            javaMethodBinding = null;
            reportError("Failed to resolve super method reference", javaSuperMethodRef);
        }

        // Exclude recovered bindings as well here, as information we need
        // to extract from it below might not be available after recovery.
        if (javaMethodBinding == null || javaMethodBinding.isRecovered()) {
            // Warn and emit __untranslated_expression call with commented-out original syntax as argument.
            reportError("Failed to resolve method reference", javaSuperMethodRef);
            stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaSuperMethodRef)).setParent(stsCurrent);
            return false;
        }

        CallExpressionContext stsCallExpression = new CallExpressionContext(pushSingleExpression());
        pushCurrent(stsCallExpression);

        // | singleExpression Dot identifier  # MemberAccessExpression
        // where
        // singleExpression: | (typeReference Dot)? Super  # SuperExpression
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        pushCurrent(new SuperExpressionContext(pushSingleExpression()));

        Name javaQualifier = javaSuperMethodRef.getQualifier();
        if (javaQualifier != null) {
            String typeFQName = javaQualifier.getFullyQualifiedName();
            ITypeBinding javaTypeBinding = javaQualifier.resolveTypeBinding();
            stsCurrent.addChild(NodeBuilder.typeReference(typeFQName, javaTypeBinding)).setParent(stsCurrent);
        }

        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Super));
        popSingleExpression(); // SuperExpressionContext
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaSuperMethodRef.getName()));
        popSingleExpression(); // MemberAccessExpressionContext

        translateTypeArguments(javaSuperMethodRef.typeArguments());
        stsCallExpression.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(javaSuperMethodRef.typeArguments(), srcFile.getPath());

        // TODO: fill stsCallExpression.javaArgsSignature
        createMethodRefCallArgs(javaMethodBinding.getParameterTypes().length, 1);

        popSingleExpression(); // CallExpressionContext

        // The last child of current node is a SingleExpression which represents
        // the method reference call. It will be the body of the lambda expression.
        ParserRuleContext stsMethodRefCall = (ParserRuleContext)stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        stsCurrent.removeLastChild();

        wrapMethodRefCallWithLambda(javaMethodBinding, stsMethodRefCall, javaSuperMethodRef, false);

        exprTransformed.add(javaSuperMethodRef);
        return false;
    }

    // Java tree:
    //    TypeMethodReference:
    //       Type ::
    //          [ < Type { , Type } > ]
    //          Identifier
    // STS tree:
    //    singleExpression:
    //       OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody  # LambdaExpression
    //    where
    //       lambdaBody: singleExpression
    //       singleExpression: singleExpression typeArguments? arguments  # CallExpression
    @Override
    public boolean visit(TypeMethodReference javaTypeMethodRef) {
        Type javaType = javaTypeMethodRef.getType();
        boolean usingFunctionalInterfaceMethod = false;

        // resolveMethodBinding() can throw exceptions,
        // so let's catch them to make sure we proceed.
        IMethodBinding javaMethodBinding;
        try {
            javaMethodBinding = javaTypeMethodRef.resolveMethodBinding();
        }
        catch (Exception e) {
            javaMethodBinding = null;
            reportError("Failed to resolve type method reference", javaTypeMethodRef);
        }

        // Exclude recovered bindings as well here, as information we need
        // to extract from it below might not be available after recovery.
        if (javaMethodBinding == null || javaMethodBinding.isRecovered()) {
            if (javaType.isArrayType()) {
                // For array type, the method binding may resolve to null, if the method
                // is a synthetic method, generated by compiler (e.g. "int[]::clone").
                // In such case, use method of the functional interface that this
                // method reference is implementing for the translation.

                // See following links for reference:
                // https://bugs.eclipse.org/bugs/show_bug.cgi?id=440000
                // https://bugs.eclipse.org/bugs/show_bug.cgi?id=440344
                ITypeBinding javaInterface = javaTypeMethodRef.resolveTypeBinding();
                if (javaInterface != null) {
                    javaMethodBinding = javaInterface.getFunctionalInterfaceMethod();
                    usingFunctionalInterfaceMethod = true;
                }
            } else {

                // Warn and emit __untranslated_expression call with commented-out original syntax as argument.
                reportError("Failed to resolve method reference", javaTypeMethodRef);
                stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaTypeMethodRef)).setParent(stsCurrent);
                return false;
            }
        }

        translateClassMethodReference(javaTypeMethodRef, javaMethodBinding, javaTypeMethodRef.getName(),
                javaType, true, usingFunctionalInterfaceMethod);

        exprTransformed.add(javaTypeMethodRef);
        return false;
    }

    // Java tree:
    //    ExpressionMethodReference:
    //       Expression ::
    //          [ < Type { , Type } > ]
    //          Identifier
    // STS tree:
    //    singleExpression:
    //       OpenParen parameterList? CloseParen typeAnnotation Arrow lambdaBody  # LambdaExpression
    //    where
    //       lambdaBody: singleExpression
    //       singleExpression: singleExpression typeArguments? arguments  # CallExpression
    @Override
    public boolean visit(ExpressionMethodReference javaExprMethodRef) {
        // resolveMethodBinding() can throw exceptions,
        // so let's catch them to make sure we proceed.
        IMethodBinding javaMethodBinding;
        try {
            javaMethodBinding = javaExprMethodRef.resolveMethodBinding();
        }
        catch (Exception e) {
            javaMethodBinding = null;
            reportError("Failed to resolve expression method reference", javaExprMethodRef);
        }

        Expression javaExpr = javaExprMethodRef.getExpression();
        ITypeBinding exprType = javaExpr.resolveTypeBinding();
        boolean isArrayType = exprType != null && exprType.isArray();
        boolean usingFunctionalInterfaceMethod = false;

        // Exclude recovered bindings as well here, as information we need
        // to extract from it below might not be available after recovery.
        if (javaMethodBinding == null || javaMethodBinding.isRecovered()) {
            if(isArrayType) {
                // For array type, the method binding may resolve to null, if the method
                // is a synthetic method, generated by compiler (e.g. "int[]::clone").
                // In such case, use method of the functional interface that this
                // method reference is implementing for the translation.

                // See following links for reference:
                // https://bugs.eclipse.org/bugs/show_bug.cgi?id=440000
                // https://bugs.eclipse.org/bugs/show_bug.cgi?id=440344
                ITypeBinding javaInterface = javaExprMethodRef.resolveTypeBinding();
                if (javaInterface != null) {
                    javaMethodBinding = javaInterface.getFunctionalInterfaceMethod();
                    usingFunctionalInterfaceMethod = true;
                }
            } else {
                // Warn and emit __untranslated_expression call with commented-out original syntax as argument.
                reportError("Failed to resolve method reference", javaExprMethodRef);
                stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaExprMethodRef)).setParent(stsCurrent);
                return false;
            }
        }

        // Figure out if the expression used with this method reference
        // is a type name.
        boolean isTypeMethodRef = false;
        if (javaExpr instanceof Name) {
            IBinding exprBinding = ((Name) javaExpr).resolveBinding();

            if (exprBinding == null) {
                reportError("Failed to resolve qualifier in method reference expression", javaExprMethodRef);
            }
            else if (exprBinding.getKind() == IBinding.TYPE) {
                isTypeMethodRef = true;
            }
        }

        translateClassMethodReference(javaExprMethodRef, javaMethodBinding, javaExprMethodRef.getName(),
                javaExpr, isTypeMethodRef, usingFunctionalInterfaceMethod);

        exprTransformed.add(javaExprMethodRef);
        return false;
    }

    private void translateClassMethodReference(MethodReference javaMethodRef, IMethodBinding javaMethodBinding, SimpleName javaName,
                                               ASTNode javaTypeOrExpression, boolean isTypeMethodRef, boolean usingFunctionalInterfaceMethod) {
        // Sanity check: References to static methods via parameterized types are not allowed in Java.
        boolean isStatic = (javaMethodBinding.getModifiers() & Modifier.STATIC) != 0;
        if (javaTypeOrExpression.getNodeType() == ASTNode.PARAMETERIZED_TYPE && isStatic) {
            // Warn and emit __untranslatedExpression call
            reportError("Invalid reference to a static method of parameterized type", javaMethodRef);
            stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaMethodRef));
            return;
        }

        CallExpressionContext stsCallExpression = new CallExpressionContext(pushSingleExpression());
        pushCurrent(stsCallExpression);

        boolean needInstanceParam = false;
        int lambdaParamIdx = 1;

        // | singleExpression Dot identifier  # MemberAccessExpression
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        if (isTypeMethodRef && !isStatic) {
            // For type method reference to an instance method, the first parameter
            // of the lambda expression is used as an instance for the method call.
            // We need to manually add such parameter to lambda expression, as the
            // receiver parameter is not present in the referenced method, unless
            // we are using the binding of the functional interface method, which
            // would include it to correspond to the signature of referenced method.
            stsCurrent.addChild(NodeBuilder.identifierExpression(METHOD_REF_PARAM_PREFIX + lambdaParamIdx++)).setParent(stsCurrent);
            needInstanceParam = !usingFunctionalInterfaceMethod;
        } else {
            javaTypeOrExpression.accept(this);
        }

        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaName));
        popSingleExpression(); // MemberAccessExpressionContext

        translateTypeArguments(javaMethodRef.typeArguments());
        stsCallExpression.javaTypeArgs = NodeBuilder.buildTypeArgsSignature(javaMethodRef.typeArguments(), srcFile.getPath());
        // TODO: Fill stsCallExpression.javaArgsSignature

        // In case of type method reference, the arity of the functional interface method
        // would be one more than that of the referenced method (due to having a parameter
        // for an instance). In this case, we skip one argument for the call, so that the
        // arity of call corresponds to the arity of referenced method.
        boolean skipOneParam = isTypeMethodRef && usingFunctionalInterfaceMethod;
        int argsCount = javaMethodBinding.getParameterTypes().length;
        createMethodRefCallArgs(skipOneParam ? argsCount - 1 : argsCount, lambdaParamIdx);

        popSingleExpression(); // CallExpressionContext

        // The last child of current node is a SingleExpression which represents the method reference call.
        // It will be the body of the lambda expression.
        ParserRuleContext stsMethodRefCall = (ParserRuleContext)stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        stsCurrent.removeLastChild();

        wrapMethodRefCallWithLambda(javaMethodBinding, stsMethodRefCall, javaMethodRef, needInstanceParam);
    }

    // Java AST:
    // TryStatement:
    //    try [ ( Resource { ; Resource } ) ]
    //    Block
    //    [ { CatchClause } ]
    //    [ finally Block ]
    // Resource:
    //    VariableDeclarationExpression | Name
    // CatchClause:
    //    catch ( FormalParameter ) Block
    //
    // STS AST:
    //    tryStatement
    //    : Try block (catchClause+ | catchClause* defaultCatch)
    //    ;
    //
    //    catchClause
    //    : Catch exceptionParameter block
    //    ;
    //
    //    exceptionParameter
    //    : OpenParen Identifier typeAnnotation CloseParen
    //    ;
    //
    //    defaultCatch
    //    : Catch (OpenParen Identifier CloseParen)? block
    //
    @Override
    public boolean visit(TryStatement javaTryStatement) {
        List<CatchClause> javaCatchClauses = javaTryStatement.catchClauses();

        // If there are no catch clauses (implying there must be a finally clause),
        // don't emit try statement. Emit a plain block instead with defer statement
        // representing finally clause.
        if (!javaCatchClauses.isEmpty()) {
            pushStatement(new TryStatementContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
            pushCurrent(new BlockContext(stsCurrent, 0));
        }
        else {
            pushStatement(new BlockContext(stsCurrent, 0));
        }

        // If there is a finally clause, create a defer statement
        // and add it to the beginning of try block
        Block javaFinally = javaTryStatement.getFinally();
        if (javaFinally != null) {
            pushStatement(new DeferStatementContext(stsCurrent, 0));
            stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Defer));
            javaFinally.accept(this);
            popStatement(); // DeferStatementContext
        }

        int resCount = processTryResources(javaTryStatement.resources());

        // If try statement is parametrized with resources, then try block
        // executes only after all resources are initialized successfully.
        // To conform to this condition, translate try block in the context
        // of try statement generated for the last resource.
        TryStatementContext stsResourceTryStmt = getCurrentTry();
        if (resCount > 0) {
            if(stsResourceTryStmt == null) {
                // No try statements were generated for resources. Warn and
                // translate the try-block in the context of this try statement.
                reportError("Failed to process resources correctly", javaTryStatement);
            }
            else {
                pushCurrent(stsResourceTryStmt.block(), false);
            }
        }

        // NOTE: Can't call javaTryBlock.accept as that will
        // emit StatementContext which we don't need here
        Block javaTryBlock = javaTryStatement.getBody();
        translateBlockStatements(javaTryBlock);

        if (resCount > 0 && stsResourceTryStmt != null) {
            popCurrent(); // stsResourceTryStmt.block()
        }

        if (!javaCatchClauses.isEmpty()) {
            popCurrent(); // BlockContext
        }
        else {
            popStatement(); // BlockContext
        }

        for (CatchClause javaCatchClause: javaCatchClauses) {
            SingleVariableDeclaration javaException = javaCatchClause.getException();
            Type javaExceptionType = javaException.getType();
            Block javaCatchBody = javaCatchClause.getBody();
            SimpleName javaExceptionName = javaException.getName();

            if (javaExceptionType.isUnionType()) {
                List<Type> javaExcTypes = ((UnionType)javaExceptionType).types();
                for (Type javaExcType : javaExcTypes) {
                    createCatchClause(javaExcType, javaExceptionName, javaCatchBody);
                }
            }
            else {
                createCatchClause(javaExceptionType, javaExceptionName, javaCatchBody);
            }

        }

        if (!javaCatchClauses.isEmpty()) {
            popStatement(); // TryStatementContext
        }

        // Remove generated try statements from the stack.
        while (resCount > 0) {
            stsCurrentTryStatement.pop();
            --resCount;
        }

        stmtTransformed.add(javaTryStatement);
        return false;
    }

    private void createCatchClause(Type javaExceptionType,
                                   SimpleName javaExceptionName,
                                   Block javaClauseBody) {
        pushCurrent(new CatchClauseContext(stsCurrent,0));

        ITypeBinding javaExcTypeBinding = NodeBuilder.getTypeBinding(javaExceptionType);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.CATCH));

        pushCurrent(new ExceptionParameterContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(javaExceptionName));
        if (isValidExceptionType(javaExcTypeBinding)) {
            pushCurrent(new TypeAnnotationContext(stsCurrent, 0));
            javaExceptionType.accept(this);
            popCurrent(); // TypeAnnotationContext
        }
        else {
            // Warn and emit __UnknownType__ for invalid exception types
            reportError("Failed to resolve exception type", javaExceptionType);
            stsCurrent.addChild(NodeBuilder.unknownTypeAnnotation(javaExceptionType)).setParent(stsCurrent);
        }
        // Do check to save some machine cycles on method call
        if( !isRuntimeExceptionType(javaExcTypeBinding) && checkThrownExceptionSet(javaClauseBody))
            removeThrownException(javaExcTypeBinding);
        popCurrent(); // ExceptionParameterContext

        // NOTE: Can't call javaClauseBody.accept as that will
        // emit StatementContext which we don't need here
        pushCurrent(new BlockContext(stsCurrent, 0));
        translateBlockStatements(javaClauseBody);
        popCurrent(); // BlockContext

        popCurrent(); // CatchClauseContext
    }
    private boolean isRuntimeExceptionType(ITypeBinding javaExcType) {
        return isValidExceptionType(javaExcType) &&
                (javaExcType.isEqualTo(RUNTIME_EXCEPTION_TYPE) ||
                 javaExcType.isSubTypeCompatible(RUNTIME_EXCEPTION_TYPE));
    }

    private boolean isValidExceptionType(ITypeBinding javaExcType) {
        return javaExcType != null && !javaExcType.isRecovered() && javaExcType.isClass() &&
               (javaExcType.isEqualTo(THROWABLE_TYPE) || javaExcType.isSubTypeCompatible(THROWABLE_TYPE));
    }

    private int processTryResources(List<Expression> javaResources) {
        // Generate try statement for each resource. Each try statement
        // will contain the try statement for the next resource, or block
        // of the original try statement.
        int resCounter = 0;

        for (Expression javaResExpr : javaResources) {
            if (javaResExpr.getNodeType() == ASTNode.VARIABLE_DECLARATION_EXPRESSION) {
                VariableDeclarationExpression javaVarDeclExpr = (VariableDeclarationExpression) javaResExpr;
                List<VariableDeclarationFragment> javaResDeclList = javaVarDeclExpr.fragments();
                for (VariableDeclarationFragment javaResDecl : javaResDeclList) {
                    TryStatementContext stsResourceTryStmt = getCurrentTry();
                    if (resCounter > 0) {
                        if(stsResourceTryStmt == null) {
                            // Emit untranslated_try_resource code, warn and bail out.
                            stsCurrent.addChild(NodeBuilder.untranslatedTryResource(javaResExpr, stsCurrent)).setParent(stsCurrent);
                            reportError("No enclosing try statement for resource", javaResExpr);
                            continue;
                        }
                        else {
                            pushCurrent(stsResourceTryStmt.block(), false);
                        }
                    }

                    // Translate resource variable declaration. It should always be declared final.
                    int javaResVarMods = javaVarDeclExpr.getModifiers() | Modifier.FINAL;
                    ArrayList<VariableDeclarationFragment> javaDeclFragmentList = new ArrayList<>();
                    javaDeclFragmentList.add(javaResDecl);
                    pushStatement(new VariableOrConstantDeclarationContext(stsCurrent, 0));
                    createAndFillVarOrConstDeclarationList(javaResVarMods, javaDeclFragmentList, javaVarDeclExpr.getType());
                    popStatement(); // VariableOrConstantDeclarationContext

                    emitTryStmtForResourceAllocation(javaResDecl.getName());

                    if (resCounter > 0 && stsResourceTryStmt != null) {
                        popCurrent(); // stsResourceTryStmt.block()
                    }

                    ++resCounter;
                }

                exprTransformed.add(javaResExpr);
            }
            else {
                // Resource expression is either variable access or field access.

                // NOTE: Currently, one case (try(this) { .. }) doesn't work properly due to
                // bug in eclipse JDT: https://bugs.eclipse.org/bugs/show_bug.cgi?id=577128
                // This problem is present in the version of library that we are currently
                // restricted to use in migrator. Once this restriction is removed, we will
                // update the library to more recent version, that contains fix for that bug.

                TryStatementContext stsResourceTryStmt = getCurrentTry();
                if (resCounter > 0) {
                    if(stsResourceTryStmt == null) {
                        // Emit untranslated_try_resource code, warn and bail out.
                        stsCurrent.addChild(NodeBuilder.untranslatedTryResource(javaResExpr, stsCurrent)).setParent(stsCurrent);
                        reportError("No enclosing try statement for resource", javaResExpr);
                        continue;
                    }
                    else {
                        pushCurrent(stsResourceTryStmt.block(), false);
                    }
                }

                emitTryStmtForResourceAllocation(javaResExpr);

                if (resCounter > 0 && stsResourceTryStmt != null) {
                    popCurrent(); // stsResourceTryStmt.block()
                }

                ++resCounter;
            }
        }

        return resCounter;
    }

    private void emitTryStmtForResourceAllocation(Expression javaResourceName) {
        // The code for resource is emitted according to the Java specification:
        // https://docs.oracle.com/javase/specs/jls/se9/html/jls-14.html#jls-14.20.3.1

        // Throwable #primaryExc = null;
        String primaryExceptionVarName = "primaryExc_res" + stsCurrentTryStatement.size();
        pushStatement(new VariableOrConstantDeclarationContext(stsCurrent, 0));
        pushCurrent(createVarOrConstDeclarationList(0));
        pushCurrent(createVarOrConstDeclaration(0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(primaryExceptionVarName));
        stsCurrent.addChild(NodeBuilder.typeAnnotation("Throwable")).setParent(stsCurrent);
        pushCurrent(new InitializerContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
        popCurrent(); // InitializerContext
        popCurrent(); // VarOrConstDeclaration
        popCurrent(); // VarOrConstDeclarationListContext
        popStatement(); // VariableOrConstantDeclarationContext

        TryStatementContext stsTryStmt = new TryStatementContext(stsCurrent, 0);
        pushStatement(stsTryStmt);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
        pushCurrent(new BlockContext(stsCurrent, 0));

        // defer { [if-stmt for resource disposal] }
        pushStatement(new DeferStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Defer));

        // if (Identifier != null) { .. }
        IfStatementContext stsIfStmt = new IfStatementContext(stsCurrent, 0);
        pushStatement(stsIfStmt);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.If));
        pushCurrent(new EqualityExpressionContext(pushSingleExpression()));
        javaResourceName.accept(this);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.NotEquals));
        stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
        popSingleExpression(); // EqualityExpressionContext
        pushStatement(new BlockContext(stsCurrent, 0));

        // if (#primaryExc != null) { .. }
        IfStatementContext stsInnerIfStmt = new IfStatementContext(stsCurrent, 0);
        pushStatement(stsInnerIfStmt);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.If));
        pushCurrent(new EqualityExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression(primaryExceptionVarName)).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.NotEquals));
        stsCurrent.addChild(NodeBuilder.nullLiteral()).setParent(stsCurrent);
        popSingleExpression(); // EqualityExpressionContext

        // Try statement for resource disposal
        pushStatement(new BlockContext(stsCurrent, 0));
        emitTryStmtForResourceDisposal(javaResourceName, primaryExceptionVarName);
        popStatement(); // BlockContext

        ParseTree lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(lastChild instanceof StatementContext);
        stsInnerIfStmt.ifStmt = (StatementContext)lastChild;

        // else { Identifier.close(); }
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Else));
        pushStatement(new BlockContext(stsCurrent, 0));
        pushStatement(new ExpressionStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
        pushCurrent(new CallExpressionContext(pushSingleExpression()));
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        javaResourceName.accept(this);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("close"));
        popSingleExpression(); // MemberAccessExpressionContext
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        popCurrent(); // ArgumentsContext
        popSingleExpression(); // CallExpressionContext
        popStatement(); // ExpressionStatementContext
        popStatement(); // BlockContext

        lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(lastChild instanceof StatementContext);
        stsInnerIfStmt.elseStmt = (StatementContext)lastChild;
        popStatement(); // IfStatementContext
        popStatement(); // BlockContext

        lastChild = stsCurrent.getChild(stsCurrent.getChildCount() - 1);
        assert(lastChild instanceof StatementContext);
        stsIfStmt.ifStmt = (StatementContext)lastChild;
        popStatement(); // IfStatementContext

        popStatement(); // DeferStatementContext
        popCurrent(); // BlockContext
        emitCatchClauseForResourceAllocation(primaryExceptionVarName);
        popStatement(); // TryStatementContext

        stsCurrentTryStatement.push(stsTryStmt);
    }

    private void emitCatchClauseForResourceAllocation(String primaryExceptionVarName) {
        // catch (Throwable #t) {
        //     #primaryExc = #t;
        //     throw #t;
        // }
        pushCurrent(new CatchClauseContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.CATCH));
        pushCurrent(new ExceptionParameterContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("t"));
        stsCurrent.addChild(NodeBuilder.typeAnnotation("Throwable")).setParent(stsCurrent);
        popCurrent(); // ExceptionParameterContext
        pushCurrent(new BlockContext(stsCurrent, 0));

        pushStatement(new ExpressionStatementContext(stsCurrent, 0));
        pushCurrent(new AssignmentExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression(primaryExceptionVarName)).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Assign));
        stsCurrent.addChild(NodeBuilder.identifierExpression("t")).setParent(stsCurrent);
        popSingleExpression(); // AssignmentExpressionContext
        popStatement(); // ExpressionStatementContext

        pushStatement(new ThrowStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Throw));
        stsCurrent.addChild(NodeBuilder.identifierExpression("t")).setParent(stsCurrent);
        popStatement(); // ThrowStatementContext

        popCurrent(); // BlockContext
        popCurrent(); // CatchClauseContext
    }
    private void emitTryStmtForResourceDisposal(Expression javaResourceName, String primaryExceptionVarName) {
        // try { #resource.close(); } catch {..}
        pushStatement(new TryStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
        pushCurrent(new BlockContext(stsCurrent, 0));
        pushStatement(new ExpressionStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Try));
        pushCurrent(new CallExpressionContext(pushSingleExpression()));
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        javaResourceName.accept(this);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("close"));
        popSingleExpression(); // MemberAccessExpressionContext
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        popCurrent(); // ArgumentsContext
        popSingleExpression(); // CallExpressionContext
        popStatement(); // ExpressionStatementContext
        popCurrent(); // BlockContext
        emitCatchClauseForResourceDisposal(primaryExceptionVarName);
        popStatement(); // TryStatementContext
    }

    private void emitCatchClauseForResourceDisposal(String primaryExceptionVarName) {
        // catch (Throwable #suppressedExc) { #primaryExc.addSuppressed(#suppressedExc); }
        pushCurrent(new CatchClauseContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier(StaticTSParser.CATCH));
        pushCurrent(new ExceptionParameterContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("suppressedExc"));
        stsCurrent.addChild(NodeBuilder.typeAnnotation("Throwable")).setParent(stsCurrent);
        popCurrent(); // ExceptionParameterContext

        pushCurrent(new BlockContext(stsCurrent, 0));
        pushStatement(new ExpressionStatementContext(null, 0));
        pushCurrent(new CallExpressionContext(pushSingleExpression()));
        pushCurrent(new MemberAccessExpressionContext(pushSingleExpression()));
        stsCurrent.addChild(NodeBuilder.identifierExpression(primaryExceptionVarName)).setParent(stsCurrent);
        stsCurrent.addChild(NodeBuilder.terminalIdentifier("addSuppressed"));
        popSingleExpression(); // MemberAccessExpressionContext
        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.identifierExpression("suppressedExc")).setParent(stsCurrent);
        popCurrent(); // ExpressionSequenceContext
        popCurrent(); // ArgumentsContext
        popSingleExpression(); // CallExpressionContext
        popStatement(); // ExpressionStatementContext
        popCurrent(); // BlockContext
        popCurrent(); // CatchClauseContext
    }

    @Override
    public boolean visit(ThrowStatement javaThrowStatement) {
        Expression exceptionExpr = javaThrowStatement.getExpression();

        pushStatement(new ThrowStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Throw));
        if(checkThrownExceptionSet(javaThrowStatement))
            addThrownException(exceptionExpr.resolveTypeBinding());

        exceptionExpr.accept(this);

        popStatement();
        stmtTransformed.add(javaThrowStatement);

        return false;
    }

    // Java:
    // synchronized(X) { statements }
    //
    // STS:
    // { MonitorEnter(X); defer MonitorExit(X); statements }
    @Override
    public boolean visit(SynchronizedStatement javaSynchrStmt) {
        pushStatement(new BlockContext(stsCurrent, 0));

        // Add MonitorEnter call
        Expression javaExpr = javaSynchrStmt.getExpression();
        createIntrinsicCall("MonitorEnter", javaExpr);

        // Add deferred MonitorExit call
        pushStatement(new DeferStatementContext(stsCurrent, 0));
        stsCurrent.addChild(NodeBuilder.terminalNode(StaticTSParser.Defer));
        createIntrinsicCall("MonitorExit", javaExpr);
        popStatement(); // DeferStatementContext

        // Translate block statements
        List<Statement> javaStmts = javaSynchrStmt.getBody().statements();
        for (Statement javaStmt : javaStmts)
            javaStmt.accept(this);

        popStatement(); // BlockContext

        stmtTransformed.add(javaSynchrStmt);
        return false;
    }

    private CallExpressionContext createIntrinsicCall(String name, Expression... args) {
        pushStatement(new ExpressionStatementContext(stsCurrent, 0));

        CallExpressionContext stsCallExpr = new CallExpressionContext(pushSingleExpression());
        pushCurrent(stsCallExpr);

        stsCurrent.addChild(NodeBuilder.identifierExpression(name)).setParent(stsCurrent);

        pushCurrent(new ArgumentsContext(stsCurrent, 0));
        pushCurrent(new ExpressionSequenceContext(stsCurrent, 0));

        for (Expression arg : args)
            arg.accept(this);

        popCurrent(); // ExpressionSequenceContext
        popCurrent(); // ArgumentsContext

        popSingleExpression(); // CallExpressionContext
        popStatement(); // ExpressionStatementContext

        return stsCallExpr;
    }

    // NOTE: We don't translate annotations yet, so
    // no need to bother with annotation types.
    @Override
    public boolean visit(AnnotationTypeDeclaration node) {
        return false;
    }

    // NOTE: The following AST nodes should not appear in Java 9 sources
    // but since they are supported by the version of Eclipse JDT we use,
    // let's report in case we see them.
    @Override
    public boolean visit(UnionType javaUnionType) {
        // Emit __UnknownType__, warn and continue.
        reportError("Unsupported Java syntax (union type)", javaUnionType);
        return false;
    }

    @Override
    public boolean visit(TextBlock javaTextBlock) {
        // Emit __untranslatedExpression call, warn and continue.
        stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaTextBlock)).setParent(stsCurrent);
        reportError("Unsupported Java syntax (text block)", javaTextBlock);
        return false;
    }

    @Override
    public boolean visit(SwitchExpression javaSwitchExpression) {
        // Emit __untranslatedExpression call, warn and continue.
        stsCurrent.addChild(NodeBuilder.untranslatedExpression(javaSwitchExpression)).setParent(stsCurrent);
        reportError("Unsupported Java syntax (switch expression)", javaSwitchExpression);
        return false;
    }

    @Override
    public boolean visit(YieldStatement javaYieldStatement) {
        // Emit __untranslatedStatement call, warn and continue.
        stsCurrent.addChild(NodeBuilder.untranslatedStatement(javaYieldStatement, stsCurrent)).setParent(stsCurrent);
        reportError("Unsupported Java syntax (yield statement)", javaYieldStatement);
        return false;
    }
}
