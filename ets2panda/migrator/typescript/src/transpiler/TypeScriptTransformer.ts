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

import * as ts from "typescript";
import { StaticTSContextBase } from "../staticts/StaticTSContextBase";
import * as sts from "../../build/typescript/StaticTSParser";
import * as TranslationUtils from "./TranslationUtils";
import * as NodeBuilder from "./NodeBuilder";
import * as NodeCloner from "../staticts/NodeCloner";
import { CmdOptions } from "./CommandLineParser";
import { TerminalNode } from "antlr4ts/tree";
import { DummyContext } from "../staticts/DummyContext";

type VisitFunction<T extends ts.Node> = (tsNode: T) => StaticTSContextBase;
type VisitorTable = { [key: number]: VisitFunction<ts.Node> };
type ExportTable = { [key: string]: string[] };

type stsHeritageContext = sts.ClassExtendsClauseContext 
                        | sts.InterfaceExtendsClauseContext 
                        | sts.ImplementsClauseContext;

type stsCaseOrDefaultClause = sts.CaseClauseContext | sts.DefaultClauseContext;

type stsClassMembers = sts.ClassFieldDeclarationContext | sts.ClassMethodDeclarationContext |
                        sts.ConstructorDeclarationContext | sts.ClassDeclarationContext |
                        sts.InterfaceDeclarationContext | sts.EnumDeclarationContext;

type stsBlockLikeContext = sts.BlockContext | sts.ClassBodyContext | stsCaseOrDefaultClause;

// This specific implementation of Set has a restriction that
// only non-synthetic nodes may be added to the set (i.e. nodes, 
// that originated from the source code, rather than produced
// by TypeChecker). This helps to avoid including synthetic nodes 
// in the calculation of transformation rate.
// See TypeScriptTransformer.translateSignature as an example,
// where we create a synthetic type node for the omitted return
// type of function and translate it with visitor method.
class NodeSet<T extends ts.Node> extends Set<T> {
    public override add(value: T): this {
        return TranslationUtils.nodeIsSynthesized(value)
            ? this
            : super.add(value);
    }
}

export class TypeScriptTransformer {
    private tsTypeChecker: ts.TypeChecker;

    private stsTopLevelComments: TerminalNode[];

    private stsCU: sts.CompilationUnitContext;

    private stsBlockLikeContexts: stsBlockLikeContext[];

    private tsExports: ExportTable = {};
    
    private hasExportDecls = false;

    private typeRefRenames = new Map<sts.ClassBodyContext, Map<string, string>>();

    private static countStmtTotal = 0;
    private static countExprTotal = 0;
    private static countDeclTotal = 0;
    private static countTypeTotal = 0;
    private static countStmtTransformed = 0;
    private static countExprTransformed = 0;
    private static countDeclTransformed = 0;
    private static countTypeTransformed = 0;
    private exprSet = new NodeSet<ts.Expression>();
    private stmtSet = new NodeSet<ts.Statement>();
    private declSet = new NodeSet<ts.Declaration>();
    private typeSet = new NodeSet<ts.TypeNode>();
    private exprTransformed = new NodeSet<ts.Expression>();
    private stmtTransformed = new NodeSet<ts.Statement>();
    private declTransformed = new NodeSet<ts.Declaration>();
    private typeTransformed = new NodeSet<ts.TypeNode>();

    // The SyntaxKind enum defines additional elements at the end of the enum
    // that serve as markers (FirstX/LastX). Those elements are initialized
    // with indices of the previously defined elements. As result, the enum
    // may return incorrect name for a certain kind index (e.g. 'FirstStatement'
    // instead of 'VariableStatement').
    // The following code creates a map with correct syntax kind names.
    // It can be used when need to print name of syntax kind of certain
    // AST node in diagnostic messages.
    private static tsSyntaxKindNames: string[];
    static {
        if (CmdOptions.VerboseMode) {
            // Since it's for diagnostics only, initialize the collection
            // only in verbose mode.
            let newArray: string[] = [];
            let keys = Object.keys(ts.SyntaxKind);
            let values = Object.values(ts.SyntaxKind);

            for(let i = 0; i < values.length; i++) {
                let val = values[i];
                let kindNum = typeof(val) === 'string' ? parseInt(val) : val;
                if (kindNum && !newArray[kindNum]) {
                    newArray[kindNum] = keys[i];
                }
            }
            TypeScriptTransformer.tsSyntaxKindNames = newArray;
        }
    }

    constructor(private tsSourceFile: ts.SourceFile, private tsProgram: ts.Program) {
        this.tsTypeChecker = tsProgram.getTypeChecker();
        this.stsTopLevelComments = [];
        this.stsBlockLikeContexts = [];
    }

    public static getTransformationRate(): number {
        if (CmdOptions.VerboseMode) {
            console.log("Statements: " + TypeScriptTransformer.countStmtTransformed + " out of " + TypeScriptTransformer.countStmtTotal +
                " (" + ((TypeScriptTransformer.countStmtTransformed / TypeScriptTransformer.countStmtTotal) * 100).toFixed(1) + "%)");
            console.log("Expressions: " + TypeScriptTransformer.countExprTransformed + " out of " + TypeScriptTransformer.countExprTotal +
                " (" + ((TypeScriptTransformer.countExprTransformed / TypeScriptTransformer.countExprTotal) * 100).toFixed(1) + "%)");
            console.log("Declarations: " + TypeScriptTransformer.countDeclTransformed + " out of " + TypeScriptTransformer.countDeclTotal +
                " (" + ((TypeScriptTransformer.countDeclTransformed / TypeScriptTransformer.countDeclTotal) * 100).toFixed(1) + "%)");
            console.log("Types: " + TypeScriptTransformer.countTypeTransformed + " out of " + TypeScriptTransformer.countTypeTotal +
                " (" + ((TypeScriptTransformer.countTypeTransformed / TypeScriptTransformer.countTypeTotal) * 100).toFixed(1) + "%)");
        }

        let countTransformed = TypeScriptTransformer.countStmtTransformed + TypeScriptTransformer.countExprTransformed + 
            TypeScriptTransformer.countDeclTransformed + TypeScriptTransformer.countTypeTransformed;
        let countTotal = TypeScriptTransformer.countStmtTotal + TypeScriptTransformer.countExprTotal + 
            TypeScriptTransformer.countDeclTotal + TypeScriptTransformer.countTypeTotal;
        return countTransformed / countTotal;
    }

    public transform(): sts.CompilationUnitContext {
        if (CmdOptions.ConversionRateMode) {
            this.calculateTotalNodesForConvRate(this.tsSourceFile);
        }

        // Report file being translated if in verbose mode (for debugging purposes mostly).
        if (CmdOptions.VerboseMode) console.log("Transpiling " + this.tsSourceFile.fileName);

        this.visitSourceFile(this.tsSourceFile);   

        if (CmdOptions.ConversionRateMode) {
            // Update total and transformed AST node counts.
            TypeScriptTransformer.countStmtTotal += this.stmtSet.size;
            TypeScriptTransformer.countExprTotal += this.exprSet.size;
            TypeScriptTransformer.countDeclTotal += this.declSet.size;
            TypeScriptTransformer.countTypeTotal += this.typeSet.size;

            TypeScriptTransformer.countStmtTransformed += this.stmtTransformed.size;
            TypeScriptTransformer.countExprTransformed += this.exprTransformed.size;
            TypeScriptTransformer.countDeclTransformed += this.declTransformed.size;
            TypeScriptTransformer.countTypeTransformed += this.typeTransformed.size;

            if (CmdOptions.VerboseMode && CmdOptions.ConvRateVerboseMode) {
                // Print all nodes that weren't translated.
                let setDifference = (setA: Set<ts.Node>, setB: Set<ts.Node>) => new Set([...setA].filter(x => !setB.has(x)));

                let printUntranslatedNodes = (untranslatedNodes: Set<ts.Node>) => {
                    for (const tsNode of untranslatedNodes) {
                        console.log(`Untranslated ${TypeScriptTransformer.tsSyntaxKindNames[tsNode.kind]} at ${this.getLocation(tsNode)}.`);
                    }
                }

                printUntranslatedNodes(setDifference(this.declSet, this.declTransformed));
                printUntranslatedNodes(setDifference(this.exprSet, this.exprTransformed));
                printUntranslatedNodes(setDifference(this.stmtSet, this.stmtTransformed));
                printUntranslatedNodes(setDifference(this.typeSet, this.typeTransformed));
            }
        }

        return this.stsCU;
    }

    private calculateTotalNodesForConvRate(tsSourceFile: ts.SourceFile) {
        // Count total number of statements, expressions, declarations
        // and types in the AST that we expect to transform. This is used
        // in conversion rate computation.

        let visitBodyStatements = (tsBody: ts.Block) => {
            for (const tsStmt of tsBody.statements) {
                visitNode(tsStmt);
            }
        }
        
        let visitNode = (tsNode: ts.Node) => {
            if (TranslationUtils.isExpression(tsNode) &&
                    // Names are translated manually by and large, almost
                    // never by visitor method, so it's hard to count them
                    // properly. Assume we handle them all and ignore.
                    tsNode.kind !== ts.SyntaxKind.Identifier && tsNode.kind !== ts.SyntaxKind.PrivateIdentifier) {
                this.exprSet.add(tsNode);
            }
            else if (TranslationUtils.isStatement(tsNode)) {
                this.stmtSet.add(tsNode);
            }
            else if (TranslationUtils.isDeclaration(tsNode)) {
                this.declSet.add(tsNode);
            }
            else if (ts.isTypeNode(tsNode)) {
                this.typeSet.add(tsNode);
            }

            // Count child nodes.
            if (ts.isFunctionDeclaration(tsNode)
                    || ts.isConstructorDeclaration(tsNode)
                    || ts.isMethodDeclaration(tsNode)
                    || ts.isGetAccessorDeclaration(tsNode)
                    || ts.isSetAccessorDeclaration(tsNode)
                    || ts.isFunctionExpression(tsNode)
                    || ts.isArrowFunction(tsNode)) {
                // For any function-like declaration, visit its children
                // manually to avoid counting its body as a statement.

                if (tsNode.type)
                    visitNode(tsNode.type);

                if (tsNode.typeParameters) {
                    for (const tsTypeParam of tsNode.typeParameters)
                        visitNode(tsTypeParam);
                }

                for (const tsParam of tsNode.parameters)
                    visitNode(tsParam);

                // For the arrow function, body might be either a block,
                // or an expression. For the latter, visit the node as is.
                if (tsNode.body) {
                    if (ts.isBlock(tsNode.body))
                        visitBodyStatements(tsNode.body);
                    else
                        visitNode(tsNode.body);
                }
            } else if (ts.isClassStaticBlockDeclaration(tsNode)) {
                // Count only children of the static block.
                visitBodyStatements(tsNode.body)
            }
            else if (ts.isEnumMember(tsNode)) {
                // Count only the initializer expression of enum member.
                if (tsNode.initializer)
                    visitNode(tsNode.initializer);
            }
            // Do not visit children of import/export declarations as we
            // don't want to count string literals used to specify paths.
            // Also don't visit children of ExpressionWithTypeArguments
            // nodes, as we count them as types, both here and in translation.
            // For any other syntax kind, visit all children.
            else if (!ts.isExportDeclaration(tsNode) && !ts.isImportDeclaration(tsNode) &&
                     !ts.isExpressionWithTypeArguments(tsNode)) {
                tsNode.forEachChild(visitNode);
            }
        }

        visitNode(tsSourceFile);
    }

    private getLocation(tsNode: ts.Node): string {
        // LineAndCharacher is 0-based, thus add '1' to both line and character.
        // Use "tsNode.getStart()" instead of "tsNode.pos", as the latter may
        // return incorrect result due to untrimmed leading trivia.
        let lineAndChar = ts.getLineAndCharacterOfPosition(tsNode.getSourceFile(), tsNode.getStart());
        return `${this.tsSourceFile.fileName}:(${lineAndChar.line + 1},${lineAndChar.character + 1})`;
    }

    private reportMessage(message: string, tsNode: ts.Node) {
        if (CmdOptions.VerboseMode && tsNode && !TranslationUtils.nodeIsSynthesized(tsNode)) {
            console.log(message + " at " + this.getLocation(tsNode));
        }
    }

    private reportError(message: string, tsNode: ts.Node) {
        if (CmdOptions.VerboseMode && tsNode && !TranslationUtils.nodeIsSynthesized(tsNode)) {
            console.error(message + " at " + this.getLocation(tsNode));
        }
    }

    private addToBlockLikeContext(stsStmt: sts.StatementContext | stsClassMembers, depth: number = 1, 
                                  stsAccessMod: number = sts.StaticTSParser.Private): boolean {
        let index = this.stsBlockLikeContexts.length - depth;
        if (index < 0) return false;

        let stsBlockLikeCtx = this.stsBlockLikeContexts[index];

        // If block context is case clause or default clause, do not
        // wrap statement with StatementOrLocalDeclaration node.
        if (stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_block ||
            stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_constructorBody) {
            stsBlockLikeCtx.addChild(NodeBuilder.statementOrLocalDeclaration(stsStmt));
            return true;
        }

        if (stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_caseClause ||
            stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_defaultClause) {
            if (stsStmt.ruleIndex === sts.StaticTSParser.RULE_statement) {
                stsBlockLikeCtx.addChild(stsStmt);
                return true;
            }

            // Recurse until we find the right context for this non-statement
            // (read - declaration) node, or run out of contexts.
            return this.addToBlockLikeContext(stsStmt, depth+1, stsAccessMod);
        }

        if (stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_classBody &&
            stsStmt.ruleIndex !== sts.StaticTSParser.RULE_statement) {
            stsBlockLikeCtx.addChild(NodeBuilder.classMember(stsStmt, stsAccessMod));
            return true;
        }

        return false;
    }

    readonly visitorTable : VisitorTable = {
        [ts.SyntaxKind.SourceFile]: this.visitSourceFile,
        [ts.SyntaxKind.ModuleDeclaration]: this.visitModuleDeclaration,
        [ts.SyntaxKind.ClassDeclaration]: this.visitClassDeclaration,
        [ts.SyntaxKind.PropertyDeclaration]: this.visitPropertyDeclaration,
        [ts.SyntaxKind.MethodDeclaration]: this.visitMethodDeclaration,
        [ts.SyntaxKind.GetAccessor]: this.visitAccessor,
        [ts.SyntaxKind.SetAccessor]: this.visitAccessor,
        [ts.SyntaxKind.Constructor]: this.visitConstructor,
        [ts.SyntaxKind.FunctionDeclaration]: this.visitFunctionDeclaration,
        [ts.SyntaxKind.InterfaceDeclaration]: this.visitInterfaceDeclaration,
        [ts.SyntaxKind.MethodSignature]: this.visitMethodSignature,
        [ts.SyntaxKind.PropertySignature]: this.visitPropertySignature,
        [ts.SyntaxKind.EnumDeclaration]: this.visitEnumDeclaration,
        [ts.SyntaxKind.ImportDeclaration]: this.visitImportDeclaration,
        [ts.SyntaxKind.ExportDeclaration]: this.visitExportDeclaration,
        [ts.SyntaxKind.ExportAssignment]: this.visitExportAssignment,
        [ts.SyntaxKind.ClassStaticBlockDeclaration]: this.visitClassStaticBlock,
        [ts.SyntaxKind.Parameter]: this.visitParameter,
        [ts.SyntaxKind.Block]: this.visitBlock,
        [ts.SyntaxKind.TypeReference]: this.visitTypeReference,
        [ts.SyntaxKind.ArrayType]: this.visitArrayType,
        [ts.SyntaxKind.IntersectionType]: this.visitIntersectionType,
        [ts.SyntaxKind.FunctionType]: this.visitFunctionType,
        [ts.SyntaxKind.UnionType]: this.visitUnionType,
        [ts.SyntaxKind.VariableStatement]: this.visitVariableStatement,
        [ts.SyntaxKind.NullKeyword]: this.visitNullLiteral,
        [ts.SyntaxKind.TrueKeyword]: this.visitTrueLiteral,
        [ts.SyntaxKind.FalseKeyword]: this.visitFalseLiteral,
        [ts.SyntaxKind.NumericLiteral]: this.visitNumericLiteral,
        [ts.SyntaxKind.StringLiteral]: this.visitStringLiteral,
        [ts.SyntaxKind.NoSubstitutionTemplateLiteral]: this.visitNoSubstitutionTemplateLiteral,
        [ts.SyntaxKind.ArrayLiteralExpression]: this.visitArrayLiteralExpression,
        [ts.SyntaxKind.TemplateExpression]: this.visitTemplateExpression,
        [ts.SyntaxKind.TaggedTemplateExpression]: this.visitTaggedTemplateExpression,
        [ts.SyntaxKind.ParenthesizedExpression]: this.visitParenthesizedExpression,
        [ts.SyntaxKind.PrefixUnaryExpression]: this.visitPrefixUnaryExpression,
        [ts.SyntaxKind.PostfixUnaryExpression]: this.visitPostfixUnaryExpression,
        [ts.SyntaxKind.NonNullExpression]: this.visitNonNullExpression,
        [ts.SyntaxKind.BinaryExpression]: this.visitBinaryExpression,
        [ts.SyntaxKind.ConditionalExpression]: this.visitConditionalExpression,
        [ts.SyntaxKind.AsExpression]: this.visitAsExpression,
        [ts.SyntaxKind.PropertyAccessExpression]: this.visitPropertyAccessExpression,
        [ts.SyntaxKind.CallExpression]: this.visitCallExpression,
        [ts.SyntaxKind.NewExpression]: this.visitNewExpression,
        [ts.SyntaxKind.ElementAccessExpression]: this.visitElementAccessExpression,
        [ts.SyntaxKind.FunctionExpression]: this.visitFunctionExpression,
        [ts.SyntaxKind.ArrowFunction]: this.visitArrowFunction,
        [ts.SyntaxKind.Identifier]: this.visitIdentifier,
        [ts.SyntaxKind.ThisKeyword]: this.visitThisExpression,
        [ts.SyntaxKind.SuperKeyword]: this.visitSuperExpression,
        [ts.SyntaxKind.VoidExpression]: this.visitVoidExpression,
        [ts.SyntaxKind.AwaitExpression]: this.visitAwaitExpression,
        [ts.SyntaxKind.ClassExpression]: this.visitClassExpression,
        [ts.SyntaxKind.ObjectLiteralExpression]: this.visitObjectLiteral,
        [ts.SyntaxKind.TypeAliasDeclaration]: this.visitTypeAliasDeclaration,
        [ts.SyntaxKind.HeritageClause]: this.visitHeritageClause,
        [ts.SyntaxKind.ExpressionStatement]: this.visitExpressionStatement,
        [ts.SyntaxKind.IfStatement]: this.visitIfStatement,
        [ts.SyntaxKind.BreakStatement]: this.visitBreakStatement,
        [ts.SyntaxKind.ContinueStatement]: this.visitContinueStatement,
        [ts.SyntaxKind.ReturnStatement]: this.visitReturnStatement,
        [ts.SyntaxKind.LabeledStatement]: this.visitLabeledStatement,
        [ts.SyntaxKind.EmptyStatement]: this.visitEmptyStatement,
        [ts.SyntaxKind.ForStatement]: this.visitForStatement,
        [ts.SyntaxKind.ForInStatement]: this.visitForInStatement,
        [ts.SyntaxKind.ForOfStatement]: this.visitForOfStatement,
        [ts.SyntaxKind.WhileStatement]: this.visitWhileStatement,
        [ts.SyntaxKind.DoStatement]: this.visitDoStatement,
        [ts.SyntaxKind.SwitchStatement]: this.visitSwitchStatement,
        [ts.SyntaxKind.ThrowStatement]: this.visitThrowStatement,
        [ts.SyntaxKind.TryStatement]: this.visitTryStatement,
        [ts.SyntaxKind.CatchClause]: this.visitCatchClause
    }
   
    visitNode(tsNode: ts.Node): StaticTSContextBase {
        // Call corresponding visit function for specified node.
        let visitFn = this.visitorTable[tsNode.kind];

        if (visitFn) {
            // Since we call certain 'visit' function as a callback, the 'this'
            // inside 'visit' function won't refer to the instance context, and
            // instead it will be 'undefined'. We need to explicitly bind 'this'
            // to the method call. For this purpose, use the 'Function.call' API.
            return visitFn.call(this, tsNode);
        }

        if (TranslationUtils.isExpression(tsNode)) {
            return this.reportUntranslatedExpression(tsNode as ts.Expression);
        } 
        
        if (TranslationUtils.isStatement(tsNode)) {
            return this.reportUntranslatedStatement(tsNode as ts.Statement);
        } 
        
        if (ts.isTypeNode(tsNode)) {
            return this.reportUntranslatedType(tsNode);
        }

        let tsNodeKind = TypeScriptTransformer.tsSyntaxKindNames[tsNode.kind];
        this.reportError("Failed to translate syntax construct of kind " + tsNodeKind, tsNode);
        return null;
    }

    visitSourceFile(tsSourceFile: ts.SourceFile): sts.CompilationUnitContext {
        this.stsCU = new sts.CompilationUnitContext(undefined, 0);
        for(const tsNode of tsSourceFile.statements) {
            // Drop top-level empty statements.
            if (tsNode.kind === ts.SyntaxKind.EmptyStatement) continue;

            if (TranslationUtils.isValidTopLevelDeclaration(tsNode)) {
                let stsChildNode = this.visitNode(tsNode);
                if (stsChildNode) {
                    this.stsCU.addChild(stsChildNode);
                }
                else if (this.stsCU.childCount > 0 && this.stsTopLevelComments.length > 0) {
                    // Add all accumulated top-level comments to the last child node we added earlier. 
                    let stsLastChild = this.stsCU.getChild(this.stsCU.childCount-1) as StaticTSContextBase;
                    for (let stsComment of this.stsTopLevelComments) {
                        stsLastChild.addTrailingComment(stsComment);
                    }

                    // Clear list of top-level comments.
                    this.stsTopLevelComments = [];
                }
            }
            else {
                // Warn and add a top-level comment with original syntax.
                this.reportError("Failed to translate top-level statement", tsNode);
                this.addTopLevelComment("Untranslated top-level statement", tsNode);
            }
        }
        
        // Add all remaining top-level comments to CU itself.
        if (this.stsTopLevelComments.length > 0) {
            for (let stsComment of this.stsTopLevelComments) {
                this.stsCU.addTrailingComment(stsComment);
            }
        }

        // Process exported names, if necessary.
        if (this.hasExportDecls) {
            for (let i = 0; i < this.stsCU.childCount; ++i) {
                let stsChildNode = this.stsCU.getChild(i) as StaticTSContextBase;
                if (stsChildNode.ruleIndex !== sts.StaticTSParser.RULE_topDeclaration) continue;

                let stsTopDecl = stsChildNode as sts.TopDeclarationContext;
                let stsTopDeclNames = TranslationUtils.getTopDeclNames(stsTopDecl);

                for (let stsTopDeclName of stsTopDeclNames) {
                    let tsExportNames = this.tsExports[stsTopDeclName];
                    if (!tsExportNames) continue;

                    for (let tsExportName of tsExportNames) {
                        if (tsExportName) {
                            let stsAliasDecl: StaticTSContextBase;
                            let stsFunDecl = stsTopDecl.functionDeclaration();
                            let stsVarOrConstDecl = stsTopDecl.variableOrConstantDeclaration();
                            if (stsFunDecl) {
                                stsAliasDecl = TranslationUtils.createAliasingFunction(stsFunDecl, tsExportName);
                            }
                            else if (stsVarOrConstDecl) {
                                let stsInitExpr = NodeBuilder.identifierExpression(stsTopDeclName);
                                stsAliasDecl = stsVarOrConstDecl.variableDeclarationList() ?
                                                NodeBuilder.singleVariableDeclaration(tsExportName, stsInitExpr) :
                                                NodeBuilder.singleConstantDeclaration(tsExportName, stsInitExpr);
                            }
                            else {
                                stsAliasDecl = NodeBuilder.typeAliasDeclaration(tsExportName, stsTopDeclName);
                            }

                            // Wrap alias declaration in exported top declaration node and  
                            // insert the latter into compilation unit's child node list 
                            // after the current top declaration.
                            // Note: increment loop counter in the process to skip the node
                            // we just inserted on the next iteration.
                            let stsNewTopDecl = NodeBuilder.topDeclaration(stsAliasDecl, true);
                            this.stsCU.children.splice(++i, 0, stsNewTopDecl);
                            stsNewTopDecl.setParent(this.stsCU);
                        }
                        else {
                            // Add export modifier, if it's not already there.
                            if (!stsTopDecl.Export()) {
                                stsTopDecl.children.unshift(NodeBuilder.terminalNode(sts.StaticTSParser.Export));
                            }
                        }
                    }
                }
            }
        }

        return this.stsCU;
    }

    visitModuleDeclaration(tsModuleDecl: ts.ModuleDeclaration): sts.TopDeclarationContext {
        let stsNamespaceDecl = new sts.NamespaceDeclarationContext(undefined, 0);
        
        // NOTE: TS namespaces can't be exported as default, so no need 
        // to call getDeclarationName function here to handle that.
        stsNamespaceDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Namespace));
        stsNamespaceDecl.addChild(NodeBuilder.terminalIdentifier(tsModuleDecl.name));

        // Translate module body.
        let tsModuleBody = tsModuleDecl.body;
        let stsNamespaceBody = new sts.NamespaceBodyContext(stsNamespaceDecl, 0);
        if (tsModuleBody) {
            if (ts.isModuleBlock(tsModuleBody)) {
                for (let tsStmt of tsModuleBody.statements) {
                    let isTranslated = false;
                    
                    if (TranslationUtils.isValidSTSNamespaceMember(tsStmt)) {
                        let stsNamespaceMember = this.visitNode(tsStmt);
                        if (stsNamespaceMember) {
                            stsNamespaceBody.addChild(stsNamespaceMember);
                            isTranslated = true;
                        }
                    }

                    if (!isTranslated) {
                        // Warn and emit DummyContext node with original syntax as comment.
                        this.reportError("Failed to translate namespace member", tsStmt);

                        let stsDummyNode = new DummyContext(stsNamespaceBody, 0);
                        let stsComment = NodeBuilder.multiLineComment("/* " + tsStmt.getText() + " */");
                        stsDummyNode.addTrailingComment(stsComment);
                        stsNamespaceBody.addChild(stsDummyNode);
                    }
                }
            }
            else {
                // Warn and emit DummyContext node with original syntax as comment.
                this.reportError("Failed to translate namespace body", tsModuleBody);

                let stsDummyNode = new DummyContext(stsNamespaceBody, 0);
                let stsComment = NodeBuilder.multiLineComment("/* " + tsModuleBody.getText() + " */");
                stsDummyNode.addTrailingComment(stsComment);
                stsNamespaceBody.addChild(stsDummyNode);
            }
        }

        stsNamespaceDecl.addChild(stsNamespaceBody);
        this.declTransformed.add(tsModuleDecl);

        // Always wrap in TopDeclarationContext as
        // STS allows only top-level namespaces.
        let tsModifiers = ts.getModifiers(tsModuleDecl);
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword);
        return NodeBuilder.topDeclaration(stsNamespaceDecl, isExported);
    }

    visitClassDeclaration(tsClassDecl: ts.ClassDeclaration): StaticTSContextBase {
        let stsClassDecl = this.translateClassLikeDeclaration(tsClassDecl);
        this.declTransformed.add(tsClassDecl);

        // If this is not a top-level class declaration nor a namespace member, 
        // return ClassDeclarationContext node. 
        if (!ts.isSourceFile(tsClassDecl.parent) && !ts.isModuleBlock(tsClassDecl.parent)) 
            return stsClassDecl;
        
        // Otherwise, wrap it in TopDeclarationContext or NamespaceMemberContext before returning.
        // Note: export default class C {} exports only default, not C.
        let tsModifiers = ts.getModifiers(tsClassDecl);
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword) &&
                        (!TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.DefaultKeyword) || 
                         !tsClassDecl.name);

        return ts.isSourceFile(tsClassDecl.parent) ? 
               NodeBuilder.topDeclaration(stsClassDecl, isExported) :
               NodeBuilder.namespaceMember(stsClassDecl, isExported);
    }

    private translateClassLikeDeclaration(tsClassLikeDecl: ts.ClassLikeDeclaration): sts.ClassDeclarationContext {
        let stsClassDecl = new sts.ClassDeclarationContext(undefined, 0);

        let tsClassName: string;
        if (!ts.isClassExpression(tsClassLikeDecl)) {
            // Add 'abstract' or 'open' modifier, as necessary. 
            let tsModifiers = ts.getModifiers(tsClassLikeDecl);
            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.AbstractKeyword)) {
                stsClassDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Abstract));
            }
            else {
                stsClassDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Open));
            }

            tsClassName = this.getDeclarationName(tsClassLikeDecl, tsModifiers);
        }
        else {
            if (ts.isVariableDeclaration(tsClassLikeDecl.parent)) {
                let tsVarName = tsClassLikeDecl.parent.name;
                if (ts.isIdentifier(tsVarName)) tsClassName = tsVarName.text;
            }
            else {
                tsClassName = NodeBuilder.generatedClassName();
            }
        }
        
        stsClassDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Class));
        stsClassDecl.addChild(NodeBuilder.terminalIdentifier(tsClassName));

        // Translate type parameters.
        let stsTypeParams = this.translateTypeParameters(tsClassLikeDecl.typeParameters);
        if (stsTypeParams) stsClassDecl.addChild(stsTypeParams);

        // Translate heritage clauses.
        let tsHeritage = tsClassLikeDecl.heritageClauses;
        if (tsHeritage) {
            let i = 0;
            for (let tsHeritageClause of tsHeritage) {
                if (i > 2) break; // There shouldn't be more than 2 clauses, ever.
                let stsHeritageClause = this.visitNode(tsHeritageClause);
                if (stsHeritageClause) stsClassDecl.addChild(stsHeritageClause);
                ++i;
            }
        }

        // Process class members.
        let stsClassBody = new sts.ClassBodyContext(stsClassDecl, 0);
        this.stsBlockLikeContexts.push(stsClassBody);
        stsClassDecl.addChild(stsClassBody);

        // If translating a named class expression, store its name along
        // with the name of resulting STS class so that we can rename
        // references to that class within its appropriately.
        // See visitTypeRefence function for details.
        if (ts.isClassExpression(tsClassLikeDecl) && tsClassLikeDecl.name) {
            let typeRenamingMap = this.typeRefRenames.get(stsClassBody);
            if (!typeRenamingMap) {
                typeRenamingMap = new Map<string, string>();
                this.typeRefRenames.set(stsClassBody, typeRenamingMap);
            }
            typeRenamingMap.set(tsClassLikeDecl.name.text, tsClassName);
        }

        for (const tsClassMember of tsClassLikeDecl.members) {
            let stsNode = this.visitNode(tsClassMember);
            if (!stsNode) {
                // Emit DummyContext node with original syntax as comment.
                stsNode = new DummyContext(stsClassBody, 0);
                let stsComment = NodeBuilder.multiLineComment("/* Untranslated class member: " + 
                                                                tsClassMember.getText() + " */");
                stsNode.addLeadingComment(stsComment);
            }

            stsClassBody.addChild(stsNode);
        }

        this.stsBlockLikeContexts.pop();
        return stsClassDecl;
    }

    private getDeclarationName(tsDecl: ts.ClassDeclaration | ts.InterfaceDeclaration | 
                                       ts.EnumDeclaration | ts.FunctionDeclaration, 
                                       tsModifiers: readonly ts.Modifier[]): string {
        let tsClassName: string;
        if (tsDecl.name) {
            tsClassName = tsDecl.name.text;

            // Add exported type alias with default as alias name.
            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.DefaultKeyword)) {
                this.addExportedName(tsClassName, sts.StaticTSParser.DEFAULT);
            }
        }
        else {
            // Use default as class name.
            tsClassName = sts.StaticTSParser.DEFAULT;
        }

        return tsClassName;
    }

    visitPropertyDeclaration(tsPropertyDecl: ts.PropertyDeclaration): sts.ClassMemberContext {
        let stsClassMember = new sts.ClassMemberContext(undefined, 0);
        let tsPropertyName = tsPropertyDecl.name;

        // Set access modifiers. In case of no modifier set 'public'.
        let tsModifiers = ts.getModifiers(tsPropertyDecl);
        let stsModifierCode = TranslationUtils.getAccessModifierCode(tsModifiers, tsPropertyName);
        stsClassMember.addChild(NodeBuilder.accessibilityModifier(stsModifierCode));

        let stsClassFieldDeclarationContext = new sts.ClassFieldDeclarationContext(stsClassMember, 0)
        stsClassMember.addChild(stsClassFieldDeclarationContext);

        let stsVarOrConstDeclaration: StaticTSContextBase;
        // set 'const' modifier for TS 'readonly' class fields only if initializer is present.
        // in other case value may be set in constructor
        if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ReadonlyKeyword)) {
            if (tsPropertyDecl.initializer) {
                stsVarOrConstDeclaration = new sts.ConstantDeclarationContext(stsClassFieldDeclarationContext, 0);
                stsClassFieldDeclarationContext.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.READONLY));
            }
            else {
                this.reportError("Translating readonly class property as non-constant field: No initializer", tsPropertyDecl);
            }
        }
        if (!stsVarOrConstDeclaration) {
            stsVarOrConstDeclaration = new sts.VariableDeclarationContext(stsClassFieldDeclarationContext, 0);
        }

        // Add static modifier, if necessary.
        if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.StaticKeyword)) {
            stsClassFieldDeclarationContext.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Static));
        }

        stsClassFieldDeclarationContext.addChild(stsVarOrConstDeclaration);

        this.addPropertyName(tsPropertyName, stsVarOrConstDeclaration, "class property");

        let stsTypeRef : NodeBuilder.STSTypeContext;
        if (tsPropertyDecl.type) {
            stsTypeRef = this.translateType(tsPropertyDecl.type);
            stsVarOrConstDeclaration.addChild(NodeBuilder.typeAnnotation(stsTypeRef));
        }
        else if (!tsPropertyDecl.initializer) {
            // If both property type and initializer are not specified, then
            // property type is 'any'. Translate it as __UnknownType__ for now.
            stsVarOrConstDeclaration.addChild(NodeBuilder.unknownTypeAnnotation());
        }

        if (tsPropertyDecl.initializer) {
            let stsInit = new sts.InitializerContext(stsVarOrConstDeclaration, 0);
            stsInit.addChild(this.visitNode(tsPropertyDecl.initializer))
            stsVarOrConstDeclaration.addChild(stsInit);
        }

        this.declTransformed.add(tsPropertyDecl);
        return stsClassMember;
    }

    visitMethodDeclaration(tsMethodDecl: ts.MethodDeclaration): sts.ClassMemberContext {
        let stsClassMember = new sts.ClassMemberContext(undefined, 0);
        let tsMethodName = tsMethodDecl.name;

        // Set access modifier. In case of no modifier set 'public'.
        let tsModifiers = ts.getModifiers(tsMethodDecl);
        let stsModifierCode = TranslationUtils.getAccessModifierCode(tsModifiers, tsMethodName);
        stsClassMember.addChild(NodeBuilder.accessibilityModifier(stsModifierCode));

        let stsClassMethodDeclaration = new sts.ClassMethodDeclarationContext(stsClassMember, 0);
        stsClassMember.addChild(stsClassMethodDeclaration);

        let stsClassMethod: StaticTSContextBase = null;
        if (!tsMethodDecl.body) {
            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.AbstractKeyword)) { 
                // Abstract method.
                stsClassMethod = new sts.AbstractOrNativeClassMethodContext(stsClassMethodDeclaration)

                let stsModifierCode = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.AbstractKeyword) ?
                                        sts.StaticTSParser.Abstract : sts.StaticTSParser.Native;
                stsClassMethod.addChild(NodeBuilder.terminalNode(stsModifierCode));
            }
            else {
                // Warn and return null.
                // TODO: Handle overloading method signatures, if possible.
                this.reportError("Failed to translate method declaration: No body and no abstract or declare modifier", tsMethodDecl);
                return null;
            }
        }
        else {
            // not abstract method
            stsClassMethod = new sts.ClassMethodWithBodyContext(stsClassMethodDeclaration)
        }

        // Add static modifier, if necessary.
        if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.StaticKeyword)) {
            stsClassMethod.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Static));
        }
        stsClassMethodDeclaration.addChild(stsClassMethod);

        let stsComment = this.addMethodName(tsMethodName, stsClassMethod);

        // If the above addMethodName call returned a comment, 
        // attach it to the method signature, as we can't attach
        // it to the method name itself.
        let stsSignature = this.translateSignature(tsMethodDecl);
        if (stsComment) stsSignature.addLeadingComment(stsComment);
        stsClassMethod.addChild(stsSignature);

        if (tsMethodDecl.body) {
            // Translate method body.
            stsClassMethod.addChild(this.visitNode(tsMethodDecl.body));
        }

        this.declTransformed.add(tsMethodDecl);
        return stsClassMember;
    }

    private addMethodName(tsMethodName: ts.PropertyName, stsEnclNode: StaticTSContextBase): TerminalNode {
        let stsMethodName = NodeBuilder.terminalIdentifier(tsMethodName);

        let stsComment: TerminalNode;
        if (TranslationUtils.isInvalidOrModified(stsMethodName)) {
            stsComment = NodeBuilder.multiLineComment("/* Original method name: " + tsMethodName.getText() + " */");
        }

        stsEnclNode.addChild(stsMethodName);
        return stsComment;
    }

    visitAccessor(tsAccessor: ts.GetAccessorDeclaration | ts.SetAccessorDeclaration): StaticTSContextBase {
        let stsMember: StaticTSContextBase;
        let stsAccessor: StaticTSContextBase;
        let isGetter = ts.isGetAccessor(tsAccessor);
        let isInInterface = ts.isInterfaceDeclaration(tsAccessor.parent);

        if (isInInterface) {
            stsMember = new sts.InterfaceMemberContext(undefined, 0);
            stsAccessor = isGetter ? new sts.InterfaceGetterContext(stsMember)
                                   : new sts.InterfaceSetterContext(stsMember);
        }
        else {
            let tsModifiers = ts.getModifiers(tsAccessor);
            stsMember = new sts.ClassMemberContext(undefined, 0);

            // Add access modifiers.
            let stsModifierCode = TranslationUtils.getAccessModifierCode(tsModifiers, tsAccessor.name);
            stsMember.addChild(NodeBuilder.accessibilityModifier(stsModifierCode));

            stsAccessor = isGetter ? new sts.ClassGetterDeclarationContext(stsMember, 0)
                                   : new sts.ClassSetterDeclarationContext(stsMember, 0);

            // Add getter-specific modifiers.
            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.AbstractKeyword) || !tsAccessor.body) {
                stsAccessor.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Abstract));
            }

            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.OverrideKeyword)) {
                stsAccessor.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Override));
            }

            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.StaticKeyword)) {
                stsAccessor.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Static));
            }
        }

        let stsAccessorHeader: StaticTSContextBase;
        if (isGetter) {
            stsAccessorHeader = new sts.GetterHeaderContext(stsAccessor, 0);
            stsAccessorHeader.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.GET));
            stsAccessorHeader.addChild(NodeBuilder.terminalIdentifier(tsAccessor.name));

            // Translate getter return type.
            let tsGetterRetType = this.getReturnTypeFromSignatureDecl(tsAccessor);
            if (tsGetterRetType) {
                let stsGetterType = this.translateType(tsGetterRetType);
                stsAccessorHeader.addChild(NodeBuilder.typeAnnotation(stsGetterType));
            }
            else {
                // Warn and emit __UnknownType__
                this.reportError("Failed to infer getter return type", tsAccessor);
                stsAccessorHeader.addChild(NodeBuilder.unknownTypeAnnotation())
            }
        }
        else {
            stsAccessorHeader = new sts.SetterHeaderContext(stsAccessor, 0);
            stsAccessorHeader.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.SET));
            stsAccessorHeader.addChild(NodeBuilder.terminalIdentifier(tsAccessor.name));

            // Translate setter parameter.
            let stsParam: StaticTSContextBase;
            if (tsAccessor.parameters && tsAccessor.parameters.length > 0) {
                stsParam = this.visitNode(tsAccessor.parameters[0]);
            }
            else {
                // Shouldn't ever get here! But if we do, somehow,
                // warn and emit __InvalidName__ : __UnknownType__
                this.reportError("No parameter found for setter", tsAccessor);

                stsParam = new sts.ParameterContext(stsAccessorHeader, 0);
                stsParam.addChild(NodeBuilder.invalidIdentifier());
                stsParam.addChild(NodeBuilder.unknownTypeAnnotation());
            }

            stsAccessorHeader.addChild(stsParam);
        }


        stsAccessor.addChild(stsAccessorHeader);

        // Translate getter body, if any.
        if (tsAccessor.body) {
            stsAccessor.addChild(this.visitNode(tsAccessor.body));
        }

        stsMember.addChild(stsAccessor);

        this.declTransformed.add(tsAccessor);
        return stsMember;
    }

    private getReturnTypeFromSignatureDecl(tsSignatureDecl: ts.SignatureDeclaration): ts.TypeNode {
        if (tsSignatureDecl.type) return tsSignatureDecl.type;

        // Use type checker to get the actual return type.
        let tsSingature = this.tsTypeChecker.getSignatureFromDeclaration(tsSignatureDecl);
        let tsSignatureType = tsSingature.getReturnType();
        return this.tsTypeChecker.typeToTypeNode(tsSignatureType, tsSignatureDecl, 
                                                 ts.NodeBuilderFlags.None);
    }

    visitConstructor(tsCtorDecl: ts.ConstructorDeclaration): sts.ClassMemberContext {
        // Don't translate body-less ctors.
        if (!tsCtorDecl.body) {
            // Warn and return null.
            this.reportError("Failed to translate constructor declaration: No body", tsCtorDecl);
            return null;
        }

        let stsClassMember = new sts.ClassMemberContext(undefined, 0);

        // Set access modifier. In case of no modifier set 'public'.
        let tsModifiers = ts.getModifiers(tsCtorDecl);
        let stsModifierCode = TranslationUtils.getAccessModifierCode(tsModifiers);
        stsClassMember.addChild(NodeBuilder.accessibilityModifier(stsModifierCode));

        let stsCtorDecl = new sts.ConstructorDeclarationContext(stsClassMember, 0);
        stsCtorDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Constructor));

        // Translate type parameters.
        let stsTypeParams = this.translateTypeParameters(tsCtorDecl.typeParameters);
        if (stsTypeParams) stsCtorDecl.addChild(stsTypeParams);

        // Translate formal parameters.
        let stsParams = this.translateFormalParameters(tsCtorDecl.parameters);
        if (stsParams) stsCtorDecl.addChild(stsParams);

        // Translate ctor body.
        let stsCtorBody = new sts.ConstructorBodyContext(stsCtorDecl, 0);
        let stsBlock = this.visitNode(tsCtorDecl.body) as sts.BlockContext;
        for (let i = 0; i < stsBlock.childCount; ++i) {
            let stsChild = stsBlock.getChild(i) as StaticTSContextBase;
            if (stsChild) stsCtorBody.addChild(stsChild);
        }
        stsCtorDecl.addChild(stsCtorBody);

        // For each parameter property (if any), emit an assignment
        // of parameter value to an instance field with the same name
        // which we should have emitted while translating parameters
        // (see visitParameter method for details).
        let index = (stsCtorBody.childCount > 0 && stsCtorBody.getChild(0) instanceof sts.ConstructorCallContext) ? 1 : 0;
        for (let tsParam of tsCtorDecl.parameters) {
            if (ts.getModifiers(tsParam) && ts.isIdentifier(tsParam.name)) {
                let stsFieldName = NodeBuilder.terminalIdentifier(tsParam.name);
                let stsFieldAccess = NodeBuilder.memberAccess(NodeBuilder.thisExpression(), stsFieldName);
                let stsParamNameExpr = NodeBuilder.identifierExpression(tsParam.name);
                let stsAssignExpr = NodeBuilder.assignmentExpression(stsFieldAccess, stsParamNameExpr);

                let stsExprStmt = new sts.ExpressionStatementContext(undefined, 0);
                stsExprStmt.addChild(stsAssignExpr);

                let stsStatement = NodeBuilder.statement(stsExprStmt);
                let stsStmtOrLocalDecl = NodeBuilder.statementOrLocalDeclaration(stsStatement);

                if (index < stsCtorBody.childCount) {
                    stsCtorBody.children.splice(index, 0, stsStmtOrLocalDecl);
                    stsStmtOrLocalDecl.setParent(stsCtorBody);
                }
                else {
                    stsCtorBody.addChild(stsStmtOrLocalDecl);
                }
                ++index;
            }
        }

        stsClassMember.addChild(stsCtorDecl);
        this.declTransformed.add(tsCtorDecl);
        return stsClassMember;
    }

    visitInterfaceDeclaration(tsInterfaceDecl: ts.InterfaceDeclaration): StaticTSContextBase {
        let tsModifiers = ts.getModifiers(tsInterfaceDecl);
        let stsInterfaceDecl = new sts.InterfaceDeclarationContext(undefined, 0);

        let tsInterfaceName = this.getDeclarationName(tsInterfaceDecl, tsModifiers);
        stsInterfaceDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Interface));
        stsInterfaceDecl.addChild(NodeBuilder.terminalIdentifier(tsInterfaceName));

        // Translate type parameters.
        let stsTypeParams = this.translateTypeParameters(tsInterfaceDecl.typeParameters);
        if (stsTypeParams) stsInterfaceDecl.addChild(stsTypeParams);

        // Translate heritage clause.
        let tsHeritage = tsInterfaceDecl.heritageClauses;
        if (tsHeritage && tsHeritage.length > 0) {
            // There should never be more than one extends clause for interfaces.
            let stsExtendsClause = this.visitNode(tsInterfaceDecl.heritageClauses[0]);
            if (stsExtendsClause) stsInterfaceDecl.addChild(stsExtendsClause);
        }

        // Translate interface body.
        let stsInterfaceBody = new sts.InterfaceBodyContext(stsInterfaceDecl, 0);
        for (let tsInterfaceMember of tsInterfaceDecl.members) {
            let stsInterfaceMember = this.visitNode(tsInterfaceMember);
            if (!stsInterfaceMember) {
                // Emit dummy node with original syntax as a comment.
                stsInterfaceMember = new DummyContext(stsInterfaceBody, 0);
                let stsComment = NodeBuilder.multiLineComment("/* Untranslated interface member: " + 
                                                                tsInterfaceMember.getText() + " */");
                stsInterfaceMember.addLeadingComment(stsComment);
            }
            
            stsInterfaceBody.addChild(stsInterfaceMember);
        }
        stsInterfaceDecl.addChild(stsInterfaceBody);

        this.declTransformed.add(tsInterfaceDecl);
        
        // If this is not a top-level interface declaration nor a namespace member,
        // return InterfaceDeclarationContext node.
        if (!ts.isSourceFile(tsInterfaceDecl.parent) && !ts.isModuleBlock(tsInterfaceDecl.parent)) 
            return stsInterfaceDecl;

        // Otherwise, wrap it in TopDeclarationContext or NamespaceMemberContext before returning.
        // Note: export default interface I {} exports only default, not I.
        // Also note that interface declaration requires a name, hence we
        // don't check for the absense of name here, as opposed to class or
        // function declarations.
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword) &&
                        !TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.DefaultKeyword);

        return ts.isSourceFile(tsInterfaceDecl.parent) ? 
               NodeBuilder.topDeclaration(stsInterfaceDecl, isExported) :
               NodeBuilder.namespaceMember(stsInterfaceDecl, isExported);
    }

    visitMethodSignature(tsMethodSignature: ts.MethodSignature): sts.InterfaceMemberContext {
        let stsInterfaceMember = new sts.InterfaceMemberContext(undefined, 0);
        let stsInterfaceMethod = new sts.InterfaceMethodContext(stsInterfaceMember);

        let stsComment = this.addMethodName(tsMethodSignature.name, stsInterfaceMethod);
        if (stsComment) stsInterfaceMethod.addTrailingComment(stsComment);

        stsInterfaceMethod.addChild(this.translateSignature(tsMethodSignature));

        stsInterfaceMember.addChild(stsInterfaceMethod);
        this.declTransformed.add(tsMethodSignature);
        return stsInterfaceMember;
    }

    visitPropertySignature(tsPropSignature: ts.PropertySignature): sts.InterfaceMemberContext {
        let stsInterfaceMember = new sts.InterfaceMemberContext(undefined, 0);
        let stsInterfaceField = new sts.InterfaceFieldContext(stsInterfaceMember);

        let tsModifiers = ts.getModifiers(tsPropSignature);
        if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ReadonlyKeyword))
            stsInterfaceField.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.READONLY));

        let stsVarDecl = new sts.VariableDeclarationContext(stsInterfaceField, 0);
        stsVarDecl.addChild(NodeBuilder.terminalIdentifier(tsPropSignature.name));

        if (tsPropSignature.type) {
            let stsType = this.translateType(tsPropSignature.type);
            stsVarDecl.addChild(NodeBuilder.typeAnnotation(stsType));
        }
        else {
            this.reportError("Failed to infer type of property signature", tsPropSignature);
            stsVarDecl.addChild(NodeBuilder.unknownTypeAnnotation());
        }

        stsInterfaceField.addChild(stsVarDecl);
        stsInterfaceMember.addChild(stsInterfaceField);

        this.declTransformed.add(tsPropSignature);
        return stsInterfaceMember;
    }

    visitHeritageClause(tsHeritageClause: ts.HeritageClause): stsHeritageContext {
        let tsToken = tsHeritageClause.token;
        let stsHeritageClause: stsHeritageContext;
        let isClassExtends = false;
        if (tsToken === ts.SyntaxKind.ExtendsKeyword) {
            let tsParent = tsHeritageClause.parent;
            if (ts.isInterfaceDeclaration(tsParent)) {
                stsHeritageClause = new sts.InterfaceExtendsClauseContext(undefined, 0);
            }
            else {
                stsHeritageClause = new sts.ClassExtendsClauseContext(undefined, 0);
                isClassExtends = true;
            }

            stsHeritageClause.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.EXTENDS));
        }
        else {
            stsHeritageClause = new sts.ImplementsClauseContext(undefined, 0);
            stsHeritageClause.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.IMPLEMENTS));
        }

        let stsTypeContainer = isClassExtends ? stsHeritageClause : 
                                                new sts.InterfaceTypeListContext(stsHeritageClause, 0);

        for (let tsType of tsHeritageClause.types) {
            // Translate only what we can convert to STS type refs,
            // everything else denote as __UnknownType__.
            let tsTypeExpr = tsType.expression;
            let stsTypeRef: sts.TypeReferenceContext;
            if (ts.isIdentifier(tsTypeExpr) || ts.isPropertyAccessExpression(tsTypeExpr)) {
                if (ts.isIdentifier(tsTypeExpr)) {
                    stsTypeRef = NodeBuilder.typeReference(tsTypeExpr);
                }
                else {
                    // There is only one case we should allow here, namely
                    // reference to a type qualified by a single enclosing
                    // namespace (NOTE: Not by a namespace object!)
                    if (this.isQualifiedByNamespace(tsTypeExpr)) {
                        stsTypeRef = NodeBuilder.typeReference(tsTypeExpr.getText());
                    }
                }
            }
            if (stsTypeRef) {
                // Count both identifiers and property accesses
                // as transformed types as we include them as such
                // in total counts.
                this.typeTransformed.add(tsType);
            }
            else {
                // Warn and emit __UnknownType__.
                stsTypeRef = this.reportUntranslatedType(tsType);
            }

            // Translate type arguments.
            let stsTypeArgs = this.translateTypeArguments(tsType.typeArguments, tsTypeExpr);
            if (stsTypeArgs) {
                let stsTypeRefParts = stsTypeRef.typeReferencePart();
                stsTypeRefParts[stsTypeRefParts.length-1].addChild(stsTypeArgs);
            }

            stsTypeContainer.addChild(stsTypeRef);

            if (isClassExtends) { 
                // There should be no more than one type in class extends clause.
                if (tsHeritageClause.types.length > 1) break;
            }
            else {
                // Add interface type list to heritage clause.
                stsHeritageClause.addChild(stsTypeContainer);
            }
        }

        return stsHeritageClause;
    }

    visitEnumDeclaration(tsEnumDecl: ts.EnumDeclaration): StaticTSContextBase {
        let stsResult = this.isCompatibleWithSTSEnum(tsEnumDecl) ?
                        this.translateEnumDeclAsSTSEnum(tsEnumDecl):
                        this.translateEnumDeclAsClass(tsEnumDecl);

        // Don't emit empty enums. Last child or resulting node is
        // either a ClassBodyContext or EnumBodyContext and should
        // have no children if the original enum was empty or we 
        // failed to translate all its elements.
        let stsLastChild = stsResult.getChild(stsResult.childCount-1);
        if (stsLastChild.childCount === 0) {
            // Warn and, if this is a top-level enum, add a top-level comment with
            // original enum declaration syntax. 
            // Note: No need to do the same for block-level enums as they will be 
            // picked up by visitBlock function and emitted as __untranslated_statement() 
            // calls there.
            this.reportError("Failed to translate enum declaration", tsEnumDecl);

            if (ts.isSourceFile(tsEnumDecl.parent)) {
                this.addTopLevelComment("Untranslated enum declaration", tsEnumDecl);
            }

            return null;
        }

        this.declTransformed.add(tsEnumDecl);

        // If this is not a top-level enum declaration nor a namespace member,
        // return resulting node as is.
        if (!ts.isSourceFile(tsEnumDecl.parent) && !ts.isModuleBlock(tsEnumDecl.parent)) 
            return stsResult;

        // Otherwise, wrap it in TopDeclarationContext or NamespaceMemberContext before returning.
        let tsModifiers = ts.getModifiers(tsEnumDecl);
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword);

        return ts.isSourceFile(tsEnumDecl.parent) ? 
               NodeBuilder.topDeclaration(stsResult, isExported) :
               NodeBuilder.namespaceMember(stsResult, isExported);
    }

    private translateEnumDeclAsClass(tsEnumDecl: ts.EnumDeclaration): sts.ClassDeclarationContext {
        let stsClassDecl = new sts.ClassDeclarationContext(undefined, 0);

        stsClassDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Class));
        stsClassDecl.addChild(NodeBuilder.terminalIdentifier(tsEnumDecl.name.text));

        // TODO: Do we need to extend class Enum<T> here?

        // Translate enum members.
        let stsInitValue = 0;
        let stsClassBodyComments: TerminalNode[] = [];
        let stsClassBody = new sts.ClassBodyContext(stsClassDecl, 0);
        this.stsBlockLikeContexts.push(stsClassBody);

        for (let tsEnumMember of tsEnumDecl.members) {
            let stsClassMember = new sts.ClassMemberContext(stsClassDecl, 0);
            stsClassMember.addChild(NodeBuilder.accessibilityModifier(sts.StaticTSParser.Public));

            let stsFieldDecl = new sts.ClassFieldDeclarationContext(stsClassMember, 0);
            stsFieldDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Static));
            stsFieldDecl.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.READONLY));

            let stsConstDecl = new sts.ConstantDeclarationContext(stsFieldDecl, 0);
            this.addPropertyName(tsEnumMember.name, stsConstDecl, "enum member");

            let stsInitializer: sts.SingleExpressionContext;
            let tsEnumMemberInit = tsEnumMember.initializer;
            if (tsEnumMemberInit) {
                stsInitializer = this.visitNode(tsEnumMemberInit);
                if (!stsInitializer) {
                    stsInitializer = this.reportUntranslatedExpression(tsEnumMemberInit, "enum member initializer")
                }

                // If initializer is numerical constant expression, use its value 
                // (incremented by 1) as initial value for the following enum members
                // without an initializer (if any). Otherwise, reset initial value to 0.
                let tsConstValue = this.tsTypeChecker.getConstantValue(tsEnumMember);
                stsInitValue = (typeof tsConstValue === 'number') ? tsConstValue + 1: 0;
            }
            else {
                // This has to be a numeric value, so just emit numeric literal 
                // and increment initial value by 1.
                stsInitializer = NodeBuilder.numericLiteral(stsInitValue.toString());
                ++stsInitValue;
            }

            let stsInitializerContext = new sts.InitializerContext(stsConstDecl, 0);
            stsInitializerContext.addChild(stsInitializer);
            stsConstDecl.addChild(stsInitializerContext);

            // Pick up unattached comments that may have
            // been created by addPropertyName call above. 
            if (stsClassBodyComments.length > 0) {
                for (let stsComment of stsClassBodyComments) {
                    stsConstDecl.addLeadingComment(stsComment);
                }
                stsClassBodyComments = [];
            }

            stsFieldDecl.addChild(stsConstDecl);
            stsClassMember.addChild(stsFieldDecl);
            stsClassBody.addChild(stsClassMember);
            
            this.declTransformed.add(tsEnumMember);
        }

        this.stsBlockLikeContexts.pop();
        stsClassDecl.addChild(stsClassBody);
        return stsClassDecl;
    }

    private translateEnumDeclAsSTSEnum(tsEnumDecl: ts.EnumDeclaration): sts.EnumDeclarationContext {
        let stsEnumDecl = new sts.EnumDeclarationContext(undefined, 0);

        stsEnumDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Enum));
        stsEnumDecl.addChild(NodeBuilder.terminalIdentifier(tsEnumDecl.name.text));
        
        // Translate enum members.
        let stsEnumBodyComments: TerminalNode[] = [];
        let stsEnumBody = new sts.EnumBodyContext(stsEnumDecl, 0);
        for (let tsEnumMember of tsEnumDecl.members) {
            let stsEnumMember = new sts.EnumMemberContext(stsEnumBody, 0);
            this.addPropertyName(tsEnumMember.name, stsEnumMember, "enum member");

            let tsEnumMemberInit = tsEnumMember.initializer;
            if (tsEnumMemberInit) {
                let stsInitializer = this.visitNode(tsEnumMemberInit);
                if (!stsInitializer) {
                    stsInitializer = this.reportUntranslatedExpression(tsEnumMemberInit, "enum member initializer");
                }
                stsEnumMember.addChild(stsInitializer);
            }
            
            // Pick up unattached comments that may have
            // been created by addPropertyName call above. 
            if (stsEnumBodyComments.length > 0) {
                for (let stsComment of stsEnumBodyComments) {
                    stsEnumMember.addLeadingComment(stsComment);
                }
                stsEnumBodyComments = [];
            }

            stsEnumBody.addChild(stsEnumMember);
            
            this.declTransformed.add(tsEnumMember);
        }

        stsEnumDecl.addChild(stsEnumBody);
        return stsEnumDecl;
    }

    private addTopLevelComment(commentHeader: string, tsNode: ts.Node): void {
        let stsComment = NodeBuilder.multiLineComment("/* " + commentHeader + ":\n" + 
                                                      tsNode.getText() + " */");
        this.stsTopLevelComments.push(stsComment);
    }

    // Returns false if there is at least one enum member with 
    // non-constant value or a value of non-integer type.
    private isCompatibleWithSTSEnum(tsEnumDecl: ts.EnumDeclaration): boolean {
        for (let tsEnumMember of tsEnumDecl.members) {
            if (tsEnumMember.initializer) {
                let tsConstValue = this.tsTypeChecker.getConstantValue(tsEnumMember);
                if (tsConstValue === undefined) return false;
                
                if (typeof tsConstValue !== 'number' || 
                    tsConstValue.toFixed(0) !== tsConstValue.toString())
                    return false;
            }
        }

        return true;
    }

    private addPropertyName(tsPropName: ts.PropertyName, stsEnclNode: StaticTSContextBase, stsEnclNodeKind: string): void {
        let stsPropName = NodeBuilder.terminalIdentifier(tsPropName);

        if (TranslationUtils.isInvalidOrModified(stsPropName)) {
            // Append a comment with original property name syntax.
            let stsComment = NodeBuilder.multiLineComment("/* Original " + stsEnclNodeKind + " name: " + 
                                                            tsPropName.getText() + " */");
            stsEnclNode.addTrailingComment(stsComment);
        }

        stsEnclNode.addChild(stsPropName);
    }

    visitFunctionDeclaration(tsFunDecl: ts.FunctionDeclaration): StaticTSContextBase {
        let tsModifiers = ts.getModifiers(tsFunDecl);
        let tsFunName = this.getDeclarationName(tsFunDecl, tsModifiers);

        if (ts.isSourceFile(tsFunDecl.parent) || ts.isModuleBlock(tsFunDecl.parent)) {
            // Don't translate generator functions.
            if (tsFunDecl.asteriskToken) {
                this.reportError("Failed to translate generator function declaration", tsFunDecl);
                this.addTopLevelComment("Untranslated generator function declaration", tsFunDecl);
                return null;
            }

            let stsFunDecl = new sts.FunctionDeclarationContext(undefined, 0);

            // Add async modifier, if necessary.
            if (TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.AsyncKeyword)) {
                stsFunDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Async));
            }

            stsFunDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Function));
            stsFunDecl.addChild(NodeBuilder.terminalIdentifier(tsFunName));

            let stsSignature = this.translateSignature(tsFunDecl);
            stsFunDecl.addChild(stsSignature);
            
            if (tsFunDecl.body) {
                // Translate function body.
                stsFunDecl.addChild(this.visitNode(tsFunDecl.body));
            }
            else {
                // TODO: Handle overloading function signatures, if possible.
                this.reportError("Failed to translate function declaration: No body", tsFunDecl);
                this.addTopLevelComment("Untranslated overloading function declaration", tsFunDecl);
                return null;
            }

            this.declTransformed.add(tsFunDecl);

            // Wrap it in TopDeclarationContext or NamespaceMemberContext before returning.
            // Note: export default function foo{} exports default, not foo.
            let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword) &&
                            (!TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.DefaultKeyword) ||
                             !tsFunDecl.name);

            return ts.isSourceFile(tsFunDecl.parent) ? 
                   NodeBuilder.topDeclaration(stsFunDecl, isExported) :
                   NodeBuilder.namespaceMember(stsFunDecl, isExported);
        }
        else {
            // Function declaration is block-scoped. Translate function as 
            // lambda expression. Create local variable with the name of the
            // function and initialize it with the lambda.

            // STS currently doesn't allow type parameters on lambda expressions.
            let tsTypeParams = tsFunDecl.typeParameters;
            if (tsTypeParams && tsTypeParams.length > 0) {
                return this.reportUntranslatedStatement(tsFunDecl, "local generic function declaration");
            }

            // Don't translate local generator functions.
            if (tsFunDecl.asteriskToken) {
                return this.reportUntranslatedStatement(tsFunDecl, "local generator function declaration");
            }

            // Also don't translate overload signatures for local functions.
            if (!tsFunDecl.body) {
                return this.reportUntranslatedStatement(tsFunDecl, "local function declaration: No body");
            }
            
            let stsVarOrConstDecl = new sts.VariableOrConstantDeclarationContext(undefined, 0);
            stsVarOrConstDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Let));

            let stsVarDeclList = new sts.VariableDeclarationListContext(stsVarOrConstDecl, 0);
            stsVarOrConstDecl.addChild(stsVarDeclList);

            let stsVarDecl = new sts.VariableDeclarationContext(stsVarDeclList, 0); 
            stsVarDecl.addChild(NodeBuilder.terminalIdentifier(tsFunName));
            stsVarDeclList.addChild(stsVarDecl);

            let stsInit = new sts.InitializerContext(stsVarDecl, 0);
            stsInit.addChild(this.translateLambdaExpression(tsFunDecl))
            stsVarDecl.addChild(stsInit);

            this.declTransformed.add(tsFunDecl);
            return stsVarOrConstDecl;
        }
    }

    private translateSignature(tsSignatureDecl: ts.SignatureDeclaration): sts.SignatureContext {
        let stsSignature = new sts.SignatureContext(undefined, 0);

        // Translate type parameters.
        let stsTypeParams = this.translateTypeParameters(tsSignatureDecl.typeParameters);
        if (stsTypeParams) stsSignature.addChild(stsTypeParams);

        // Translate formal parameters.
        let stsParameterList = this.translateFormalParameters(tsSignatureDecl.parameters);
        if (stsParameterList) stsSignature.addChild(stsParameterList);

        // Translate return type.
        let tsRetTypeNode = this.getReturnTypeFromSignatureDecl(tsSignatureDecl);

        let stsTypeRef: NodeBuilder.STSTypeContext;
        if (tsRetTypeNode) {
            stsTypeRef = this.translateType(tsRetTypeNode);
        }
        else {
            // If type checker didn't do any good, warn and emit __UnknownType__.
            this.reportError("Failed to infer return type", tsSignatureDecl);
            stsTypeRef = NodeBuilder.unknownTypeReference();
        }

        stsSignature.addChild(NodeBuilder.typeAnnotation(stsTypeRef));
        return stsSignature;
    }

    private translateFormalParameters(tsParameters: ts.NodeArray<ts.ParameterDeclaration>): sts.ParameterListContext {
        // Sanity check.
        if (!tsParameters || tsParameters.length === 0) return null;

        let stsParameterList = new sts.ParameterListContext(undefined, 0);
        for (const tsParameter of tsParameters) {
            let stsParam = this.visitNode(tsParameter);

            if (stsParam) {
                stsParameterList.addChild(stsParam);
            }
            else {
                // Warn and emit a comment with original parameter syntax
                this.reportError("Failed to translate destructuring parameter", tsParameter);
                let stsComment = NodeBuilder.multiLineComment("/* " + tsParameter.getText() + " */");
                stsParameterList.addTrailingComment(stsComment);
            }
        }

        return stsParameterList;
    }

    visitParameter(tsParameter: ts.ParameterDeclaration): StaticTSContextBase {
        let stsParam = tsParameter.dotDotDotToken ? new sts.VariadicParameterContext(undefined, 0)
                                                  : new sts.ParameterContext(undefined, 0);

        let tsParamName = tsParameter.name;
        if (ts.isIdentifier(tsParamName)) {
            if (tsParameter.dotDotDotToken) {
                stsParam.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Ellipsis));
            }
            
            stsParam.addChild(NodeBuilder.terminalIdentifier(tsParamName));

            let tsParamType = tsParameter.type;
            if (!tsParamType) {
                // Use type checker to recover actual parameter type.
                let tsType = this.tsTypeChecker.getTypeAtLocation(tsParameter);
                tsParamType = this.tsTypeChecker.typeToTypeNode(tsType, tsParameter, 
                                                                ts.NodeBuilderFlags.None);
            }

            let stsParamType: NodeBuilder.STSTypeContext;
            if (tsParamType) {
                stsParamType = this.translateType(tsParamType);
            }
            else {
                // If type checker didn't do any good, warn and emit __UnknownType__.
                this.reportError("Failed to infer parameter type", tsParameter);
                stsParamType = NodeBuilder.unknownTypeReference();
            }
            
            let tsInitExpr = tsParameter.initializer;
            let stsInitializer: sts.InitializerContext = null;
            if (tsInitExpr) {
                // Add default value to the parameter.
                stsInitializer = new sts.InitializerContext(stsParam, 0);
                stsInitializer.addChild(this.visitNode(tsInitExpr));
            }
            else if (tsParameter.questionToken) {
                // Make parameter type nullable and add default value (null).
                stsParamType = NodeBuilder.nullableType(stsParamType);
                stsInitializer = new sts.InitializerContext(stsParam, 0);
                stsInitializer.addChild(NodeBuilder.nullLiteral());
            }

            stsParam.addChild(NodeBuilder.typeAnnotation(stsParamType));
            if (stsInitializer) stsParam.addChild(stsInitializer);
            
            // If this is a constructor property declaration, 
            // create class field declaration and add it to 
            // current class body.
            let tsModifiers = ts.getModifiers(tsParameter);
            if (tsModifiers) {
                let stsFieldDecl = new sts.ClassFieldDeclarationContext(undefined, 0);
                let stsVarDecl = new sts.VariableDeclarationContext(stsFieldDecl, 0);
            
                stsVarDecl.addChild(NodeBuilder.terminalIdentifier(tsParamName));
                stsVarDecl.addChild(NodeBuilder.typeAnnotation(stsParamType));
                
                stsFieldDecl.addChild(stsVarDecl);

                // Add class field declaration with access modifier to class body.
                let stsModifierCode = TranslationUtils.getAccessModifierCode(tsModifiers, tsParamName);
                if (!this.addToBlockLikeContext(stsFieldDecl, 1, stsModifierCode)) {
                    // Warn if we're in wrong context.
                    this.reportError("Failed to create class field for constructor parameter property", tsParameter);
                }
            }
        } 
        else {
            // TODO: Translate destructuring parameter.
            return null;
        }

        this.declTransformed.add(tsParameter);
        return stsParam;
    }

    visitBlock(tsBlock: ts.Block): StaticTSContextBase {
        let stsBlock = new sts.BlockContext(undefined, 0);
        this.stsBlockLikeContexts.push(stsBlock);

        for (const tsStmt of tsBlock.statements) {
            // Drop empty statements in this block.
            if (tsStmt.kind === ts.SyntaxKind.EmptyStatement) {
                // Count empty statements as transformed.
                this.stmtTransformed.add(tsStmt);
                continue;
            }

            let stsStmt = this.visitNode(tsStmt);
            if (!stsStmt) stsStmt = this.reportUntranslatedStatement(tsStmt);

            // If the incoming statement is a constructor call, don't wrap it in
            // StatementOrLocalDeclarationContext node, as required by STS grammar.
            if (stsStmt.ruleIndex !== sts.StaticTSParser.RULE_constructorCall) {
                stsStmt = NodeBuilder.statementOrLocalDeclaration(stsStmt);
            }
            
            stsBlock.addChild(stsStmt);
        }

        this.stsBlockLikeContexts.pop();

        if (!TranslationUtils.notStatementBlock(tsBlock)) {
            // Block itself is a statement. Wrap it up with Statement context.
            // Count the block as transformed statement.
            this.stmtTransformed.add(tsBlock);
            return NodeBuilder.statement(stsBlock); 
        }

        return stsBlock;
    }

    private translateType(tsType: ts.TypeNode): NodeBuilder.STSTypeContext {
        // If this is a parenthesized type, unwrap it.
        tsType = TranslationUtils.unwrapParenthesizedType(tsType);

        switch (tsType.kind) {
            case ts.SyntaxKind.NumberKeyword:
            case ts.SyntaxKind.BooleanKeyword:
            case ts.SyntaxKind.BigIntKeyword:
            case ts.SyntaxKind.StringKeyword:
            case ts.SyntaxKind.VoidKeyword:
            case ts.SyntaxKind.ObjectKeyword:
            case ts.SyntaxKind.NeverKeyword:
            case ts.SyntaxKind.TypePredicate:
                this.typeTransformed.add(tsType);
                return NodeBuilder.builtinType(tsType);
            default:
                return this.visitNode(tsType) as NodeBuilder.STSTypeContext;
        }
    }
    
    visitTypeReference(tsTypeRef: ts.TypeReferenceNode): sts.TypeReferenceContext {
        let stsTypeRef = new sts.TypeReferenceContext(undefined, 0);

        let tsTypeName: string;
        if (ts.isQualifiedName(tsTypeRef.typeName)) {
            // There is only one case we should allow here, namely reference 
            // to a type qualified by a single enclosing namespace.
            let tsQualifier = tsTypeRef.typeName.left;
            if (ts.isIdentifier(tsQualifier)) {
                let tsQualifierSym = this.tsTypeChecker.getSymbolAtLocation(tsQualifier);
                if (TranslationUtils.isValueModule(tsQualifierSym)) {
                    tsTypeName = NodeBuilder.entityNameToString(tsTypeRef.typeName);
                }
            }
        }
        else {
            tsTypeName = tsTypeRef.typeName.text;
        }
        if (!tsTypeName) return this.reportUntranslatedType(tsTypeRef, "type reference");

        // If we're in a class body context, check whether this
        // type reference refers to a named class expression and
        // if so, rename it appropriately.
        let stsClassBody = this.getCurrentClassBody();
        let typeRenamingMap = this.typeRefRenames.get(stsClassBody);
        if (stsClassBody && typeRenamingMap && typeRenamingMap.size > 0) {
           let stsTypeName = typeRenamingMap.get(tsTypeName);
           if (stsTypeName) tsTypeName = stsTypeName;
        }
 
        let stsTypeRefPart = NodeBuilder.typeReferencePart(tsTypeName);
        
        // Translate type arguments
        let stsTypeArgs = this.translateTypeArguments(tsTypeRef.typeArguments, tsTypeRef);
        if (stsTypeArgs) stsTypeRefPart.addChild(stsTypeArgs);

        stsTypeRef.addChild(stsTypeRefPart);

        this.typeTransformed.add(tsTypeRef);
        return stsTypeRef;
    }

    visitArrayType(tsArrayType: ts.ArrayTypeNode): sts.ArrayTypeContext {
        let stsArrayType = new sts.ArrayTypeContext(undefined, 0);
        stsArrayType.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.OpenBracket));
        stsArrayType.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.CloseBracket));

        // Flatten nested (multidimensional) array types,
        // as required by STS grammar.
        let tsElemType = tsArrayType.elementType;
        while (ts.isArrayTypeNode(tsElemType)) {
            stsArrayType.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.OpenBracket));
            stsArrayType.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.CloseBracket));

            // Count multidimensional array type as transformed.
            this.typeTransformed.add(tsElemType);

            tsElemType = tsElemType.elementType;
        } 

        // Translate non-array element type and add it
        // as first child node to ArrayTypeContext node.
        // Note: Need to set parent explicitly as we
        // don't use addChild method here.
        let stsElemType = this.translateType(tsElemType);
        stsArrayType.children.unshift(stsElemType);
        stsElemType.setParent(stsArrayType);

        this.typeTransformed.add(tsArrayType);
        return stsArrayType;
    }

    visitIntersectionType(tsIntersectionType: ts.IntersectionTypeNode): StaticTSContextBase {
        // STS allows explicit intersection types only in as expressions and type parameter
        // constraints. For all other contexts allowed in TS return __UnknownType__. 
        let tsParentNode = tsIntersectionType.parent;
        if (!tsParentNode || (!ts.isAsExpression(tsParentNode) && !ts.isTypeParameterDeclaration(tsParentNode)))
            return this.reportUntranslatedType(tsIntersectionType, "intersection type");

        let stsIntersectionType = new sts.IntersectionTypeContext(undefined, 0);

        for (let tsComponentType of tsIntersectionType.types) {
            let stsComponentType = this.translateType(tsComponentType);
            stsIntersectionType.addChild(stsComponentType);
        }

        this.typeTransformed.add(tsIntersectionType);
        return stsIntersectionType;
    }

    visitFunctionType(tsFunctionType: ts.FunctionTypeNode): NodeBuilder.STSTypeContext {
        // STS currently doesn't allow type parameters on function types.
        if (tsFunctionType.typeParameters) {
            return this.reportUntranslatedType(tsFunctionType, "function type");
        }

        let stsSignature = this.translateSignature(tsFunctionType);
        
        let stsFunctionType = new sts.FunctionTypeContext(undefined, 0);
        let stsSignatureParams = stsSignature.parameterList();
        if (stsSignatureParams) stsFunctionType.addChild(stsSignatureParams);
        stsFunctionType.addChild(stsSignature.typeAnnotation());

        this.typeTransformed.add(tsFunctionType);
        return stsFunctionType;
    }

    visitUnionType (tsUnionType: ts.UnionTypeNode): StaticTSContextBase {
        // Translate union types of the form T | null or null | T as 
        // STS nullable type. For all other forms return __UnknownType__.
        if (!TranslationUtils.isNullableType(tsUnionType))
            return this.reportUntranslatedType(tsUnionType, "union type");

        let tsType = TranslationUtils.isNullLiteralType(tsUnionType.types[1]) ?
                     tsUnionType.types[0] : tsUnionType.types[1];

        let stsType = this.translateType(tsType);
        
        this.typeTransformed.add(tsUnionType);
        return NodeBuilder.nullableType(stsType);
    }

    visitImportDeclaration(tsImportDecl: ts.ImportDeclaration): sts.ImportDeclarationContext {
        let tsModuleSpec = tsImportDecl.moduleSpecifier;
        let tsImportClause = tsImportDecl.importClause;

        // Sanity check.
        if (!ts.isStringLiteral(tsModuleSpec) || !tsImportClause) {
            // Warn and add a top-level comment with original import declaration syntax.
            this.reportError("Failed to translate import declaration", tsImportDecl);
            this.addTopLevelComment("Untranslated import declaration", tsImportDecl);
            return null;
        }

        let stsImportDecl = new sts.ImportDeclarationContext(undefined, 0);
        stsImportDecl.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Import));

        let tsNamedBindings = tsImportClause.namedBindings;
        if (tsNamedBindings) {
            if (ts.isNamespaceImport(tsNamedBindings)) {
                let tsNamespaceImport = tsImportClause.namedBindings as ts.NamespaceImport;
                let stsImportBinding = new sts.ImportBindingContext(stsImportDecl, 0);

                stsImportBinding.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.As));
                stsImportBinding.addChild(NodeBuilder.terminalIdentifier(tsNamespaceImport.name.text));
                
                stsImportDecl.addChild(stsImportBinding);
            }
            else {
                let tsNamedImports = tsNamedBindings as ts.NamedImports;

                for (let tsImportSpec of tsNamedImports.elements) {
                    let stsImportBinding = new sts.ImportBindingContext(stsImportDecl, 0);

                    let tsImportPropName = tsImportSpec.propertyName;
                    if (tsImportPropName) {
                        stsImportBinding.addChild(NodeBuilder.qualifiedName(tsImportPropName.text));
                        stsImportBinding.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.As));
                        stsImportBinding.addChild(NodeBuilder.terminalIdentifier(tsImportSpec.name.text));
                    }
                    else 
                        stsImportBinding.addChild(NodeBuilder.qualifiedName(tsImportSpec.name.text));

                    stsImportDecl.addChild(stsImportBinding);
                }
            }
        }
        else if (tsImportClause.name) {
            // This is default import, i.e. import d from "path",
            // which is equivalent to import {default as d} from "path".
            let tsDefaultKeyword = ts.tokenToString(ts.SyntaxKind.DefaultKeyword);            
            let stsImportBinding = new sts.ImportBindingContext(stsImportDecl, 0);

            stsImportBinding.addChild(NodeBuilder.qualifiedName(tsDefaultKeyword));
            stsImportBinding.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.As));
            stsImportBinding.addChild(NodeBuilder.terminalIdentifier(tsImportClause.name.text));

            stsImportDecl.addChild(stsImportBinding);
        }

        stsImportDecl.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.FROM));
        stsImportDecl.addChild(NodeBuilder.terminalStringLiteral(tsModuleSpec.text));

        this.stmtTransformed.add(tsImportDecl);
        return stsImportDecl;
    }

    visitExportDeclaration(tsExportDecl: ts.ExportDeclaration): StaticTSContextBase {
        let tsModuleSpec = tsExportDecl.moduleSpecifier;
        let tsExportClause = tsExportDecl.exportClause;

        if (tsModuleSpec || !tsExportClause || ts.isNamespaceExport(tsExportClause)) {
            // Just warn and emit a comment with original syntax.
            // NOTE: We can't translate re-exports. 
            this.reportError("Failed to translate export declaration", tsExportDecl);
            this.addTopLevelComment("Untranslated export declaration:", tsExportDecl);
            return null;
        }

        // Store all exported names so that we add export modifier 
        // and emit type aliases and/or aliasing functions later.
        for (let tsNamedExport of tsExportClause.elements) {
            let key: string, value: string;
            if (tsNamedExport.propertyName) {
                key = tsNamedExport.propertyName.text;
                value = tsNamedExport.name.text;
            }
            else {
                key = tsNamedExport.name.text;
                value = null;
            }

            this.addExportedName(key, value);
        }

        this.stmtTransformed.add(tsExportDecl);
        return null;
    }

    visitExportAssignment(tsExportAssignment: ts.ExportAssignment): StaticTSContextBase {
        if (tsExportAssignment.isExportEquals) {
            // Legacy export syntax (export = name), not supported.
            this.reportError("Failed to translate export assignment", tsExportAssignment);
            this.addTopLevelComment("Untranslated export assignment", tsExportAssignment);
            return null;
        }

        // Default export, i.e. export default <expression>.
        let tsExportedExpr = tsExportAssignment.expression;
        if (ts.isIdentifier(tsExportedExpr)) {
            // If exporting an identifier, map it to default.
            this.addExportedName(tsExportedExpr.text, sts.StaticTSParser.DEFAULT);
            this.stmtTransformed.add(tsExportAssignment);
            return null;
        }

        // If exporting a value, emit default variable initialized to that value and export it.
        let stsInitExpr = this.visitNode(tsExportedExpr);
        let stsVarOrConstDecl = NodeBuilder.singleVariableDeclaration(sts.StaticTSParser.DEFAULT, stsInitExpr);
        
        this.stmtTransformed.add(tsExportAssignment);
        return NodeBuilder.topDeclaration(stsVarOrConstDecl, true);
    }

    private addExportedName(key: string, value: string): void {
        if (this.tsExports[key]) {
            this.tsExports[key].push(value);
        }
        else {
            this.tsExports[key] = [value];
        }

        if (!this.hasExportDecls) this.hasExportDecls = true;
    }

    visitVariableStatement(tsVarStmt: ts.VariableStatement): StaticTSContextBase {
        // TODO: Should we hoist var-declared variables onto enclosing function scope?

        let stsVarOrConstDecl = TranslationUtils.createVarOrConstDeclaration(tsVarStmt.declarationList);

        // Translate declaration list.
        // Note: For some reason, const flag is not set on variable statement itself, so
        // we need to query declaration list inside it to figure out which keyword to add.
        let stsVarDeclList = this.translateVariableDeclarationList(tsVarStmt.declarationList, 
                                                    TranslationUtils.isConst(tsVarStmt.declarationList));
        if (stsVarDeclList.childCount > 0) {
            stsVarOrConstDecl.addChild(stsVarDeclList);
        }
        else {
            // Bail out we couldn't translate any declarations inside the list.
            // Emit a comment with original syntax of the entire statement if
            // we're at the top level; otherwise, it'll be done automatically
            // in visitBlock function.
            if (ts.isSourceFile(tsVarStmt.parent)) {
                this.addTopLevelComment("Untranslated variable declaration", tsVarStmt);
            }
            return null;
        }

        this.stmtTransformed.add(tsVarStmt);

        // If this is not a top-level declaration nor a namespace member, return declaration node;
        // it'll be wrapped in StatementOrLocalDeclarationContext inside visitBlock function (see above).
        if (!ts.isSourceFile(tsVarStmt.parent) && !ts.isModuleBlock(tsVarStmt.parent)) 
            return stsVarOrConstDecl;

        // Otherwise, wrap it in TopDeclarationContext or NamespaceMemberContext before returning.
        let tsModifiers = ts.getModifiers(tsVarStmt)
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword);
        
        return ts.isSourceFile(tsVarStmt.parent) ? 
               NodeBuilder.topDeclaration(stsVarOrConstDecl, isExported) : 
               NodeBuilder.namespaceMember(stsVarOrConstDecl, isExported);
    }

    translateVariableDeclarationList(tsVarDeclList: ts.VariableDeclarationList, isConst: boolean): StaticTSContextBase {
        let stsDeclList = TranslationUtils.createVarOrConstDeclarationList(isConst);

        for (const tsVarDecl of tsVarDeclList.declarations) {
            let stsVarDecl = this.translateVariableDeclaration(tsVarDecl, isConst);

            if (stsVarDecl) {
                stsDeclList.addChild(stsVarDecl);
            }
            else {
                // Warn and add a comment with original variable declaration syntax.
                this.reportError("Failed to translate destructuring declaration", tsVarDecl);
                let stsComment = NodeBuilder.multiLineComment("/* " + tsVarDecl.getText() + " */");
                stsDeclList.addTrailingComment(stsComment);
            }
        }

        return stsDeclList;
    }

    translateVariableDeclaration(tsVarDecl: ts.VariableDeclaration, isConst: boolean, 
                                translateInitializer: boolean = true): StaticTSContextBase {
        let stsDecl: StaticTSContextBase = isConst 
                ? new sts.ConstantDeclarationContext(undefined, 0)
                : new sts.VariableDeclarationContext(undefined, 0); 

        let varName = tsVarDecl.name;
        if (ts.isIdentifier(varName)) {
            stsDecl.addChild(NodeBuilder.terminalIdentifier(varName.text));

            if (tsVarDecl.type) {
                let stsTypeRef = this.translateType(tsVarDecl.type);
                stsDecl.addChild(NodeBuilder.typeAnnotation(stsTypeRef));
            }
            else if (tsVarDecl.initializer && !translateInitializer) {
                // If initalizer is present but should not be translated, try to infer
                // variable type using the TypeChecker.
                let stsTypeRef : NodeBuilder.STSTypeContext;
                let tsType = this.tsTypeChecker.getTypeAtLocation(tsVarDecl);
                let tsTypeNode = this.tsTypeChecker.typeToTypeNode(tsType, undefined, 
                                                                ts.NodeBuilderFlags.None);

                // If type checker didn't do any good, return __UnknownType__.
                stsTypeRef = tsTypeNode ? this.translateType(tsTypeNode) : NodeBuilder.unknownTypeReference();
                stsDecl.addChild(NodeBuilder.typeAnnotation(stsTypeRef));
            }
            else if (!tsVarDecl.initializer) {
                // If both variable's type and initializer are not specified, then
                // variable's type is 'any'. Warn and emit __UnknownType__.
                this.reportError("Failed to infer variable type", tsVarDecl); 
                stsDecl.addChild(NodeBuilder.unknownTypeAnnotation());
            }

            if (tsVarDecl.initializer && translateInitializer) {
                let stsInitExpr = this.visitNode(tsVarDecl.initializer);

                if (ts.isClassExpression(tsVarDecl.initializer)) {
                    // We've already emitted a class named as the variable
                    // (see visitClassExpression), so there is nothing more
                    // to do here. Emit DummyContext node to make this
                    // variable declaration invisible in STS output.
                    stsDecl = new DummyContext(undefined, 0);
                }
                else {
                    let stsInit = new sts.InitializerContext(stsDecl, 0);
                    stsInit.addChild(stsInitExpr);
                    stsDecl.addChild(stsInit);
                }
            }
            
            this.declTransformed.add(tsVarDecl);
        } else {
            // TODO: Translate destructuring declaration.
            return null;
        }

        return stsDecl;
    }

    visitNullLiteral(tsNullLiteral: ts.NullLiteral): sts.SingleExpressionContext {
        this.exprTransformed.add(tsNullLiteral);
        return NodeBuilder.nullLiteral();
    }

    visitTrueLiteral(tsTrueLiteral: ts.TrueLiteral): sts.SingleExpressionContext {
        this.exprTransformed.add(tsTrueLiteral);
        return NodeBuilder.boolLiteral(true);
    }

    visitFalseLiteral(tsFalseLiteral: ts.FalseLiteral): sts.SingleExpressionContext {
        this.exprTransformed.add(tsFalseLiteral);
        return NodeBuilder.boolLiteral(false);
    }
    
    visitNumericLiteral(tsNumericLiteral: ts.NumericLiteral): sts.SingleExpressionContext {
        this.exprTransformed.add(tsNumericLiteral);
        return NodeBuilder.numericLiteral(tsNumericLiteral.getText());
    }
    
    visitStringLiteral(tsStringLiteral: ts.StringLiteral): sts.SingleExpressionContext {
        this.exprTransformed.add(tsStringLiteral);
        return NodeBuilder.stringLiteral(tsStringLiteral.getText());
    }

    visitNoSubstitutionTemplateLiteral(tsNoSubstTemplateLiteral: ts.NoSubstitutionTemplateLiteral): sts.SingleExpressionContext {
        // This form of template literal doesn't have any embedded
        // expressions. Simply translate as a string literal.
        this.exprTransformed.add(tsNoSubstTemplateLiteral);
        return NodeBuilder.stringLiteral(TranslationUtils.getTemplateText(tsNoSubstTemplateLiteral));
    }

    visitTemplateExpression(tsTemplateExpr: ts.TemplateExpression): sts.SingleExpressionContext {
        // Translate template expression as a concatenation of template's
        // strings and expressions using the "+" operator.

        let stsResultExpr: StaticTSContextBase;
        if (tsTemplateExpr.head.text) {
            stsResultExpr = NodeBuilder.stringLiteral(TranslationUtils.getTemplateText(tsTemplateExpr.head));
        }

        let templateSpans = tsTemplateExpr.templateSpans;
        if (templateSpans.length === 1 && !tsTemplateExpr.head.text && !templateSpans[0].literal.text) {
            // Template literal has one single expression, and no string parts.
            // If expression is not a String type, wrap it up with toString()
            // call as the template literal has to return the "string" value.
            // Otherwise, return the translated expression as is.
            let tsSpanExpr = templateSpans[0].expression;
            let stsSpanExpr = this.visitNode(tsSpanExpr);
            let tsExprType = this.tsTypeChecker.getTypeAtLocation(tsSpanExpr);
            if (!(tsExprType.getFlags() & (ts.TypeFlags.StringLike))) {
                // Wrap up expression with parentheses, if needed.
                if (tsSpanExpr.kind !== ts.SyntaxKind.ParenthesizedExpression && tsSpanExpr.kind !== ts.SyntaxKind.Identifier) {
                    stsSpanExpr = NodeBuilder.parenthesizedExpression(stsSpanExpr);
                }

                stsSpanExpr = NodeBuilder.wrapExpressionWithToStringCall(stsSpanExpr);
            }
            
            this.exprTransformed.add(tsTemplateExpr);
            return stsSpanExpr;
        }

        for (const tsTemplateSpan of templateSpans) {
            let tsSpanLiteral = tsTemplateSpan.literal;
            let tsSpanExpr = tsTemplateSpan.expression;
            let stsSpanExpr = this.visitNode(tsSpanExpr);

            // If span expression is binary or conditional expression, wrap it up
            // with parentheses to preserve correct evaluation of the expression
            // in resulting string concatenation.
            if (tsSpanExpr.kind === ts.SyntaxKind.BinaryExpression || tsSpanExpr.kind === ts.SyntaxKind.ConditionalExpression) {
                stsSpanExpr = NodeBuilder.parenthesizedExpression(stsSpanExpr);
            }

            // Concat template span expression.
            if (!stsResultExpr)
                stsResultExpr = stsSpanExpr;
            else
                stsResultExpr = NodeBuilder.additiveExpression(stsResultExpr, stsSpanExpr);

            // Concat template span literal.
            if (tsSpanLiteral.text) {
                stsResultExpr = NodeBuilder.additiveExpression(stsResultExpr, NodeBuilder.stringLiteral(TranslationUtils.getTemplateText(tsSpanLiteral)));
            }
        }

        this.exprTransformed.add(tsTemplateExpr);
        return stsResultExpr;
    }

    visitTaggedTemplateExpression(tsTaggedTemplateExpr: ts.TaggedTemplateExpression): sts.SingleExpressionContext {
        // Tagged template is translated as a function call, where call
        // target is a 'tag' expression, first argument is an array of
        // template string values, and remaining arguments are the
        // embedded expressions of template expression.
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsCallExpr = new sts.CallExpressionContext(stsSingleExpr);

        stsCallExpr.addChild(this.visitNode(tsTaggedTemplateExpr.tag));
        
        let stsTypeArgs = this.translateTypeArguments(tsTaggedTemplateExpr.typeArguments, tsTaggedTemplateExpr.tag);
        if (stsTypeArgs) stsCallExpr.addChild(stsTypeArgs);

        let stsArguments = new sts.ArgumentsContext(stsCallExpr, 0);
        let stsArgsExprSeq = new sts.ExpressionSequenceContext(stsArguments, 0);
        stsArguments.addChild(stsArgsExprSeq);
        stsCallExpr.addChild(stsArguments);

        let stsArgExpr = new sts.SingleExpressionContext(stsArgsExprSeq, 0);
        let stsArrayLiteralExpr = new sts.ArrayLiteralExpressionContext(stsArgExpr);
        let stsArrayExprSeq = new sts.ExpressionSequenceContext(stsArrayLiteralExpr, 0);
        stsArrayLiteralExpr.addChild(stsArrayExprSeq);
        stsArgExpr.addChild(stsArrayLiteralExpr);
        stsArgsExprSeq.addChild(stsArgExpr);

        let tsTemplateLiteral = tsTaggedTemplateExpr.template;
        if (ts.isNoSubstitutionTemplateLiteral(tsTemplateLiteral)) {
            stsArrayExprSeq.addChild(this.visitNode(tsTemplateLiteral));
        }
        else {
            // If template literal is empty, add "empty" string literal to array. 
            let templateText = tsTemplateLiteral.head.text.length > 0 ? TranslationUtils.getTemplateText(tsTemplateLiteral.head) : '""';
            stsArrayExprSeq.addChild(NodeBuilder.stringLiteral(templateText));
            
            for (let tsTemplateSpan of tsTemplateLiteral.templateSpans) {
                // If template literal is empty, add "empty" string literal to array. 
                templateText = tsTemplateSpan.literal.text.length > 0 ? TranslationUtils.getTemplateText(tsTemplateSpan.literal) : '""';
                stsArrayExprSeq.addChild(NodeBuilder.stringLiteral(templateText));
                stsArgsExprSeq.addChild(this.visitNode(tsTemplateSpan.expression));
            }
            
            // Since template literal is not visited here, count it as transformed.
            this.exprTransformed.add(tsTemplateLiteral);
        }

        stsSingleExpr.addChild(stsCallExpr);
        
        this.exprTransformed.add(tsTaggedTemplateExpr);
        return stsSingleExpr;
    }

    visitExpressionStatement(tsExprStmt: ts.ExpressionStatement): StaticTSContextBase {
        let stsExpr = this.visitNode(tsExprStmt.expression);
        let stsResultNode: StaticTSContextBase = stsExpr;

        // Calls to superclass ctor should not be wrapped
        // in ExpressionStatementContext node as we emit
        // a separate kind of AST node for them (see 
        // visitCallExpression method for details).
        if (!TranslationUtils.isSuperCall(tsExprStmt)) {
            let stsExprStmt = new sts.ExpressionStatementContext(undefined, 0);
            stsExprStmt.addChild(stsExpr);

            stsResultNode = NodeBuilder.statement(stsExprStmt);
        }

        this.stmtTransformed.add(tsExprStmt);
        return stsResultNode;
    }

    visitPrefixUnaryExpression(tsPrefixUnaryExpr: ts.PrefixUnaryExpression): sts.SingleExpressionContext {
        let stsOperand = this.visitNode(tsPrefixUnaryExpr.operand);
        this.exprTransformed.add(tsPrefixUnaryExpr);
        return NodeBuilder.prefixUnaryExpression(tsPrefixUnaryExpr, stsOperand);
    }

    visitPostfixUnaryExpression(tsPostfixUnaryExpr: ts.PostfixUnaryExpression): sts.SingleExpressionContext {
        let stsOperand = this.visitNode(tsPostfixUnaryExpr.operand);
        this.exprTransformed.add(tsPostfixUnaryExpr);
        return NodeBuilder.postfixUnaryExpression(tsPostfixUnaryExpr, stsOperand);
    }

    visitNonNullExpression(tsNonNullExpr: ts.NonNullExpression): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        
        let stsNonNullExpr = new sts.NonNullExpressionContext(stsSingleExpr);
        stsNonNullExpr.addChild(this.visitNode(tsNonNullExpr.expression));

        this.exprTransformed.add(tsNonNullExpr);
        stsSingleExpr.addChild(stsNonNullExpr);
        return stsSingleExpr;
    }

    visitBinaryExpression(tsBinaryExpr: ts.BinaryExpression): sts.SingleExpressionContext {
        // NOTE: We don't have '**', '**=', '&&=', '||=', and '??=' operators in STS,
        // so those are getting lowered in the output code, following the JS specification:
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators

        if (TranslationUtils.isAssignmentOperator(tsBinaryExpr.operatorToken)) {
            return this.translateAssignmentExpression(tsBinaryExpr);
        }
        else {
            // Translate binary operator expression.
            let stsLeftOperand = this.visitNode(tsBinaryExpr.left);

            // For instanceof expression, STS allows primary type only as right operand.
            // As such, we translate only what conforms to STS requirements; for the rest,
            // we warn and emit __UnknownType__.
            let tsRightOperand = tsBinaryExpr.right;
            let stsRightOperand: StaticTSContextBase;
            if (tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword) {
                stsRightOperand = new sts.PrimaryTypeContext(undefined, 0);
                let stsTypeRef: sts.TypeReferenceContext;

                if (ts.isIdentifier(tsRightOperand)) {
                    let tsRightOperandType = this.tsTypeChecker.getTypeAtLocation(tsRightOperand);
                    if (TranslationUtils.isClassOrInterface(tsRightOperandType)) {
                        stsTypeRef = NodeBuilder.typeReference(tsRightOperand);
                    }
                }
                if (!stsTypeRef) stsTypeRef = this.reportUntranslatedType(tsRightOperand);

                stsRightOperand.addChild(stsTypeRef);
            }
            else {
                stsRightOperand = this.visitNode(tsRightOperand);
            }

            let stsBinaryExpr = NodeBuilder.binaryExpression(tsBinaryExpr, stsLeftOperand, stsRightOperand);
            
            if (stsBinaryExpr) {
                this.exprTransformed.add(tsBinaryExpr);
                return stsBinaryExpr;
            }

            return this.reportUntranslatedExpression(tsBinaryExpr);
        }
    }

    private translateAssignmentExpression(tsBinaryExpr: ts.BinaryExpression): sts.SingleExpressionContext {
        let tsOpToken = tsBinaryExpr.operatorToken;
        
        if (tsOpToken.kind === ts.SyntaxKind.AmpersandAmpersandEqualsToken
            || tsOpToken.kind === ts.SyntaxKind.BarBarEqualsToken) {
            return this.translateLogicalAssignment(tsBinaryExpr);
        }
        if (tsOpToken.kind === ts.SyntaxKind.QuestionQuestionEqualsToken) {
            return this.translateNullishCoalescingAssignment(tsBinaryExpr);
        }

        // Translate simple/compound assignment.
        let stsExpr = new sts.SingleExpressionContext(undefined, 0)

        let stsAssignExpr : StaticTSContextBase;
        if (tsOpToken.kind === ts.SyntaxKind.EqualsToken) {
            stsAssignExpr = new sts.AssignmentExpressionContext(stsExpr);
        } else {
            stsAssignExpr = new sts.AssignmentOperatorExpressionContext(stsExpr);
        }
        stsExpr.addChild(stsAssignExpr);

        stsAssignExpr.addChild(this.visitNode(tsBinaryExpr.left));

        if (tsOpToken.kind === ts.SyntaxKind.EqualsToken) {
            stsAssignExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Assign));
        } else {
            let stsAssignOp = NodeBuilder.assignmentOperator(tsOpToken);
            if (!stsAssignOp) {
                return this.reportUntranslatedExpression(tsBinaryExpr, "assignment expression");
            }
            stsAssignExpr.addChild(NodeBuilder.assignmentOperator(tsOpToken));
        }

        stsAssignExpr.addChild(this.visitNode(tsBinaryExpr.right));

        this.exprTransformed.add(tsBinaryExpr);
        return stsExpr;
    }

    private translateLogicalAssignment(tsBinaryExpr: ts.BinaryExpression): sts.SingleExpressionContext {
        // Translation goes as follows:
        // 'x &&= f()'   --->   'x && (x = f())'
        // 'x ||= f()'   --->   'x || (x = f())'

        let isLogicalAnd = tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandEqualsToken;

        let stsExpr = new sts.SingleExpressionContext(undefined, 0)
        let stsLogicalOpExpr;
        if (isLogicalAnd)
            stsLogicalOpExpr = new sts.LogicalAndExpressionContext(stsExpr);
        else
            stsLogicalOpExpr = new sts.LogicalOrExpressionContext(stsExpr);
        stsExpr.addChild(stsLogicalOpExpr);

        stsLogicalOpExpr.addChild(this.visitNode(tsBinaryExpr.left));
        stsLogicalOpExpr.addChild(NodeBuilder.terminalNode(
            isLogicalAnd
            ? sts.StaticTSParser.And
            : sts.StaticTSParser.Or));

        let stsSingleExpr = new sts.SingleExpressionContext(stsLogicalOpExpr, 0);
        stsLogicalOpExpr.addChild(stsSingleExpr);
        let stsRhsParenthExpr = new sts.ParenthesizedExpressionContext(stsSingleExpr);
        stsSingleExpr.addChild(stsRhsParenthExpr)

        stsSingleExpr = new sts.SingleExpressionContext(stsRhsParenthExpr, 0);
        stsRhsParenthExpr.addChild(stsSingleExpr);
        let stsRhsAssign = new sts.AssignmentExpressionContext(stsSingleExpr);
        stsSingleExpr.addChild(stsRhsAssign);

        stsRhsAssign.addChild(this.visitNode(tsBinaryExpr.left));
        stsRhsAssign.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Assign));
        stsRhsAssign.addChild(this.visitNode(tsBinaryExpr.right));

        this.exprTransformed.add(tsBinaryExpr);
        return stsExpr;
    }

    private translateNullishCoalescingAssignment(tsBinaryExpr: ts.BinaryExpression): sts.SingleExpressionContext {
        // Translation goes as follows:
        // 'x ??= f()'   --->   'x = x ?? f()'
        // Create assignment and add LHS expression.
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsAssignExpr = new sts.AssignmentExpressionContext(stsSingleExpr);
        stsAssignExpr.addChild(this.visitNode(tsBinaryExpr.left));
        stsAssignExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Assign));

        // Create null-coalescing expression and add it as RHS of assignment.
        let stsRhsSingleExpr = new sts.SingleExpressionContext(stsAssignExpr, 0);
        let stsNullCoalesceExpr = new sts.NullCoalescingExpressionContext(stsRhsSingleExpr);
        stsNullCoalesceExpr.addChild(this.visitNode(tsBinaryExpr.left));
        stsNullCoalesceExpr.addChild(this.visitNode(tsBinaryExpr.right));
        stsRhsSingleExpr.addChild(stsNullCoalesceExpr);
        stsAssignExpr.addChild(stsRhsSingleExpr);
        stsSingleExpr.addChild(stsAssignExpr);

        this.exprTransformed.add(tsBinaryExpr);
        return stsSingleExpr;
    }

    visitConditionalExpression(tsConditionaExpr: ts.ConditionalExpression): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsTernaryExpr = new sts.TernaryExpressionContext(stsSingleExpr);
        stsTernaryExpr.addChild(this.visitNode(tsConditionaExpr.condition));
        stsTernaryExpr.addChild(this.visitNode(tsConditionaExpr.whenTrue));
        stsTernaryExpr.addChild(this.visitNode(tsConditionaExpr.whenFalse));
        stsSingleExpr.addChild(stsTernaryExpr);

        this.exprTransformed.add(tsConditionaExpr);
        return stsSingleExpr;
    }

    visitIdentifier(tsIdentifier: ts.Identifier): sts.SingleExpressionContext {
        // If we see a namespace reference here, it's got to be invalid
        // as we handle the valid cases explicitly in visitNewExpression,
        // visitPropertyAccessExpression, and visitHeritageClause functions.
        let tsType = this.tsTypeChecker.getTypeAtLocation(tsIdentifier);
        if (tsType && TranslationUtils.isValueModule(tsType.symbol))
            return this.reportInvalidExpression(tsIdentifier, "namespace reference");

        // Don't count names as transformed as most of them are transformed manually.
        return NodeBuilder.identifierExpression(tsIdentifier.text);
    }

    visitAsExpression(tsAsExpr: ts.AsExpression): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);

        let stsCastExpr = new sts.CastExpressionContext(stsSingleExpr);
        stsCastExpr.addChild(this.visitNode(tsAsExpr.expression));
        stsCastExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.As));
        
        // Translate target type and wrap it in PrimaryTypeContext 
        // unless it's an intersection type.
        let stsType = this.translateType(tsAsExpr.type);
        if (stsType.ruleIndex !== sts.StaticTSParser.RULE_intersectionType) {
            let stsPrimaryType = new sts.PrimaryTypeContext(stsCastExpr, 0);
            stsPrimaryType.addChild(stsType);

            stsCastExpr.addChild(stsPrimaryType);
        }
        else {
            stsCastExpr.addChild(stsType);
        }
        stsSingleExpr.addChild(stsCastExpr);

        this.exprTransformed.add(tsAsExpr);
        return stsSingleExpr;
    }

    visitPropertyAccessExpression(tsPropertyAccessExpr: ts.PropertyAccessExpression): sts.SingleExpressionContext {
        // TODO: Translate getter/setter call.

        // Check that base expression is not a namespace object.
        let stsBaseExpr: StaticTSContextBase;
        let tsBaseExpr = tsPropertyAccessExpr.expression;
        let tsBaseExprType = this.tsTypeChecker.getTypeAtLocation(tsBaseExpr);
        if (tsBaseExprType && TranslationUtils.isValueModule(tsBaseExprType.symbol)) {
            let tsBaseExprSym = this.tsTypeChecker.getSymbolAtLocation(tsBaseExpr);
            if (ts.isIdentifier(tsBaseExpr) && TranslationUtils.isValueModule(tsBaseExprSym)) {
                // Valid namespace reference, translate as identifier expression.
                stsBaseExpr = NodeBuilder.identifierExpression(tsBaseExpr);
            }
            else {
                // Warn and emit __invalid_expression call.
                stsBaseExpr = this.reportInvalidExpression(tsBaseExpr, "namespace object");
            }
        }
        else {
            // Translate base expression.
            stsBaseExpr = this.visitNode(tsBaseExpr);
        }

        // Translate property name.
        let stsMemberName = NodeBuilder.terminalIdentifier(tsPropertyAccessExpr.name);
        if (!stsMemberName) {
            // Warn and emit __UnknownName__.
            this.reportError("Failed to translate property name", tsPropertyAccessExpr.name);
            stsMemberName = NodeBuilder.invalidIdentifier();
        }

        let stsMemberAccessExpr = NodeBuilder.memberAccess(stsBaseExpr, stsMemberName, 
                                                    !!tsPropertyAccessExpr.questionDotToken,
                                                    tsPropertyAccessExpr.name.text);

        this.exprTransformed.add(tsPropertyAccessExpr);
        return stsMemberAccessExpr;
    }

    visitCallExpression(tsCallExpr: ts.CallExpression): StaticTSContextBase {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);

        let stsCallExpr: StaticTSContextBase; 
        let isSuperCall = tsCallExpr.expression.kind === ts.SyntaxKind.SuperKeyword;
        if (isSuperCall) {
            // For superclass ctor calls, create ConstructorCallContext
            // node instead of regular CallExpressionContext node.
            stsCallExpr = new sts.ConstructorCallContext(undefined, 0);
            stsCallExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Super));

            // Count super keyword as translated expression.
            this.exprTransformed.add(tsCallExpr.expression);
        }
        else {
            stsCallExpr = new sts.CallExpressionContext(stsSingleExpr);
            stsSingleExpr.addChild(stsCallExpr);

            let funcExpr = this.visitNode(tsCallExpr.expression);
            if (!funcExpr) {
                // Warn and return __untranslated_expression call.
                return this.reportUntranslatedExpression(tsCallExpr, "function call");
            }

            stsCallExpr.addChild(funcExpr);
        }
        
        let stsTypeArgs = this.translateTypeArguments(tsCallExpr.typeArguments, tsCallExpr);
        if (stsTypeArgs) stsCallExpr.addChild(stsTypeArgs);

        if (tsCallExpr.questionDotToken) {
            // Add question mark to indicate that this is a null-safe call.
            stsCallExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.QuestionMark));
        }

        stsCallExpr.addChild(this.translateArguments(tsCallExpr.arguments));
        
        this.exprTransformed.add(tsCallExpr);
        return isSuperCall ? stsCallExpr : stsSingleExpr;
    }

    private translateArguments(tsArgs: ts.NodeArray<ts.Expression>): sts.ArgumentsContext {
        let stsArguments = new sts.ArgumentsContext(undefined, 0);

        if (tsArgs && tsArgs.length > 0) {
            let stsExprSeq = new sts.ExpressionSequenceContext(stsArguments, 0);
            for (const tsArg of tsArgs) {
                stsExprSeq.addChild(this.visitNode(tsArg));
            }
            stsArguments.addChild(stsExprSeq);
        }

        return stsArguments;
    }

    visitNewExpression(tsNewExpr: ts.NewExpression): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsNewClassInstExpr = new sts.NewClassInstanceExpressionContext(stsSingleExpr);

        stsNewClassInstExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.New));

        // Translate only what we can convert to STS type refs,
        // everything else denote as __UnknownType__.
        let tsTypeExpr = tsNewExpr.expression;
        let stsTypeRef: sts.TypeReferenceContext;
        let tsTypeExprType = this.tsTypeChecker.getTypeAtLocation(tsTypeExpr);
        let isClass = TranslationUtils.isClass(tsTypeExprType);
        if (ts.isIdentifier(tsTypeExpr) && isClass) {
            // Don't count identifiers as transformed expressions
            // as we don't include them in total counts, either.
            stsTypeRef = NodeBuilder.typeReference(tsTypeExpr);
        }
        else if (ts.isPropertyAccessExpression(tsTypeExpr)) {
            // There is only one case we should allow here, namely reference to a class 
            // qualified by a single enclosing namespace (NOTE: Not by a namespace object!)
            if (this.isQualifiedByNamespace(tsTypeExpr) && isClass) {
                stsTypeRef = NodeBuilder.typeReference(tsTypeExpr.getText());
                this.exprTransformed.add(tsTypeExpr);
            }
        }
        if (!stsTypeRef) {
            // Warn and emit __UnknownType__.
            stsTypeRef = this.reportUntranslatedType(tsTypeExpr, "type expression");
        }
        
        // Add type arguments to type reference, if any.
        let stsTypeArgs = this.translateTypeArguments(tsNewExpr.typeArguments, tsNewExpr);
        if (stsTypeArgs) {
            let stsTypeRefParts = stsTypeRef.typeReferencePart();
            stsTypeRefParts[stsTypeRefParts.length-1].addChild(stsTypeArgs);
        }

        stsNewClassInstExpr.addChild(stsTypeRef);
        stsNewClassInstExpr.addChild(this.translateArguments(tsNewExpr.arguments));

        stsSingleExpr.addChild(stsNewClassInstExpr);

        this.exprTransformed.add(tsNewExpr);
        return stsSingleExpr;
    }

    private isQualifiedByNamespace(tsPropAccessExpr: ts.PropertyAccessExpression): boolean {
        let tsBaseExpr = tsPropAccessExpr.expression;
        if (ts.isIdentifier(tsBaseExpr)) {
            let tsBaseExprType = this.tsTypeChecker.getTypeAtLocation(tsBaseExpr);
            let tsBaseExprSym = this.tsTypeChecker.getSymbolAtLocation(tsBaseExpr);
            return tsBaseExprType && TranslationUtils.isValueModule(tsBaseExprType.symbol) &&
                   TranslationUtils.isValueModule(tsBaseExprSym);
        }

        return false;
    }

    visitTypeAliasDeclaration(tsTypeAliasDecl: ts.TypeAliasDeclaration): StaticTSContextBase {
        let stsTypeAliasDecl = NodeBuilder.typeAliasDeclaration(tsTypeAliasDecl.name.text, 
                                        this.translateType(tsTypeAliasDecl.type), 
                                        this.translateTypeParameters(tsTypeAliasDecl.typeParameters));

        this.declTransformed.add(tsTypeAliasDecl);

        // If this is not a top-level declaration nor a namespace member, 
        // return TypeAliasDeclarationContext node.
        if (!ts.isSourceFile(tsTypeAliasDecl.parent) && !ts.isModuleBlock(tsTypeAliasDecl.parent)) 
            return stsTypeAliasDecl;

        // Otherwise, wrap it in TopDeclarationContext or NamespaceMemberContext node.
        let tsModifiers = ts.getModifiers(tsTypeAliasDecl);
        let isExported = TranslationUtils.hasModifier(tsModifiers, ts.SyntaxKind.ExportKeyword);

        return ts.isSourceFile(tsTypeAliasDecl.parent) ? 
               NodeBuilder.topDeclaration(stsTypeAliasDecl, isExported) :
               NodeBuilder.namespaceMember(stsTypeAliasDecl, isExported);
    }

    private translateTypeParameters(tsTypeParams: ts.NodeArray<ts.TypeParameterDeclaration>): sts.TypeParametersContext {
        // Sanity check.
        if (!tsTypeParams) return null;

        let stsTypeParams = new sts.TypeParametersContext(undefined, 0);
        let stsTypeParamList = new sts.TypeParameterListContext(stsTypeParams, 0);
        for (let tsTypeParam of tsTypeParams) {
            let stsTypeParam = new sts.TypeParameterContext(stsTypeParamList, 0);
            stsTypeParam.addChild(NodeBuilder.terminalIdentifier(tsTypeParam.name.text));
            
            // Translate constraint
            let tsConstraint = ts.getEffectiveConstraintOfTypeParameter(tsTypeParam);
            if (tsConstraint) {
                let stsConstraint = new sts.ConstraintContext(stsTypeParam, 0);
                stsConstraint.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.EXTENDS));

                // Check that bounding type is a type reference or an intersection type,
                // otherwise warn and replace with __UnknownType.
                let stsBoundType = this.translateType(tsConstraint);
                if (stsBoundType.ruleIndex !== sts.StaticTSParser.RULE_typeReference &&
                    stsBoundType.ruleIndex !== sts.StaticTSParser.RULE_intersectionType) {
                        stsBoundType = this.reportUntranslatedType(tsConstraint, "type parameter bound");
                }
                stsConstraint.addChild(stsBoundType);
                stsTypeParam.addChild(stsConstraint);
            }

            // TODO: Handle modifiers, default and expression properties.
            stsTypeParamList.addChild(stsTypeParam);
            
            this.declTransformed.add(tsTypeParam);
        }

        stsTypeParams.addChild(stsTypeParamList);
        return stsTypeParams;
    }

    private getTypeParameters(tsNode: ts.Node): ts.NodeArray<ts.TypeParameterDeclaration> {
        if (ts.isNewExpression(tsNode) || ts.isCallExpression(tsNode)) tsNode = tsNode.expression;
        else if (ts.isTypeReferenceNode(tsNode)) tsNode = tsNode.typeName;

        // If symbol is an alias, get the original aliased symbol.
        let tsSymbol = tsNode ? this.tsTypeChecker.getSymbolAtLocation(tsNode) : null;
        if (TranslationUtils.isAlias(tsSymbol)) tsSymbol = this.tsTypeChecker.getAliasedSymbol(tsSymbol);

        if (!tsSymbol || this.tsTypeChecker.isUnknownSymbol(tsSymbol) || !tsSymbol.declarations) {
            // Return empty array if we couldn't resolve the symbol so that we'll still translate 
            // type arguments as is (see translateTypeArguments function below for details).
            return ts.factory.createNodeArray<ts.TypeParameterDeclaration>();
        }

        for (let tsDecl of tsSymbol.declarations) {
            // Don't fetch type parameters for local functions and lambda-like expressions
            // as we translate them all as lambdas and STS prohibits generic lambdas. This
            // will cause us to emit type arguments at call-site (if any) as comments and
            // issue a warning (see translateTypeArguments function below for details).
            if (ts.isClassDeclaration(tsDecl) || ts.isInterfaceDeclaration(tsDecl) ||
                (ts.isFunctionDeclaration(tsDecl) && !ts.isBlock(tsDecl.parent)) || 
                ts.isMethodDeclaration(tsDecl)) {
                if (tsDecl.typeParameters && tsDecl.typeParameters.length > 0) 
                    return tsDecl.typeParameters;
            }
        }

        return null;
    }

    private translateTypeArguments(tsTypeArgs: ts.NodeArray<ts.TypeNode>, tsGeneric: ts.Node): sts.TypeArgumentsContext {
        let tsTypeParams = this.getTypeParameters(tsGeneric);
        if (!tsTypeParams) {
            if (tsTypeArgs && tsTypeArgs.length > 0) {
                // Warn and return empty type argument list with original syntax as comment.
                this.reportError("Failed to translate type arguments: Type or function is not or cannot be generic", tsGeneric);

                let stsCommentText: string = "";
                for (let i = 0; i < tsTypeArgs.length; ++i) {
                    if (!TranslationUtils.nodeIsSynthesized(tsTypeArgs[i])) {
                        if (i > 0) stsCommentText += ", ";
                        stsCommentText += tsTypeArgs[i].getText();
                    }
                }

                if (stsCommentText) {
                    let stsTypeArgs = new sts.TypeArgumentsContext(undefined, 0);
                    let stsTypeArgList = new sts.TypeArgumentListContext(stsTypeArgs, 0);
                    stsTypeArgList.addTrailingComment(NodeBuilder.multiLineComment("/* " + stsCommentText + " */"));
                    stsTypeArgs.addChild(stsTypeArgList);
                    return stsTypeArgs;
                }
            }

            return null;
        }

        // Translate explicitly specified type arguments (if any). 
        let stsTypeArgList = new sts.TypeArgumentListContext(undefined, 0);
        if (tsTypeArgs) {
            for (let tsTypeArg of tsTypeArgs) {
                let stsTypeArg = new sts.TypeArgumentContext(stsTypeArgList, 0);
                stsTypeArg.addChild(this.translateType(tsTypeArg));
                stsTypeArgList.addChild(stsTypeArg);
            }
        }

        // If there are unused type parameters, look up and
        // translate default or inferred type arguments.
        if (stsTypeArgList.childCount < tsTypeParams.length) {
            if (ts.isCallLikeExpression(tsGeneric)) {
                let tsSignature = this.tsTypeChecker.getResolvedSignature(tsGeneric);
                let tsSyntaxKind = ts.isNewExpression(tsGeneric) ? ts.SyntaxKind.Constructor : 
                                                                   ts.SyntaxKind.FunctionDeclaration;
                let tsSignatureDecl = this.tsTypeChecker.signatureToSignatureDeclaration(tsSignature,
                                                                             tsSyntaxKind, undefined, 
                                                    ts.NodeBuilderFlags.WriteTypeArgumentsOfSignature);
                let tsResolvedTypeArgs = tsSignatureDecl ? tsSignatureDecl.typeArguments : null;
                if (tsResolvedTypeArgs && tsResolvedTypeArgs.length > 0) {
                    for (let i = stsTypeArgList.childCount; i < tsResolvedTypeArgs.length; ++i) {
                        let stsTypeArg = new sts.TypeArgumentContext(stsTypeArgList, 0);
                        stsTypeArg.addChild(this.translateType(tsResolvedTypeArgs[i]));
                        stsTypeArgList.addChild(stsTypeArg);
                    }
                }
                else {
                    // Warn and continue.
                    this.reportError("Failed to infer type arguments", tsGeneric);
                }
            }
            else {
                for (let i = stsTypeArgList.childCount; i < tsTypeParams.length; ++i) {
                    let tsDefaultTypeArg = tsTypeParams[i].default;
                    let stsTypeArg = new sts.TypeArgumentContext(stsTypeArgList, 0);

                    if (tsDefaultTypeArg) {
                        stsTypeArg.addChild(this.translateType(tsDefaultTypeArg));
                    }
                    else {
                        // Warn and emit __UnknownType.
                        this.reportError("Failed to resolve default type argument", tsGeneric);
                        stsTypeArg.addChild(NodeBuilder.unknownTypeReference(null));
                    }

                    stsTypeArgList.addChild(stsTypeArg);
                }
            }
        }

        // Return null if we end up with empty type argument list.
        if (stsTypeArgList.childCount === 0) return null;

        let stsTypeArgs = new sts.TypeArgumentsContext(undefined, 0);
        stsTypeArgs.addChild(stsTypeArgList);
        return stsTypeArgs;
    }

    visitParenthesizedExpression(tsParenthExpr: ts.ParenthesizedExpression): sts.SingleExpressionContext {
        let stsExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsParenthExpr = new sts.ParenthesizedExpressionContext(stsExpr);
        stsExpr.addChild(stsParenthExpr);
        stsParenthExpr.addChild(this.visitNode(tsParenthExpr.expression));
        
        this.exprTransformed.add(tsParenthExpr);
        return stsExpr;
    }

    visitIfStatement(tsIfStmt: ts.IfStatement): sts.StatementContext {
        let stsIfStmt = new sts.IfStatementContext(undefined, 0);
        stsIfStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.If));
        stsIfStmt.addChild(this.visitNode(tsIfStmt.expression));
        stsIfStmt._ifStmt = (this.visitNode(tsIfStmt.thenStatement) as sts.StatementContext);
        stsIfStmt.addChild(stsIfStmt._ifStmt);

        let tsElseStmt = tsIfStmt.elseStatement;
        if (tsElseStmt) {
            stsIfStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Else));
            stsIfStmt._elseStmt = (this.visitNode(tsElseStmt) as sts.StatementContext);
            stsIfStmt.addChild(stsIfStmt._elseStmt);
        }

        this.stmtTransformed.add(tsIfStmt);
        return NodeBuilder.statement(stsIfStmt);
    }

    visitContinueStatement(tsContinueStmt: ts.ContinueStatement): sts.StatementContext {
        let stsContinueStmt = new sts.ContinueStatementContext(undefined, 0);
        stsContinueStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Continue));

        let tsLabel = tsContinueStmt.label;
        if (tsLabel) {
            stsContinueStmt.addChild(NodeBuilder.terminalIdentifier(tsLabel.text));
        }

        this.stmtTransformed.add(tsContinueStmt);
        return NodeBuilder.statement(stsContinueStmt);
    }

    visitBreakStatement(tsBreakStmt: ts.BreakStatement): sts.StatementContext {
        let stsBreakStmt = new sts.BreakStatementContext(undefined, 0);
        stsBreakStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Break));

        let tsLabel = tsBreakStmt.label;
        if (tsLabel) {
            stsBreakStmt.addChild(NodeBuilder.terminalIdentifier(tsLabel.text));
        }

        this.stmtTransformed.add(tsBreakStmt);
        return NodeBuilder.statement(stsBreakStmt);
    }

    visitReturnStatement(tsReturnStmt: ts.ReturnStatement): sts.StatementContext {
        let stsReturnStmt = new sts.ReturnStatementContext(undefined, 0);
        stsReturnStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Return));

        let tsExpr = tsReturnStmt.expression;
        if (tsExpr) {
            stsReturnStmt.addChild(this.visitNode(tsExpr));
        }

        this.stmtTransformed.add(tsReturnStmt);
        return NodeBuilder.statement(stsReturnStmt);
    }

    visitLabeledStatement(tsLabeledStmt: ts.LabeledStatement): sts.StatementContext {
        let stsLabeledStmt = new sts.LabelledStatementContext(undefined, 0);
        stsLabeledStmt.addChild(NodeBuilder.terminalIdentifier(tsLabeledStmt.label.text));
        stsLabeledStmt.addChild(this.visitNode(tsLabeledStmt.statement));
        
        this.stmtTransformed.add(tsLabeledStmt);
        return NodeBuilder.statement(stsLabeledStmt);
    }

    visitEmptyStatement(tsEmptyStmt: ts.EmptyStatement): sts.StatementContext {
        // Replace by null literal if in labelled statement context,
        // otherwise return an empty block.
        let stsStmt: sts.StatementContext;
        if (tsEmptyStmt.parent.kind === ts.SyntaxKind.LabeledStatement) {
            let exprStmt = new sts.ExpressionStatementContext(undefined, 0);
            exprStmt.addChild(NodeBuilder.nullLiteral());
            stsStmt = NodeBuilder.statement(exprStmt);
        } else {
            stsStmt = NodeBuilder.statement(new sts.BlockContext(undefined, 0));
        }

        this.stmtTransformed.add(tsEmptyStmt);
        return stsStmt;
    }

    visitForStatement(tsForStmt: ts.ForStatement): sts.StatementContext {
        let stsIterStmt = new sts.IterationStatementContext(undefined, 0);
        let stsForStmt = new sts.ForStatementContext(stsIterStmt);

        stsForStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.For));

        let tsForInit = tsForStmt.initializer;
        if (tsForInit) {
            let stsForInit = new sts.ForInitContext(stsForStmt, 0);
            stsForStmt.addChild(stsForInit);

            if (ts.isVariableDeclarationList(tsForInit)) {
                // Currently, STS doesn't support const declaration in
                // the loop initializer. In that case, warn and emit 'let'
                // declaration instead.
                stsForInit.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Let));
                stsForInit.addChild(this.translateVariableDeclarationList(tsForInit, false)); 
                if (TranslationUtils.isConst(tsForInit)) {
                    this.reportError("Emitted let declaration instead of const", tsForInit);
                }
            } else {
                let stsExprSeq = new sts.ExpressionSequenceContext(stsForInit, 0);
                stsForInit.addChild(stsExprSeq);

                if (TranslationUtils.isCommaOperatorExpression(tsForInit)) {
                    this.processCommaOperatorExpression(tsForInit, stsExprSeq);
                } else {
                    stsExprSeq.addChild(this.visitNode(tsForInit));
                }
            }
        }

        let tsCond = tsForStmt.condition;
        if (tsCond) {
            stsForStmt.addChild(this.visitNode(tsCond));
        }

        let tsIncr = tsForStmt.incrementor;
        if (tsIncr) {
            let stsExprSeq = new sts.ExpressionSequenceContext(stsForStmt, 0);
            stsForStmt.addChild(stsExprSeq);

            if (TranslationUtils.isCommaOperatorExpression(tsIncr)) {
                this.processCommaOperatorExpression(tsIncr, stsExprSeq);
            } else {
                stsExprSeq.addChild(this.visitNode(tsIncr));
            }
        }

        stsForStmt.addChild(this.visitNode(tsForStmt.statement));

        stsIterStmt.addChild(stsForStmt);
        
        this.stmtTransformed.add(tsForStmt);
        return NodeBuilder.statement(stsIterStmt);
    }

    private processCommaOperatorExpression(tsBinaryExpr: ts.BinaryExpression, stsExprSeq: sts.ExpressionSequenceContext): void {
        // Comma operator is represented by a binary expression, where left
        // operand may be another comma operator expression. Traverse binary
        // operator nodes recursively and translate each operand of the comma
        // operators, adding result of translation to given expression sequence.
        if (TranslationUtils.isCommaOperatorExpression(tsBinaryExpr.left)) {
            this.processCommaOperatorExpression(tsBinaryExpr.left, stsExprSeq);
        } else {
            stsExprSeq.addChild(this.visitNode(tsBinaryExpr.left));
        }

        stsExprSeq.addChild(this.visitNode(tsBinaryExpr.right));
        this.exprTransformed.add(tsBinaryExpr);
    }

    visitForOfStatement(tsForOfStmt: ts.ForOfStatement): sts.StatementContext {
        let stsIterStmt = new sts.IterationStatementContext(undefined, 0);
        let stsForOfStmt = new sts.ForOfStatementContext(stsIterStmt);

        stsForOfStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.For));
        stsForOfStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Let));

        // Note: Currently, STS doesn't support const or destructuring
        // declaration, or using an existing object as a loop variable.
        // For a const declaration, simply emit the 'let' declaration
        // instead. For other unsupported cases, skip translation of the
        // for loop header (see the code below). 
        let translatedInitializer = false;
        let tsForInit = tsForOfStmt.initializer;
        if (ts.isVariableDeclarationList(tsForInit)) {
            let tsForInitDecl = tsForInit.declarations[0];
            if (ts.isIdentifier(tsForInitDecl.name)) {
                stsForOfStmt.addChild(NodeBuilder.terminalIdentifier(tsForInitDecl.name.text));

                let tsVarType = tsForInitDecl.type;
                if (tsVarType) {
                    stsForOfStmt.addChild(NodeBuilder.typeAnnotation(this.translateType(tsVarType)));
                }

                if (TranslationUtils.isConst(tsForInit)) {
                    this.reportError("Emitted let declaration instead of const", tsForInit);
                }

                translatedInitializer = true;

                // Count variable declaration as transformed.
                this.declTransformed.add(tsForInitDecl);
            }
        }

        if (!translatedInitializer) {
            // Warn and translate only the loop body. Add comment with original
            // syntax of For loop header to the result of translation.
            this.reportError("Failed to translate For loop header", tsForOfStmt);
            let stsStmt = this.visitNode(tsForOfStmt.statement) as sts.StatementContext;
            stsStmt.addLeadingComment(NodeBuilder.untranslatedForHeaderComment(tsForOfStmt));
            return stsStmt;
        }

        stsForOfStmt.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.OF));
        stsForOfStmt.addChild(this.visitNode(tsForOfStmt.expression));
        stsForOfStmt.addChild(this.visitNode(tsForOfStmt.statement));

        stsIterStmt.addChild(stsForOfStmt);
        
        this.stmtTransformed.add(tsForOfStmt);
        return NodeBuilder.statement(stsIterStmt);
    }
    
    visitForInStatement(tsForInStmt: ts.ForInStatement): sts.StatementContext {
        // Cannot translate the For-in loop due to its dynamic behavior
        // of iterating over object's enumerable string properties and
        // returning the key values.
        // Warn and translate only the loop body. Add comment with original
        // syntax of For loop header to the result of translation.
        this.reportError("Failed to translate For loop header", tsForInStmt);
        let stsStmt = this.visitNode(tsForInStmt.statement) as sts.StatementContext;
        stsStmt.addLeadingComment(NodeBuilder.untranslatedForHeaderComment(tsForInStmt));
        return stsStmt;
    }

    visitWhileStatement(tsWhileStmt: ts.WhileStatement): sts.StatementContext {
        let stsIterStmt = new sts.IterationStatementContext(undefined, 0);
        let stsWhileStmt = new sts.WhileStatementContext(stsIterStmt);

        stsWhileStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.While));
        stsWhileStmt.addChild(this.visitNode(tsWhileStmt.expression));
        stsWhileStmt.addChild(this.visitNode(tsWhileStmt.statement));
        
        stsIterStmt.addChild(stsWhileStmt);
        
        this.stmtTransformed.add(tsWhileStmt);
        return NodeBuilder.statement(stsIterStmt);
    }

    visitDoStatement(tsDoStmt: ts.DoStatement): sts.StatementContext {
        let stsIterStmt = new sts.IterationStatementContext(undefined, 0);
        let stsDoStmt = new sts.DoStatementContext(stsIterStmt);

        stsDoStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Do));
        stsDoStmt.addChild(this.visitNode(tsDoStmt.statement));
        stsDoStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.While));
        stsDoStmt.addChild(this.visitNode(tsDoStmt.expression));
        
        stsIterStmt.addChild(stsDoStmt);
        
        this.stmtTransformed.add(tsDoStmt);
        return NodeBuilder.statement(stsIterStmt);
    }

    visitElementAccessExpression(tsElementAccessExpr: ts.ElementAccessExpression): sts.SingleExpressionContext {
        let tsBaseExpr = tsElementAccessExpr.expression;
        let tsIndexExpr = tsElementAccessExpr.argumentExpression;
        let tsBaseExprType = this.tsTypeChecker.getTypeAtLocation(tsBaseExpr);
        let tsBaseExprTypeNode = this.tsTypeChecker.typeToTypeNode(tsBaseExprType, undefined, ts.NodeBuilderFlags.None);
        
        let stsSingleExpr: sts.SingleExpressionContext;
        if ((tsBaseExprType.isClassOrInterface() || 
            TranslationUtils.isThisOrSuperExpr(tsBaseExpr) || 
            TranslationUtils.isEnumType(tsBaseExprType)) && 
            (ts.isStringLiteral(tsIndexExpr) || ts.isNumericLiteral(tsIndexExpr))) {
            // Translate as member access.
            let stsBaseExpr = this.visitNode(tsBaseExpr);
            let stsMemberName = NodeBuilder.terminalIdentifier(tsIndexExpr);
            stsSingleExpr = NodeBuilder.memberAccess(stsBaseExpr, stsMemberName, 
                                                    !!tsElementAccessExpr.questionDotToken,
                                                    tsIndexExpr.text);
        }
        else if (ts.isArrayLiteralExpression(tsBaseExpr) || TranslationUtils.isArrayNotTupleType(tsBaseExprTypeNode)) {
            // Translate as array access.
            stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
            let stsArrayAccess = new sts.ArrayAccessExpressionContext(stsSingleExpr);
            stsArrayAccess.addChild(this.visitNode(tsBaseExpr));

            if (tsElementAccessExpr.questionDotToken) {
                // Add question mark to indicate that this array access is null-safe.
                stsArrayAccess.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.QuestionMark));
            }

            let stsIndexExpr = new sts.IndexExpressionContext(stsArrayAccess, 0);
            stsIndexExpr.addChild(this.visitNode(tsIndexExpr));
            stsArrayAccess.addChild(stsIndexExpr);

            stsSingleExpr.addChild(stsArrayAccess);
        }
        else {
            // Warn and return __untranslated_expression() call.
            return this.reportUntranslatedExpression(tsElementAccessExpr, "element access expression");
        }

        this.exprTransformed.add(tsElementAccessExpr);
        return stsSingleExpr;
    }

    visitArrayLiteralExpression(tsArrayLiteral: ts.ArrayLiteralExpression): sts.SingleExpressionContext {
        // Check that this is an array literal, not tuple literal.
        // Note: Consider empty literals to be array literals.
        let tsType = this.tsTypeChecker.getTypeAtLocation(tsArrayLiteral);
        let tsTypeNode = this.tsTypeChecker.typeToTypeNode(tsType, undefined, ts.NodeBuilderFlags.None);
        if (tsArrayLiteral.elements.length > 0 && !TranslationUtils.isArrayNotTupleType(tsTypeNode)) {
            // Warn and emit __untranslated_expression() call.
            return this.reportUntranslatedExpression(tsArrayLiteral, "tuple literal");
        }

        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsArrayLiteralExpr = new sts.ArrayLiteralExpressionContext(stsSingleExpr);

        if (tsArrayLiteral.elements.length > 0) {
            let stsExprSeq = new sts.ExpressionSequenceContext(stsArrayLiteralExpr, 0);
            stsArrayLiteralExpr.addChild(stsExprSeq);

            for (let tsExpr of tsArrayLiteral.elements) {
                stsExprSeq.addChild(this.visitNode(tsExpr));
            }
        }

        stsSingleExpr.addChild(stsArrayLiteralExpr);
        this.exprTransformed.add(tsArrayLiteral);
        return stsSingleExpr;
    }
    
    visitSwitchStatement(tsSwitchStmt: ts.SwitchStatement): sts.StatementContext {
        let stsSwitchStmt = new sts.SwitchStatementContext(undefined, 0);
        stsSwitchStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Switch));

        // STS restricts the type of switch expression to be number, string or Enum.
        let tsSwitchExprType = this.tsTypeChecker.getTypeAtLocation(tsSwitchStmt.expression);
        if ((tsSwitchExprType.getFlags() & (ts.TypeFlags.NumberLike | ts.TypeFlags.StringLike)) || TranslationUtils.isEnumType(tsSwitchExprType)) {
            stsSwitchStmt.addChild(this.visitNode(tsSwitchStmt.expression))
        } else {
            stsSwitchStmt.addChild(this.reportInvalidExpression(tsSwitchStmt.expression, "switch expression"));
        }

        // Create a block to capture declarations that should be
        // moved outside of case and/or default clauses (if any).
        let stsBlock = new sts.BlockContext(undefined, 0);
        this.stsBlockLikeContexts.push(stsBlock);
        stsSwitchStmt.addChild(this.translateSwitchCaseClauses(tsSwitchStmt));
        this.stsBlockLikeContexts.pop();

        // If any declarations were captured in the above block,
        // add switch to it as well before returning that block.
        // Otherwise, return the switch itself.
        let stsResult: StaticTSContextBase = stsSwitchStmt;
        if (stsBlock.childCount > 0) {
            stsBlock.addChild(NodeBuilder.statementOrLocalDeclaration(NodeBuilder.statement(stsSwitchStmt)));
            stsResult = stsBlock;
        }

        this.stmtTransformed.add(tsSwitchStmt);
        return NodeBuilder.statement(stsResult);
    }

    private translateSwitchCaseClauses(tsSwitchStmt: ts.SwitchStatement): sts.CaseBlockContext {
        let stsCaseBlock = new sts.CaseBlockContext(undefined, 0);
        let stsCaseClauses: sts.CaseClausesContext;
        let tsCaseBlock = tsSwitchStmt.caseBlock;
        let translatedDefaultClause = false;

        for (const tsCaseClause of tsCaseBlock.clauses) {
            if (!stsCaseClauses) {
                stsCaseClauses = new sts.CaseClausesContext(stsCaseBlock, 0);

                if (!translatedDefaultClause)
                    stsCaseBlock._leftCases = stsCaseClauses;
                else
                    stsCaseBlock._rightCases = stsCaseClauses;

                stsCaseBlock.addChild(stsCaseClauses);
            }

            let stsCaseClause: stsCaseOrDefaultClause;
            if (ts.isCaseClause(tsCaseClause)) {
                stsCaseClause = new sts.CaseClauseContext(stsCaseClauses, 0);
                stsCaseClause.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Case));

                // STS allows only a constant expression or the name of an enum type
                // for a case expression.
                let tsCaseExpr = tsCaseClause.expression;
                let tsCaseExprType = this.tsTypeChecker.getTypeAtLocation(tsCaseExpr);
                if (ts.isNumericLiteral(tsCaseExpr) || ts.isStringLiteralLike(tsCaseExpr) || tsCaseExprType.flags & ts.TypeFlags.EnumLike) {
                    stsCaseClause.addChild(this.visitNode(tsCaseExpr));
                } else {
                    stsCaseClause.addChild(this.reportInvalidExpression(tsCaseExpr, "case expression"));
                }

                stsCaseClauses.addChild(stsCaseClause);
            } 
            else {
                stsCaseClause = new sts.DefaultClauseContext(stsCaseBlock, 0);
                stsCaseClause.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.DEFAULT))
                stsCaseBlock.addChild(stsCaseClause);
                
                translatedDefaultClause = true;
                stsCaseClauses = undefined;
            }

            this.stsBlockLikeContexts.push(stsCaseClause);

            // Create a block to receive all statements and local
            // declarations (except functions - see below) for the
            // current clause. If there are no local declarations,
            // we'll transfer the statements to the clause later on.
            let stsBlock = new sts.BlockContext(stsCaseClause, 0);
            this.stsBlockLikeContexts.push(stsBlock);

            for (const tsStmt of tsCaseClause.statements) {
                // Functions inside case or default clauses in TS are visible
                // and callable throughout the entire switch statement, so we
                // need to put resulting functional object to switch statement's
                // enclosing scope. Make sure we skip the block created above and
                // the case or default clause itself; addToBlockLikeContext function 
                // will then promote the functional object to the right scope.
                let depth = ts.isFunctionDeclaration(tsStmt) ? 2 : 1;
                this.addToBlockLikeContext(this.visitNode(tsStmt), depth);
            }
            
            this.stsBlockLikeContexts.pop(); // BlockContext
            this.stsBlockLikeContexts.pop(); // CaseOrDefaultClause

            // If no local declarations were produced, transfer all statements from block 
            // to the current clause. Otherwise, add the block itself to the current clause.
            if (!stsBlock.statementOrLocalDeclaration().find(child => !child.statement())) {
                for (let stsStmtOrDecl of stsBlock.statementOrLocalDeclaration()) {
                    let stsStmt = stsStmtOrDecl.statement();
                    if (stsStmt) stsCaseClause.addChild(stsStmt);
                }
            }
            else {
                stsCaseClause.addChild(NodeBuilder.statement(stsBlock));
            }
        }

        return stsCaseBlock;
    }

    visitFunctionExpression(tsFunctionExpr: ts.FunctionExpression): sts.SingleExpressionContext {
        // Don't translate generator function expressions. Warn and emit __untranslated_expression() call.
        if (tsFunctionExpr.asteriskToken) {
            return this.reportUntranslatedExpression(tsFunctionExpr, "generator function expression");
        }

        // STS currently doesn't allow type parameters on lambda expressions.
        let tsTypeParams = tsFunctionExpr.typeParameters;
        if (tsTypeParams && tsTypeParams.length > 0) {
            return this.reportUntranslatedExpression(tsFunctionExpr, "function expression")
        }

        let stsLambdaExpr = this.translateLambdaExpression(tsFunctionExpr);
        this.exprTransformed.add(tsFunctionExpr);
        return stsLambdaExpr;
    }

    visitArrowFunction(tsArrowFunction: ts.ArrowFunction): sts.SingleExpressionContext {
        // STS currently doesn't allow type parameters on lambda expressions.
        let tsTypeParams = tsArrowFunction.typeParameters;
        if (tsTypeParams && tsTypeParams.length > 0) {
            return this.reportUntranslatedExpression(tsArrowFunction, "arrow function")
        }

        let stsLambdaExpr = this.translateLambdaExpression(tsArrowFunction);
        this.exprTransformed.add(tsArrowFunction);
        return stsLambdaExpr;
    }

    private translateLambdaExpression(tsFunctionExpr: ts.FunctionLikeDeclaration): sts.SingleExpressionContext {
        let stsExpr = new sts.SingleExpressionContext(undefined, 0); 
        let stsLambdaExpr = new sts.LambdaExpressionContext(stsExpr);
        stsExpr.addChild(stsLambdaExpr);

        // Translate signature.
        let stsSignature = this.translateSignature(tsFunctionExpr);
        let stsSignatureParams = stsSignature.parameterList();
        if (stsSignatureParams) stsLambdaExpr.addChild(stsSignatureParams);
        stsLambdaExpr.addChild(stsSignature.typeAnnotation());

        // Translate lambda body.
        let stsLambdaBody = new sts.LambdaBodyContext(stsLambdaExpr, 0);
        stsLambdaBody.addChild(this.visitNode(tsFunctionExpr.body));

        stsLambdaExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Arrow));
        stsLambdaExpr.addChild(stsLambdaBody);
        
        return stsExpr;
    }
    
    visitThisExpression(tsThisExpr: ts.ThisExpression): sts.SingleExpressionContext {
        // Don't translate this unless we're in class body context.
        if (!this.getCurrentClassBody()) return this.reportUntranslatedExpression(tsThisExpr);

        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);

        let stsThisExpr = new sts.ThisExpressionContext(stsSingleExpr);
        stsThisExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.This));

        stsSingleExpr.addChild(stsThisExpr);
        this.exprTransformed.add(tsThisExpr);
        return stsSingleExpr;
    }

    visitSuperExpression(tsSuperExpr: ts.SuperExpression): sts.SingleExpressionContext {
        // Don't translate super unless we're in class context.
        if (!this.getCurrentClassBody()) return this.reportUntranslatedExpression(tsSuperExpr);
        
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);

        let stsSuperExpr = new sts.SuperExpressionContext(stsSingleExpr);
        stsSuperExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Super));

        stsSingleExpr.addChild(stsSuperExpr);
        this.exprTransformed.add(tsSuperExpr);
        return stsSingleExpr;
    }

    visitVoidExpression(tsVoidExpr: ts.VoidExpression): sts.SingleExpressionContext {
        let stsVoidExpr = NodeBuilder.identifierExpression(sts.StaticTSParser.VOID);
        let tsArgExpr = tsVoidExpr.expression;

        // Translate argument expression and add it as 
        // expression statement to enclosing block.
        let stsExprStatement = new sts.ExpressionStatementContext(undefined, 0);
        stsExprStatement.addChild(this.visitNode(tsArgExpr));
        let isAdded = this.addToBlockLikeContext(NodeBuilder.statement(stsExprStatement));

        if (!isAdded) {
            // If failed to add, warn and add argument expression as comment.
            this.reportError("Failed to translate argument of void expression", tsArgExpr);
            let stsComment = NodeBuilder.multiLineComment("/* " + tsArgExpr.getText() + " */");
            stsVoidExpr.addTrailingComment(stsComment);
        }

        this.exprTransformed.add(tsVoidExpr);
        return stsVoidExpr;
    }

    visitAwaitExpression(tsAwaitExpr: ts.AwaitExpression): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);

        let stsAwaitExpr = new sts.AwaitExpressionContext(stsSingleExpr);
        stsAwaitExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Await));
        stsAwaitExpr.addChild(this.visitNode(tsAwaitExpr.expression));

        stsSingleExpr.addChild(stsAwaitExpr);
        return stsSingleExpr;
    }

    visitClassExpression(tsClassExpr: ts.ClassExpression): sts.SingleExpressionContext {
        let stsClassDecl = this.translateClassLikeDeclaration(tsClassExpr);
        if (!this.addToBlockLikeContext(stsClassDecl)) {
            // If there is no enclosing block or class, add declaration to CU.
            this.stsCU.addChild(NodeBuilder.topDeclaration(stsClassDecl, false));
        }
        
        // Emit lambda expression with ctor signature returning new object of the class above.
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsLambdaExpr = new sts.LambdaExpressionContext(stsSingleExpr);

        let stsCtorArgs: sts.SingleExpressionContext[] = [];
        let stsCtorDecl = TranslationUtils.findCtorDecl(stsClassDecl);
        if (stsCtorDecl) {
            // Clone ctor parameter list, if exists.
            let stsCtorParams = stsCtorDecl.parameterList();
            if (stsCtorParams) {
                stsLambdaExpr.addChild(NodeCloner.cloneParameterList(stsCtorParams));

                // Fill ctor args list, to be used in new class instance expression below.
                for (let stsCtorParam of stsCtorParams.parameter()) {
                    let stsCtorParamName = stsCtorParam.Identifier().text;
                    let stsCtorArg = NodeBuilder.identifierExpression(stsCtorParamName);
                    stsCtorArgs.push(stsCtorArg);
                }
            }
        }

        let stsClassName = stsClassDecl.Identifier().text;
        stsLambdaExpr.addChild(NodeBuilder.typeAnnotation(stsClassName));
        stsLambdaExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Arrow));

        let stsLambdaBody = new sts.LambdaBodyContext(stsLambdaExpr, 0);
        stsLambdaBody.addChild(NodeBuilder.newClassInstanceExpression(stsClassName, ...stsCtorArgs));

        stsLambdaExpr.addChild(stsLambdaBody);
        stsSingleExpr.addChild(stsLambdaExpr);

        this.exprTransformed.add(tsClassExpr);
        return stsSingleExpr;
    }

    private getCurrentClassBody(): sts.ClassBodyContext {
        for (let i = this.stsBlockLikeContexts.length-1; i >= 0; --i) {
            let stsBlockLikeCtx = this.stsBlockLikeContexts[i];
            if (stsBlockLikeCtx.ruleIndex === sts.StaticTSParser.RULE_classBody)
                return stsBlockLikeCtx as sts.ClassBodyContext;
        }

        return null;
    }

    visitObjectLiteral(tsObjectLiteral: ts.ObjectLiteralExpression): sts.SingleExpressionContext {
        let tsClassName = this.getClassNameForObjectLiteral(tsObjectLiteral);
        if (!tsClassName) {
            // Warn and emit __invalid_expression call.
            return this.reportInvalidExpression(tsObjectLiteral, "object literal: Cannot infer corresponding class");
        }

        // If object literal contains methods or accessors, translate as anonymous 
        // class object creation, with explicit field assignments in ctor.
        if (tsObjectLiteral.properties.find(prop => ts.isMethodDeclaration(prop) || ts.isAccessor(prop))) {
            return this.translateAsAnonymousClassObject(tsObjectLiteral, tsClassName);
        }
        
        // Translate as class composite.
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsClassComposite = new sts.ClassCompositeExpressionContext(stsSingleExpr);
        let stsNameValueSeq = new sts.NameValueSequenceContext(stsClassComposite, 0);

        for (let tsObjLiteralProp of tsObjectLiteral.properties) {
            if (ts.isPropertyAssignment(tsObjLiteralProp)) {
                // Translate as is.
                let stsNameValuePair = new sts.NameValuePairContext(stsNameValueSeq, 0);
                stsNameValuePair.addChild(NodeBuilder.terminalIdentifier(tsObjLiteralProp.name));
                stsNameValuePair.addChild(this.visitNode(tsObjLiteralProp.initializer));
                stsNameValueSeq.addChild(stsNameValuePair);
            }
            else if (ts.isShorthandPropertyAssignment(tsObjLiteralProp) && 
                    !tsObjLiteralProp.equalsToken && !tsObjLiteralProp.objectAssignmentInitializer) {
                // Translate as f: f where first f names the class field and second f  
                // names a variable that should exist in the enclosing context.
                let stsNameValuePair = new sts.NameValuePairContext(stsNameValueSeq, 0);
                stsNameValuePair.addChild(NodeBuilder.terminalIdentifier(tsObjLiteralProp.name));
                stsNameValuePair.addChild(NodeBuilder.identifierExpression(tsObjLiteralProp.name.text));
                stsNameValueSeq.addChild(stsNameValuePair);
            }
            else {
                // Warn and emit a comment with original syntax.
                this.reportError("Failed to translate object literal member", tsObjLiteralProp);
                
                let stsComment = NodeBuilder.multiLineComment("/* " + tsObjLiteralProp.getText() + " */");
                stsNameValueSeq.addTrailingComment(stsComment);
            }
        }

        stsClassComposite.addChild(stsNameValueSeq);
        stsSingleExpr.addChild(stsClassComposite);

        this.exprTransformed.add(tsObjectLiteral);
        return stsSingleExpr;
    }

    private getClassNameForObjectLiteral(tsObjectLiteral: ts.ObjectLiteralExpression): string {
        // Valid contexts for use of class composite are those where we can infer 
        // corresponding class compatible with it. Namely:
        // 1. Initializer in variable declaration with type specified explicitly.
        // 2. Initializer in property declaration with type specified explicitly.
        // 3. RHS of assignment expression where type of LHS can be resolved.
        // 4. Argument in call expression or new expression where parameter type can be resolved.
        let tsParent = tsObjectLiteral.parent;
        if ((ts.isVariableDeclaration(tsParent) || ts.isPropertyDeclaration(tsParent)) && tsParent.type) {
            let tsType = this.tsTypeChecker.getTypeFromTypeNode(tsParent.type);
            if (TranslationUtils.isClass(tsType)) return tsType.symbol.name;
        }
        else if (ts.isBinaryExpression(tsParent) && tsParent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            let tsType = this.tsTypeChecker.getTypeAtLocation(tsParent.left);
            if (TranslationUtils.isClass(tsType)) return tsType.symbol.name;
        }
        else if (ts.isCallExpression(tsParent) || ts.isNewExpression(tsParent)) {
            // Get signature of callable object (function, ctor, etc.) being invoked.
            let tsSignature = this.tsTypeChecker.getResolvedSignature(tsParent);
            if (!tsSignature || !tsParent.arguments) return null; // Make sure signature has arguments.

            let index = tsParent.arguments.findIndex(arg => arg == tsObjectLiteral);
            if (index === -1) return null; // Make sure object literal is among the arguments.

            // Get signature declaration.
            let tsSignatureDecl = tsSignature.getDeclaration();
            if (!tsSignatureDecl) return null;
            
            // Get corresponding parameter and its type.
            let tsParams = tsSignatureDecl.parameters;
            if (index >= tsParams.length) index = tsParams.length-1;
            let tsParamTypeNode = tsParams[index].type;
            if (tsParamTypeNode) {
                if (tsParams[index].dotDotDotToken && tsParamTypeNode.kind === ts.SyntaxKind.ArrayType)
                    tsParamTypeNode = (tsParamTypeNode as ts.ArrayTypeNode).elementType;

                let tsParamType = this.tsTypeChecker.getTypeFromTypeNode(tsParamTypeNode);
                if (TranslationUtils.isClass(tsParamType)) return tsParamType.symbol.name;
            }
        }

        return null;
    }

    private translateAsAnonymousClassObject(tsObjectLiteral: ts.ObjectLiteralExpression, tsClassName: string): sts.SingleExpressionContext {
        let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
        let stsNewClassInstExpr = new sts.NewClassInstanceExpressionContext(stsSingleExpr);

        stsNewClassInstExpr.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.New));
        stsNewClassInstExpr.addChild(NodeBuilder.typeReference(tsClassName));

        // Translate method declarations on spot and collect necessary info
        // from property assignments so that we can emit corresponding field
        // assignments in ctor later.
        let stsFieldAssignments = new Map<TerminalNode, ts.Expression>();
        let stsClassBody = new sts.ClassBodyContext(stsNewClassInstExpr, 0);
        this.stsBlockLikeContexts.push(stsClassBody);
        for (let tsObjectLiteralProp of tsObjectLiteral.properties) {
            let isTranslated = false;
            if (ts.isMethodDeclaration(tsObjectLiteralProp) || ts.isAccessor(tsObjectLiteralProp)) {
                let stsClassMethodDeclaration = this.visitNode(tsObjectLiteralProp);
                if (stsClassMethodDeclaration) {
                    stsClassBody.addChild(stsClassMethodDeclaration);
                    isTranslated = true;
                }
            }
            else if (ts.isPropertyAssignment(tsObjectLiteralProp)) {
                let stsFieldName = NodeBuilder.terminalIdentifier(tsObjectLiteralProp.name);
                stsFieldAssignments.set(stsFieldName, tsObjectLiteralProp.initializer);
                isTranslated = true;
            }
            else if (ts.isShorthandPropertyAssignment(tsObjectLiteralProp) &&
                    !tsObjectLiteralProp.equalsToken && !tsObjectLiteralProp.objectAssignmentInitializer) {
                // Corresponding initializer here matches field name and names
                // a variable that should exist in the enclosing context.
                let stsFieldName = NodeBuilder.terminalIdentifier(tsObjectLiteralProp.name);
                stsFieldAssignments.set(stsFieldName, tsObjectLiteralProp.name);
                isTranslated = true;
            }

            if (!isTranslated) {
                // Warn and emit a comment with original syntax.
                this.reportError("Failed to translate object literal member", tsObjectLiteralProp);

                let stsDummyNode = new DummyContext(stsClassBody, 0);
                let stsComment = NodeBuilder.multiLineComment("/* " + tsObjectLiteralProp.getText() + " */");
                stsDummyNode.addLeadingComment(stsComment);
                stsClassBody.addChild(stsDummyNode);
            }
        }

        if (stsFieldAssignments.size > 0) {
            // If we saw property assignments, emit constructor
            // and place corresponding field assignments there.
            let stsCtor = new sts.ConstructorDeclarationContext(undefined, 0);
            stsCtor.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Constructor));

            let stsNewClassInstExprArgs = new sts.ArgumentsContext(stsCtor, 0);
            let stsNewClassInstExprArgList = new sts.ExpressionSequenceContext(stsNewClassInstExprArgs, 0);

            let stsCtorBody = new sts.ConstructorBodyContext(stsCtor, 0);
            stsCtorBody.addChild(NodeBuilder.superCall());

            let stsCtorParams = new sts.ParameterListContext(stsCtor, 0);
            for (let stsFieldName of stsFieldAssignments.keys()) {
                // Add field initializer to argument list of the 
                // anonymous class instance creation expression.
                let tsInitExpr = stsFieldAssignments.get(stsFieldName);
                let stsNewClassInstExprArg = this.visitNode(tsInitExpr);
                stsNewClassInstExprArgList.addChild(stsNewClassInstExprArg);

                // Compute type of field initializer and use it to construct
                // corresponding parameter of anonymous class ctor.
                let tsParamType = this.tsTypeChecker.getTypeAtLocation(tsInitExpr.parent);
                let tsParamTypeNode = this.tsTypeChecker.typeToTypeNode(tsParamType, tsObjectLiteral, ts.NodeBuilderFlags.None);
                let stsParamType = this.translateType(tsParamTypeNode);

                let stsParam = new sts.ParameterContext(stsCtorParams, 0);
                stsParam.addChild(stsFieldName);
                stsParam.addChild(NodeBuilder.typeAnnotation(stsParamType));
                stsCtorParams.addChild(stsParam);

                // Create field assignment and add it to ctor body.
                let stsMemberAccess = NodeBuilder.memberAccess(NodeBuilder.thisExpression(), stsFieldName);
                let stsMemberValue = NodeBuilder.identifierExpression(stsFieldName.text);
                let stsAssignExpr = NodeBuilder.assignmentExpression(stsMemberAccess, stsMemberValue);

                let stsExprStmt = new sts.ExpressionStatementContext(undefined, 0);
                stsExprStmt.addChild(stsAssignExpr);

                let stsStatement = NodeBuilder.statement(stsExprStmt);
                stsCtorBody.addChild(NodeBuilder.statementOrLocalDeclaration(stsStatement));
            }

            stsNewClassInstExprArgs.addChild(stsNewClassInstExprArgList);
            stsNewClassInstExpr.addChild(stsNewClassInstExprArgs);

            stsCtor.addChild(stsCtorParams);
            stsCtor.addChild(stsCtorBody);

            stsClassBody.addChild(NodeBuilder.classMember(stsCtor, sts.StaticTSParser.Public));
        }

        this.stsBlockLikeContexts.pop();
        stsNewClassInstExpr.addChild(stsClassBody);
        stsSingleExpr.addChild(stsNewClassInstExpr);
        
        this.exprTransformed.add(tsObjectLiteral);
        return stsSingleExpr;
    }

    visitClassStaticBlock(tsClassStaticBlock: ts.ClassStaticBlockDeclaration): StaticTSContextBase {
        let stsClassBody = this.getCurrentClassBody();
        if (stsClassBody && !stsClassBody._clinit) {
            let stsBlock = this.visitNode(tsClassStaticBlock.body);

            // First static block encountered: Add class initializer node to class body.
            stsClassBody._clinit = new sts.ClassInitializerContext(stsClassBody, 0);
            stsClassBody._clinit.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Static));
            stsClassBody._clinit.addChild(stsBlock);

            this.declTransformed.add(tsClassStaticBlock);
            return stsClassBody._clinit;
        }
 
        // Secondary static block: Warn and return null.
        this.reportError("Failed to translate class static block", tsClassStaticBlock);
        return null;
    }

    visitThrowStatement(tsThrowStmt: ts.ThrowStatement): sts.StatementContext {
        let stsThrowStmt = new sts.ThrowStatementContext(undefined, 0);
        stsThrowStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Throw));

        // Translate expression being thrown.
        let stsExpr = this.visitNode(tsThrowStmt.expression);
        if (!stsExpr) stsExpr = this.reportUntranslatedExpression(tsThrowStmt.expression);

        // Wrap expression in Error object, i.e.:
        // throw expr --> throw new Error("", expr)
        let stsError = NodeBuilder.newClassInstanceExpression("Error", 
                                        NodeBuilder.stringLiteral("''"), stsExpr);
        stsThrowStmt.addChild(stsError);

        this.stmtTransformed.add(tsThrowStmt);
        return NodeBuilder.statement(stsThrowStmt);
    }

    visitTryStatement(tsTryStmt: ts.TryStatement): sts.StatementContext {
        // Translate try block first as we may have to emit it alone
        // in case there are no catch clauses in this try statement.
        let stsTryBlock = this.visitNode(tsTryStmt.tryBlock);

        let stsResultStmt: StaticTSContextBase;
        if (tsTryStmt.catchClause) {            
            stsResultStmt = new sts.TryStatementContext(undefined, 0);
            stsResultStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Try));
            stsResultStmt.addChild(stsTryBlock);

            // Translate catch clause.
            let stsCatch = this.visitNode(tsTryStmt.catchClause);
            stsResultStmt.addChild(stsCatch);
        }
        else {
            // If there are no catch clauses, emit the try block alone. 
            // The finally clause must be present in this case - it will be 
            // translated as defer statement and added to the try block below.
            stsResultStmt = stsTryBlock;
        }

        // Translate finally block, if exists.
        // Add it as defer statement to try block.
        if (tsTryStmt.finallyBlock) {
            let stsDeferStmt = new sts.DeferStatementContext(stsTryBlock, 0);
            stsDeferStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Defer));

            let stsFinallyBlock = this.visitNode(tsTryStmt.finallyBlock);
            stsDeferStmt.addChild(NodeBuilder.statement(stsFinallyBlock));

            let stsDeferStmtOrLocalDecl = NodeBuilder.statementOrLocalDeclaration(
                                                    NodeBuilder.statement(stsDeferStmt));
            stsDeferStmtOrLocalDecl.setParent(stsTryBlock);
            stsTryBlock.children.splice(0, 0, stsDeferStmtOrLocalDecl);
        }

        this.stmtTransformed.add(tsTryStmt);
        return NodeBuilder.statement(stsResultStmt);
    }

    visitCatchClause(tsCatch: ts.CatchClause): sts.DefaultCatchContext {
        let stsCatch = new sts.DefaultCatchContext(undefined, 0);
        stsCatch.addChild(NodeBuilder.terminalIdentifier(sts.StaticTSParser.CATCH));

        // Translate block first, in case we'll need 
        // to add a comment to it later (see below).
        let stsCatchBlock = this.visitNode(tsCatch.block);

        // Translate exception name.
        if (tsCatch.variableDeclaration) {
            let tsExceptionName = tsCatch.variableDeclaration.name;

            if (ts.isIdentifier(tsExceptionName)) {
                stsCatch.addChild(NodeBuilder.terminalIdentifier(tsExceptionName));
            }
            else {
                // Warn and emit __InvalidName__.
                this.reportError("Failed to translate exception name in catch clause", tsCatch);
                stsCatch.addChild(NodeBuilder.invalidIdentifier());

                // Add comment with original syntax to catch block.
                let stsComment = NodeBuilder.multiLineComment("/* Original exception name: " + 
                                                                tsExceptionName.getText() + " */");
                stsCatchBlock.addLeadingComment(stsComment);
            }
        }

        stsCatch.addChild(stsCatchBlock);
        return stsCatch;
    }
    
    reportUntranslatedType(tsTypeNode: ts.TypeNode | ts.Expression, typeKind?: string): sts.TypeReferenceContext {
        // Warn and emit __UnknownType__.
        if (!typeKind) typeKind = "type";
        this.reportError("Failed to translate " + typeKind, tsTypeNode);
        return NodeBuilder.unknownTypeReference(tsTypeNode);
    }

    reportUntranslatedExpression(tsExpression: ts.Expression, exprKind?: string): sts.SingleExpressionContext {
        // Warn and emit __untranslated_expression() call.
        if (!exprKind) exprKind = "expression";
        this.reportError("Failed to translate " + exprKind, tsExpression);
        return NodeBuilder.untranslatedExpression(tsExpression);
    }

    reportUntranslatedStatement(tsStatement: ts.Statement, stmtKind?: string): sts.StatementContext {
        // Warn and emit __untranslated_statement() call.
        if (!stmtKind) stmtKind = "statement";
        this.reportError("Failed to translate " + stmtKind, tsStatement);
        return NodeBuilder.untranslatedStatement(tsStatement);
    }

    reportInvalidExpression(tsExpression: ts.Expression, exprKind?: string): sts.SingleExpressionContext {
        // Warn and emit __invalid_expression() call.
        if (!exprKind) exprKind = "expression";
        this.reportError("Failed to translate " + exprKind, tsExpression);
        return NodeBuilder.invalidExpression(tsExpression);
    }
}