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

import { ParserRuleContext, Token } from 'antlr4ts'
import { ParseTree, TerminalNode } from 'antlr4ts/tree'
import { StaticTSParser, IfStatementContext, SwitchStatementContext, CaseClausesContext, CaseBlockContext } from '../../build/typescript/StaticTSParser'

export class StaticTSContextBase extends ParserRuleContext {
    private leadingComments: TerminalNode[];
    private trailingComments: TerminalNode[];

    constructor(parent: ParserRuleContext | undefined, invokingStateNumber: number) {
        super(parent, invokingStateNumber);
    }

    addLeadingComment(stsComment: TerminalNode): void {
        if (!this.leadingComments) this.leadingComments = [];
        this.leadingComments.push(stsComment);
    }

    addTrailingComment(stsComment: TerminalNode): void {
        if (!this.trailingComments) this.trailingComments = [];
        this.trailingComments.push(stsComment);
    }

    setLeadingComments(stsComments: TerminalNode[]): void {
        this.leadingComments = stsComments;
    }

    setTrailingComments(stsComments: TerminalNode[]): void {
        this.trailingComments = stsComments;
    }

    getLeadingComments(): TerminalNode[] {
        return this.leadingComments;
    }

    getTrailingComments(): TerminalNode[] {
        return this.trailingComments;
    }

    hasLeadingComments(): boolean {
        return this.leadingComments && this.leadingComments.length != 0;
    }

    hasTrailingComments(): boolean {
        return this.trailingComments && this.trailingComments.length != 0;
    }

    private static indent : number;
    private getXmlIndent = () => " ".repeat(4 * StaticTSContextBase.indent);

    toXML() : string {
        // Reset indent before recursing into AST
        StaticTSContextBase.indent = 0;
        let header : string = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        return header + this.toXMLImpl(null);
    }

    private toXMLImpl(parent: StaticTSContextBase) : string {
        let nodeName : string = this.constructor.name;
        let xmlIndent : string = this.getXmlIndent();
    
        // If current node has no children, return one-line XML tag;
        // otherwise create opening XML and proceed to child nodes.
        let result : string = xmlIndent + "<" + nodeName;
        
        // If this node is labeled in a parent rule, it needs to be
        // assigned to a corresponding field of the parent node. Add
        // additional attribute to specify the name of such field.
        let parentField = this.getParentFieldName(parent);
        if (parentField) {
            result += " parentField = \"" + parentField + "\"";
        }

        if (this.childCount === 0 && !this.hasLeadingComments() && !this.hasTrailingComments()) {
            return result + "/>\n";
        }
    
        result += ">\n";
    
        // Increase indent and process children.
        ++StaticTSContextBase.indent;
        for (let i = 0; i < this.childCount; ++i) {
            let childNode : ParseTree = this.getChild(i);
            
            if (childNode instanceof StaticTSContextBase) {
                result += childNode.toXMLImpl(this);
            }
            else if (childNode instanceof TerminalNode) {
                result += this.terminalToXml(childNode);
            }
        }

        // Write the node's comments.
        if (this.hasLeadingComments()) {
            for (let comment of this.leadingComments) {
                result += this.terminalToXml(comment, "true");
            }
        }
        if (this.hasTrailingComments()) {
            for (let comment of this.trailingComments) {
                result += this.terminalToXml(comment, "false");
            }
        }

        // Decrease indent after processing children.
        --StaticTSContextBase.indent;
    
        // Add closing XML tag.
        result += xmlIndent + "</" + nodeName + ">\n";
    
        return result;
    }

    private terminalToXml(stsTerm : TerminalNode, isLeadingCommentAttr?: string): string {
        // Can't recurse into TerminalNode as it doesn't extend
        // the current class, so process terminals in place.
        let token : Token = stsTerm.symbol;
        let kind : string = StaticTSParser.VOCABULARY.getSymbolicName(token.type);
        let xmlIndent : string = this.getXmlIndent();
        let result = xmlIndent + "<TerminalNode kind = \"" + kind + "\"";                
        
        if (isLeadingCommentAttr) {
            result += " isLeadingComment = \"" + isLeadingCommentAttr + "\"";
        }

        if (this.outputTokenText(token)) {
            result += " text = \"" + token.text + "\"";
        }
        result += "/>\n";

        return result;
    }

    private outputTokenText(token : Token) : boolean {
        return token.type === StaticTSParser.Identifier ||
               token.type === StaticTSParser.StringLiteral ||
               token.type === StaticTSParser.CharLiteral ||
               token.type === StaticTSParser.DecimalLiteral ||
               token.type === StaticTSParser.HexIntegerLiteral ||
               token.type === StaticTSParser.OctalIntegerLiteral ||
               token.type === StaticTSParser.BinaryIntegerLiteral ||
               token.type === StaticTSParser.SingleLineComment ||
               token.type === StaticTSParser.MultiLineComment;
    }

    private getParentFieldName(parent: StaticTSContextBase): string {
        let child: StaticTSContextBase = this;

        if (parent instanceof IfStatementContext) {
            if (parent._ifStmt === child) {
                return "ifStmt";
            }
            else if (parent._elseStmt === child) {
                return "elseStmt";
            }
        }
        else if (parent instanceof CaseBlockContext) {
            if (parent._leftCases === child) {
                return "leftCases";
            }
            else if (parent._rightCases === child) {
                return "rightCases";
            }
        }

        return null;
    }
}
