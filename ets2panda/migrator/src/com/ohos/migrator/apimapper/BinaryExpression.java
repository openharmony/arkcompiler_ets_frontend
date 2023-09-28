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

package com.ohos.migrator.apimapper;

import com.ohos.migrator.java.NodeBuilder;
import com.ohos.migrator.staticTS.NodeClonner;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.MultiplicativeExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.AdditiveExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.BitShiftExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.RelationalExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.EqualityExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.BitAndExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.BitXOrExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.BitOrExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.LogicalAndExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.LogicalOrExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.ShiftOperatorContext;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;

import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <BinaryExpression operation="* OR / OR % OR + OR - OR << OR >> OR >>> OR < OR <= OR == OR != OR >= OR > OR & OR  ^ OR | OR && OR ||">
//      // The two operands of the operation which could be either:
//      <SrcArgument index="src.index.value"/> // The source Argument with the specified index.
//      // or any of possible literals
//      // or any of the suitable SingleExpressions which may use source arguments to form the expression.
//  </BinaryExpression>
public class BinaryExpression {
    static public String tag = "BinaryExpression";
    private enum Operation {
        MULTIPLY, DIVIDE, REMAINDER, PLUS, MINUS, SHIFT_LEFT, SHIFT_RIGHT, UNSIGN_SHIFT_RIGH, LESS, LESS_EQUAL, EQUAL, NOT_EQUAL,
        MORE_EQUAL, MORE, BIT_AND, BIT_XOR, BIT_OR, AND, OR
    }

    private Object operand1 = null;
    private Object operand2 = null;
    private Operation operation;

    private void setOperand(Object op) {
        if (operand1 == null) {
            operand1 = op;
        }
        else {
            assert operand2 == null;
            operand2 = op;
        }
    }

    static BinaryExpression read(XMLEventReader xmlReader, XMLEvent xmlBinaryExpressionEvent) throws XMLStreamException {
        BinaryExpression binaryExpression = new BinaryExpression();

        assert xmlBinaryExpressionEvent.isStartElement();
        StartElement startBinaryExpressionElement = xmlBinaryExpressionEvent.asStartElement();

        String op = getAttribute(startBinaryExpressionElement, operationAttr);

        if ("*".equals(op)) {
            binaryExpression.operation = Operation.MULTIPLY;
        }
        else if ("/".equals(op)) {
            binaryExpression.operation = Operation.DIVIDE;
        } else if ("%".equals(op)) {
            binaryExpression.operation = Operation.REMAINDER;
        } else if ("+".equals(op)) {
            binaryExpression.operation = Operation.PLUS;
        } else if ("-".equals(op)) {
            binaryExpression.operation = Operation.MINUS;
        } else if ("<<".equals(op)) {
            binaryExpression.operation = Operation.SHIFT_LEFT;
        } else if (">>".equals(op)) {
            binaryExpression.operation = Operation.SHIFT_RIGHT;
        } else if (">>>".equals(op)) {
            binaryExpression.operation = Operation.UNSIGN_SHIFT_RIGH;
        } else if ("<".equals(op)) {
            binaryExpression.operation = Operation.LESS;
        } else if ("<=".equals(op)) {
            binaryExpression.operation = Operation.LESS_EQUAL;
        } else if ("==".equals(op)) {
            binaryExpression.operation = Operation.EQUAL;
        } else if ("!=".equals(op)) {
            binaryExpression.operation = Operation.NOT_EQUAL;
        } else if (">=".equals(op)) {
            binaryExpression.operation = Operation.MORE_EQUAL;
        } else if (">".equals(op)) {
            binaryExpression.operation = Operation.MORE;
        } else if ("&".equals(op)) {
            binaryExpression.operation = Operation.BIT_AND;
        } else if ("^".equals(op)) {
            binaryExpression.operation = Operation.BIT_XOR;
        } else if ("|".equals(op)) {
            binaryExpression.operation = Operation.BIT_OR;
        } else if ("&&".equals(op)) {
            binaryExpression.operation = Operation.AND;
        } else if ("||".equals(op)) {
            binaryExpression.operation = Operation.OR;
        } else {
            assert false;
        }

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagSrcArgument.equals(tag)) {
                    binaryExpression.setOperand(Integer.valueOf(getAttribute(startElement, indexAttr)));
                }
                else if (Literal.tag.equals(tag)) {
                    binaryExpression.setOperand(Literal.read(xmlReader, xmlEvent));
                }
                else if (CallExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(CallExpression.read(xmlReader, xmlEvent));
                }
                else if (UnaryExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(UnaryExpression.read(xmlReader, xmlEvent));
                }
                else if (BinaryExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(BinaryExpression.read(xmlReader, xmlEvent));
                }
                else if (TernaryExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(TernaryExpression.read(xmlReader, xmlEvent));
                }
                else if (ThisExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(ThisExpression.read(xmlReader, xmlEvent));
                }
                else if (SuperExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(SuperExpression.read(xmlReader, xmlEvent));
                }
                else if (ArrayLiteralExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(ArrayLiteralExpression.read(xmlReader, xmlEvent));
                }
                else if (CastExpression.tag.equals(tag)) {
                    binaryExpression.setOperand(CastExpression.read(xmlReader, xmlEvent));
                }
                else
                    assert false;
            }
            else  if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (BinaryExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagSrcArgument.equals(tag) || Literal.tag.equals(tag) || CallExpression.tag.equals(tag)
                            || UnaryExpression.tag.equals(tag) || BinaryExpression.tag.equals(tag)
                            || TernaryExpression.tag.equals(tag) || ThisExpression.tag.equals(tag)
                            || SuperExpression.tag.equals(tag) || ArrayLiteralExpression.tag.equals(tag)
                            || CastExpression.tag.equals(tag));
                }
            }
        }

        return binaryExpression;
    }

    static private ParserRuleContext buildArktsOperandNode(Object operand, List<SingleExpressionContext> arktsOrigArguments) {
        ParserRuleContext arktsOperand = null;

        if (operand instanceof Integer) {
            int index = (Integer)operand;
            assert (arktsOrigArguments != null);
            assert (arktsOrigArguments.size() > index);

            //arktsOperand = (ParserRuleContext)arktsOrigArguments.get(index);
            arktsOperand = NodeClonner.clone(arktsOrigArguments.get(index));
        }
        else if (operand instanceof Literal) {
            arktsOperand = ((Literal)operand).buildArktsNode();
        }
        else if (operand instanceof CallExpression) {
            arktsOperand = ((CallExpression)operand).buildArktsNode(null, null, arktsOrigArguments);
        }
        else if (operand instanceof UnaryExpression) {
            arktsOperand = ((UnaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof BinaryExpression) {
            arktsOperand = ((BinaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof TernaryExpression) {
            arktsOperand = ((TernaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof ThisExpression) {
            arktsOperand = ((ThisExpression)operand).buildArktsNode();
        }
        else if (operand instanceof SuperExpression) {
            arktsOperand = ((SuperExpression)operand).buildArktsNode();
        }
        else if (operand instanceof ArrayLiteralExpression) {
            arktsOperand = ((ArrayLiteralExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof CastExpression) {
            arktsOperand = ((CastExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else
            assert false;

        return arktsOperand;
    }

    private ShiftOperatorContext shiftOperator() {
        StaticTSParser.ShiftOperatorContext arktsShiftOp = new StaticTSParser.ShiftOperatorContext(null, 0);

        if (operation == Operation.SHIFT_LEFT) {
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.LessThan));
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.LessThan));
        }
        else if (operation == Operation.SHIFT_RIGHT) {
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
        }
        else if (operation == Operation.UNSIGN_SHIFT_RIGH) {
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
            arktsShiftOp.addChild(NodeBuilder.terminalNode(StaticTSParser.MoreThan));
        }

        return arktsShiftOp;
    }

    private int arktsOperatorType() {
        int arktsOperator = -1;

        if (operation == Operation.MULTIPLY) arktsOperator = StaticTSParser.Multiply;
        else if (operation == Operation.DIVIDE) arktsOperator = StaticTSParser.Divide;
        else if (operation == Operation.REMAINDER) arktsOperator = StaticTSParser.Modulus;
        else if (operation == Operation.PLUS) arktsOperator = StaticTSParser.Plus;
        else if (operation == Operation.MINUS) arktsOperator = StaticTSParser.Minus;
        else if (operation == Operation.LESS) arktsOperator = StaticTSParser.LessThan;
        else if (operation == Operation.MORE) arktsOperator = StaticTSParser.MoreThan;
        else if (operation == Operation.LESS_EQUAL) arktsOperator = StaticTSParser.LessThanEquals;
        else if (operation == Operation.MORE_EQUAL) arktsOperator = StaticTSParser.GreaterThanEquals;
        else if (operation == Operation.EQUAL) arktsOperator = StaticTSParser.Equals;
        else if (operation == Operation.NOT_EQUAL) arktsOperator = StaticTSParser.NotEquals;
        else if (operation == Operation.AND) arktsOperator = StaticTSParser.BitAnd;
        else if (operation == Operation.BIT_XOR) arktsOperator = StaticTSParser.BitXor;
        else if (operation == Operation.OR) arktsOperator = StaticTSParser.BitOr;
        else if (operation == Operation.AND) arktsOperator = StaticTSParser.And;
        else if (operation == Operation.OR) arktsOperator = StaticTSParser.Or;

        assert(arktsOperator != -1);

        return arktsOperator;
    }

    private ParseTree createArktsInfixOperator() {
        if (operation == Operation.SHIFT_LEFT || operation == Operation.SHIFT_RIGHT || operation == Operation.UNSIGN_SHIFT_RIGH)
            return shiftOperator();
        else
            return NodeBuilder.terminalNode(arktsOperatorType());
    }

    public SingleExpressionContext buildArktsNode(List<SingleExpressionContext> arktsOrigArguments) {
        SingleExpressionContext arktsBinExprParent = new SingleExpressionContext();
        SingleExpressionContext arktsBinExpr = null;

        switch (operation) {
            case MULTIPLY:
                arktsBinExpr = new MultiplicativeExpressionContext(arktsBinExprParent);
                break;

            case DIVIDE:
                arktsBinExpr = new MultiplicativeExpressionContext(arktsBinExprParent);
                break;

            case PLUS:
                arktsBinExpr = new AdditiveExpressionContext(arktsBinExprParent);
                break;

            case MINUS:
                arktsBinExpr = new AdditiveExpressionContext(arktsBinExprParent);
                break;

            case SHIFT_LEFT:
                arktsBinExpr = new BitShiftExpressionContext(arktsBinExprParent);
                break;

            case SHIFT_RIGHT:
                arktsBinExpr = new BitShiftExpressionContext(arktsBinExprParent);
                break;

            case UNSIGN_SHIFT_RIGH:
                arktsBinExpr = new BitShiftExpressionContext(arktsBinExprParent);
                break;

            case LESS:
                arktsBinExpr = new RelationalExpressionContext(arktsBinExprParent);
                break;

            case LESS_EQUAL:
                arktsBinExpr = new RelationalExpressionContext(arktsBinExprParent);
                break;

            case EQUAL:
                arktsBinExpr = new EqualityExpressionContext(arktsBinExprParent);
                break;

            case NOT_EQUAL:
                arktsBinExpr = new EqualityExpressionContext(arktsBinExprParent);
                break;

            case MORE_EQUAL:
                arktsBinExpr = new RelationalExpressionContext(arktsBinExprParent);
                break;

            case MORE:
                arktsBinExpr = new RelationalExpressionContext(arktsBinExprParent);
                break;

            case BIT_AND:
                arktsBinExpr = new BitAndExpressionContext(arktsBinExprParent);
                break;

            case BIT_XOR:
                arktsBinExpr = new BitXOrExpressionContext(arktsBinExprParent);
                break;

            case BIT_OR:
                arktsBinExpr = new BitOrExpressionContext(arktsBinExprParent);
                break;

            case AND:
                arktsBinExpr = new LogicalAndExpressionContext(arktsBinExprParent);
                break;

            case OR:
                arktsBinExpr = new LogicalOrExpressionContext(arktsBinExprParent);
                break;
        }

        arktsBinExpr.addChild(buildArktsOperandNode(operand1, arktsOrigArguments)).setParent(arktsBinExpr);
        arktsBinExpr.addAnyChild(createArktsInfixOperator()).setParent(arktsBinExpr);
        arktsBinExpr.addChild(buildArktsOperandNode(operand2, arktsOrigArguments)).setParent(arktsBinExpr);

        assert (arktsBinExpr != null);
        arktsBinExprParent.addChild(arktsBinExpr).setParent(arktsBinExprParent);

        return arktsBinExprParent;
    }
}
