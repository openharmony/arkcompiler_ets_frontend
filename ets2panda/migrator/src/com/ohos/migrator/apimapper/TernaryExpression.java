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

import com.ohos.migrator.staticTS.NodeClonner;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TernaryExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;

import static com.ohos.migrator.apimapper.Util.*;

import org.antlr.v4.runtime.RuleContext;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <TernaryExpression>
//      // The tree operands which form the TernaryExpression and could be any of:
//      <SrcArgument index="src.index.value"/> <!-- The source Argument with the specified index.
//      // or any of possible literals
//      // or any of the suitable SingleExpressions which may use source arguments to form the expression.
//  </TernaryExpression>
public class TernaryExpression {
    static public String tag = "TernaryExpression";

    private Object operand1 = null;
    private Object operand2 = null;
    private Object operand3 = null;

    private void setOperand(Object op) {
        if (operand1 == null) {
            operand1 = op;
        }
        else if (operand2 == null) {
            operand2 = op;
        }
        else {
            assert operand3 == null;
            operand3 = op;
        }
    }

    static TernaryExpression read(XMLEventReader xmlReader, XMLEvent xmlTernaryExpressionEvent) throws XMLStreamException {
        TernaryExpression ternaryExpression = new TernaryExpression();

        assert xmlTernaryExpressionEvent.isStartElement();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagSrcArgument.equals(tag)) {
                    ternaryExpression.setOperand(Integer.valueOf(getAttribute(startElement, indexAttr)));
                }
                else if (Literal.tag.equals(tag)) {
                    ternaryExpression.setOperand(Literal.read(xmlReader, xmlEvent));
                }
                else if (CallExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(CallExpression.read(xmlReader, xmlEvent));
                }
                else if (UnaryExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(UnaryExpression.read(xmlReader, xmlEvent));
                }
                else if (BinaryExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(BinaryExpression.read(xmlReader, xmlEvent));
                }
                else if (TernaryExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(TernaryExpression.read(xmlReader, xmlEvent));
                }
                else if (ThisExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(ThisExpression.read(xmlReader, xmlEvent));
                }
                else if (SuperExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(SuperExpression.read(xmlReader, xmlEvent));
                }
                else if (ArrayLiteralExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(ArrayLiteralExpression.read(xmlReader, xmlEvent));
                }
                else if (CastExpression.tag.equals(tag)) {
                    ternaryExpression.setOperand(CastExpression.read(xmlReader, xmlEvent));
                }
                else {
                    assert false;
                }
            }
            else  if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (TernaryExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagSrcArgument.equals(tag)|| Literal.tag.equals(tag) || CallExpression.tag.equals(tag)
                            || UnaryExpression.tag.equals(tag) || BinaryExpression.tag.equals(tag)
                            || TernaryExpression.tag.equals(tag) || ThisExpression.tag.equals(tag)
                            || SuperExpression.tag.equals(tag) || ArrayLiteralExpression.tag.equals(tag)
                            || CastExpression.tag.equals(tag));
                }
            }
        }

        return ternaryExpression;
    }

    private RuleContext buildOperandArktsNode(Object operand, List<SingleExpressionContext> arktsOrigArguments) {
        SingleExpressionContext arktsResultNode = null;

        if (operand instanceof Integer) {
            int index = (Integer)operand;
            assert (arktsOrigArguments != null);
            assert (index >= 0 && index < arktsOrigArguments.size());
            //return (RuleContext)arktsOrigArguments.get(index);
            return NodeClonner.clone(arktsOrigArguments.get(index));
        }
        else if (operand instanceof Literal) {
            return ((Literal)operand).buildArktsNode();
        }
        else if (operand instanceof CallExpression) {
            return ((CallExpression)operand).buildArktsNode(null, null, arktsOrigArguments);
        }
        else if (operand instanceof UnaryExpression) {
            return ((UnaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof BinaryExpression) {
            return ((BinaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof TernaryExpression) {
            return ((TernaryExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof ThisExpression) {
            return ((ThisExpression)operand).buildArktsNode();
        }
        else if (operand instanceof SuperExpression) {
            return ((SuperExpression)operand).buildArktsNode();
        }
        else if (operand instanceof ArrayLiteralExpression) {
            return ((ArrayLiteralExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else if (operand instanceof CastExpression) {
            return ((CastExpression)operand).buildArktsNode(arktsOrigArguments);
        }
        else {
            assert false;
        }

        return arktsResultNode;
    }
    public SingleExpressionContext buildArktsNode(List<SingleExpressionContext> arktsOrigArguments) {
        SingleExpressionContext arktsTernaryExprParent = new SingleExpressionContext();
        TernaryExpressionContext arktsTernaryExpr = new TernaryExpressionContext(arktsTernaryExprParent);

        arktsTernaryExpr.addChild(buildOperandArktsNode(operand1, arktsOrigArguments)).setParent(arktsTernaryExpr);
        arktsTernaryExpr.addChild(buildOperandArktsNode(operand2, arktsOrigArguments)).setParent(arktsTernaryExpr);
        arktsTernaryExpr.addChild(buildOperandArktsNode(operand3, arktsOrigArguments)).setParent(arktsTernaryExpr);

        arktsTernaryExprParent.addChild(arktsTernaryExpr).setParent(arktsTernaryExprParent);

        return arktsTernaryExprParent;
    }
}
