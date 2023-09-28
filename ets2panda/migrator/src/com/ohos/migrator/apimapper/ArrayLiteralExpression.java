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
import com.ohos.migrator.staticTS.parser.StaticTSParser.ExpressionSequenceContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.ArrayLiteralExpressionContext;

import static com.ohos.migrator.apimapper.Util.getAttribute;
import static com.ohos.migrator.apimapper.Util.indexAttr;
import static com.ohos.migrator.apimapper.Util.tagSrcArgument;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

//  <ArrayLiteralExpression>
//      // A sequence of SingleExpressions which could be any of:
//      <SrcArgument index="src.index.value"/> <!-- The source Argument with the specified index. -->
//      // or any of possible literals
//      // or any of the suitable SingleExpressions which may use source arguments to form the expression.
//  </ArrayLiteralExpression>
public class ArrayLiteralExpression extends ArrayList<Object> {
    static public String tag = "ArrayLiteralExpression";

    private List<Object> elemsnts = new ArrayList<>();

    static ArrayLiteralExpression read(XMLEventReader xmlReader, XMLEvent xmlArrayLiteralExpressionEvent) throws XMLStreamException {
        ArrayLiteralExpression arrayLiteral = new ArrayLiteralExpression();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagSrcArgument.equals(tag)) {
                    arrayLiteral.elemsnts.add(Integer.valueOf(getAttribute(startElement, indexAttr)));
                }
                else if (Literal.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(Literal.read(xmlReader, xmlEvent));
                }
                else if (CallExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(CallExpression.read(xmlReader, xmlEvent));
                }
                else if (UnaryExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(UnaryExpression.read(xmlReader, xmlEvent));
                }
                else if (BinaryExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(BinaryExpression.read(xmlReader, xmlEvent));
                }
                else if (TernaryExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(TernaryExpression.read(xmlReader, xmlEvent));
                }
                else if (ThisExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(ThisExpression.read(xmlReader, xmlEvent));
                }
                else if (SuperExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(SuperExpression.read(xmlReader, xmlEvent));
                }
                else if (ArrayLiteralExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(ArrayLiteralExpression.read(xmlReader, xmlEvent));
                }
                else if (CastExpression.tag.equals(tag)) {
                    arrayLiteral.elemsnts.add(CastExpression.read(xmlReader, xmlEvent));
                }
                else
                    assert false;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (ArrayLiteralExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert(tagSrcArgument.equals(tag) || Literal.tag.equals(tag) || CallExpression.tag.equals(tag)
                        || UnaryExpression.tag.equals(tag) || BinaryExpression.tag.equals(tag)
                        || TernaryExpression.tag.equals(tag) || ThisExpression.tag.equals(tag)
                        || SuperExpression.tag.equals(tag) || ArrayLiteralExpression.tag.equals(tag)
                        || CastExpression.tag.equals(tag));
                }
            }
        }

        return arrayLiteral;
    }

    public SingleExpressionContext buildArktsNode(List<SingleExpressionContext> arktsOrigArguments) {
        SingleExpressionContext arktsArrayLiteralExprParent = new SingleExpressionContext();
        ArrayLiteralExpressionContext arktsArrayLiteralExpr = new ArrayLiteralExpressionContext(arktsArrayLiteralExprParent);
        arktsArrayLiteralExprParent.addChild(arktsArrayLiteralExpr).setParent(arktsArrayLiteralExprParent);

        ExpressionSequenceContext arktsExprSequence = new ExpressionSequenceContext(arktsArrayLiteralExpr, 0);
        arktsArrayLiteralExpr.addChild(arktsExprSequence).setParent(arktsArrayLiteralExpr);

        for (Object element : elemsnts) {
            if (element instanceof Integer) {
                arktsExprSequence.addChild(NodeClonner.clone(arktsOrigArguments.get((Integer)element))).setParent(arktsExprSequence);
            }
            else if (element instanceof Literal) {
                arktsExprSequence.addChild(((Literal)element).buildArktsNode()).setParent(arktsExprSequence);
            }
            else if (element instanceof CallExpression) {
                arktsExprSequence.addChild(((CallExpression)element).buildArktsNode(null, null, arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else if (element instanceof UnaryExpression) {
                arktsExprSequence.addChild(((UnaryExpression)element).buildArktsNode(arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else if (element instanceof BinaryExpression) {
                arktsExprSequence.addChild(((BinaryExpression)element).buildArktsNode(arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else if (element instanceof TernaryExpression) {
                arktsExprSequence.addChild(((TernaryExpression)element).buildArktsNode(arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else if (element instanceof ThisExpression) {
                arktsExprSequence.addChild(((ThisExpression)element).buildArktsNode()).setParent(arktsExprSequence);
            }
            else if (element instanceof SuperExpression) {
                arktsExprSequence.addChild(((SuperExpression)element).buildArktsNode()).setParent(arktsExprSequence);
            }
            else if (element instanceof ArrayLiteralExpression) {
                arktsExprSequence.addChild(((ArrayLiteralExpression)element).buildArktsNode(arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else if (element instanceof CastExpression) {
                arktsExprSequence.addChild(((CastExpression)element).buildArktsNode(arktsOrigArguments)).setParent(arktsExprSequence);
            }
            else
                assert false;
        }

        return arktsArrayLiteralExprParent;
    }
}
