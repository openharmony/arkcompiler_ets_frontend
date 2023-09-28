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
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.ArgumentsContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.ExpressionSequenceContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

import static com.ohos.migrator.apimapper.Util.*;

//  <Arguments> // List of arguments. List of any the following child elements:
//      <SrcArgument index="src.index.value"/>  // The source Argument with the specified index.
//                                             // Any of the possible literals:
//      <Literal type="null OR boolean OR string OR char OR decimal OR hexInteger OR octalInteger OR binaryInteger" value="proper_value"/>
//
//      <!-- Any of the suitable SingleExpressions (see the grammar) which may use source arguments to form the expression: -->
//      <CallExpression/>
//      <UnaryExpression index="src.index.value" operation="- or + or ~ or !"/> // The unary operation applied to the source Argument with the specified index.
//      <BinaryExpression operation="* or + or << or >> or >>> or < or <= or == or >= or > or &amp; or  ^ or | or &amp;&amp; or ||">
//          // The two operands of the operation which could be either:
//          <SrcArgument index="src.index.value"/> // The source Argument with the specified index.
//          // or any of possible literals
//          // or any of the suitable SingleExpressions which may use source arguments to form the expression.
//      </BinaryExpression>
//      <TernaryExpression>
//          // The tree operands which form the TernaryExpression and could be any of:
//          <SrcArgument index="src.index.value"/> // The source Argument with the specified index.
//          // or any of possible literals
//          //or any of the suitable SingleExpressions which may use source arguments to form the expression.
//      </TernaryExpression>
//      <ThisExpression>
//          <TypeReference/>
//      </ThisExpression>
//      <SuperExpression>
//          <TypeReference/>
//      </SuperExpression>
//      <ArrayLiteralExpression>
//          // A sequence of SingleExpressions which could be any of:
//          <SrcArgument index="src.index.value"/> // The source Argument with the specified index.
//          // or any of possible literals
//          // or any of the suitable SingleExpressions which may use source arguments to form the expression.
//      </ArrayLiteralExpression>
//      <CastExpression>
//          // A SingleExpression which could be any of:
//          <IntersectionType/>
//          <PrimaryType/>
//      </CastExpression>
//  </Arguments>

public class Arguments extends  ArrayList<Object> {
    static public String tag = "Arguments";

    static private String tagSrcObject = "SrcObject";

    // The list of arguments. Its elements could be any of:
    //      - Integer - index of the source Argumens list.
    //      - Short - the tail of source Arguments (starting from the specified index) has to be combined in the array.
    //      - Leteral
    //      - CallExpression
    //      - UnaryExpression
    //      - BinaryExpression
    //      - TernaryExpression
    //      - ThisExpression
    //      - SuperExpression
    //      - ArrayLiteralExpression
    //      - CastExpression
    //      - NewClassInstanceExpression

    static public Arguments read(XMLEventReader xmlReader, XMLEvent xmlArgumentsEvent) throws XMLStreamException {
        Arguments arguments = new Arguments();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                // Note: Here is some kind of hack:
                //      Integer <==> SrcArgument
                //  and
                //      Short <==> SrcArgumentsTail
                // It's to don't introduce special classes for these two cases.
                if (tagSrcArgument.equals(tag)) {
                    arguments.add(Integer.valueOf(getAttribute(startElement, indexAttr)));
                }
                else if (tagSrcArgumentsTail.equals(tag)) {
                    arguments.add(Short.valueOf(getAttribute(startElement, indexAttr)));
                }
                // Note: Again a hack: Bool type means the original object has to be used as the argument at current position.
                else if (tagSrcObject.equals(tag)) {
                    arguments.add(Boolean.TRUE);
                }
                else if (Literal.tag.equals(tag)) {
                    arguments.add(Literal.read(xmlReader, xmlEvent));
                }
                else if (CallExpression.tag.equals(tag)) {
                    arguments.add(CallExpression.read(xmlReader, xmlEvent));
                }
                else if (UnaryExpression.tag.equals(tag)) {
                    arguments.add(UnaryExpression.read(xmlReader, xmlEvent));
                }
                else if (BinaryExpression.tag.equals(tag)) {
                    arguments.add(BinaryExpression.read(xmlReader, xmlEvent));
                }
                else if (TernaryExpression.tag.equals(tag)) {
                    arguments.add(TernaryExpression.read(xmlReader, xmlEvent));
                }
                else if (ThisExpression.tag.equals(tag)) {
                    arguments.add(ThisExpression.read(xmlReader, xmlEvent));
                }
                else if (SuperExpression.tag.equals(tag)) {
                    arguments.add(SuperExpression.read(xmlReader, xmlEvent));
                }
                else if (ArrayLiteralExpression.tag.equals(tag)) {
                    arguments.add(ArrayLiteralExpression.read(xmlReader, xmlEvent));
                }
                else if (CastExpression.tag.equals(tag)) {
                    arguments.add(CastExpression.read(xmlReader, xmlEvent));
                }
                else if (NewClassInstanceExpression.tag.equals(tag)) {
                    arguments.add(NewClassInstanceExpression.read(xmlReader));
                }
                else
                    assert false : "Unexpected XmlElement " + tag;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (Arguments.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagSrcArgument.equals(tag) || tagSrcArgumentsTail.equals(tag) || Literal.tag.equals(tag)
                            || CallExpression.tag.equals(tag) || UnaryExpression.tag.equals(tag)
                            || BinaryExpression.tag.equals(tag) || TernaryExpression.tag.equals(tag)
                            || ThisExpression.tag.equals(tag) || SuperExpression.tag.equals(tag)
                            || ArrayLiteralExpression.tag.equals(tag) || CastExpression.tag.equals(tag));
                }
            }
        }

        return arguments;
    }

    public void rebuildArktsNode(SingleExpressionContext arktsOrigObject, ExpressionSequenceContext arktsExpressionSequence, List<TypeArgumentContext> arktsOrigTypeArguments, List<SingleExpressionContext> arktsOrigArguments) {
        arktsExpressionSequence.children.clear();

        for(Object ruleArg : this) {
            if (ruleArg instanceof Integer) { // "SrcArgument"
                int index = (Integer)ruleArg;
                //assert (arktsExpressionSequence.children != null);
                assert (arktsOrigArguments.size() > index);

                //arktsExpressionSequence.children.add(arktsOrigArguments.get(index));
                arktsExpressionSequence.addChild(NodeClonner.clone(arktsOrigArguments.get(index))).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof Short) {
                int startIndex = (Short)ruleArg;
                assert (arktsOrigArguments.size() > startIndex);

                SingleExpressionContext arktsArrayLiteralExprParent = new SingleExpressionContext();
                StaticTSParser.ArrayLiteralExpressionContext arktsArrayLiteralExpr = new StaticTSParser.ArrayLiteralExpressionContext(arktsArrayLiteralExprParent);
                arktsArrayLiteralExprParent.addChild(arktsArrayLiteralExpr).setParent(arktsArrayLiteralExprParent);

                ExpressionSequenceContext arktsExprSequence = new ExpressionSequenceContext(arktsArrayLiteralExpr, 0);
                arktsArrayLiteralExpr.addChild(arktsExprSequence).setParent(arktsArrayLiteralExpr);

                int n = arktsOrigArguments.size();
                for (int i = startIndex; i < n; i++) {
                    // Note: Hack. The parent of original argument node is NOT changed to arktsExprSequence.
                    // If the parent has to be sed then a clones of original nodes will have to be created.
                    arktsExprSequence.addChild(NodeClonner.clone(arktsOrigArguments.get(i))).setParent(arktsExprSequence);
                }

                arktsExpressionSequence.addChild(arktsArrayLiteralExprParent);
            }
            else if (ruleArg instanceof Boolean) {
                assert ((Boolean)ruleArg);
                assert (arktsExpressionSequence.children != null);
                assert (arktsOrigObject != null);
                arktsExpressionSequence.addChild(arktsOrigObject);
            }
            else if (ruleArg instanceof Literal) {
                arktsExpressionSequence.addChild(((Literal)ruleArg).buildArktsNode()).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof CallExpression) {
                arktsExpressionSequence.addChild(((CallExpression)ruleArg).buildArktsNode(arktsOrigObject, arktsOrigTypeArguments, arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof UnaryExpression) {
                arktsExpressionSequence.addChild(((UnaryExpression)ruleArg).buildArktsNode(arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof BinaryExpression) {
                arktsExpressionSequence.addChild(((BinaryExpression)ruleArg).buildArktsNode(arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof TernaryExpression) {
                arktsExpressionSequence.addChild(((TernaryExpression)ruleArg).buildArktsNode(arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof ThisExpression) {
                arktsExpressionSequence.addChild(((ThisExpression)ruleArg).buildArktsNode()).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof SuperExpression) {
                arktsExpressionSequence.addChild(((SuperExpression)ruleArg).buildArktsNode()).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof ArrayLiteralExpression) {
                arktsExpressionSequence.addChild(((ArrayLiteralExpression)ruleArg).buildArktsNode(arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof CastExpression) {
                arktsExpressionSequence.addChild(((CastExpression)ruleArg).buildArktsNode(arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else if (ruleArg instanceof NewClassInstanceExpression) {
                arktsExpressionSequence.addChild(((NewClassInstanceExpression)ruleArg).buildArktsNode(arktsOrigObject, arktsOrigArguments)).setParent(arktsExpressionSequence);
            }
            else
                assert false;
        }
    }

    // arguments: OpenParen expressionSequence? CloseParen
    // expressionSequence: singleExpression (Comma singleExpression)*
    public ArgumentsContext buildArktsNode(SingleExpressionContext arktsOrigObject, List<TypeArgumentContext> arktsOrigTypeArguments, List<SingleExpressionContext> arktsOrigArguments) {
        ArgumentsContext arktsArguments = new ArgumentsContext(null, 0);
        ExpressionSequenceContext arktsExpressionSequence = new ExpressionSequenceContext(arktsArguments, 0);
        arktsExpressionSequence.children = new ArrayList<>();
        arktsArguments.addChild(arktsExpressionSequence).setParent(arktsArguments);

        if (arktsOrigObject != null) {
            rebuildArktsNode(arktsOrigObject, arktsExpressionSequence, arktsOrigTypeArguments, arktsOrigArguments);
        }

        return arktsArguments;
    }
}
