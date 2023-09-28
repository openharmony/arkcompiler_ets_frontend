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
import com.ohos.migrator.staticTS.parser.StaticTSParser.CastExpressionContext;

import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <CastExpression>
//      // | singleExpression As (intersectionType | primaryType) # CastExpression
//      <SrcArgument index="0"/>
//      <IntersectionType/>
//      <PrimaryType/>
//  </CastExpression>
public class CastExpression {
    static public String tag = "CastExpression";

    private int index;
    private PrimaryType primaryType = null;
    private IntersectionType intersectionType = null;

    static CastExpression read(XMLEventReader xmlReader, XMLEvent xmlCastExpressionEvent) throws XMLStreamException {
        CastExpression castExpression = new CastExpression();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagSrcArgument.equals(tag)) {
                    castExpression.index = Integer.valueOf(getAttribute(startElement, indexAttr));
                }
                else if (PrimaryType.tag.equals(tag)) {
                    castExpression.primaryType = PrimaryType.read(xmlReader);
                }
                else if (IntersectionType.tag.equals(tag)) {
                    castExpression.intersectionType = IntersectionType.read(xmlReader, xmlEvent);
                }
                else
                    assert false : "Unexpected XmlElement " + tag;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (CastExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagSrcArgument.equals(tag) || PrimaryType.tag.equals(tag) || IntersectionType.tag.equals(tag));
                }
            }
        }

        return castExpression;
    }

    public SingleExpressionContext buildArktsNode(List<SingleExpressionContext> arktsOrigArguments) {
        assert (arktsOrigArguments != null);
        assert (index >= 0 && arktsOrigArguments.size() > index);

        SingleExpressionContext arktsCastExprParent = new SingleExpressionContext();
        CastExpressionContext arktsCastExpr = new CastExpressionContext(arktsCastExprParent);
        arktsCastExprParent.addChild(arktsCastExpr).setParent(arktsCastExprParent);

        //arktsCastExpr.addChild(arktsOrigArguments.get(index));
        arktsCastExpr.addChild(NodeClonner.clone(arktsOrigArguments.get(index))).setParent(arktsCastExpr);
        arktsCastExpr.addChild(NodeBuilder.terminalNode(StaticTSParser.As));

        if (primaryType != null ) {
            arktsCastExpr.addChild(primaryType.buildArktsNode());
        }
        else {
            assert (intersectionType != null);
            arktsCastExpr.addChild(intersectionType.buildArktsNode());
        }

        return arktsCastExprParent;
    }
}
