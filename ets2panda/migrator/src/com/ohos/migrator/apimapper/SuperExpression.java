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
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

//  <SuperExpression>
//      <!-- | (typeReference Dot)? Super  # SuperExpression -->
//      <TypeReference/> // Optional
//  </SuperExpression>
public class SuperExpression {
    static public String tag = "SuperExpression";

    private TypeReference typeReference = null;

    static SuperExpression read(XMLEventReader xmlReader, XMLEvent xmlThisExpressionEvent) throws XMLStreamException {
        SuperExpression superExpression = new SuperExpression();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (TypeReference.tag.equals(tag)) {
                    superExpression.typeReference = TypeReference.read(xmlReader, xmlEvent);
                }
                else {
                    assert false;
                }
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (SuperExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (TypeReference.tag.equals(tag));
                }
            }
        }

        return superExpression;
    }

    public SingleExpressionContext buildArktsNode() {
        return NodeBuilder.superExpression(typeReference.buildArktsNode(null));
    }
}
