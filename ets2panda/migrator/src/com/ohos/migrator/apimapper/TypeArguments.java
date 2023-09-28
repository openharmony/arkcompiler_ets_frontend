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
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentsContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentListContext;

import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

//  <TypeArguments>
//      <SrcTypeArgument index="src.index.value"/> <!-- The source TypeArgument with the specified index. -->
//      <TypeReference arktsName="arkts.qualified.name">
//          <TypeArguments>         // Optional type arguments. Any sequence of children of following types:
//              <TypeReference/>
//              <ArrayType/>        // Look below for the structure of arrayType element.
//              <WildcardType/>     // Look below for the structure of wildcardType element.
//          </TypeArguments>
//      </TypeReference>
//      <ArrayType>
//          <PredefinedType name="Byte | Short | Int | Long | Float | Double | Boolean | String | Char| Void"/>
//          // or
//          <TypeReference/>        // Look above for the structure of typeReference element.
//      <ArrayType/>
//      <WildcardType>
//          <WildcardBound type="extends of super"> // Optional. If not specified then only a question mark will be used as the wildcard type.
//              <TypeReference/>    // Look above for the structure of typeReference element.
//          </WildcardBound>
//      </WildcardType>
//  </TypeArguments>
public class TypeArguments {
    static public String tag = "TypeArguments";

    // The list of arguments. Its elements could be any of:
    //      - Integer - index of the source TypeArgumens list.
    //      - TypeReference
    //      - ArrayType
    //      - WildcardType
    private List<Object> arguments = new ArrayList<>();

    static public TypeArguments read(XMLEventReader xmlReader) throws XMLStreamException {
        TypeArguments typeArguments = new TypeArguments();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagSrcTypeArgument.equals(tag)) {
                    typeArguments.arguments.add(Integer.valueOf(getAttribute(startElement, indexAttr)));
                }
                else if (TypeReference.tag.equals(tag)) {
                    typeArguments.arguments.add(TypeReference.read(xmlReader, xmlEvent));
                }
                else if (ArrayType.tag.equals(tag)) {
                    typeArguments.arguments.add(ArrayType.read(xmlReader));
                }
                else if (WildcardType.tag.equals(tag)) {
                    typeArguments.arguments.add(WildcardType.read(xmlReader, xmlEvent));
                }
                else assert false;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (TypeArguments.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagSrcTypeArgument.equals(tag) || TypeReference.tag.equals(tag) || ArrayType.tag.equals(tag)
                            || WildcardType.tag.equals(tag));
                }
            }
        }

        return typeArguments;
    }

    // ArkTS Tree:
    //    typeArguments: LessThan typeArgumentList? MoreThan
    //    typeArgumentList: typeArgument (Comma typeArgument)*
    //    typeArgument: typeReference | arrayType | wildcardType
    public TypeArgumentsContext buildArktsNode(List<TypeArgumentContext> origArktsTypeArgsList) {//{List<Type> javaTypeArgs) {
        TypeArgumentsContext arktsTypeArguments = new TypeArgumentsContext(null, 0);

        TypeArgumentListContext arktsTypeArgumentList = new TypeArgumentListContext(arktsTypeArguments, 0);
        arktsTypeArguments.addChild(arktsTypeArgumentList);

        for (Object arg : arguments) {
            TypeArgumentContext arktsTypeArgument = new TypeArgumentContext(null, 0);
            arktsTypeArgumentList.addChild(arktsTypeArgument).setParent(arktsTypeArgumentList);

            if (arg instanceof Integer) {
                assert (origArktsTypeArgsList != null);
                Integer index = (Integer)arg;
                //arktsTypeArgument.children.add(origArktsTypeArgsList.get(index));
                arktsTypeArgument.addChild(NodeClonner.clone(origArktsTypeArgsList.get(index))).setParent(arktsTypeArgument);
            }
            else if (arg instanceof TypeReference) {
                arktsTypeArgument.addChild(((TypeReference)arg).buildArktsNode(origArktsTypeArgsList)).setParent(arktsTypeArgument);
            }
            else if (arg instanceof ArrayType) {
                arktsTypeArgument.addChild(((ArrayType)arg).buildArktsNode(origArktsTypeArgsList)).setParent(arktsTypeArgument);
            }
            else if (arg instanceof WildcardType) {
                arktsTypeArgument.addChild(((WildcardType)arg).buildArktsNode(origArktsTypeArgsList)).setParent(arktsTypeArgument);
            }
            else
                assert false;
        }

        return arktsTypeArguments;
    }

}
