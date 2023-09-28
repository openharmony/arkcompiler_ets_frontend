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

import com.ohos.migrator.apimapper.*;
import com.ohos.migrator.staticTS.NodeBuilderBase;
import com.ohos.migrator.staticTS.NodeClonner;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;

import com.ohos.migrator.staticTS.parser.StaticTSParserBaseVisitor;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;

import static com.ohos.migrator.apimapper.Util.*;


public class JavaApiMapper extends StaticTSParserBaseVisitor<Void> {
    static private StringBuilder sb = new StringBuilder();

    static private QName javaMethodNameAttr = new QName("javaMethodName");
    static public QName javaTypeAttr = new QName("javaType");
    static public QName javaTypeArgsAttr = new QName("javaTypeArgs");
    static public QName javaMethodTypeArgsAttr = new QName("javaMethodTypeArgs");
    static public QName javaMethodArgsAttr = new QName("javaMethodArgs");
    static public QName javaImportAttr = new QName("javaImport");

    //  <ImportDeclarationRule javaImport="imported.name.one" action="remove" />
    // or
    //  <ImportDeclarationRule javaImport="imported.name.two" action="replace">
    //      <ImportDeclaration arktsItem="item" arktsFrom="path"/>
    //      // ...
    //  </ImportDeclarationRule>
    static private class ImportDeclarationRule {
        static public String tag = "ImportDeclarationRule";
        private String javaImport = null;
        private List<String> arktsItems = null;
        private List<String> arktsAliases = null;
        private List<String> arktsFromPaths = null;

        // ArkTS:
        // importDeclaration: Import importBinding (Comma importBinding)* Comma? From StringLiteral SemiColon?
        // importBinding: (Multiply | qualifiedName (Dot Multiply)?) (As Identifier)?
        private void addNewImports(ParserRuleContext arktsParent, int position) {
            assert (arktsItems != null && arktsFromPaths != null);
            assert (arktsItems.size() == arktsFromPaths.size());

            int n = arktsItems.size();

            for (int i = 0; i < n; i++) {
                String arktsItem = arktsItems.get(i);
                String arktsAlias = arktsAliases.get(i); // It may be null.
                String arktsFromPath = arktsFromPaths.get(i);
                ImportDeclarationContext arktsImportDeclaration = new ImportDeclarationContext(arktsParent, 0);
                arktsImportDeclaration.addChild(NodeBuilderBase.terminalNode(StaticTSParser.Import));

                ImportBindingContext arktsImportBinding = new ImportBindingContext(arktsImportDeclaration, 0);
                arktsImportBinding.addChild(NodeBuilderBase.qualifiedName(arktsItem)).setParent(arktsImportBinding);

                if (arktsAlias != null) {
                    arktsImportBinding.addChild(NodeBuilderBase.terminalNode(StaticTSParser.As));
                    arktsImportBinding.addChild(NodeBuilderBase.terminalIdentifier(arktsAlias));
                }

                arktsImportDeclaration.addChild(arktsImportBinding).setParent(arktsImportDeclaration);

                arktsImportDeclaration.addChild(NodeBuilderBase.terminalIdentifier(StaticTSParser.FROM));
                arktsImportDeclaration.addChild(NodeBuilderBase.terminalNode(StaticTSParser.StringLiteral, arktsFromPath));

                // Add the new nodes in place of the removed one.
                if (arktsParent.getChildCount() > 0)
                    arktsParent.children.add(position, arktsImportDeclaration);
                else
                    arktsParent.addChild(arktsImportDeclaration);

                arktsImportDeclaration.setParent(arktsParent);
            }
        }

        public void apply(ImportDeclarationContext arktsImportDeclaration) {
            assert (arktsImportDeclaration.parent instanceof ParserRuleContext);
            ParserRuleContext arktsParent = (ParserRuleContext) arktsImportDeclaration.parent;

            assert (arktsParent.children != null);
            int position = arktsParent.children.indexOf(arktsImportDeclaration);
            // The current importDeclaraion has to be removed in any case.
            arktsParent.children.remove(arktsImportDeclaration);

            if (arktsItems != null && arktsFromPaths != null) {
                addNewImports(arktsParent, position);
            }
        }

        public void apply(CompilationUnitContext arktsCompilationUnit) {
            ImportDeclarationContext arktsImportFirst = arktsCompilationUnit.importDeclaration(0);
            int position = (arktsImportFirst != null) ? arktsCompilationUnit.children.indexOf(arktsImportFirst) : 0;

            addNewImports(arktsCompilationUnit, position);
        }

        static public String signature(ImportDeclarationContext arktsImportDeclatation) {
            return arktsImportDeclatation.javaImport;
        }

        public String signature(StartElement importDeclarationElement) {
            javaImport = getAttribute(importDeclarationElement, javaImportAttr);
            return javaImport;
        }

        static ImportDeclarationRule read(XMLEventReader xmlReader, XMLEvent xmlImportDeclarationRuleEvent, StartElement ruleStartElement) throws XMLStreamException {
            ImportDeclarationRule rule = new ImportDeclarationRule();

            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    assert "ImportDeclaration".equals(startElement.getName().getLocalPart()) : "<ImportDeclarationRule> may has only <ImportDeclaration> child";
                    String arktsItem = getAttribute(startElement, arktsItemAttr);
                    String arktsAlias = getAttribute(startElement, arktsAliasAttr); // It may be null, and it's a valid case.
                    String arktsFrom = getAttribute(startElement, arktsFromAttr);
                    assert (arktsItem != null && arktsFrom != null);

                    if (rule.arktsItems == null) {
                        assert (rule.arktsFromPaths == null);
                        assert (rule.arktsAliases == null);
                        rule.arktsItems = new ArrayList<>();
                        rule.arktsAliases = new ArrayList<>();
                        rule.arktsFromPaths = new ArrayList<>();
                    }

                    rule.arktsItems.add(arktsItem);
                    rule.arktsAliases.add(arktsAlias);
                    rule.arktsFromPaths.add(arktsFrom);
                }
                else if (xmlEvent.isEndElement()) {
                    // It has to be either <ImportDeclaration/> or <ImportDeclarationRule/>
                    EndElement endElement = xmlEvent.asEndElement();
                    if (ImportDeclarationRule.tag.equals(endElement.getName().getLocalPart())) {
                        break;
                    }
                    else {
                        // Just eat EndElement for <ImportDeclaration/> element.
                        assert "ImportDeclaration".equals(endElement.getName().getLocalPart());
                    }
                }
            }

            return rule;
        }
    }

    static private void renameIdentifier(IdentifierExpressionContext arktsIdentifier, String arktsNewName) {
        arktsIdentifier.children.clear();
        arktsIdentifier.addChild(NodeBuilderBase.terminalIdentifier(arktsNewName));
    }

    //  <CallExpressionRule javaObjectType="java.object.type"  javaObjectTypeArgs="list.of.java.types" javaMethodName="methodName" javaMethodTypeArgs="list.of.java.types" javaMethodArgs="list.of.java.types">
    //     <ArktsTypeName value="arktsTypeName"/>      // Optional qualified name of ArkTS class or interface for a static
    //                                                 // method call. If the method is a static one then it should be called
    //                                                 // via qualified name of the class or interface. The class/interface in ArkTS may change.
    //     <ArktsMethodName value="arktsMethodName"/>  //Optional method rename. If it's not specified then the method name remains.
    //     <TypeArguments/>                            // Optional list of new type arguments. If it's not specified then
    //                                                 // the current type arguments remain.
    //     <Arguments/>                                // Optional new list of arguments. If it's not specified then
    //                                                 // the current arguments remain.
    //    </CallExpressionRule>
    static private class CallExpressionRule {
        static public String tag = "CallExpressionRule";

        private JavaApiMapper mapper = null; // It is needed for recursive iteration over the subtree.

        private String dstArktsTypeName = null;
        // ArktsObject may be:
        //   either of type NewClassInstanceExpression
        //   or of type Integer - index of source argument which should be used as the object whose method has to be called.
        private Object dstArktsObject = null;
        private String dstArktsMethodName = null;
        private TypeArguments dstArktsObjectTypeArgs = null;
        private TypeArguments dstArktsMethodTypeArgs = null;
        private Arguments dstArguments = null;

        static private String tagArktsTypeName = "ArktsTypeName";
        static private String tagArktsObject = "ArktsObject";
        static private String tagArktsMethodName = "ArktsMethodName";
        static private String tagArktsObjectTypeArgs = "ArktsObjectTypeArgs";
        static private String tagArktsMethodTypeArgs = "ArktsMethodTypeArgs";

        public CallExpressionRule(JavaApiMapper mapper) {
            this.mapper = mapper;
        }

        private void renameMethod(SingleExpressionContext arktsMethodExpression) {
            if (arktsMethodExpression instanceof IdentifierExpressionContext) {
                assert (isStringEmpty(dstArktsTypeName));
                renameIdentifier((IdentifierExpressionContext)arktsMethodExpression, dstArktsMethodName);
            }
            else if (arktsMethodExpression instanceof SingleExpressionContext && (dstArktsTypeName != null || dstArktsMethodName != null)) {
                assert arktsMethodExpression.getChildCount() > 0;
                ParseTree arktsChildNode = arktsMethodExpression.getChild(0);

                if (arktsChildNode instanceof MemberAccessExpressionContext) {
                    rebuildMemberAccessExpression((MemberAccessExpressionContext)arktsChildNode, dstArktsTypeName, dstArktsMethodName, dstArktsObjectTypeArgs);
                }
                else assert false; // TODO:
            }
        }

        private void makeMethodGlobal(CallExpressionContext arktsCallExpression) {
            SingleExpressionContext arktsMethodExpression = arktsCallExpression.singleExpression();

            if (arktsMethodExpression instanceof SingleExpressionContext) {
                assert arktsMethodExpression.getChildCount() == 1;
                ParseTree arktsChildNode = arktsMethodExpression.getChild(0);

                if (arktsChildNode instanceof MemberAccessExpressionContext) {
                    // Remove from the CallExpressionContext current arktsMethodExpression which represents a MemberAccessExpression...
                    arktsCallExpression.children.remove(arktsMethodExpression);
                    // ...build a new IdentifierExpressionContext...
                    IdentifierExpressionContext arktsIdentifierExpression = new IdentifierExpressionContext(new SingleExpressionContext());
                    MemberAccessExpressionContext arktsMemberAccessExpr = (MemberAccessExpressionContext)arktsChildNode;
                    arktsIdentifierExpression.addChild(arktsMemberAccessExpr.Identifier());
                    // ...and replace with it the removed MemberAccessExpression in the CallExpression node.
                    arktsCallExpression.addChild(arktsIdentifierExpression).setParent(arktsCallExpression);
                }
                else if (arktsMethodExpression instanceof IdentifierExpressionContext) {
                    // Nothing to do.
                }
                else assert false; // TODO:
            }
        }

        private void substituteObject(CallExpressionContext arktsCallExpression, List<SingleExpressionContext> arktsOrigArgsList) {
            SingleExpressionContext arktsMethodExpression = arktsCallExpression.singleExpression();
            assert (arktsMethodExpression.getChild(0) instanceof MemberAccessExpressionContext);
            MemberAccessExpressionContext arktsMemberAccessExpr = (MemberAccessExpressionContext)arktsMethodExpression.getChild(0);
            SingleExpressionContext arktsOrigObject = arktsMemberAccessExpr.singleExpression();

            SingleExpressionContext arktsNewObject = null;

            if (dstArktsObject instanceof NewClassInstanceExpression) {
                arktsNewObject = ((NewClassInstanceExpression)dstArktsObject).buildArktsNode(arktsOrigObject, arktsOrigArgsList);
            }
            else if (dstArktsObject instanceof Integer) {
                int index = (Integer)dstArktsObject;
                assert (arktsCallExpression.children != null);
                assert (arktsOrigArgsList.size() > index);

                arktsNewObject = NodeClonner.clone(arktsOrigArgsList.get(index));
            }
            else assert false;

            if (arktsNewObject != null) {
                arktsMemberAccessExpr.children.remove(arktsOrigObject);
                arktsMemberAccessExpr.addChild(arktsNewObject).setParent(arktsMemberAccessExpr);
            }
        }

        private void substituteType(CallExpressionContext arktsCallExpression) {
            SingleExpressionContext arktsMethodExpression = arktsCallExpression.singleExpression();
            assert (arktsMethodExpression.getChild(0) instanceof MemberAccessExpressionContext);
            MemberAccessExpressionContext arktsMemberAccessExpr = (MemberAccessExpressionContext)arktsMethodExpression.getChild(0);

            SingleExpressionContext arktsIdentifier = arktsMemberAccessExpr.singleExpression();
            assert (arktsIdentifier.getChildCount() == 1 && arktsIdentifier.getChild(0) instanceof IdentifierExpressionContext);
            IdentifierExpressionContext arktsIdentifierExpr = (IdentifierExpressionContext)arktsIdentifier.getChild(0);
            assert (arktsIdentifierExpr.getChildCount() == 1);
            arktsIdentifierExpr.children.clear();
            arktsIdentifierExpr.addChild(NodeBuilderBase.terminalIdentifier(dstArktsTypeName));
        }

        private List<SingleExpressionContext> getOrigArgs(CallExpressionContext arktsCallExpression) {
            ArgumentsContext arktsArguments = arktsCallExpression.arguments();
            ExpressionSequenceContext arktsExpressionSequence = arktsArguments.expressionSequence();
            List<SingleExpressionContext> arktsOrigArguments;

            if (arktsExpressionSequence == null) { // The list of arguments may be empty.
                arktsExpressionSequence = new ExpressionSequenceContext(arktsArguments, 0);
                arktsExpressionSequence.children = new ArrayList<>();
                arktsArguments.addChild(arktsExpressionSequence).setParent(arktsArguments);
                arktsOrigArguments = new ArrayList<>(0); // Init with an empty list just to don't hava NPE.
            }
            else {
                // The list of arguments will be completely rebuild. At the same time new arguments may refer to
                // the same arguments from the old list. So preserve the old list of arguments.
                arktsOrigArguments = new ArrayList<SingleExpressionContext>();
                for(ParseTree arktsNode : arktsExpressionSequence.children) {
                    arktsOrigArguments.add((SingleExpressionContext)arktsNode);
                }
            }

            return arktsOrigArguments;
        }

        public void apply(CallExpressionContext arktsCallExpression) {
            List<SingleExpressionContext> arktsOrigArgsList = null;
            if (dstArguments != null || dstArktsObject != null) {
                arktsOrigArgsList = getOrigArgs(arktsCallExpression);
            }

            if (dstArktsTypeName != null) {
                assert (dstArktsObject == null);
                if (dstArktsTypeName.isEmpty()) { // Note: Here it's checked for NOT null AND empty string.
                    makeMethodGlobal(arktsCallExpression);
                } else {
                    substituteType(arktsCallExpression);
                }
            } else if (dstArktsObject != null) {
                substituteObject(arktsCallExpression, arktsOrigArgsList);
            }

            if (dstArktsMethodName != null) {
                assert (!dstArktsMethodName.isEmpty());
                renameMethod(arktsCallExpression.singleExpression());
            }

            TypeArgumentsContext origArktsMethodTypeArgs = arktsCallExpression.typeArguments();

            if (dstArktsMethodTypeArgs == null) {
                if (origArktsMethodTypeArgs != null) {
                    // Java method is generic (has type arguments) and its ArtTS equivalent is NOT a generic one then
                    // just remove the type arguments.
                    arktsCallExpression.children.remove(origArktsMethodTypeArgs);
                }
            }
            else { // dstArktsMethodTypeArgs != null
                List<TypeArgumentContext> origArktsTypeArgsList = null;

                if (origArktsMethodTypeArgs != null) {
                    assert (origArktsMethodTypeArgs.typeArgumentList() != null);

                    origArktsTypeArgsList = origArktsMethodTypeArgs.typeArgumentList().typeArgument();

                    arktsCallExpression.children.remove(origArktsMethodTypeArgs);
                }

                arktsCallExpression.addChild(dstArktsMethodTypeArgs.buildArktsNode(origArktsTypeArgsList)).setParent(arktsCallExpression);
            }

            if (dstArguments != null) {
                ArgumentsContext arktsArguments = arktsCallExpression.arguments();
                ExpressionSequenceContext arktsExpressionSequence = arktsArguments.expressionSequence();

                // Build the new one based on the rule's list of arguments.
                List<TypeArgumentContext> arktsOrigTypeArguments = null;
                TypeArgumentsContext arktsTypeArguments = arktsCallExpression.typeArguments();
                if (arktsTypeArguments != null) {
                    arktsOrigTypeArguments = arktsTypeArguments.typeArgumentList().typeArgument();
                }

                dstArguments.rebuildArktsNode(arktsCallExpression.singleExpression(), arktsExpressionSequence, arktsOrigTypeArguments, arktsOrigArgsList);
            }

            //arktsCallExpression.accept(mapper);
            mapper.visitChildren(arktsCallExpression); // Apply the mapping rules to the children of the rebuilt CallExpression.
        }

        static private String signature(String javaType, String javaTypeArgs, String javaMethodName, String javaMethodTypeArgs, String javaMethodArgs) {
            sb.setLength(0); // Clear the StringBuilder.

            if (!isStringEmpty(javaType)) {
                sb.append(javaType);
            }

            sb.append('@');

            if (!isStringEmpty(javaTypeArgs)) {
                sb.append(javaTypeArgs);
            }

            sb.append('@');

            if (!isStringEmpty(javaMethodName)) {
                sb.append(javaMethodName);
            }

            sb.append('@');

            if (!isStringEmpty(javaMethodTypeArgs)) {
                sb.append(javaMethodTypeArgs);
            }

            sb.append('@');

            if (!isStringEmpty(javaMethodArgs)) {
                sb.append(javaMethodArgs);
            }

            return sb.toString();
        }

        public List<String> signature(StartElement callExpressionElement) {
            String javaType = getAttribute(callExpressionElement, javaTypeAttr);
            String javaTypeArgs = getAttribute(callExpressionElement, javaTypeArgsAttr);
            String javaMethodName = getAttribute(callExpressionElement, javaMethodNameAttr);
            String javaMethodTypeArgs = getAttribute(callExpressionElement, javaMethodTypeArgsAttr);
            String javaMethodArgs = getAttribute(callExpressionElement, javaMethodArgsAttr);

            List<String> signatures = new ArrayList<>();
            for (String type : javaType.split(",")) {
                type = type.trim();
                if (!type.isEmpty()) {
                    signatures.add(signature(type, javaTypeArgs, javaMethodName, javaMethodTypeArgs, javaMethodArgs));
                }
            }

            return signatures;
        }

        static public String signature1(CallExpressionContext arktsCall) {
            return signature(arktsCall.javaType, arktsCall.javaTypeArgs, arktsCall.javaName, arktsCall.javaMethodTypeArgs, arktsCall.javaMethodArgs);
        }

        static public String signature2(CallExpressionContext arktsCall) {
            return signature(arktsCall.javaType, arktsCall.javaTypeArgs, arktsCall.javaName, null, arktsCall.javaMethodArgs);
        }

        static public String signature3(CallExpressionContext arktsCall) {
            return signature(arktsCall.javaType, null, arktsCall.javaName, arktsCall.javaMethodTypeArgs, arktsCall.javaMethodArgs);
        }

        static public String signature4(CallExpressionContext arktsCall) {
            return signature(arktsCall.javaType, null, arktsCall.javaName, null, arktsCall.javaMethodArgs);
        }

        static CallExpressionRule read(XMLEventReader xmlReader, JavaApiMapper mapper) throws XMLStreamException {
            CallExpressionRule callExpressionRule = new CallExpressionRule(mapper);

            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    String tag = startElement.getName().getLocalPart();

                    if (tagArktsTypeName.equals(tag)) {
                        callExpressionRule.dstArktsTypeName = getAttribute(startElement, valueAttr);
                    }
                    else if (tagArktsObject.equals(tag)) {
                        // This XmlElement as a child may have either NewClassInstanceExpression or SrcArgument.
                        while (xmlReader.hasNext()) {
                            xmlEvent = xmlReader.nextEvent();
                            if (xmlEvent.isStartElement()) {
                                startElement = xmlEvent.asStartElement();
                                tag = startElement.getName().getLocalPart();

                                if (NewClassInstanceExpression.tag.equals(tag)) {
                                    callExpressionRule.dstArktsObject = NewClassInstanceExpression.read(xmlReader);
                                }
                                else if (tagSrcArgument.equals(tag)) {
                                    callExpressionRule.dstArktsObject = Integer.valueOf(getAttribute(startElement, indexAttr));
                                }
                                else assert false : "Unexpected XmlElement " + tag;
                            }
                            else if (xmlEvent.isEndElement()) {
                                EndElement endElement = xmlEvent.asEndElement();
                                tag = endElement.getName().getLocalPart();

                                if (tagArktsObject.equals(tag)) {
                                    break;
                                }
                                else {
                                    assert (tagSrcArgument.equals(tag) || NewClassInstanceExpression.tag.equals(tag));
                                }
                            }
                        }
                    }
                    else if (tagArktsMethodName.equals(tag)) {
                        callExpressionRule.dstArktsMethodName = getAttribute(startElement, valueAttr);
                    }
                    else if (tagArktsObjectTypeArgs.equals(tag)) {
                        while (xmlReader.hasNext()) {
                            xmlEvent = xmlReader.nextEvent();
                            if (xmlEvent.isStartElement()) {
                                tag = xmlEvent.asStartElement().getName().getLocalPart();

                                if (TypeArguments.tag.equals(tag)) {
                                    callExpressionRule.dstArktsObjectTypeArgs = TypeArguments.read(xmlReader);
                                }
                            }
                            else if (xmlEvent.isEndElement()) {
                                tag = xmlEvent.asEndElement().getName().getLocalPart();

                                if (tagArktsObjectTypeArgs.equals(tag)) {
                                    break;
                                }
                                else
                                    assert false;
                            }
                        }
                    }
                    else if (tagArktsMethodTypeArgs.equals(tag)) {
                        while (xmlReader.hasNext()) {
                            xmlEvent = xmlReader.nextEvent();
                            if (xmlEvent.isStartElement()) {
                                tag = xmlEvent.asStartElement().getName().getLocalPart();

                                if (TypeArguments.tag.equals(tag)) {
                                    callExpressionRule.dstArktsMethodTypeArgs = TypeArguments.read(xmlReader);
                                }
                            }
                            else if (xmlEvent.isEndElement()) {
                                tag = xmlEvent.asEndElement().getName().getLocalPart();

                                if (tagArktsMethodTypeArgs.equals(tag)) {
                                    break;
                                }
                                else
                                    assert false;
                            }
                        }
                    }
                    else if (Arguments.tag.equals(tag)) {
                        callExpressionRule.dstArguments = Arguments.read(xmlReader, xmlEvent);
                    }
                    else assert false : "Unexpected XmlElement " + tag;
                }
                else if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    String tag = endElement.getName().getLocalPart();

                    if (CallExpressionRule.tag.equals(tag)) {
                        break;
                    }
                    else {
                        assert (tagArktsTypeName.equals(tag) || tagArktsMethodName.equals(tag)
                                || TypeArguments.tag.equals(tag) || Arguments.tag.equals(tag));
                    }
                }
            }

            return callExpressionRule;
        }
    }

    // <MemberAccessExpressionRule javaObjectType="java.object.type" javaMemberName="javaMemberName" arktsName="arktsMemberName"/>
    static private class MemberAccessExpressionRule {
        static public String tag = "MemberAccessExpressionRule";

        private JavaApiMapper mapper = null; // It is needed for recursive iteration over the subtree.

        private String arktsName = null;
        private TypeReference typeReference = null; // Optional ArkTS type for a static field access.
        private CallExpression callExpression = null; //

        public MemberAccessExpressionRule(JavaApiMapper mapper) {
            this.mapper = mapper;
        }

        // ArkTS:
        //  | singleExpression Dot Identifier # MemberAccessExpression
        public void apply(MemberAccessExpressionContext arktsMemberAccessExpression) {
            assert arktsName != null;

            arktsMemberAccessExpression.children.remove(arktsMemberAccessExpression.Identifier());

            if (arktsName != null) {
                arktsMemberAccessExpression.addChild(NodeBuilderBase.terminalIdentifier(arktsName));
            }

            if (typeReference != null) {
                arktsMemberAccessExpression.children.remove(arktsMemberAccessExpression.singleExpression());
                arktsMemberAccessExpression.addChild(typeReference.buildArktsNode(null)).setParent(arktsMemberAccessExpression);
            }
            else if (callExpression != null) {
                arktsMemberAccessExpression.children.remove(arktsMemberAccessExpression.singleExpression());
                arktsMemberAccessExpression.addChild(callExpression.buildArktsNode(null, null, null)).setParent(arktsMemberAccessExpression);
            }

            mapper.visitChildren(arktsMemberAccessExpression);
         }

        static private String signature(String javaObjectType, String javaName) {
            sb.setLength(0); // Clear the StringBuilder.

            if (!isStringEmpty(javaObjectType)) {
                sb.append(javaObjectType);
            }

            sb.append('@');

            if (!isStringEmpty(javaName)) {
                sb.append(javaName);
            }

            return sb.toString();
        }

        static public String signature(MemberAccessExpressionContext arktsMemberAccessExpression) {
            return signature(arktsMemberAccessExpression.javaType, arktsMemberAccessExpression.javaName);
        }

        static public String signature(StartElement callExpressionElement) {
            String javaObjectType = getAttribute(callExpressionElement, javaTypeAttr);
            String javaName = getAttribute(callExpressionElement, javaMethodNameAttr);

            return signature(javaObjectType, javaName);
        }
        static MemberAccessExpressionRule read(XMLEventReader xmlReader, StartElement ruleStartElement, JavaApiMapper mapper) throws XMLStreamException {
            MemberAccessExpressionRule memberAccessExpressionRule = new MemberAccessExpressionRule(mapper);

            memberAccessExpressionRule.arktsName = getAttribute(ruleStartElement, arktsNameAttr);

            // Read an optional <TypeReferenc> element and the end event (</MemberAccessExpressionRule>)
            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    String tag = startElement.getName().getLocalPart();

                    if (TypeReference.tag.equals(tag)) {
                        memberAccessExpressionRule.typeReference = TypeReference.read(xmlReader, xmlEvent);
                    }
                    else if (CallExpression.tag.equals(tag)) {
                        memberAccessExpressionRule.callExpression = CallExpression.read(xmlReader, xmlEvent);
                    }
                    else assert false;
                }
                else if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    assert MemberAccessExpressionRule.tag.equals(endElement.getName().getLocalPart());
                    break;
                }
            }

            return memberAccessExpressionRule;
        }
    }

//    <NewClassInstanceExpressionRule javaType="java.class" javaTypeArgs="comma.separated.list.of.types" javaMethodTypeArgs="comma.separated.list.of.types" javaArgs="comma.separated.list.of.types">
//        <TypeReference/>      // Optional ArkTS class. If it's not specified then current class remains.
//        <TypeArguments/>      // Optional list of ArkTS type arguments. If it's not specified then the current type arguments remain.
//        <Arguments/>          // Optional new list of arguments. If it's not specified then the current arguments remain.
//    </NewClassInstanceExpressionRule>
    static private class NewClassInstanceExpressionRule {
        static public String tag = "NewClassInstanceExpressionRule";

        private JavaApiMapper mapper = null; // It is needed for recursive iteration over the subtree.

        private TypeReference typeReference = null;
        private TypeArguments typeArguments = null;
        private Arguments arguments = null;

        public NewClassInstanceExpressionRule(JavaApiMapper mapper) {
            this.mapper = mapper;
        }

        // ArkTS:
        //    New typeArguments? typeReference arguments? classBody?  # NewClassInstanceExpression
        public void apply(NewClassInstanceExpressionContext arktsNewClassInstanceExpression) {
            TypeArgumentsContext arktsOrigTypeArguments = arktsNewClassInstanceExpression.typeArguments();
            List<TypeArgumentContext> arktsOrigTypeArgsList = null;

            if (typeReference != null) {
                TypeReferenceContext arktsOrigTypeReference = arktsNewClassInstanceExpression.typeReference();
                arktsNewClassInstanceExpression.children.remove(arktsOrigTypeReference);

                if (arktsOrigTypeArguments != null) {
                    arktsOrigTypeArgsList = arktsOrigTypeArguments.typeArgumentList().typeArgument();
                }

                arktsNewClassInstanceExpression.addChild(typeReference.buildArktsNode(arktsOrigTypeArgsList)).setParent(arktsNewClassInstanceExpression);
            }

            if (typeArguments != null) {
                arktsNewClassInstanceExpression.children.remove(arktsOrigTypeArguments);

                if (arktsOrigTypeArguments != null) {
                    arktsOrigTypeArgsList = arktsOrigTypeArguments.typeArgumentList().typeArgument();
                }

                arktsNewClassInstanceExpression.addChild(typeArguments.buildArktsNode(arktsOrigTypeArgsList)).setParent(arktsNewClassInstanceExpression);
            }

            if (arguments != null) {
                ExpressionSequenceContext arktsExpressionSequence = arktsNewClassInstanceExpression.arguments().expressionSequence();

                // The list of arguments will be completely rebuild. At the same time new arguments may referes to some arguments
                // from the old list. So preserve the old list of arguments.
                List<SingleExpressionContext> arktsOrigArguments = new ArrayList<>();
                for (ParseTree arktsNode : arktsExpressionSequence.children) {
                    arktsOrigArguments.add((SingleExpressionContext) arktsNode);
                }

                // Clear the current list of arguments...
                arktsExpressionSequence.children.clear();
                // ...and build the new one based on the rule's list of arguments.

                if (arktsOrigTypeArguments != null) {
                    arktsOrigTypeArgsList = arktsOrigTypeArguments.typeArgumentList().typeArgument();
                }

                arguments.rebuildArktsNode(null, arktsExpressionSequence, arktsOrigTypeArgsList, arktsOrigArguments);
            }

            mapper.visitChildren(arktsNewClassInstanceExpression); // Apply the mapping rules to the children of the rebuilt NewClassInstanceExpression.
        }

        static private String signature(String javaObjectType, String javaObjectTypeArgs, String javaMethodTypeArgs, String javaMethodArgs) {
            sb.setLength(0); // Clear the StringBuilder.

            if (!isStringEmpty(javaObjectType)) {
                sb.append(javaObjectType);
            }

            sb.append('@');

            if (!isStringEmpty(javaObjectTypeArgs)) {
                sb.append(javaObjectTypeArgs);
            }

            sb.append('@');

            if (!isStringEmpty(javaMethodTypeArgs)) {
                sb.append(javaMethodTypeArgs);
            }

            sb.append('@');

            if (!isStringEmpty(javaMethodArgs)) {
                sb.append(javaMethodArgs);
            }

            return sb.toString();
        }

        static public String signature(StartElement newClassInstanceExpressionElement) {
            String javaType = getAttribute(newClassInstanceExpressionElement, javaTypeAttr);
            String javaTypeArgs = getAttribute(newClassInstanceExpressionElement, javaTypeArgsAttr);
            String javaMethodTypeArgs = getAttribute(newClassInstanceExpressionElement, javaMethodTypeArgsAttr);
            String javaMethodArgs = getAttribute(newClassInstanceExpressionElement, javaMethodArgsAttr);

            return signature(javaType, javaTypeArgs, javaMethodTypeArgs, javaMethodArgs);
        }

        static public String signature(NewClassInstanceExpressionContext arktsNewClass) {
            return signature(arktsNewClass.javaType, arktsNewClass.javaTypeArgs, arktsNewClass.javaMethodTypeArgs, arktsNewClass.javaMethodArgs);
        }

        static NewClassInstanceExpressionRule read(XMLEventReader xmlReader, XMLEvent xmlNewClassExpressionEvent, StartElement ruleStartElement, JavaApiMapper mapper) throws XMLStreamException {
            NewClassInstanceExpressionRule newClassExpressionRule = new NewClassInstanceExpressionRule(mapper);

            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    String tag = startElement.getName().getLocalPart();

                    if (TypeReference.tag.equals(tag)) {
                        newClassExpressionRule.typeReference = TypeReference.read(xmlReader, xmlEvent);
                    }
                    else if (TypeArguments.tag.equals(tag)) {
                        newClassExpressionRule.typeArguments = TypeArguments.read(xmlReader);
                    }
                    else if (Arguments.tag.equals(tag)) {
                        newClassExpressionRule.arguments = Arguments.read(xmlReader, xmlEvent);
                    }
                    else assert false;
                }
                else if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    assert NewClassInstanceExpressionRule.tag.equals(endElement.getName().getLocalPart());
                    break;
                }
            }

            return newClassExpressionRule;
        }
    }

    //  <TypeReferenceRule javaObjectType="list.of.java.types" javaObjectTypeArgs="list.of.java.types">
    //      <TypeReference/>
    //   </TypeReferenceRule>

    static private class TypeReferenceRule {
        static public String tag = "TypeReferenceRule";

        private TypeReference typeReference = null;

        public void apply(TypeReferenceContext arktsTypeReference) {
            assert typeReference != null;

            // TODO: The code here expects that there is only 1 TypeReferencePart. If really there will be case
            //       with many TypeReferenceParts then the code has to be addopted to it.
            TypeReferencePartContext arktsOrigTypeReferencePart = arktsTypeReference.typeReferencePart(0);
            List<TypeArgumentContext> arktsOrigTypeArgsList = null;
            TypeArgumentsContext arktsTypeArguments = arktsOrigTypeReferencePart.typeArguments();

            if (arktsTypeArguments != null) {
                arktsOrigTypeArgsList = arktsTypeArguments.typeArgumentList().typeArgument();
            }

            assert (arktsTypeReference.parent instanceof ParserRuleContext);
            ParserRuleContext arktsTypeReferenceParent = (ParserRuleContext) arktsTypeReference.parent;
            // NOTE: Don't use arktsTypeReferenceParent.addChild() to replace current type reference with the new one.
            //       That method adds a new element to the end of the children list. And here its important
            //       to preserve the order of child elements.
            int index = arktsTypeReferenceParent.children.indexOf(arktsTypeReference);
            arktsTypeReferenceParent.children.remove(arktsTypeReference);
            TypeReferenceContext arktsNewTypeReference = typeReference.buildArktsNode(arktsOrigTypeArgsList);
            arktsNewTypeReference.setParent(arktsTypeReferenceParent);
            arktsTypeReferenceParent.children.add(index, arktsNewTypeReference);
            //arktsTypeReferenceParent.addChild(typeReference.buildArktsNode(arktsOrigTypeArgsList)).setParent(arktsTypeReferenceParent);
        }

        static private String signature(String javaObjectType, String javaObjectTypeArgs) {
            sb.setLength(0); // Clear the StringBuilder.

            if (!isStringEmpty(javaObjectType)) {
                sb.append(javaObjectType);
            }

            sb.append('@');

            if (!isStringEmpty(javaObjectTypeArgs)) {
                sb.append(javaObjectTypeArgs);
            }

            return sb.toString();
        }

        static public String signature(StartElement typeReferenceElement) {
            String javaObjectType = getAttribute(typeReferenceElement, javaTypeAttr);
            String javaObjectTypeArgs = getAttribute(typeReferenceElement, javaTypeArgsAttr);

            return signature(javaObjectType, javaObjectTypeArgs);
        }

        static public String signature(TypeReferenceContext arktsTypeReference) {
            return signature(arktsTypeReference.javaType, arktsTypeReference.javaTypeArgs);
        }

        static TypeReferenceRule read(XMLEventReader xmlReader, XMLEvent xmlNewClassExpressionEvent, StartElement ruleStartElement) throws XMLStreamException {
            TypeReferenceRule typeReferenceRule = new TypeReferenceRule();

            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    String tag = startElement.getName().getLocalPart();

                    if (TypeReference.tag.equals(tag)) {
                        typeReferenceRule.typeReference = TypeReference.read(xmlReader, xmlEvent);
                    }
                    else assert false;
                }
                else if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    assert TypeReferenceRule.tag.equals(endElement.getName().getLocalPart());
                    break;
                }
            }

            return typeReferenceRule;
        }
    }

    // For some items from 'java.lang' package its equivalents in ArkTS located in NOT implicitly imported packages.
    // To make such items available for usage corresponding imports have to be added to the resulting code.
    // In the first iteration add the imports always without attempt to figure out whether any item of the packages is
    // really used in the code or not.
    private HashSet<ImportDeclarationRule> mandatoryImportRules = new HashSet<>();
    private HashMap<String, ImportDeclarationRule> importDeclarationRules = new HashMap<>();
    private HashMap<String, CallExpressionRule> callExpressionRules = new HashMap<>();
    private HashMap<String, MemberAccessExpressionRule> memberAccessExpressionRules = new HashMap<>();
    private HashMap<String, NewClassInstanceExpressionRule> newClassInstanceExpressionRules = new HashMap<>();
    private HashMap<String, TypeReferenceRule> typeReferenceRules = new HashMap<>();

    @Override
    public Void visitCompilationUnit(CompilationUnitContext arktsCompilationUnit) {
        // Some rules remove nodes from arktsCompilationUnit. And it brakes super.visitCompilationUnit() work
        // as it tries to iterate over the original number of child nodes. So here is not used the base class
        // implementation of visitCompilationUnit().
        //super.visitCompilationUnit(arktsCompilationUnit);

        int i = 0;
        int count = arktsCompilationUnit.getChildCount();

        while (i < count) {
            ParseTree node = arktsCompilationUnit.getChild(i);
            node.accept(this);

            int n = arktsCompilationUnit.getChildCount();
            if (count == n) {
                i++;
            }
            else {
                count = n;
            }
        }

        for(ImportDeclarationRule rule : mandatoryImportRules) {
            rule.apply(arktsCompilationUnit);
        }

        return null;
    }

    @Override
    public Void visitImportDeclaration(ImportDeclarationContext arktsImportDeclatation) {
        ImportDeclarationRule rule = importDeclarationRules.get(ImportDeclarationRule.signature(arktsImportDeclatation));
        if (rule != null) {
            rule.apply(arktsImportDeclatation);
        }

        return null;
    }

    @Override
    public Void visitCallExpression(CallExpressionContext arktsCallExpression) {
        CallExpressionRule rule = callExpressionRules.get(CallExpressionRule.signature1(arktsCallExpression));

        if (rule == null) {
            rule = callExpressionRules.get(CallExpressionRule.signature2(arktsCallExpression));
        }

        if (rule == null) {
            rule = callExpressionRules.get(CallExpressionRule.signature3(arktsCallExpression));
        }

        if (rule == null) {
            rule = callExpressionRules.get(CallExpressionRule.signature4(arktsCallExpression));
        }

        if (rule != null) {
            rule.apply(arktsCallExpression);
        }
        else {
            visitChildren(arktsCallExpression); // Apply the mapping rules to the children of the rebuilt CallExpression.
        }

        return null;
    }

    @Override
    public Void visitMemberAccessExpression(MemberAccessExpressionContext arktsMemberAccessExpression) {
        MemberAccessExpressionRule rule = memberAccessExpressionRules.get(MemberAccessExpressionRule.signature(arktsMemberAccessExpression));
        if (rule != null) {
            rule.apply(arktsMemberAccessExpression);
        }
        else {
            visitChildren(arktsMemberAccessExpression);
        }

        return null;
    }

    @Override
    public Void visitNewClassInstanceExpression(NewClassInstanceExpressionContext arktsNewClassInstanceExpression) {
        NewClassInstanceExpressionRule rule = newClassInstanceExpressionRules.get(NewClassInstanceExpressionRule.signature(arktsNewClassInstanceExpression));
        if (rule != null) {
            rule.apply(arktsNewClassInstanceExpression);
        }
        else {
            visitChildren(arktsNewClassInstanceExpression);
        }

        return null;
    }

    @Override
    public Void visitTypeReference(TypeReferenceContext arktsTypeReference) {
        TypeReferenceRule rule = typeReferenceRules.get(TypeReferenceRule.signature(arktsTypeReference));
        if (rule != null) {
            rule.apply(arktsTypeReference);
        }
        else {
            visitChildren(arktsTypeReference);
        }

        return null;
    }

    static private String tagJavaApiMappingRules = "JavaApiMappingRules";

    private JavaApiMapper(XMLEventReader xmlReader) throws XMLStreamException {
        Stack<String> tagStart = new Stack<>();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (ImportDeclarationRule.tag.equals(tag)) {
                    ImportDeclarationRule rule = ImportDeclarationRule.read(xmlReader, xmlEvent, startElement);
                    String signature = rule.signature(startElement);

                    if (rule.javaImport == null) {
                        mandatoryImportRules.add(rule);
                    }
                    else {
                        assert !isStringEmpty(signature) && rule != null;
                        importDeclarationRules.put(signature, rule);
                    }
                }
                else if (CallExpressionRule.tag.equals(tag)) {
                    CallExpressionRule rule = CallExpressionRule.read(xmlReader, this);
                    List<String> signatures = rule.signature(startElement);

                    for (String signature : signatures) {
                        callExpressionRules.put(signature, rule);
                    }
                }
                else if (MemberAccessExpressionRule.tag.equals(tag)) {
                    String signature = MemberAccessExpressionRule.signature(startElement);
                    MemberAccessExpressionRule rule = MemberAccessExpressionRule.read(xmlReader, startElement, this);

                    assert !isStringEmpty(signature) && rule != null;
                    memberAccessExpressionRules.put(signature, rule);
                }
                else if (NewClassInstanceExpressionRule.tag.equals(tag)) {
                    String signature = NewClassInstanceExpressionRule.signature(startElement);
                    NewClassInstanceExpressionRule rule = NewClassInstanceExpressionRule.read(xmlReader, xmlEvent, startElement, this);

                    assert !isStringEmpty(signature) && rule != null;
                    newClassInstanceExpressionRules.put(signature, rule);
                }
                else if (TypeReferenceRule.tag.equals(tag)) {
                    String signature = TypeReferenceRule.signature(startElement);
                    TypeReferenceRule rule = TypeReferenceRule.read(xmlReader, xmlEvent, startElement);

                    assert !isStringEmpty(signature) && rule != null;
                    typeReferenceRules.put(signature, rule);
                }
                else {
                    // All other XML elements are ignored. They are used only for grouping of the rule elements.
                    // Just remember of name of the start element to verify end element with the same name will be met.
                    tagStart.push(tag);
                    //assert tagJavaApiMappingRules.equals(tag);
                }
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();
                if (tagJavaApiMappingRules.equals(tag)) {
                    break;
                }
                else {
                    assert tagStart.peek().equals(tag) : "Unexpected XmlElement " + tag;
                    tagStart.pop();
                }
            }
        }
    }

    static public JavaApiMapper readRules(String path) throws FileNotFoundException, XMLStreamException {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        FileInputStream fis = new FileInputStream(path);
        XMLEventReader xmlReader = xmlInputFactory.createXMLEventReader(fis);
        return new JavaApiMapper(xmlReader);
    }
}
