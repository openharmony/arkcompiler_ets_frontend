# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required (VERSION 3.5.0)

include(cmake/coverage.cmake)

project (es2panda)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(GENERATED_DIR ${OUTPUT_DIR}/generated)
set(GENERATED_STAMP ${OUTPUT_DIR}/gen_dir.stamp)
file(MAKE_DIRECTORY "${GENERATED_DIR}")
if(PANDA_WITH_ETS)
  file(WRITE "${GENERATED_DIR}/arktsconfig.json"
      "{\n"
      "  \"compilerOptions\": {\n"
      "    \"baseUrl\": \"${PANDA_ROOT}\",\n"
      "    \"paths\": {\n"
      "      \"std\": [\"${PANDA_ROOT}/plugins/ets/stdlib/std\"],\n"
      "      \"escompat\": [\"${PANDA_ROOT}/plugins/ets/stdlib/escompat\"],\n"
      "      \"import_tests\": [\"${CMAKE_CURRENT_SOURCE_DIR}/test/parser/ets/import_tests\"],\n"
      "      \"dynamic_import_tests\": [\"${CMAKE_CURRENT_SOURCE_DIR}/test/parser/ets/dynamic_import_tests\"]\n"
      "    },\n"
      "    \"dynamicPaths\": {\n"
      "      \"dynamic_js_import_tests\": {\"language\": \"js\", \"hasDecl\": false},\n"
      "      \"${CMAKE_CURRENT_SOURCE_DIR}/test/parser/ets/dynamic_import_tests\": {\"language\": \"js\", \"hasDecl\": true}\n"
      "    }\n"
      "  }\n"
      "}\n"
  )
endif()

add_custom_command(
  OUTPUT ${GENERATED_STAMP}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${OUTPUT_DIR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${GENERATED_DIR}
  COMMAND ${CMAKE_COMMAND} -E touch ${GENERATED_STAMP}
)

set(TEMPLATES
  isa.h.erb
  formats.h.erb
)

panda_isa_gen(
  TEMPLATES ${TEMPLATES}
  SOURCE ${CMAKE_CURRENT_LIST_DIR}/compiler/templates
  DESTINATION ${GENERATED_DIR}
  EXTRA_DEPENDENCIES ${GENERATED_STAMP}
)

panda_gen(
    DATA ${CMAKE_CURRENT_SOURCE_DIR}/lexer/scripts/keywords.yaml
    TARGET_NAME es2panda_keywords
    TEMPLATES keywords.h.erb
    REQUIRES
       ${CMAKE_CURRENT_SOURCE_DIR}/lexer/scripts/keywords.rb
    SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/lexer/templates
    DESTINATION ${GENERATED_DIR}
)

panda_gen(
    DATA ${CMAKE_CURRENT_SOURCE_DIR}/compiler/scripts/signatures.yaml
    TARGET_NAME es2panda_signatures
    TEMPLATES signatures.h.erb
    REQUIRES
       ${CMAKE_CURRENT_SOURCE_DIR}/compiler/scripts/signatures.rb
    SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/compiler/templates
    DESTINATION ${GENERATED_DIR}
)

set(ES2PANDA_LIB_SRC
  es2panda.cpp
  binder/ASBinder.cpp
  binder/TSBinder.cpp
  binder/TypedBinder.cpp
  binder/ETSBinder.cpp
  binder/JSBinder.cpp
  binder/binder.cpp
  binder/declaration.cpp
  binder/recordTable.cpp
  binder/scope.cpp
  binder/variable.cpp
  compiler/base/catchTable.cpp
  compiler/base/condition.cpp
  compiler/base/destructuring.cpp
  compiler/base/hoisting.cpp
  compiler/base/iterators.cpp
  compiler/base/lexenv.cpp
  compiler/base/literals.cpp
  compiler/base/lreference.cpp
  compiler/base/optionalChain.cpp
  compiler/core/ASTVerifier.cpp
  compiler/core/codeGen.cpp
  compiler/core/compileJob.cpp
  compiler/core/compileQueue.cpp
  compiler/core/compilerContext.cpp
  compiler/core/compilerImpl.cpp
  compiler/core/dynamicContext.cpp
  compiler/core/emitter.cpp
  compiler/core/JSCompiler.cpp
  compiler/core/JSemitter.cpp
  compiler/core/envScope.cpp
  compiler/core/function.cpp
  compiler/core/labelTarget.cpp
  compiler/core/moduleContext.cpp
  compiler/core/pandagen.cpp
  compiler/core/programElement.cpp
  compiler/core/regAllocator.cpp
  compiler/core/regScope.cpp
  compiler/core/regSpiller.cpp
  compiler/core/ETSCompiler.cpp
  compiler/core/ETSemitter.cpp
  compiler/core/ETSGen.cpp
  compiler/core/ETSfunction.cpp
  compiler/core/switchBuilder.cpp
  compiler/core/targetTypeContext.cpp
  compiler/core/vReg.cpp
  compiler/debugger/debuginfoDumper.cpp
  compiler/function/asyncFunctionBuilder.cpp
  compiler/function/asyncGeneratorFunctionBuilder.cpp
  compiler/function/functionBuilder.cpp
  compiler/function/generatorFunctionBuilder.cpp
  compiler/lowering/checkerPhase.cpp
  compiler/lowering/phase.cpp
  compiler/lowering/util.cpp
  compiler/lowering/ets/generateDeclarations.cpp
  compiler/lowering/ets/opAssignment.cpp
  compiler/lowering/ets/unionLowering.cpp
  ir/astDump.cpp
  ir/astNode.cpp
  ir/irnode.cpp
  ir/typeNode.cpp
  ir/opaqueTypeNode.cpp
  ir/base/catchClause.cpp
  ir/base/classElement.cpp
  ir/base/classDefinition.cpp
  ir/base/classProperty.cpp
  ir/base/classStaticBlock.cpp
  ir/base/decorator.cpp
  ir/base/metaProperty.cpp
  ir/base/methodDefinition.cpp
  ir/base/property.cpp
  ir/base/scriptFunction.cpp
  ir/base/spreadElement.cpp
  ir/base/templateElement.cpp
  ir/base/tsIndexSignature.cpp
  ir/base/tsMethodSignature.cpp
  ir/base/tsPropertySignature.cpp
  ir/base/tsSignatureDeclaration.cpp
  ir/expression.cpp
  ir/expressions/arrayExpression.cpp
  ir/expressions/arrowFunctionExpression.cpp
  ir/expressions/assignmentExpression.cpp
  ir/expressions/awaitExpression.cpp
  ir/expressions/binaryExpression.cpp
  ir/expressions/callExpression.cpp
  ir/expressions/chainExpression.cpp
  ir/expressions/classExpression.cpp
  ir/expressions/conditionalExpression.cpp
  ir/expressions/directEvalExpression.cpp
  ir/expressions/functionExpression.cpp
  ir/expressions/identifier.cpp
  ir/expressions/importExpression.cpp
  ir/expressions/literal.cpp
  ir/expressions/literals/bigIntLiteral.cpp
  ir/expressions/literals/booleanLiteral.cpp
  ir/expressions/literals/charLiteral.cpp
  ir/expressions/literals/nullLiteral.cpp
  ir/expressions/literals/numberLiteral.cpp
  ir/expressions/literals/regExpLiteral.cpp
  ir/expressions/literals/stringLiteral.cpp
  ir/expressions/memberExpression.cpp
  ir/expressions/newExpression.cpp
  ir/expressions/objectExpression.cpp
  ir/expressions/omittedExpression.cpp
  ir/expressions/sequenceExpression.cpp
  ir/expressions/superExpression.cpp
  ir/expressions/taggedTemplateExpression.cpp
  ir/expressions/templateLiteral.cpp
  ir/expressions/thisExpression.cpp
  ir/expressions/unaryExpression.cpp
  ir/expressions/updateExpression.cpp
  ir/expressions/yieldExpression.cpp
  ir/module/exportAllDeclaration.cpp
  ir/module/exportDefaultDeclaration.cpp
  ir/module/exportNamedDeclaration.cpp
  ir/module/exportSpecifier.cpp
  ir/module/importDeclaration.cpp
  ir/module/importDefaultSpecifier.cpp
  ir/module/importNamespaceSpecifier.cpp
  ir/module/importSpecifier.cpp
  ir/statement.cpp
  ir/statements/assertStatement.cpp
  ir/statements/blockStatement.cpp
  ir/statements/breakStatement.cpp
  ir/statements/classDeclaration.cpp
  ir/ets/etsStructDeclaration.cpp
  ir/statements/continueStatement.cpp
  ir/statements/debuggerStatement.cpp
  ir/statements/doWhileStatement.cpp
  ir/statements/emptyStatement.cpp
  ir/statements/expressionStatement.cpp
  ir/statements/forInStatement.cpp
  ir/statements/forOfStatement.cpp
  ir/statements/forUpdateStatement.cpp
  ir/statements/functionDeclaration.cpp
  ir/statements/ifStatement.cpp
  ir/statements/labelledStatement.cpp
  ir/statements/loopStatement.cpp
  ir/statements/returnStatement.cpp
  ir/statements/switchCaseStatement.cpp
  ir/statements/switchStatement.cpp
  ir/statements/throwStatement.cpp
  ir/statements/tryStatement.cpp
  ir/statements/variableDeclaration.cpp
  ir/statements/variableDeclarator.cpp
  ir/statements/whileStatement.cpp
  ir/as/namedType.cpp
  ir/as/prefixAssertionExpression.cpp
  ir/ets/etsClassLiteral.cpp
  ir/ets/etsFunctionType.cpp
  ir/ets/etsLaunchExpression.cpp
  ir/ets/etsNewArrayInstanceExpression.cpp
  ir/ets/etsNewClassInstanceExpression.cpp
  ir/ets/etsNewMultiDimArrayInstanceExpression.cpp
  ir/ets/etsPackageDeclaration.cpp
  ir/ets/etsParameterExpression.cpp
  ir/ets/etsPrimitiveType.cpp
  ir/ets/etsScript.cpp
  ir/ets/etsTypeReference.cpp
  ir/ets/etsTypeReferencePart.cpp
  ir/ets/etsUnionType.cpp
  ir/ets/etsWildcardType.cpp
  ir/ets/etsImportSource.cpp
  ir/ts/tsAnyKeyword.cpp
  ir/ts/tsArrayType.cpp
  ir/ts/tsAsExpression.cpp
  ir/ts/tsBigintKeyword.cpp
  ir/ts/tsBooleanKeyword.cpp
  ir/ts/tsClassImplements.cpp
  ir/ts/tsConditionalType.cpp
  ir/ts/tsConstructorType.cpp
  ir/ts/tsEnumDeclaration.cpp
  ir/ts/tsEnumMember.cpp
  ir/ts/tsExternalModuleReference.cpp
  ir/ts/tsFunctionType.cpp
  ir/ts/tsImportEqualsDeclaration.cpp
  ir/ts/tsImportType.cpp
  ir/ts/tsIndexedAccessType.cpp
  ir/ts/tsInferType.cpp
  ir/ts/tsInterfaceBody.cpp
  ir/ts/tsInterfaceDeclaration.cpp
  ir/ts/tsInterfaceHeritage.cpp
  ir/ts/tsIntersectionType.cpp
  ir/ts/tsLiteralType.cpp
  ir/ts/tsMappedType.cpp
  ir/ts/tsModuleBlock.cpp
  ir/ts/tsModuleDeclaration.cpp
  ir/ts/tsNamedTupleMember.cpp
  ir/ts/tsNeverKeyword.cpp
  ir/ts/tsNonNullExpression.cpp
  ir/ts/tsNullKeyword.cpp
  ir/ts/tsNumberKeyword.cpp
  ir/ts/tsObjectKeyword.cpp
  ir/ts/tsParameterProperty.cpp
  ir/ts/tsParenthesizedType.cpp
  ir/ts/tsQualifiedName.cpp
  ir/ts/tsStringKeyword.cpp
  ir/ts/tsThisType.cpp
  ir/ts/tsTupleType.cpp
  ir/ts/tsTypeAliasDeclaration.cpp
  ir/ts/tsTypeAssertion.cpp
  ir/ts/tsTypeLiteral.cpp
  ir/ts/tsTypeOperator.cpp
  ir/ts/tsTypeParameter.cpp
  ir/ts/tsTypeParameterDeclaration.cpp
  ir/ts/tsTypeParameterInstantiation.cpp
  ir/ts/tsTypePredicate.cpp
  ir/ts/tsTypeQuery.cpp
  ir/ts/tsTypeReference.cpp
  ir/ts/tsUndefinedKeyword.cpp
  ir/ts/tsUnionType.cpp
  ir/ts/tsUnknownKeyword.cpp
  ir/ts/tsVoidKeyword.cpp
  lexer/ASLexer.cpp
  lexer/keywords.cpp
  lexer/keywordsUtil.cpp
  lexer/lexer.cpp
  lexer/ETSLexer.cpp
  lexer/TSLexer.cpp
  lexer/regexp/regexp.cpp
  lexer/token/number.cpp
  lexer/token/sourceLocation.cpp
  lexer/token/token.cpp
  parser/context/classPrivateContext.cpp
  parser/context/parserContext.cpp
  parser/expressionParser.cpp
  parser/ASparser.cpp
  parser/JSparser.cpp
  parser/parserImpl.cpp
  parser/ETSparser.cpp
  parser/TSparser.cpp
  parser/TypedParser.cpp
  parser/program/program.cpp
  parser/statementParser.cpp
  checker/checker.cpp
  checker/checkerContext.cpp
  checker/ETSAnalyzer.cpp
  checker/ETSchecker.cpp
  checker/TSchecker.cpp
  checker/ASchecker.cpp
  checker/TSAnalyzer.cpp
  checker/JSchecker.cpp
  checker/ets/aliveAnalyzer.cpp
  checker/ets/arithmetic.cpp
  checker/ets/baseAnalyzer.cpp
  checker/ets/boxingConverter.cpp
  checker/ets/castingContext.cpp
  checker/ets/conversion.cpp
  checker/ets/dynamic.cpp
  checker/ets/function.cpp
  checker/ets/enum.cpp
  checker/ets/helpers.cpp
  checker/ets/narrowingConverter.cpp
  checker/ets/narrowingWideningConverter.cpp
  checker/ets/object.cpp
  checker/ets/primitiveWrappers.cpp
  checker/ets/typeConverter.cpp
  checker/ets/typeCreation.cpp
  checker/ets/typeRelationContext.cpp
  checker/ets/unboxingConverter.cpp
  checker/ets/wideningConverter.cpp
  checker/ts/binaryLikeExpression.cpp
  checker/ts/destructuringContext.cpp
  checker/ts/function.cpp
  checker/ts/helpers.cpp
  checker/ts/object.cpp
  checker/ts/typeCreation.cpp
  checker/ts/typeElaborationContext.cpp
  checker/ts/util.cpp
  checker/types/signature.cpp
  checker/types/type.cpp
  checker/types/typeRelation.cpp
  checker/types/globalTypesHolder.cpp
  checker/types/ets/byteType.cpp
  checker/types/ets/charType.cpp
  checker/types/ets/doubleType.cpp
  checker/types/ets/floatType.cpp
  checker/types/ets/intType.cpp
  checker/types/ets/longType.cpp
  checker/types/ets/shortType.cpp
  checker/types/ets/etsArrayType.cpp
  checker/types/ets/etsBooleanType.cpp
  checker/types/ets/etsDynamicType.cpp
  checker/types/ets/etsEnumType.cpp
  checker/types/ets/etsExtensionFuncHelperType.cpp
  checker/types/ets/etsFunctionType.cpp
  checker/types/ets/etsObjectType.cpp
  checker/types/ets/etsStringType.cpp
  checker/types/ets/etsTypeParameter.cpp
  checker/types/ets/etsUnionType.cpp
  checker/types/ets/etsVoidType.cpp
  checker/types/ets/wildcardType.cpp
  checker/types/ets/etsAsyncFuncReturnType.cpp
  checker/types/ts/anyType.cpp
  checker/types/ts/arrayType.cpp
  checker/types/ts/bigintLiteralType.cpp
  checker/types/ts/bigintType.cpp
  checker/types/ts/booleanLiteralType.cpp
  checker/types/ts/booleanType.cpp
  checker/types/ts/constructorType.cpp
  checker/types/ts/enumLiteralType.cpp
  checker/types/ts/enumType.cpp
  checker/types/ts/functionType.cpp
  checker/types/ts/indexInfo.cpp
  checker/types/ts/interfaceType.cpp
  checker/types/ts/neverType.cpp
  checker/types/ts/nonPrimitiveType.cpp
  checker/types/ts/nullType.cpp
  checker/types/ts/numberLiteralType.cpp
  checker/types/ts/numberType.cpp
  checker/types/ts/objectDescriptor.cpp
  checker/types/ts/objectLiteralType.cpp
  checker/types/ts/objectType.cpp
  checker/types/ts/stringLiteralType.cpp
  checker/types/ts/stringType.cpp
  checker/types/ts/tupleType.cpp
  checker/types/ts/typeParameter.cpp
  checker/types/ts/typeReference.cpp
  checker/types/ts/undefinedType.cpp
  checker/types/ts/unionType.cpp
  checker/types/ts/unknownType.cpp
  checker/types/ts/voidType.cpp
  util/arktsconfig.cpp
  util/bitset.cpp
  util/declgenEts2Ts.cpp
  util/helpers.cpp
  util/ustring.cpp
)

panda_add_library(es2panda-lib ${PANDA_DEFAULT_LIB_TYPE} ${ES2PANDA_LIB_SRC})
add_dependencies(es2panda-lib isa_gen_es2panda es2panda_keywords es2panda_signatures)

set(ICU_INCLUDE_DIRS
    ${PANDA_THIRD_PARTY_SOURCES_DIR}/icu/icu4c/source/common
    ${PANDA_THIRD_PARTY_SOURCES_DIR}/icu/icu4c/source/i18n
    ${PANDA_THIRD_PARTY_SOURCES_DIR}/icu/icu4c/source
)

panda_target_include_directories(es2panda-lib SYSTEM
  PRIVATE ${ICU_INCLUDE_DIRS}
)

panda_target_include_directories(es2panda-lib
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${OUTPUT_DIR}
)

panda_target_compile_options(es2panda-lib
  PRIVATE -fexceptions -Werror=shadow
)

panda_target_link_libraries(es2panda-lib
  PUBLIC arkbase hmicuuc.z
  PRIVATE arkassembler
)

if((CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1) OR
   (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0))
    panda_target_link_libraries(es2panda-lib
      PUBLIC stdc++fs
    )
endif()

if (PANDA_FUZZILLI)
  panda_target_compile_options(es2panda-lib
      PRIVATE -fPIC
  )
endif()
panda_add_sanitizers(TARGET es2panda-lib SANITIZERS
  ${PANDA_SANITIZERS_LIST})

# libes2panda does not include bytecode optimizer, because it is used in
# libarkruntime, and conflict with JIT setup ensues
set(ES2PANDA_PUBLIC_SOURCES
  public/es2panda_lib.cpp
  util/generateBin.cpp
  util/options.cpp
)


panda_add_library(es2panda-public ${PANDA_DEFAULT_LIB_TYPE} ${ES2PANDA_PUBLIC_SOURCES})
add_dependencies(es2panda-public es2panda-lib)

panda_target_include_directories(es2panda-public
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${OUTPUT_DIR}
)

panda_target_compile_definitions(es2panda-public
  PRIVATE "DEFAULT_ARKTSCONFIG=\"${GENERATED_DIR}/arktsconfig.json\""
)

panda_target_compile_options(es2panda-public
  PRIVATE -fexceptions -Werror=shadow
)

panda_target_link_libraries(es2panda-public
  PUBLIC arkbase es2panda-lib
  PRIVATE arkbytecodeopt
)

panda_add_sanitizers(TARGET es2panda-public SANITIZERS
  ${PANDA_SANITIZERS_LIST})

add_subdirectory(aot)

if(PANDA_WITH_TESTS)
  add_subdirectory(test)
endif()
