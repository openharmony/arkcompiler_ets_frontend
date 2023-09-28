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

package com.ohos.migrator.test.java;

import java.lang.annotation.*;

class named_types {
    // Tests qualified types in SimpleType AST form
    java.lang.String text;

    public static class inner<T> {
         public class innertoo {
             public class inneragain {
             }
         }
    }
}

class auxilliary {
    // Tests qualified types in NameQualifiedType AST form
    public named_types. @TypeAnn inner foo() {
        return null;
    }

    // Tests qualified types in QualifiedType AST form
    public named_types.inner<String>.innertoo.inneragain bar() {
        return null;
    }

    // Test qualified types in ParametrizedType AST form
    public named_types.inner<String> foobar(named_types.inner<?> arg) {
        return null;
    }

    public named_types.inner<? extends String> barfoo(named_types.inner<? super String> arg) {
        return null;
    }
}

@Target(ElementType.TYPE_USE)
@interface TypeAnn { }
