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

package com.ohos.migrator.test.kotlin;

abstract class C {
    fun no_modifiers() { }

    abstract public fun abstract_public(): String;

    open fun open_m() { }

    private fun private_m(x : Int) { }

    protected fun protected_m(a: Int, vararg b: Double) { }

    internal fun internal_m() { }
}