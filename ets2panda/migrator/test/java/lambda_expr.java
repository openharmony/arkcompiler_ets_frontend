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

package com.ohos.migrator.tests.java;

class Main {

	interface I1 { void M(); }
	interface I2 { int M(boolean b); }
	interface I3 { int M(int i, String s); }

	void Test() {
		I1 i1 = () -> { };
		i1.M();

		I2 i2 = x -> !x ? 1 : 2;
		int i = i2.M(true);

		I2 i2_2 = getLambda();
		i2_2.M(false);

		PassLambdaByParam((x1, x2) -> x2.contains("x") ? x1 : 0);
	}

	I2 getLambda() {
		return (boolean b) -> {
			if (b)
				return 10;
			else
				return 20;
		};
	}

	int PassLambdaByParam(I3 i3) {
		return i3.M(10, "Text");
	}
}