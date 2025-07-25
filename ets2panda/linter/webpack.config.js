/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

let path = require('path');

module.exports = {
	mode: 'development',
	target: 'node',
	entry: './build/cli/main.js',
	externalsType: 'commonjs',
	externals: {
		log4js: 'log4js'
	},
	output: {
		filename: 'tslinter.js'
	},
    resolve: {
        alias: {
            json5: require.resolve('json5/dist/index.js'),
        }
    }
};
