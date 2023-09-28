let path = require('path');

module.exports = {
	mode: "development",
    	target: "node",
	entry: './build/javascript/src/linter/main.js',
	module: {
		rules: [
			{
				test: /\.js$/,
				exclude: path.resolve('./build/javascript/src/linter/TestRunner.js')
			}
		]
	},
	externalsType: 'commonjs',
	externals: {
		typescript: "typescript"
	},
	output: {
		filename: "tslinter.js"
	}
}
