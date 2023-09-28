let path = require('path');

module.exports = {
	mode: "development",
    	target: "node",
	entry: './build/src/main.js',
	externalsType: 'commonjs',
	externals: {
		typescript: "typescript",
		log4js: "log4js"
	},
	output: {
		filename: "tslinter.js"
	}
}
