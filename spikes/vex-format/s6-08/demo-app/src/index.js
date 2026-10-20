const writeConfig = require('./config')
const parseArgs = require('./args')
const decodePath = require('./url')
const render = require('./render')

module.exports = function main (argv, settings, path) {
  const args = parseArgs(argv)
  return render('Hello <%= name %>', { name: decodePath(path), config: writeConfig(settings), args })
}
