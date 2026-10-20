// Only writes INI. ini.parse / ini.decode (CVE-2020-7788) are never called.
const ini = require('ini')

module.exports = function writeConfig (settings) {
  return ini.stringify(settings)
}
