// Calls decode-uri-component's default export (CVE-2022-38900).
const decode = require('decode-uri-component')

module.exports = function decodePath (path) {
  return decode(path)
}
