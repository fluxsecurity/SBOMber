// Calls _.template (CVE-2021-23337); other lodash advisories name other functions.
const _ = require('lodash')

module.exports = function render (template, data) {
  return _.template(template)(data)
}
