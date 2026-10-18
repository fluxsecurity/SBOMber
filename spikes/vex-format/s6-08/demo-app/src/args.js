// Calls minimist() itself (CVE-2020-7598, CVE-2021-44906).
const minimist = require('minimist')

module.exports = function parseArgs (argv) {
  return minimist(argv)
}
