const lodash = require("lodash");

function run() {
  return lodash.merge({ value: 1 }, { ready: true });
}

function shadowed(lodash) {
  return lodash.merge({}, {});
}

module.exports = { run, shadowed };
