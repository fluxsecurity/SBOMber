const { merge: combine } = require("lodash");

function run() {
  return combine({ value: 1 }, { ready: true });
}

function shadowed(combine) {
  return combine({}, {});
}

module.exports = { run, shadowed };
