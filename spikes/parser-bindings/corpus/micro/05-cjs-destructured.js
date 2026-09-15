const { template, merge: mergeDeep } = require("lodash");

module.exports.apply = function apply(src, a, b) {
  return template(src)(mergeDeep(a, b));
};
