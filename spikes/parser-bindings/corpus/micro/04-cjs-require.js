const _ = require("lodash");
const path = require("node:path");

module.exports = function join(parts) {
  return _.uniq(parts).join(path.sep);
};
