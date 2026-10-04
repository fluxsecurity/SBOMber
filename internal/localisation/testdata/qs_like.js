'use strict';

var utils = require('./utils');

var parseObject = function parseObjectRecursive(chain, val, options) {
    var obj;
    if (chain.length === 0) {
        obj = val;
    } else if (chain[0] !== '__proto__') {
        obj = {};
        obj[chain[0]] = parseObject(chain.slice(1), val, options);
    }
    return obj;
};

module.exports = function (str, opts) {
    return parseObject(str.split('.'), true, opts);
};
