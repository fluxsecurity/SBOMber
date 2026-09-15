module.exports = function (args, opts) {
    var argv = { _: [] };

    function setKey (obj, keys, value) {
        var o = obj;
        keys.slice(0, -1).forEach(function (key) {
            if (key === '__proto__') return;
            o = o[key];
        });
        o[keys[keys.length - 1]] = value;
    }

    return argv;
};
