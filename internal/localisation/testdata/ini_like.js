exports.parse = exports.decode = decode
exports.stringify = exports.encode = encode
exports.safe = safe

function encode (obj, opt) {
  return String(obj)
}

function decode (str) {
  var out = {}
  var p = out
  str.split(/[\r\n]+/g).forEach(function (line, _, __) {
    if (line === '__proto__') return
    p[line] = true
  })
  return out
}

function safe (val) {
  return val
}
