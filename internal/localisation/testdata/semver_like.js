const debug = require('../internal/debug')

class Range {
  constructor (range, options) {
    this.raw = range.trim().split(/\s+/).join(' ')
    this.set = this.raw.split('||').map(r => this.parseRange(r))
  }

  format () {
    return this.set.map((comps) => comps.join(' ').trim()).join('||')
  }

  parseRange (range) {
    return range.split(' ')
  }
}

module.exports = Range

const replaceTildes = (comp, options) => {
  return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(' ')
}

const replaceTilde = (comp, options) => comp
