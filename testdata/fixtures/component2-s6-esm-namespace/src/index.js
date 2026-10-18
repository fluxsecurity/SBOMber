import * as lodash from "lodash";

export function run() {
  return lodash.merge({ value: 1 }, { ready: true });
}

export function shadowed(lodash) {
  return lodash.merge({}, {});
}
