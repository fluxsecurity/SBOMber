import merge from "lodash/merge";

export function run() {
  return merge({ value: 1 }, { ready: true });
}

export function shadowed(merge) {
  return merge({}, {});
}
