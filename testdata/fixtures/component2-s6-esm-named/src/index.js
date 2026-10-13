import { merge } from "lodash";

export function run() {
  return merge({ ok: true }, { ready: true });
}

export function shadowed(merge) {
  return merge({}, {});
}
