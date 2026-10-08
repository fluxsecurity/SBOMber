import { forEach, merge } from "lodash";

export function postWelcome(items) {
  return forEach(items, applyDefaults);
}

function applyDefaults(item) {
  return merge({}, item);
}
