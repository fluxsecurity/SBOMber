import { merge } from "lodash";

export function handleRequest(input) {
  return merge({}, input);
}
