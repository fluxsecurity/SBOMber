import { merge } from "lodash";

export function handle() {
  return merge({ value: 1 }, { ready: true });
}
