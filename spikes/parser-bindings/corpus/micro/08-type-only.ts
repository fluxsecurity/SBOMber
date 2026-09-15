import type { DebouncedFunc } from "lodash";
import { debounce } from "lodash";

export function wrap(fn: () => void): DebouncedFunc<() => void> {
  return debounce(fn, 100);
}
