import type { DebouncedFunc } from "lodash";

export type Handler = DebouncedFunc<(value: string) => void>;

export function invokeLocal(DebouncedFunc: (value: string) => void): void {
  DebouncedFunc("hello");
}
