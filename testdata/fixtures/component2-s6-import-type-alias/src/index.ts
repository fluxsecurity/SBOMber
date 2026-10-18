import type { Dictionary as Lookup } from "lodash";

export type Values = Lookup<number>;

export function invokeLocal(Lookup: (value: number) => number): number {
  return Lookup(3);
}
