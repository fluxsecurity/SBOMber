const NAME = "lodash";

export async function loadStatic() {
  const mod = await import("lodash");
  return mod.template;
}

export async function loadComputed() {
  const mod = await import(NAME);
  return mod.template;
}
