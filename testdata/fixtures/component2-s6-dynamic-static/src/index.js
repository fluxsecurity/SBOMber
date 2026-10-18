export async function run() {
  const lodash = await import("lodash");
  return lodash.merge({ value: 1 }, { ready: true });
}
