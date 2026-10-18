export async function load(packageName) {
  await import(packageName);
}
