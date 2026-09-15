import { template } from "lodash";

export function render(data) {
  return template("<%= name %>")(data);
}
