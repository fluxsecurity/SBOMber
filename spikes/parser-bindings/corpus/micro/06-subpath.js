import template from "lodash/template";
import parser from "@babel/parser/lib/index.js";

export function compile(src) {
  parser.parse(src);
  return template(src);
}
