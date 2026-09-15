import * as _ from "lodash";

const method = "template";

export function build(src, data) {
  const compiled = _.template(src);
  const dynamic = _[method](src);
  return [compiled(data), dynamic(data)];
}
