import * as React from "react";
import { format } from "date-fns";

export const Stamp = ({ at }: { at: Date }) => <span>{format(at, "PP")}</span>;
