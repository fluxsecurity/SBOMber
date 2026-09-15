package sourceanalysis

import _ "embed"

// usageQuery is the shared JS/TS extraction query proven by the parser spike.
//
//go:embed queries/usage.scm
var usageQuery []byte
