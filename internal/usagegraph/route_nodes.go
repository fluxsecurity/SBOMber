package usagegraph

import "github.com/Xsamsx/SBOMber/internal/sourceanalysis"

const syntheticModuleName = "<module>"

// graphFunctions adds inline route handlers only to the internal graph view.
// The parser's public Functions array remains unchanged.
func graphFunctions(result sourceanalysis.Result) []sourceanalysis.Function {
	functions := append([]sourceanalysis.Function(nil), result.Functions...)
	counts := make(map[int]int)
	for _, route := range result.RouteHandlers {
		if route.Synthetic {
			counts[route.Line]++
		}
	}

	for _, route := range result.RouteHandlers {
		if !route.Synthetic || counts[route.Line] != 1 ||
			route.EndLine == 0 {
			continue
		}
		functions = append(functions, sourceanalysis.Function{
			Name:      sourceanalysis.SyntheticRouteHandlerName,
			Line:      route.Line,
			Column:    route.Column,
			EndLine:   route.EndLine,
			EndColumn: route.EndColumn,
			// An inline handler is named at its own node start.
			NodeLine:   route.Line,
			NodeColumn: route.Column,
		})
	}
	return functions
}

// graphCallOwner refuses to attribute a call through a nested anonymous
// function body. A callback reference alone is not a direct-call edge.
func graphCallOwner(
	result sourceanalysis.Result,
	call sourceanalysis.Call,
) (sourceanalysis.Function, bool) {
	owner, ok := sourceanalysis.EnclosingFunction(graphFunctions(result), call)
	sameEnd := make([]sourceanalysis.Function, 0)

	for _, span := range result.AnonymousFunctions {
		if !anonymousContainsCall(span, call) {
			continue
		}
		if !ok || positionBefore(
			span.EndLine, span.EndColumn,
			owner.EndLine, owner.EndColumn,
		) {
			return sourceanalysis.Function{}, false
		}
		if span.EndLine == owner.EndLine &&
			span.EndColumn == owner.EndColumn {
			sameEnd = append(sameEnd, span)
		}
	}

	// A named arrow or an inline route may own one anonymous body whose
	// end matches the owner. Another containing body starting later is a
	// nested callback, even if both bodies end at the same position.
	if len(sameEnd) > 1 {
		first := sameEnd[0]
		for _, span := range sameEnd[1:] {
			if positionBefore(
				span.Line, span.Column, first.Line, first.Column,
			) {
				first = span
			}
		}
		for _, span := range sameEnd {
			if span.Line != first.Line || span.Column != first.Column {
				return sourceanalysis.Function{}, false
			}
		}
	}
	if !ok {
		return sourceanalysis.Function{Name: syntheticModuleName, Line: 1}, true
	}
	return owner, true
}

func positionBefore(line, column, otherLine, otherColumn int) bool {
	return line < otherLine ||
		(line == otherLine && column < otherColumn)
}

func anonymousContainsCall(span sourceanalysis.Function, call sourceanalysis.Call) bool {
	if call.Line < span.Line || call.Line > span.EndLine {
		return false
	}
	if call.Line == span.Line && call.Column < span.Column {
		return false
	}
	if call.Line == span.EndLine && call.Column >= span.EndColumn {
		return false
	}
	return true
}
