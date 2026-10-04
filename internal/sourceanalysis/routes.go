package sourceanalysis

import (
	"fmt"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// SyntheticRouteHandlerName is the exact public name for an anonymous route
// entry point.
const SyntheticRouteHandlerName = "<route_handler>"

var supportedRouteMethods = map[string]struct{}{
	"all":     {},
	"delete":  {},
	"get":     {},
	"head":    {},
	"options": {},
	"patch":   {},
	"post":    {},
	"put":     {},
	"use":     {},
}

func appendRouteHandlers(
	result *Result,
	root *treesitter.Node,
	source []byte,
) error {
	for _, call := range collectNodesByType(root, "call_expression") {
		function := call.ChildByFieldName("function")
		if function == nil || function.Kind() != "member_expression" {
			continue
		}

		receiver := function.ChildByFieldName("object")
		method := function.ChildByFieldName("property")
		if receiver == nil || method == nil ||
			receiver.Kind() != "identifier" ||
			method.Kind() != "property_identifier" {
			continue
		}

		receiverName := receiver.Utf8Text(source)
		methodName := method.Utf8Text(source)
		if receiverName != "app" && receiverName != "router" {
			continue
		}
		if _, supported := supportedRouteMethods[methodName]; !supported {
			continue
		}

		arguments := call.ChildByFieldName("arguments")
		if arguments == nil {
			return fmt.Errorf(
				"route call at bytes %d-%d has no arguments",
				call.StartByte(),
				call.EndByte(),
			)
		}

		handler, ok := uniqueRouteHandlerArgument(arguments)
		if !ok {
			continue
		}

		route := routeHandlerFromNode(
			handler,
			receiverName,
			methodName,
			source,
		)
		if route.Function == "" {
			continue
		}

		result.RouteHandlers = append(result.RouteHandlers, route)
	}

	return nil
}

func uniqueRouteHandlerArgument(
	arguments *treesitter.Node,
) (*treesitter.Node, bool) {
	var candidate *treesitter.Node

	for index := uint(0); index < arguments.NamedChildCount(); index++ {
		child := arguments.NamedChild(index)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case "identifier", "arrow_function", "function_expression":
			if candidate != nil {
				return nil, false
			}
			candidate = child
		}
	}

	return candidate, candidate != nil
}

func routeHandlerFromNode(
	handler *treesitter.Node,
	receiver string,
	method string,
	source []byte,
) RouteHandler {
	nameNode := handler
	name := ""
	synthetic := false

	switch handler.Kind() {
	case "identifier":
		name = handler.Utf8Text(source)

	case "arrow_function":
		name = SyntheticRouteHandlerName
		synthetic = true

	case "function_expression":
		nameNode = handler.ChildByFieldName("name")
		if nameNode == nil {
			nameNode = handler
			name = SyntheticRouteHandlerName
			synthetic = true
		} else {
			name = nameNode.Utf8Text(source)
		}
	}

	if name == "" || nameNode == nil {
		return RouteHandler{}
	}

	line, column := nodeLocation(source, nameNode)
	endLine, endColumn := nodeEndLocation(source, handler)
	route := RouteHandler{
		Receiver:  receiver,
		Method:    method,
		Function:  name,
		Line:      line,
		Column:    column,
		EndLine:   endLine,
		EndColumn: endColumn,
		Synthetic: synthetic,
	}

	return route
}
