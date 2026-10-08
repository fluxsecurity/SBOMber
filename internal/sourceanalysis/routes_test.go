package sourceanalysis

import (
	"path/filepath"
	"testing"
)

func TestStaticRouteHandlerCandidates(t *testing.T) {
	root := t.TempDir()
	writeTestSource(
		t,
		root,
		"routes.js",
		`app.get("/welcome", (request, response) => {
  return sendWelcome(request, response);
});

router.post("/submit", namedHandler);

client.get("/ignored", namedHandler);
items.forEach(namedHandler);

function namedHandler(request, response) {
  return response.send("ok");
}
`,
	)

	result, err := AnalyzeSource(filepath.Join(root, "routes.js"))
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	if len(result.RouteHandlers) != 2 {
		t.Fatalf(
			"route handlers = %+v, want inline and named handlers",
			result.RouteHandlers,
		)
	}

	inline := result.RouteHandlers[0]
	if inline.Receiver != "app" ||
		inline.Method != "get" ||
		inline.Function != "<route_handler>" ||
		inline.Line != 1 ||
		inline.EndLine != 3 ||
		!inline.Synthetic {
		t.Fatalf("unexpected inline route handler: %+v", inline)
	}

	named := result.RouteHandlers[1]
	if named.Receiver != "router" ||
		named.Method != "post" ||
		named.Function != "namedHandler" ||
		named.Line != 5 ||
		named.Synthetic {
		t.Fatalf("unexpected named route handler: %+v", named)
	}
}

func TestAmbiguousOrComputedRoutesStayUnsupported(t *testing.T) {
	root := t.TempDir()
	writeTestSource(
		t,
		root,
		"unsupported-routes.js",
		`app.get("/ambiguous", firstHandler, secondHandler);
app[method]("/computed", firstHandler);
registerRoute(app, firstHandler);

function firstHandler() {}
function secondHandler() {}
`,
	)

	result, err := AnalyzeSource(
		filepath.Join(root, "unsupported-routes.js"),
	)
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	if len(result.RouteHandlers) != 0 {
		t.Fatalf(
			"unsupported routes produced candidates: %+v",
			result.RouteHandlers,
		)
	}
}
