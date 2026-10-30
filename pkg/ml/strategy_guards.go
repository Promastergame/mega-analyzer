package ml

import (
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// isConstructorMethod reports whether a method is an instance or static
// initializer. Replacing the entire body of <init>/<clinit> is destructive:
// it skips the super() chain and field/static initialisation, which either
// crashes at load time (VerifyError) or leaves objects half-constructed.
// Whole-body strategies must refuse these methods and let a structure-
// preserving strategy (condition inversion / partial bypass / constant flip)
// handle them instead.
func isConstructorMethod(mi *shared.MethodInfo) bool {
	if mi == nil {
		return false
	}
	if mi.IsConstructor {
		return true
	}
	name := strings.TrimSpace(mi.Name)
	return name == "<init>" || name == "<clinit>"
}
