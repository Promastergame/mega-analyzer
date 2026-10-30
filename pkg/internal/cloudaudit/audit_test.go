package cloudaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func ids(xs []Issue) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x.ID] = true
	}
	return m
}
func TestContainerAndIAM(t *testing.T) {
	d := t.TempDir()
	y := `apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
  - securityContext:
      privileged: true
      capabilities:
        add: [SYS_ADMIN]
  volumes:
  - hostPath:
      path: /var/run/docker.sock
`
	os.WriteFile(filepath.Join(d, "pod.yaml"), []byte(y), 0644)
	iam := `{"Statement":[{"Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]}`
	os.WriteFile(filepath.Join(d, "iam.json"), []byte(iam), 0644)
	r, e := Analyze(d)
	if e != nil {
		t.Fatal(e)
	}
	got := ids(r.Issues)
	if !got["CLOUD-CONTAINER-001"] || !got["CLOUD-IAM-001"] {
		t.Fatalf("missing findings: %+v", r.Issues)
	}
}
func TestHelmTraversalOnlyInPluginMetadata(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "plugin.yaml"), []byte("name: x\nversion: ../../tmp/p\n"), 0644)
	r, _ := Analyze(d)
	if !ids(r.Issues)["CLOUD-K8S-002"] {
		t.Fatalf("missing traversal: %+v", r.Issues)
	}
}
