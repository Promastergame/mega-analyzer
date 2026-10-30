package vmware

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func executionFixture(t *testing.T) string {
	t.Helper()
	path := fixture(t)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("guestOS = \"windows9-64\"\nnumvcpus = \"6\"\nmemsize = \"8192\"\nscsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"disk.vmdk\"\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.WriteFile(filepath.Join(dir, "disk.vmdk"), []byte("# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\nRW 1 FLAT \"extent.vmdk\" 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extent.vmdk"), make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for attempt := 0; attempt < 10; attempt++ {
			if err := os.RemoveAll(dir); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return path
}

func TestPrepareVMwareBacksUpAndChangesOnlyGuestIsolation(t *testing.T) {
	path := executionFixture(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original = bytes.ReplaceAll(original, []byte(`"FALSE"`), []byte(`"TRUE"`))
	original = append(original, []byte("usb.autoConnect.device0 = \"path:test\"\nsharedFolder0.enabled = \"TRUE\"\n")...)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeVMware{path: path}
	report, err := New(fake.run, t.TempDir()).Prepare(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ConfigurationPass || !report.GuestExecution || report.Running {
		t.Fatalf("prepared report = %+v", report)
	}
	_, props, err := validateVMX(path)
	if err != nil || props["memsize"] != "8192" || props["numvcpus"] != "6" || props["ethernet0.present"] != "false" {
		t.Fatalf("unexpected guest settings: %v %v", props, err)
	}
	if _, exists := props["usb.autoconnect.device0"]; exists {
		t.Fatal("USB autoconnect rule remains")
	}
	backups, _ := filepath.Glob(path + ".mega-backup-*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	backup, _ := os.ReadFile(backups[0])
	if !bytes.Equal(backup, original) {
		t.Fatal("VMX backup is not byte-identical")
	}
	for _, args := range fake.calls {
		if args[0] != "list" && args[0] != "listSnapshots" {
			t.Fatalf("preparation started a guest operation: %v", args)
		}
	}
	prepared, _ := os.ReadFile(path)
	fake.active = true
	if _, err := New(fake.run, t.TempDir()).Prepare(context.Background(), path); err == nil {
		t.Fatal("running VM was modified")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, prepared) {
		t.Fatal("rejected preparation changed VMX")
	}
}

func TestVMDKSparseDescriptorAndUnsafeReferences(t *testing.T) {
	path := executionFixture(t)
	disk := filepath.Join(filepath.Dir(path), "disk.vmdk")
	descriptor := []byte("# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\nRW 1 SPARSE \"disk.vmdk\"\n")
	sparse := make([]byte, 1024)
	copy(sparse, "KDMV")
	binary.LittleEndian.PutUint64(sparse[28:], 1)
	binary.LittleEndian.PutUint64(sparse[36:], 1)
	copy(sparse[512:], descriptor)
	if err := os.WriteFile(disk, sparse, 0600); err != nil {
		t.Fatal(err)
	}
	_, props, _ := validateVMX(path)
	if check := checkVirtualDisks(path, props); !check.OK {
		t.Fatal(check.Message)
	}
	for _, bad := range []string{
		"# Disk DescriptorFile\ncreateType=\"fullDevice\"\nRW 1 FLAT \"extent.vmdk\" 0\n",
		"# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 1 FLAT \"\\\\.\\PhysicalDrive0\" 0\n",
		"# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 1 FLAT \"\\\\server\\disk.vmdk\" 0\n",
		"# Disk DescriptorFile\ncreateType=\"monolithicSparse\"\nparentFileNameHint=\"disk.vmdk\"\nRW 1 SPARSE \"disk.vmdk\"\n",
	} {
		if err := os.WriteFile(disk, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if checkVirtualDisks(path, props).OK {
			t.Fatalf("unsafe descriptor accepted: %s", bad)
		}
	}
	binary.LittleEndian.PutUint64(sparse[28:], ^uint64(0))
	if err := os.WriteFile(disk, sparse, 0600); err != nil {
		t.Fatal(err)
	}
	if checkVirtualDisks(path, props).OK {
		t.Fatal("overflowing sparse descriptor accepted")
	}
	props["scsi0:0.devicetype"] = "rawdisk"
	if check := checkVirtualDisks(path, props); check.OK || !strings.Contains(check.Message, "физическому") {
		t.Fatalf("raw VMX disk = %+v", check)
	}
}
