package secure_test

import (
	"errors"
	"io"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
	"github.com/tuna-os/fisherman/internal/secure"
)

func TestResolveRootBackingDevice(t *testing.T) {
	oldOutput, oldRun := runner.OutputFn, runner.RunFn
	t.Cleanup(func() { runner.OutputFn, runner.RunFn = oldOutput, oldRun })

	for name, tc := range map[string]struct {
		status string
		isLuks error
		want   string
		fails  bool
	}{
		"valid backing device":  {status: "  device: /dev/nvme0n1p2\n", want: "/dev/nvme0n1p2"},
		"multiple device lines": {status: "device: /dev/sda2\ndevice: /dev/sdb2\n", fails: true},
		"non device path":       {status: "device: relative-path\n", fails: true},
		"missing device":        {status: "type: LUKS2\n", fails: true},
		"isLuks failure":        {status: "device: /dev/sda2\n", isLuks: errors.New("not luks"), fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			runner.OutputFn = func(name string, args ...string) ([]byte, error) {
				if name != "cryptsetup" || len(args) != 2 || args[0] != "status" || args[1] != "root" {
					t.Fatalf("status command = %s %q", name, args)
				}
				return []byte(tc.status), nil
			}
			runner.RunFn = func(_ io.Reader, name string, args ...string) error {
				if name != "cryptsetup" || len(args) != 2 || args[0] != "isLuks" || args[1] != "/dev/sda2" && args[1] != "/dev/nvme0n1p2" {
					t.Fatalf("isLuks command = %s %q", name, args)
				}
				return tc.isLuks
			}
			got, err := secure.ResolveRootBackingDevice()
			if tc.fails {
				if err == nil {
					t.Fatal("ambiguous or invalid backing device accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ResolveRootBackingDevice() = %q, %v", got, err)
			}
		})
	}
}

func TestResolveTargetRootBackingDevice(t *testing.T) {
	oldOutput, oldRun := runner.OutputFn, runner.RunFn
	t.Cleanup(func() { runner.OutputFn, runner.RunFn = oldOutput, oldRun })

	for name, tc := range map[string]struct {
		findmnt string
		status  string
		want    string
		fails   bool
	}{
		"mapper source with btrfs suffix": {findmnt: "/dev/mapper/root[/@]\n", status: "device: /dev/nvme0n1p2\n", want: "/dev/nvme0n1p2"},
		"dm source":                       {findmnt: "/dev/dm-0\n", status: "device: /dev/sda2\n", want: "/dev/sda2"},
		"non mapper source":               {findmnt: "/dev/sda2\n", fails: true},
		"multiple mapper sources":         {findmnt: "/dev/mapper/root\n/dev/mapper/other\n", fails: true},
		"multiple backing devices":        {findmnt: "/dev/mapper/root\n", status: "device: /dev/sda2\ndevice: /dev/sdb2\n", fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			runner.OutputFn = func(command string, args ...string) ([]byte, error) {
				switch command {
				case "findmnt":
					if len(args) != 5 || args[0] != "-n" || args[1] != "-o" || args[2] != "SOURCE" || args[3] != "--target" || args[4] != "/target" {
						t.Fatalf("findmnt command = %s %q", command, args)
					}
					return []byte(tc.findmnt), nil
				case "cryptsetup":
					if len(args) != 2 || args[0] != "status" {
						t.Fatalf("cryptsetup command = %s %q", command, args)
					}
					return []byte(tc.status), nil
				default:
					t.Fatalf("unexpected command %q", command)
				}
				return nil, nil
			}
			runner.RunFn = func(_ io.Reader, command string, args ...string) error {
				if command != "cryptsetup" || len(args) != 2 || args[0] != "isLuks" {
					t.Fatalf("isLuks command = %s %q", command, args)
				}
				return nil
			}

			got, err := secure.ResolveTargetRootBackingDevice("/target")
			if tc.fails {
				if err == nil {
					t.Fatal("invalid target root source accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ResolveTargetRootBackingDevice() = %q, %v", got, err)
			}
		})
	}
}
