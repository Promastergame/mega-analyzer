package vmware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Console is a session-owned, loopback-only VMware VNC console. Its password
// is unrelated to Windows credentials and is replaced for every analysis.
type Console struct {
	address, password, vmx string
	port                   int
	previous               []string
	reservation            net.Listener
	ctx                    context.Context
	cancel                 context.CancelFunc
	client                 sync.Mutex
}

func (v *Console) Password() string { return v.password }

// Open admits one browser at a time, and closes its socket when the session ends.
func (v *Console) Open(ctx context.Context) (net.Conn, error) {
	if !v.client.TryLock() {
		return nil, ErrBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	unlink := context.AfterFunc(v.ctx, cancel)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", v.address)
	if err != nil {
		unlink()
		cancel()
		v.client.Unlock()
		return nil, err
	}
	owned := &consoleConn{Conn: conn}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	owned.release = func() { stop(); unlink(); cancel(); v.client.Unlock() }
	return owned, nil
}

type consoleConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *consoleConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func consoleSetting(line string) bool {
	key, _, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "\ufeff"), "=")
	return ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), "remotedisplay.vnc.")
}

func replaceConsoleSettings(data []byte, settings []string) []byte {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !consoleSetting(line) {
			lines = append(lines, strings.TrimSuffix(line, "\r"))
		}
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\r\n"), "\r\n") + "\r\n" + strings.Join(settings, "\r\n") + "\r\n")
}

func (c *Controller) writeConsoleVMX(ctx context.Context, path string, original, updated []byte) error {
	stage, err := os.CreateTemp(filepath.Dir(path), ".mega-console-*.vmx.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(stage.Name())
	_, writeErr := stage.Write(updated)
	err = errors.Join(writeErr, stage.Close())
	if err != nil {
		return err
	}
	if _, err := c.requireOff(ctx, path); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("настройки ВМ изменились при подключении консоли")
	}
	return os.Rename(stage.Name(), path)
}

func (c *Controller) prepareConsole(ctx context.Context, path string) (*Console, error) {
	if _, err := c.requireOff(ctx, path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var token [18]byte
	if _, err := rand.Read(token[:]); err != nil {
		listener.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	v := &Console{vmx: path, address: listener.Addr().String(), port: listener.Addr().(*net.TCPAddr).Port,
		password: base64.RawURLEncoding.EncodeToString(token[:6]), reservation: listener, ctx: lifetime, cancel: cancel}
	for _, line := range strings.Split(string(data), "\n") {
		if consoleSetting(line) {
			v.previous = append(v.previous, strings.TrimSuffix(line, "\r"))
		}
	}
	backup := path + ".mega-console-backup-" + hex.EncodeToString(token[6:])
	if err := os.WriteFile(backup, data, 0600); err != nil {
		v.close()
		return nil, err
	}
	settings := []string{`RemoteDisplay.vnc.enabled = "TRUE"`, `RemoteDisplay.vnc.ip = "127.0.0.1"`,
		`RemoteDisplay.vnc.port = "` + strconv.Itoa(v.port) + `"`, `RemoteDisplay.vnc.password = "` + v.password + `"`}
	if err := c.writeConsoleVMX(ctx, path, data, replaceConsoleSettings(data, settings)); err != nil {
		v.close()
		return nil, err
	}
	return v, nil
}

func (v *Console) close() {
	v.cancel()
	v.reservation.Close()
}

func (c *Controller) restoreConsole(ctx context.Context, v *Console) error {
	v.close()
	if _, err := c.requireOff(ctx, v.vmx); err != nil {
		return fmt.Errorf("настройки консоли сохраняются до выключения ВМ: %w", err)
	}
	_, props, err := validateVMX(v.vmx)
	if err != nil {
		return err
	}
	if props["remotedisplay.vnc.port"] != strconv.Itoa(v.port) || props["remotedisplay.vnc.ip"] != "127.0.0.1" {
		return errors.New("настройки консоли изменены извне; автоматическое восстановление пропущено")
	}
	current, err := os.ReadFile(v.vmx)
	if err != nil {
		return err
	}
	return c.writeConsoleVMX(ctx, v.vmx, current, replaceConsoleSettings(current, v.previous))
}
