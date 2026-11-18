//go:build linux

package tcpfingerprint

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestOptionalProxyFirstByte(t *testing.T) {
	for _, tc := range []struct {
		name, initial   string
		header, failure bool
	}{
		{"silent legacy", "", false, false},
		{"legacy", "hello", false, false},
		{"complete", string(proxySignature), true, false},
		{"partial", string(proxySignature[:4]), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			c, err := net.Dial("tcp4", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = c.Write([]byte(tc.initial)); err != nil {
				t.Fatal(err)
			}
			got, err := peekProxyHeader(s, 50*time.Millisecond)
			if got != tc.header || (err != nil) != tc.failure {
				t.Fatalf("header=%v error=%v", got, err)
			}
			data := tc.initial
			if data == "" {
				data = "late legacy"
				if _, err = io.WriteString(c, data); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(data))
			if _, err = io.ReadFull(s, b); err != nil || string(b) != data {
				t.Fatalf("payload %q error %v", b, err)
			}
		})
	}
}

// 必须通过 unshare -n 在独立网络命名空间运行，避免接触主机规则。
func TestExitCrashRecovery(t *testing.T) {
	if os.Getenv("SBOX_TEST_NFT_NETNS") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	initNS, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || self == initNS {
		t.Fatal("requires a separate network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m, err := New(ctx, option.TCPFingerprintOptions{Rewrite: true, Queue: 19518}, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SBOX_TEST_NFT_CHILD") == "1" {
		if err = m.start(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("queue-ready")
		<-ctx.Done()
		return
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExitCrashRecovery$")
	child.Env = append(os.Environ(), "SBOX_TEST_NFT_CHILD=1")
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "queue-ready\n" {
		t.Fatalf("child start: %q %v", line, err)
	}
	// 活跃实例持有队列，第二个实例须拒绝启动并保留原表。
	other, _ := New(ctx, m.options, logger.NOP())
	err = other.start()
	other.Close()
	if err == nil || !m.ownsRules(ctx) {
		t.Fatal("active owner's rules lost")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if child.Wait() == nil {
		t.Fatal("expected signal exit")
	}
	if err = m.start(); err != nil {
		t.Fatal(err)
	}
	if !m.ownsRules(ctx) {
		t.Fatal("rules missing after restart")
	}
	m.Close()
	if exec.Command("nft", "list", "table", "inet", m.tableName()).Run() == nil {
		t.Fatal("cleanup left table")
	}
	if b, err := exec.Command("nft", "create", "table", "inet", m.tableName()).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	foreign, _ := New(ctx, m.options, logger.NOP())
	err = foreign.start()
	foreign.Close()
	if err == nil || exec.Command("nft", "list", "table", "inet", m.tableName()).Run() != nil {
		t.Fatal("foreign table not preserved")
	}
}
