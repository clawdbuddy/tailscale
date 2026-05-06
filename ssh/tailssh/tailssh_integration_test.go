// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest

package tailssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/sftp"
	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
)

// This file contains integration tests of the SSH functionality. These tests
// exercise everything except for the authentication logic.
//
// The tests make the following assumptions about the environment:
//
// - OS is one of MacOS or Linux
// - Test is being run as root (e.g. go test -tags integrationtest -c . && sudo ./tailssh.test -test.run TestIntegration)
// - TAILSCALED_PATH environment variable points at tailscaled binary
// - User "testuser" exists
// - "testuser" is in groups "groupone" and "grouptwo"

// testVarRoot is a temp directory used as the TailscaleVarRoot for
// host key generation during integration tests. The test containers
// don't have system host keys (/etc/ssh/ssh_host_*_key) since they
// only install openssh-client, so getHostKeys needs a valid var root
// to generate keys into.
var testVarRoot string

func TestMain(m *testing.M) {
	debugTest.Store(true)

	// Create our log file.
	if err := os.WriteFile("/tmp/tailscalessh.log", nil, 0666); err != nil {
		log.Fatal(err)
	}

	// Create a temp directory for SSH host keys.
	var err error
	testVarRoot, err = os.MkdirTemp("", "tailssh-test-var")
	if err != nil {
		log.Fatal(err)
	}

	// Pre-flight diagnostics. Any failure here is a setup bug; fail loud
	// instead of letting subtests fail with cryptic <1s errors. Every line
	// is also useful debug context when chasing flakes from CI artifacts.
	logPreflight()

	code := m.Run()

	os.RemoveAll(testVarRoot)

	// Print any log output from the incubator subprocesses.
	if b, err := os.ReadFile("/tmp/tailscalessh.log"); err == nil && len(b) > 0 {
		log.Print(string(b))
	}

	os.Exit(code)
}

// logPreflight prints environment information that's useful for diagnosing
// CI failures. It also fails fast with a descriptive message when a required
// invariant (test user exists, has a usable shell, host keys can be created,
// tailscaled binary is present) is violated, instead of leaving the failure
// to surface as a sub-second test crash with no log output.
//
// This runs unconditionally on every test binary invocation and must remain
// cheap and side-effect-free aside from creating the host-key directory.
func logPreflight() {
	log.Printf("preflight: GOOS=%s GOARCH=%s euid=%d", runtime.GOOS, runtime.GOARCH, os.Geteuid())
	if hn, err := os.Hostname(); err == nil {
		log.Printf("preflight: hostname=%s", hn)
	}
	log.Printf("preflight: TAILSCALED_PATH=%q", os.Getenv("TAILSCALED_PATH"))
	log.Printf("preflight: TS_SSH_INTEGRATION_TEST_USER=%q", os.Getenv("TS_SSH_INTEGRATION_TEST_USER"))
	log.Printf("preflight: testVarRoot=%s", testVarRoot)

	if p := os.Getenv("TAILSCALED_PATH"); p != "" {
		if fi, err := os.Stat(p); err != nil {
			log.Fatalf("preflight: TAILSCALED_PATH=%q not usable: %v", p, err)
		} else if fi.Mode()&0111 == 0 {
			log.Fatalf("preflight: TAILSCALED_PATH=%q is not executable (mode %v)", p, fi.Mode())
		}
	}

	if sshPath, err := exec.LookPath("ssh"); err == nil {
		log.Printf("preflight: ssh=%s", sshPath)
		if out, err := exec.Command("ssh", "-V").CombinedOutput(); err == nil {
			log.Printf("preflight: ssh -V: %s", bytes.TrimSpace(out))
		}
	} else {
		log.Printf("preflight: ssh not found in PATH (%v)", err)
	}

	username := exitCodeTestUser()
	log.Printf("preflight: exitCodeTestUser=%q", username)
	if u, err := user.Lookup(username); err != nil {
		log.Fatalf("preflight: user.Lookup(%q) failed: %v", username, err)
	} else {
		log.Printf("preflight: user %q -> uid=%s gid=%s home=%s", username, u.Uid, u.Gid, u.HomeDir)
	}
	if um, err := userLookup(username); err != nil {
		log.Fatalf("preflight: userLookup(%q) failed: %v", username, err)
	} else {
		shell := um.LoginShell()
		log.Printf("preflight: login shell for %q: %q", username, shell)
		if shell == "" {
			log.Fatalf("preflight: empty login shell for %q", username)
		}
		if _, err := exec.LookPath(shell); err != nil {
			// LookPath fails on absolute paths only if the file is not
			// executable / not found.
			if _, statErr := os.Stat(shell); statErr != nil {
				log.Fatalf("preflight: login shell %q for user %q is not usable: %v", shell, username, statErr)
			}
		}
	}

	// Generate host keys eagerly so the first parallel testServer() call
	// doesn't race other concurrent calls and so that any failure surfaces
	// here with full context instead of inside the SSH server goroutine.
	if _, err := getHostKeys(testVarRoot, log.Printf); err != nil {
		log.Fatalf("preflight: getHostKeys(%q) failed: %v", testVarRoot, err)
	}
	log.Printf("preflight: host keys ready in %s/ssh", testVarRoot)
}

func TestIntegrationSSH(t *testing.T) {
	homeDir := "/home/testuser"
	if runtime.GOOS == "darwin" {
		homeDir = "/Users/testuser"
	}

	tests := []struct {
		cmd             string
		want            []string
		forceV1Behavior bool
		skip            bool
		allowSendEnv    bool
	}{
		{
			cmd:             "id",
			want:            []string{"testuser", "groupone", "grouptwo"},
			forceV1Behavior: false,
		},
		{
			cmd:             "id",
			want:            []string{"testuser", "groupone", "grouptwo"},
			forceV1Behavior: true,
		},
		{
			cmd:             "pwd",
			want:            []string{homeDir},
			skip:            os.Getenv("SKIP_FILE_OPS") == "1" || !fallbackToSUAvailable(),
			forceV1Behavior: false,
		},
		{
			cmd:             "echo 'hello'",
			want:            []string{"hello"},
			skip:            os.Getenv("SKIP_FILE_OPS") == "1" || !fallbackToSUAvailable(),
			forceV1Behavior: false,
		},
		{
			cmd:             `echo "${GIT_ENV_VAR:-unset1} ${EXACT_MATCH:-unset2} ${TESTING:-unset3} ${NOT_ALLOWED:-unset4}"`,
			want:            []string{"working1 working2 working3 unset4"},
			forceV1Behavior: false,
			allowSendEnv:    true,
		},
		{
			cmd:             `echo "${GIT_ENV_VAR:-unset1} ${EXACT_MATCH:-unset2} ${TESTING:-unset3} ${NOT_ALLOWED:-unset4}"`,
			want:            []string{"unset1 unset2 unset3 unset4"},
			forceV1Behavior: false,
			allowSendEnv:    false,
		},
	}

	for _, test := range tests {
		if test.skip {
			continue
		}

		// run every test both without and with a shell
		for _, shell := range []bool{false, true} {
			shellQualifier := "no_shell"
			if shell {
				shellQualifier = "shell"
			}

			versionQualifier := "v2"
			if test.forceV1Behavior {
				versionQualifier = "v1"
			}

			t.Run(fmt.Sprintf("%s_%s_%s", test.cmd, shellQualifier, versionQualifier), func(t *testing.T) {
				sendEnv := map[string]string{
					"GIT_ENV_VAR": "working1",
					"EXACT_MATCH": "working2",
					"TESTING":     "working3",
					"NOT_ALLOWED": "working4",
				}
				s := testSession(t, test.forceV1Behavior, test.allowSendEnv, sendEnv)

				if shell {
					err := s.RequestPty("xterm", 40, 80, ssh.TerminalModes{
						ssh.ECHO:          1,
						ssh.TTY_OP_ISPEED: 14400,
						ssh.TTY_OP_OSPEED: 14400,
					})
					if err != nil {
						t.Fatalf("unable to request PTY: %s", err)
					}

					err = s.Shell()
					if err != nil {
						t.Fatalf("unable to request shell: %s", err)
					}

					// Read the shell prompt
					s.read()
				}

				got := s.run(t, test.cmd, shell)
				for _, want := range test.want {
					if !strings.Contains(got, want) {
						t.Errorf("%q does not contain %q", got, want)
					}
				}
			})
		}
	}
}

func TestIntegrationSFTP(t *testing.T) {
	for _, forceV1Behavior := range []bool{false, true} {
		name := "v2"
		if forceV1Behavior {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			filePath := "/home/testuser/sftptest.dat"
			if forceV1Behavior || !fallbackToSUAvailable() {
				filePath = "/tmp/sftptest.dat"
			}
			wantText := "hello world"

			cl := testClient(t, forceV1Behavior, false)
			scl, err := sftp.NewClient(cl)
			if err != nil {
				t.Fatalf("can't get sftp client: %s", err)
			}

			file, err := scl.Create(filePath)
			if err != nil {
				t.Fatalf("can't create file: %s", err)
			}
			_, err = file.Write([]byte(wantText))
			if err != nil {
				t.Fatalf("can't write to file: %s", err)
			}
			err = file.Close()
			if err != nil {
				t.Fatalf("can't close file: %s", err)
			}

			file, err = scl.OpenFile(filePath, os.O_RDONLY)
			if err != nil {
				t.Fatalf("can't open file: %s", err)
			}
			defer file.Close()
			gotText, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("can't read file: %s", err)
			}
			if diff := cmp.Diff(string(gotText), wantText); diff != "" {
				t.Fatalf("unexpected file contents (-got +want):\n%s", diff)
			}

			s := testSessionFor(t, cl, nil)
			got := s.run(t, "ls -l "+filePath, false)
			if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner user: %s", got)
			} else if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner group: %s", got)
			}
		})
	}
}

func TestIntegrationSCP(t *testing.T) {
	for _, forceV1Behavior := range []bool{false, true} {
		name := "v2"
		if forceV1Behavior {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			filePath := "/home/testuser/scptest.dat"
			if !fallbackToSUAvailable() {
				filePath = "/tmp/scptest.dat"
			}
			wantText := "hello world"

			cl := testClient(t, forceV1Behavior, false)
			scl, err := scp.NewClientBySSH(cl)
			if err != nil {
				t.Fatalf("can't get sftp client: %s", err)
			}

			err = scl.Copy(context.Background(), strings.NewReader(wantText), filePath, "0644", int64(len(wantText)))
			if err != nil {
				t.Fatalf("can't create file: %s", err)
			}

			outfile, err := os.CreateTemp("", "")
			if err != nil {
				t.Fatalf("can't create temp file: %s", err)
			}
			err = scl.CopyFromRemote(context.Background(), outfile, filePath)
			if err != nil {
				t.Fatalf("can't copy file from remote: %s", err)
			}
			outfile.Close()

			gotText, err := os.ReadFile(outfile.Name())
			if err != nil {
				t.Fatalf("can't read file: %s", err)
			}
			if diff := cmp.Diff(string(gotText), wantText); diff != "" {
				t.Fatalf("unexpected file contents (-got +want):\n%s", diff)
			}

			s := testSessionFor(t, cl, nil)
			got := s.run(t, "ls -l "+filePath, false)
			if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner user: %s", got)
			} else if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner group: %s", got)
			}
		})
	}
}

func TestSSHAgentForwarding(t *testing.T) {
	// Create a client SSH key
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})
	pkFile := filepath.Join(tmpDir, "pk")
	clientKey, clientKeyRSA := generateClientKey(t, pkFile)

	// Start upstream SSH server
	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatalf("unable to listen for SSH: %s", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
	})

	// Run an SSH server that accepts connections from that client SSH key.
	gs := gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			io.WriteString(s, "Hello world\n")
		},
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) error {
			// Note - this is not meant to be cryptographically secure, it's
			// just checking that SSH agent forwarding is forwarding the right
			// key.
			a := key.Marshal()
			b := clientKey.PublicKey().Marshal()
			if !bytes.Equal(a, b) {
				return errors.New("key mismatch")
			}
			return nil
		},
	}
	go gs.Serve(l)

	// Run tailscale SSH server and connect to it
	username := "testuser"
	tailscaleAddr := testServer(t, username, false, false)
	tcl, err := ssh.Dial("tcp", tailscaleAddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.Close() })

	s, err := tcl.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Set up SSH agent forwarding on the client
	err = agent.RequestAgentForwarding(s)
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{
		PrivateKey: clientKeyRSA,
	})
	err = agent.ForwardToAgent(tcl, keyring)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to SSH to the upstream test server using the forwarded SSH key
	// and run the "true" command.
	upstreamHost, upstreamPort, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	o, err := s.CombinedOutput(fmt.Sprintf(`ssh -T -o StrictHostKeyChecking=no -p %s upstreamuser@%s "true"`, upstreamPort, upstreamHost))
	if err != nil {
		t.Fatalf("unable to call true command: %s\n%s\n-------------------------", err, o)
	}
}

// TestIntegrationParamiko attempts to connect to Tailscale SSH using the
// paramiko Python library. This library does not request 'none' auth. This
// test ensures that Tailscale SSH can correctly handle clients that don't
// request 'none' auth and instead immediately authenticate with a public key
// or password.
func TestIntegrationParamiko(t *testing.T) {
	addr := testServer(t, "testuser", true, false)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to split addr %q: %s", addr, err)
	}

	out, err := exec.Command("python3", "-c", fmt.Sprintf(`
import paramiko.client as pm
from paramiko.ecdsakey import ECDSAKey
client = pm.SSHClient()
client.set_missing_host_key_policy(pm.AutoAddPolicy)
client.connect('%s', port=%s, username='testuser', pkey=ECDSAKey.generate(), allow_agent=False, look_for_keys=False)
client.exec_command('pwd')
`, host, port)).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to connect with Paramiko using public key auth: %s\n%q", err, string(out))
	}

	out, err = exec.Command("python3", "-c", fmt.Sprintf(`
import paramiko.client as pm
from paramiko.ecdsakey import ECDSAKey
client = pm.SSHClient()
client.set_missing_host_key_policy(pm.AutoAddPolicy)
client.connect('%s', port=%s, username='testuser', password='doesntmatter', allow_agent=False, look_for_keys=False)
client.exec_command('pwd')
`, host, port)).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to connect with Paramiko using password auth: %s\n%q", err, string(out))
	}
}

// TestLocalUnixForwarding tests direct-streamlocal@openssh.com, which is what
// podman remote (issue #12409) and VSCode Remote (issue #5295) use to reach
// Unix domain sockets on the remote host through SSH. The client opens a
// channel to a Unix socket path on the server, and data is proxied through.
func TestLocalUnixForwarding(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	// Create a Unix socket server in /tmp that simulates a service like
	// podman's API socket at /run/user/<uid>/podman/podman.sock.
	socketDir, err := os.MkdirTemp("", "tailssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "test-service.sock")

	ul, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })

	// The service echoes back whatever it receives, like an API server would.
	go func() {
		for {
			conn, err := ul.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// Start Tailscale SSH server with local port forwarding enabled.
	addr := testServerWithOpts(t, testServerOpts{
		username:                 "testuser",
		allowLocalPortForwarding: true,
	})

	// Connect to the Tailscale SSH server.
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	// Open a direct-streamlocal@openssh.com channel to the Unix socket,
	// exactly as podman remote does.
	conn, err := cl.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket through SSH: %s", err)
	}
	defer conn.Close()

	// Send data through the tunnel and verify it echoes back.
	want := "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n"
	_, err = io.WriteString(conn, want)
	if err != nil {
		t.Fatalf("failed to write through tunnel: %s", err)
	}

	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	if err != nil {
		t.Fatalf("failed to read through tunnel: %s", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestReverseUnixForwarding tests streamlocal-forward@openssh.com, which tools
// like VSCode Remote and Zed use to create Unix domain sockets on the remote
// host that forward connections back to the client through SSH.
func TestReverseUnixForwarding(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	// Start Tailscale SSH server with remote port forwarding enabled.
	addr := testServerWithOpts(t, testServerOpts{
		username:                  "testuser",
		allowRemotePortForwarding: true,
	})

	// Connect to the Tailscale SSH server.
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	// Request reverse forwarding -- the server creates a Unix socket and
	// forwards incoming connections back through the SSH tunnel.
	socketDir, err := os.MkdirTemp("", "tailssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	remoteSocketPath := filepath.Join(socketDir, "reverse.sock")

	ln, err := cl.ListenUnix(remoteSocketPath)
	if err != nil {
		t.Fatalf("failed to request reverse unix forwarding: %s", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Verify the socket file was created on the server side.
	if _, err := os.Stat(remoteSocketPath); err != nil {
		t.Fatalf("reverse forwarded socket not created: %s", err)
	}

	// Accept a connection from the tunnel (client side) and write data.
	want := "hello from reverse tunnel"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, want)
	}()

	// Connect directly to the socket on the server side, simulating a
	// local process connecting to the VSCode/Zed IPC socket.
	conn, err := net.Dial("unix", remoteSocketPath)
	if err != nil {
		t.Fatalf("failed to connect to reverse forwarded socket: %s", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read from reverse forwarded socket: %s", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestUnixForwardingDenied verifies that Unix socket forwarding is rejected
// when the SSH policy does not permit port forwarding.
func TestUnixForwardingDenied(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	// Start server with forwarding disabled (the default policy).
	addr := testServerWithOpts(t, testServerOpts{
		username: "testuser",
	})

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	// Direct Unix socket forwarding should be rejected.
	_, err = cl.Dial("unix", "/tmp/anything.sock")
	if err == nil {
		t.Error("expected direct unix forwarding to be rejected, but it succeeded")
	}

	// Reverse Unix socket forwarding should also be rejected.
	socketDir, err := os.MkdirTemp("", "tailssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })

	_, err = cl.ListenUnix(filepath.Join(socketDir, "denied.sock"))
	if err == nil {
		t.Error("expected reverse unix forwarding to be rejected, but it succeeded")
	}
}

// TestUnixForwardingPathRestriction verifies that socket paths outside the
// allowed directories (home, /tmp, /run/user/<uid>) are rejected even when
// forwarding is permitted by policy.
func TestUnixForwardingPathRestriction(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	addr := testServerWithOpts(t, testServerOpts{
		username:                  "testuser",
		allowLocalPortForwarding:  true,
		allowRemotePortForwarding: true,
	})

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	// Paths outside allowed directories should be rejected.
	restrictedPaths := []string{
		"/var/run/docker.sock",
		"/etc/evil.sock",
	}
	for _, path := range restrictedPaths {
		_, err := cl.Dial("unix", path)
		if err == nil {
			t.Errorf("expected direct forwarding to %q to be rejected, but it succeeded", path)
		}
	}
}

func fallbackToSUAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	_, err := exec.LookPath("su")
	if err != nil {
		return false
	}

	// Some operating systems like Fedora seem to require login to be present
	// in order for su to work.
	_, err = exec.LookPath("login")
	return err == nil
}

type session struct {
	*ssh.Session

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (s *session) run(t *testing.T, cmdString string, shell bool) string {
	t.Helper()

	if shell {
		_, err := s.stdin.Write([]byte(fmt.Sprintf("%s\n", cmdString)))
		if err != nil {
			t.Fatalf("unable to send command to shell: %s", err)
		}
	} else {
		err := s.Start(cmdString)
		if err != nil {
			t.Fatalf("unable to start command: %s", err)
		}
	}

	return s.read()
}

func (s *session) read() string {
	ch := make(chan []byte)
	go func() {
		defer close(ch)
		for {
			b := make([]byte, 1)
			n, err := s.stdout.Read(b)
			if n > 0 {
				ch <- b
			}
			if err != nil {
				return
			}
		}
	}()

	// Read first byte in blocking fashion.
	b, ok := <-ch
	if !ok {
		return ""
	}
	_got := b

	// Read subsequent bytes until EOF or silence.
readLoop:
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				break readLoop
			}
			_got = append(_got, b...)
		case <-time.After(1 * time.Second):
			break readLoop
		}
	}

	return string(_got)
}

func testClient(t *testing.T, forceV1Behavior bool, allowSendEnv bool, authMethods ...ssh.AuthMethod) *ssh.Client {
	t.Helper()
	return testClientForUser(t, "testuser", forceV1Behavior, allowSendEnv, authMethods...)
}

func testClientForUser(t *testing.T, username string, forceV1Behavior bool, allowSendEnv bool, authMethods ...ssh.AuthMethod) *ssh.Client {
	t.Helper()
	addr := testServer(t, username, forceV1Behavior, allowSendEnv)

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	return cl
}

func testServer(t *testing.T, username string, forceV1Behavior bool, allowSendEnv bool) string {
	srv := &server{
		lb:             &testBackend{localUser: username, forceV1Behavior: forceV1Behavior, allowSendEnv: allowSendEnv},
		logf:           log.Printf,
		tailscaledPath: os.Getenv("TAILSCALED_PATH"),
		timeNow:        time.Now,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err == nil {
				go srv.HandleSSHConn(&addressFakingConn{conn})
			}
		}
	}()

	return l.Addr().String()
}

type testServerOpts struct {
	username                  string
	forceV1Behavior           bool
	allowSendEnv              bool
	allowLocalPortForwarding  bool
	allowRemotePortForwarding bool
}

func testServerWithOpts(t *testing.T, opts testServerOpts) string {
	t.Helper()
	srv := &server{
		lb: &testBackend{
			localUser:                 opts.username,
			forceV1Behavior:           opts.forceV1Behavior,
			allowSendEnv:              opts.allowSendEnv,
			allowLocalPortForwarding:  opts.allowLocalPortForwarding,
			allowRemotePortForwarding: opts.allowRemotePortForwarding,
		},
		logf:           log.Printf,
		tailscaledPath: os.Getenv("TAILSCALED_PATH"),
		timeNow:        time.Now,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err == nil {
				go srv.HandleSSHConn(&addressFakingConn{conn})
			}
		}
	}()

	return l.Addr().String()
}

func testSession(t *testing.T, forceV1Behavior bool, allowSendEnv bool, sendEnv map[string]string) *session {
	cl := testClient(t, forceV1Behavior, allowSendEnv)
	return testSessionFor(t, cl, sendEnv)
}

func testSessionFor(t *testing.T, cl *ssh.Client, sendEnv map[string]string) *session {
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range sendEnv {
		s.Setenv(k, v)
	}

	t.Cleanup(func() { s.Close() })

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	s.Stdin = stdinReader
	s.Stdout = io.MultiWriter(stdoutWriter, os.Stdout)
	s.Stderr = io.MultiWriter(stderrWriter, os.Stderr)
	return &session{
		Session: s,
		stdin:   stdinWriter,
		stdout:  stdoutReader,
		stderr:  stderrReader,
	}
}

func generateClientKey(t *testing.T, privateKeyFile string) (ssh.Signer, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	if privateKey == nil {
		t.Fatal("failed to encoded private key")
	}
	err = os.WriteFile(privateKeyFile, privateKey, 0600)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, priv
}

// testBackend implements ipnLocalBackend
type testBackend struct {
	localUser                 string
	forceV1Behavior           bool
	allowSendEnv              bool
	allowLocalPortForwarding  bool
	allowRemotePortForwarding bool
}

func (tb *testBackend) ShouldRunSSH() bool {
	return true
}

func (tb *testBackend) NetMap() *netmap.NetworkMap {
	capMap := make(set.Set[tailcfg.NodeCapability])
	if tb.forceV1Behavior {
		capMap[tailcfg.NodeAttrSSHBehaviorV1] = struct{}{}
	}
	if tb.allowSendEnv {
		capMap[tailcfg.NodeAttrSSHEnvironmentVariables] = struct{}{}
	}
	return &netmap.NetworkMap{
		SSHPolicy: &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{Any: true}},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  tb.allowLocalPortForwarding,
						AllowRemotePortForwarding: tb.allowRemotePortForwarding,
					},
					SSHUsers:  map[string]string{"*": tb.localUser},
					AcceptEnv: []string{"GIT_*", "EXACT_MATCH", "TEST?NG"},
				},
			},
		},
		AllCaps: capMap,
	}
}

func (tb *testBackend) NetMapNoPeers() *netmap.NetworkMap { return tb.NetMap() }

func (tb *testBackend) WhoIs(_ string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	return (&tailcfg.Node{}).View(), tailcfg.UserProfile{
		LoginName: tb.localUser + "@example.com",
	}, true
}

func (tb *testBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (tb *testBackend) Dialer() *tsdial.Dialer {
	return nil
}

func (tb *testBackend) TailscaleVarRoot() string {
	return testVarRoot
}

func (tb *testBackend) NodeKey() key.NodePublic {
	return key.NodePublic{}
}

type addressFakingConn struct {
	net.Conn
}

func (conn *addressFakingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("100.100.100.101"),
		Port: 22,
	}
}

func (conn *addressFakingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("100.100.100.102"),
		Port: 10002,
	}
}

// TestIntegrationExitCodes verifies that SSH exit codes are correctly
// delivered to the client through the full server stack.
//
// The test exercises the production code path end-to-end: a real SSH server
// (tailssh.server) running with TAILSCALED_PATH set so the incubator is
// invoked, a real OS user with a real login shell, and a Go x/crypto/ssh
// client interpreting the wire-level exit-status frame. The fix in #18256
// is specifically about the order of exit-status, EOF, and CHANNEL_CLOSE
// frames on the wire, which is exactly what this exercises.
//
// Transient infrastructure failures (failure to dial the listener, auth
// errors before exec) are retried; only an exit code mismatch — the actual
// behavior we are asserting — is treated as a hard failure.
func TestIntegrationExitCodes(t *testing.T) {
	username := exitCodeTestUser()

	tests := []struct {
		name     string
		cmd      string
		wantCode int
	}{
		{
			name:     "success",
			cmd:      "true",
			wantCode: 0,
		},
		{
			name:     "exit_code_passthrough",
			cmd:      "exit 42",
			wantCode: 42,
		},
		{
			// Exit code 127 for command not found, per POSIX shell convention.
			// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08_02
			name:     "command_not_found",
			cmd:      "/nonexistent/binary",
			wantCode: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)

			runOnce := func() (gotCode int, transportErr error, exitErr error, out []byte) {
				cl, dialErr := dialTestClientForUser(t, username, false, false)
				if dialErr != nil {
					return -1, dialErr, nil, nil
				}
				defer cl.Close()
				s, err := cl.NewSession()
				if err != nil {
					return -1, fmt.Errorf("NewSession: %w", err), nil, nil
				}
				defer s.Close()

				type result struct {
					out []byte
					err error
				}
				done := make(chan result, 1)
				go func() {
					o, e := s.CombinedOutput(tt.cmd)
					done <- result{out: o, err: e}
				}()

				select {
				case res := <-done:
					out = res.out
					err = res.err
				case <-time.After(20 * time.Second):
					return -1, errors.New("ssh command timed out"), nil, out
				}

				if err == nil {
					return 0, nil, nil, out
				}
				var ee *ssh.ExitError
				if errors.As(err, &ee) {
					return ee.ExitStatus(), nil, ee, out
				}
				// Anything else (channel error, EOF before exit-status,
				// transport tear-down) is treated as transport noise so
				// it can be retried. The actual bug we're catching only
				// surfaces as ExitStatus().
				return -1, fmt.Errorf("non-exit ssh error: %w", err), nil, out
			}

			const maxAttempts = 3
			var lastErr error
			var lastOut []byte
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				gotCode, transportErr, _, out := runOnce()
				if transportErr != nil {
					t.Logf("attempt %d/%d: transport-level failure: %v; output:\n%s",
						attempt, maxAttempts, transportErr, out)
					lastErr = transportErr
					lastOut = out
					time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
					continue
				}
				// We got a definitive exit code from the server. This is
				// the assertion target; never retry past this point.
				if gotCode != tt.wantCode {
					t.Fatalf("exit code = %d, want %d; output:\n%s", gotCode, tt.wantCode, out)
				}
				return
			}
			t.Fatalf("ssh command %q never completed cleanly after %d attempts; last err: %v; last output:\n%s",
				tt.cmd, maxAttempts, lastErr, lastOut)
		})
	}
}

// TestOpenSSHExitCodes verifies that exit codes are propagated to a real
// OpenSSH client. This covers the client-visible behavior from #18256.
//
// macOS ships its own OpenSSH build (LibreSSL fork) with the system, which
// is what users of #18256 actually run; that's why this test must exercise
// the OpenSSH binary, not just the Go ssh client.
//
// The auth path is "none" auth: the client offers nothing, the tailssh
// server's clientAuth callback accepts it. We disable every other auth
// method so OpenSSH has nothing to fall back to and can't pick a different
// path on different OpenSSH versions.
func TestOpenSSHExitCodes(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("skipping test without OpenSSH client: %v", err)
	}

	username := exitCodeTestUser()

	if out, err := exec.Command(sshPath, "-V").CombinedOutput(); err == nil {
		t.Logf("OpenSSH version: %s", bytes.TrimSpace(out))
	}
	t.Logf("OpenSSH test user: %s", username)

	addr := testServer(t, username, false, false)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tailssh server listening on %s", addr)

	exitStatus := func(t *testing.T, err error) int {
		t.Helper()
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
		}
		return ee.ExitCode()
	}

	// OpenSSH-side exit codes that are infrastructure failures, not the
	// behavior we're asserting. Code 255 is "ssh internal error", e.g.
	// connect/auth failure before the remote command runs.
	//
	// https://man.openbsd.org/ssh.1#EXIT_STATUS
	isTransport := func(rc int) bool { return rc == 255 }

	tests := []struct {
		name     string
		cmd      string
		wantCode int
	}{
		{
			name:     "success",
			cmd:      "true",
			wantCode: 0,
		},
		{
			name:     "exit_code_passthrough",
			cmd:      "exit 42",
			wantCode: 42,
		},
		{
			name:     "command_not_found",
			cmd:      "/nonexistent/binary",
			wantCode: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)

			runOnce := func() (rc int, out []byte) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				cmd := exec.CommandContext(ctx, sshPath,
					"-vvv",
					"-F", "/dev/null",
					"-T",
					"-o", "BatchMode=yes",
					"-o", "ConnectTimeout=15",
					"-o", "GSSAPIAuthentication=no",
					"-o", "GlobalKnownHostsFile=/dev/null",
					"-o", "HostbasedAuthentication=no",
					"-o", "IdentityAgent=none",
					"-o", "KbdInteractiveAuthentication=no",
					"-o", "NumberOfPasswordPrompts=0",
					"-o", "PasswordAuthentication=no",
					"-o", "PreferredAuthentications=none",
					"-o", "PubkeyAuthentication=no",
					"-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null",
					"-p", port,
					username+"@"+host,
					tt.cmd,
				)
				o, err := cmd.CombinedOutput()
				if ctx.Err() == context.DeadlineExceeded {
					t.Logf("ssh command timed out; output:\n%s", o)
					return 255, o
				}
				return exitStatus(t, err), o
			}

			const maxAttempts = 3
			var lastOut []byte
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				rc, out := runOnce()
				lastOut = out
				if isTransport(rc) && rc != tt.wantCode {
					t.Logf("attempt %d/%d: ssh transport-level failure (rc=255); output:\n%s",
						attempt, maxAttempts, out)
					time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
					continue
				}
				// We got a definitive exit code; this is the assertion target.
				if rc != tt.wantCode {
					t.Fatalf("ssh exit code = %d, want %d; output:\n%s", rc, tt.wantCode, out)
				}
				return
			}
			t.Fatalf("ssh command %q never returned a non-transport exit status after %d attempts; last output:\n%s",
				tt.cmd, maxAttempts, lastOut)
		})
	}
}

func exitCodeTestUser() string {
	if username := os.Getenv("TS_SSH_INTEGRATION_TEST_USER"); username != "" {
		return username
	}
	return "testuser"
}

// dumpIncubatorLogOnFail prints the contents of /tmp/tailscalessh.log
// (where the incubator's logger writes) into the test output if the test
// failed. It's the single biggest debugging affordance for CI failures
// because the incubator runs as a separate process and its output never
// reaches t.Log otherwise.
func dumpIncubatorLogOnFail(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	b, err := os.ReadFile("/tmp/tailscalessh.log")
	if err != nil {
		t.Logf("could not read incubator log: %v", err)
		return
	}
	if len(b) == 0 {
		t.Logf("incubator log is empty (no incubator was launched, or its log was rotated)")
		return
	}
	t.Logf("---- /tmp/tailscalessh.log (%d bytes) ----\n%s\n---- end of incubator log ----",
		len(b), b)
}

// dialTestClientForUser is a non-fatal variant of testClientForUser used
// by retry-aware tests: it returns the dial error instead of t.Fatal'ing.
// Server lifetime is still tied to the test via t.Cleanup inside testServer.
func dialTestClientForUser(t *testing.T, username string, forceV1Behavior bool, allowSendEnv bool, authMethods ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	addr := testServer(t, username, forceV1Behavior, allowSendEnv)
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
		Timeout:         15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// TestLocalUnixForwardingHalfClose verifies that the bidirectional copy
// in Unix socket forwarding uses half-close correctly: when one direction
// finishes, the other direction's data is not lost. This tests the bicopy
// fix where the old cancel-on-first-direction-complete approach would
// prematurely teardown the slower direction.
func TestLocalUnixForwardingHalfClose(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() { debugTest.Store(false) })

	socketDir, err := os.MkdirTemp("", "tailssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "halfclose.sock")

	ul, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })

	// Service that reads all input, then sends a delayed response.
	// With the old bicopy (cancel on first direction complete),
	// the response would be lost because the channel would be torn
	// down when the client's write side finished.
	const response = "delayed-response-after-client-closes-write"
	go func() {
		for {
			conn, err := ul.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Read all input from client.
				io.ReadAll(conn)
				// Delay, then send response.
				time.Sleep(100 * time.Millisecond)
				io.WriteString(conn, response)
			}()
		}
	}()

	addr := testServerWithOpts(t, testServerOpts{
		username:                 "testuser",
		allowLocalPortForwarding: true,
	})

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	conn, err := cl.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket through SSH: %s", err)
	}

	// Send data and close write side (half-close).
	_, err = io.WriteString(conn, "request data")
	if err != nil {
		t.Fatalf("failed to write: %s", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	} else {
		// ssh.Conn doesn't expose CloseWrite, close the write side
		// by closing the whole conn -- but then we can't read.
		// Instead, just close and rely on the server seeing EOF.
		conn.Close()
	}

	// Read the delayed response. This is the critical assertion:
	// with the old bicopy, this would fail because the connection
	// would be torn down when we closed the write side.
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read response: %s", err)
	}
	if string(got) != response {
		t.Errorf("got %q, want %q", got, response)
	}
}

// TestIntegrationSIGHUP verifies that when an SSH session is terminated,
// the child process receives SIGHUP (matching POSIX terminal disconnect
// semantics) rather than SIGKILL.
func TestIntegrationSIGHUP(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() { debugTest.Store(false) })

	markerFile := filepath.Join(t.TempDir(), "sighup-received")

	cl := testClient(t, false, false)
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Start a process that traps SIGHUP and writes a marker file.
	// The process sleeps long enough for us to close the session.
	cmd := fmt.Sprintf(
		`trap 'echo received > %s; exit 0' HUP; sleep 30`,
		markerFile,
	)
	if err := s.Start(cmd); err != nil {
		t.Fatalf("failed to start command: %v", err)
	}

	// Give the process time to set up the signal handler.
	time.Sleep(500 * time.Millisecond)

	// Close the session, which should trigger SIGHUP to the process.
	s.Close()
	cl.Close()

	// Wait for the signal handler to run and write the marker file.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(markerFile); err == nil {
			// Marker file exists -- process received SIGHUP.
			data, _ := os.ReadFile(markerFile)
			if strings.TrimSpace(string(data)) != "received" {
				t.Fatalf("unexpected marker content: %q", data)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("process did not receive SIGHUP within timeout")
}
