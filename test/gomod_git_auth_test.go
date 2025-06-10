package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	goerrors "errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/Azure/dalec"
	"github.com/Azure/dalec/test/testenv"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerui"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	goVersion       = "1.23.5"
	usernameRoot    = "root"
	customScriptDir = "/tmp/dalec/internal/scripts"

	waitOnlineTimeout = 20 * time.Second
)

// GitServicesAttributes are the basic pieces of information needed to host two git
// servers, one via SSH and one via HTTP
type GitServicesAttributes struct {
	// ServerRoot is the root filesystem path of the git server. URL paths
	// refer to repositories relative to this root
	ServerRoot string
	// PrivateRepoPath is the filesystem path, relative to `serverRoot`, where
	// the private git repository is hosted
	PrivateRepoPath string
	// privateRepoPath is the URI path in the name of the public go module;
	// this public go module has a private dependency on the repo at
	// `privateRepoPath`
	PublicRepoPath string
	// HTTP Server path is the filesystem path of the already-built HTTP
	// server, installed into its final location.
	HTTPServerPath string

	// Host is the hostname of the git server
	Host string
	// Addr is the IPv4 address to which the hostname resolves
	Addr string

	// HTTPPort is the port on which the http git server runs
	HTTPPort string
	// SSHPort is the port on which the ssh git server runs
	SSHPort string
	// AgentSock is the filesystem path of the socket exposed by the SSH agent
	AgentSock string

	// HTTPServerBuildDir is the location at which the HTTP server program's
	// code will be loaded for building
	HTTPServerBuildDir string
	// HTTPServerBuildPath is the *local filesystem* location at which the HTTP server program's
	// code can be found
	HTTPServeCodeLocalPath string
	// OutDir is the location to which dalec will output files
	OutDir string

	// _tag is a private field and should not be accessed directly
	_tag string
}

type TestState struct {
	t      *testing.T
	ctx    context.Context
	client gwclient.Client
	attr   *GitServicesAttributes
}

type file struct {
	location string
	template string
}

type script struct {
	basename string
	template string
}

func (s *script) absPath() string {
	return filepath.Join(customScriptDir, s.basename)
}

func (s *script) inject(t *testing.T, obj any) []byte {
	f := file{
		template: cleanScript(s.template),
	}

	return f.inject(t, obj)
}

func (f *file) inject(t *testing.T, obj any) []byte {
	if obj == nil {
		return []byte(f.template)
	}

	tmpl, err := template.New("depending go mod").Parse(f.template)
	if err != nil {
		t.Fatalf("could not parse template: %s", err)
	}

	type injector struct {
		any
		GoVersion string
	}

	var contents bytes.Buffer
	tmpl.Execute(&contents, injector{
		any:       obj,
		GoVersion: goVersion,
	})

	return contents.Bytes()
}

func cleanScript(s string) string {
	var b bytes.Buffer

	tb := bytes.NewBuffer([]byte(s))
	sc := bufio.NewScanner(tb)

	for sc.Scan() {
		t := sc.Text()
		if strings.TrimSpace(t) == "" {
			continue
		}

		b.WriteString(t)
		b.WriteRune('\n')
	}

	return b.String()
}

func (a *GitServicesAttributes) Tag() string {
	if a._tag != "" {
		a._tag = identity.NewID()
	}

	return a._tag
}

func (a *GitServicesAttributes) repoAbsDir() string {
	return filepath.Join(a.ServerRoot, a.PrivateRepoPath)
}

func (a *GitServicesAttributes) inGitRepo(basename string) string {
	return filepath.Join(a.repoAbsDir(), basename)
}

func TestGomodGitAuth(t *testing.T) {
	// 0. Test boilerplate
	t.Parallel()
	ctx := startTestSpan(baseCtx, t)
	netHostBuildxEnv := testenv.NewWithNetHostBuildxInstance(ctx, t)
	tmpDir := t.TempDir()
	sshID := identity.NewID()

	const sourcename = "gitauth"

	// 1. Determine basic information, like the host and port for the http and
	// ssh services; also determine the socket file location for the ssh agent
	netHostBuildxEnv.RunTest(ctx, t, func(ctx context.Context, client gwclient.Client) {
		attr := GitServicesAttributes{
			ServerRoot:             "/srv/git",
			PrivateRepoPath:        "username/private",
			PublicRepoPath:         "username/public",
			HTTPServerPath:         "",
			Host:                   "host.docker.internal",
			Addr:                   "127.0.0.1",
			HTTPPort:               findRandomAvailablePort(t),
			SSHPort:                findRandomAvailablePort(t),
			AgentSock:              filepath.Join(tmpDir, "ssh.agent.sock"),
			HTTPServerBuildDir:     "/tmp/dalec/internal/dalec_coderoot",
			HTTPServeCodeLocalPath: "./test/cmd/git_repo",
			OutDir:                 "/tmp/dalec/internal/output",
		}

		testState := TestState{
			t:      t,
			ctx:    ctx,
			client: client,
		}

		// 1.5 Generate the go mod files
		dependingModfile := file{
			location: attr.inGitRepo("go.mod"),
			template: `
module {{ .Host }}/{{ .PublicRepoPath }}

go {{ .GoVersion }}

require {{ .Host }}/{{ .PrivateRepoPath }}.git {{ .Tag }}
`,
		}

		dependentModfile := file{
			location: attr.PublicRepoPath,
			template: `
module {{ .Host }}/{{ .PrivateRepoPath }}.git

go {{ .GoVersion }}
            `,
		}

		worker := worker(client)
		// 2. Set up the git repository
		// 2a. Create the files
		repo := llb.Scratch().
			With(testState.customFile(dependentModfile)).
			With(testState.customFile(file{
				location: attr.inGitRepo("foo"),
				template: "bar\n",
			})).
			With(testState.initializedGitRepo(worker))

		// 3c. Create the hosting container by loading the git repo into it
		gitHost := worker.With(hostedRepo(repo, attr.repoAbsDir()))

		dependingModfileContents := string(dependingModfile.inject(t, attr))
		t.Run("SSH", func(t *testing.T) {
			t.Parallel()
			testState := testState
			testState.t = t

			pubkey, privkey := generateKeyPair(t)

			const githostUsername = "root"
			sshGitHost := gitHost.With(authorizedKey(pubkey, githostUsername))
			agentErrChan := testState.startSSHAgent(privkey)
			sshErrChan := testState.startSSHServer(sshGitHost)

			auth := dalec.GomodGitAuth{
				SSH: &dalec.GomodGitAuthSSH{
					ID:       sshID,
					Username: githostUsername,
				},
			}

			spec := testState.generateSpec(auth, dependingModfileContents)
			sr := newSolveRequest(
				withBuildTarget("debug/gomods"),
				withSpec(ctx, t, spec),
				withExtraHost(testState.attr.Host, testState.attr.Addr),
			)

			solveResultChan := make(chan *gwclient.Result)
			solveErrChan := make(chan error)

			outDirBase := testState.attr.PrivateRepoPath + "/user"
			solveTCh(ctx, t, testState.client, sr, solveResultChan, solveErrChan)

			var res *gwclient.Result
			select {
			case err := <-agentErrChan:
				t.Fatalf("ssh agent unexpededly failed: %s", err)
			case err := <-sshErrChan:
				t.Fatalf("ssh server unexpededly failed: %s", err)
			case err := <-solveErrChan:
				t.Fatalf("solve failed: %s", err)
			case r := <-solveResultChan:
				res = r
			}

			modDir := getDirName(ctx, t, res, outDirBase, "private.git@*")
			filename := filepath.Join(outDirBase, modDir, "foo")
			checkFile(ctx, t, filename, res, []byte("bar\n"))

			// }, testenv.WithHostNetworking, testenv.WithSSHSocket(sshID, sockfile))

			// const outDirBase = gomodGitHost + "/user"
			// res := solveT(ctx, t, c, sr)
			// modDir := getDirName(ctx, t, res, outDirBase, "private.git@*")

			// filename := filepath.Join(outDirBase, modDir, "hello")
			// checkFile(ctx, t, filename, res, []byte("hello\n"))
			// }, testenv.WithSecrets(testenv.KeyVal{
			// K: "super-secret",
			// V: "value",
			// }), testenv.WithHostNetworking)

		})

		// 3d. Load the authorized public key into the container

		// 3e. Start the SSH server

		t.Run("HTTP", func(t *testing.T) {
			t.Parallel()
			testState := testState
			testState.t = t

			httpGitHost := gitHost.With(testState.updateGitconfig())
			httpErrChan := testState.startHTTPServer(httpGitHost)

			auth := dalec.GomodGitAuth{
				Token: "super-secret",
			}

			spec := testState.generateSpec(auth, dependingModfileContents)

			sr := newSolveRequest(
				withBuildTarget("debug/gomods"),
				withSpec(ctx, t, spec),
				withExtraHost(testState.attr.Host, testState.attr.Addr),
				withBuildContext(ctx, t, "gomod-worker", worker.With(testState.updateGitconfig())),
			)

			solveResultChan := make(chan *gwclient.Result)
			solveErrChan := make(chan error)
			solveTCh(ctx, t, testState.client, sr, solveResultChan, solveErrChan)

			var res *gwclient.Result
			select {
			case err := <-httpErrChan:
				t.Fatalf("ssh server unexpededly failed: %s", err)
			case err := <-solveErrChan:
				t.Fatalf("solve failed: %s", err)
			case r := <-solveResultChan:
				res = r
			}

			outDirBase := testState.attr.PrivateRepoPath + "/user"
			modDir := getDirName(ctx, t, res, outDirBase, "private.git@*")
			filename := filepath.Join(outDirBase, modDir, "foo")
			checkFile(ctx, t, filename, res, []byte("bar\n"))
		})

	})
}

func (ts *TestState) generateSpec(auth dalec.GomodGitAuth, gomodContents string) *dalec.Spec {
	const sourceName = "gitauth"
	var port string

	switch {
	case auth.Token != "":
		port = ts.attr.HTTPPort
	case auth.SSH != nil:
		port = ts.attr.SSHPort
	default:
		ts.t.Fatal("cannot tell which kind of spec is needed, aborting")
	}

	spec := &dalec.Spec{
		Name: "gomod-git-auth",
		Sources: map[string]dalec.Source{
			sourceName: {
				Inline: &dalec.SourceInline{
					Dir: &dalec.SourceInlineDir{
						Files: map[string]*dalec.SourceInlineFile{
							"go.mod": {
								Contents: string(gomodContents),
							},
						},
					},
				},
				Generate: []*dalec.SourceGenerator{
					{
						Gomod: &dalec.GeneratorGomod{
							Auth: map[string]dalec.GomodGitAuth{
								fmt.Sprintf("%s:%s", ts.attr.Host, port): auth,
							},
						},
					},
				},
			},
		},
	}
	return spec
}

func (ts *TestState) startHTTPServer(gitHost llb.State) chan error {
	t := ts.t

	serverScript := script{
		basename: "run_http_server.sh",
		template: `
            #!/usr/bin/env sh
            exec {{ .HTTPServerPath }}/host
        `,
	}

	// This script attempts to connect to the http server. The `nc -z` flag
	// discconnects and exits with status 0 if a successful connection is made.
	// `nc -w5` gives up and exits with status 1 after a 5-second timeout.
	waitScript := script{
		basename: "wait_for_http.sh",
		template: `
            #!/usr/bin/env sh
            while ! nc -zw5 "{{ .Host }}" "{{ .HTTPPort }}"; do
                sleep 0.1
            done
        `,
	}

	httpServerBin := ts.getMainDockerContext().
		With(ts.builtHTTPServer(gitHost))

	gitHost = gitHost.
		With(ts.customScript(waitScript))

	cont := ts.newContainer(gitHost, customMount{
		dst: ts.attr.HTTPServerPath,
		st:  httpServerBin,
	})

	env := ts.getStateEnv(gitHost)
	errChan := ts.runContainer(cont, env, serverScript)

	t.Log("waiting for http server to come online")

	timeout := waitOnlineTimeout
	ts.runWaitScript(cont, env, waitScript, timeout)

	t.Logf("ssh server is online")

	return errChan
}

func (ts *TestState) builtHTTPServer(worker llb.State) llb.StateOption {
	s := script{
		basename: "build_http_server.sh",
		template: `
            #!/usr/bin/env sh
            set -ex
            cd {{ .HTTPServerBuildDir }}
            go build -o {{ .OutDir }}/host ./{{ .HTTPServeCodeLocalPath }}
        `,
	}

	return func(code llb.State) llb.State {
		return ts.runScriptOn(worker, s,
			llb.AddMount(ts.attr.HTTPServerBuildDir, code),
		).AddMount(ts.attr.OutDir, llb.Scratch())
	}
}

func (ts *TestState) getMainDockerContext() llb.State {
	var (
		t      = ts.t
		ctx    = ts.ctx
		client = ts.client
	)

	dc, err := dockerui.NewClient(client)
	if err != nil {
		t.Fatalf("could not create dockerui client: %s", err)
	}

	gitServerProgramPtr, err := dc.MainContext(ctx)
	if err != nil {
		t.Fatalf("could not obtain main docker context: %s", err)
	}

	if gitServerProgramPtr == nil {
		t.Fatalf("main context is nil")
	}

	return *gitServerProgramPtr
}

type customMount struct {
	dst string
	st  llb.State
}

func (ts *TestState) newContainer(rootfs llb.State, customMounts ...customMount) gwclient.Container {
	t := ts.t
	ctx := ts.ctx
	client := ts.client
	attr := ts.attr

	mountCfgs := []customMount{
		{
			dst: "/",
			st:  rootfs,
		},
	}
	mountCfgs = append(mountCfgs, customMounts...)

	mounts := make([]gwclient.Mount, len(mountCfgs))
	for _, cm := range customMounts {
		mounts = append(mounts, gwclient.Mount{
			Dest: cm.dst,
			Ref:  ts.stateToRef(cm.st),
		})
	}

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts:  mounts,
		NetMode: pb.NetMode_HOST,
		ExtraHosts: []*pb.HostIP{
			{
				Host: attr.Host,
				IP:   attr.Addr,
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create ssh server container: %s", err)
	}

	return cont
}

func (ts *TestState) customFile(f file) llb.StateOption {
	dir := filepath.Dir(f.location)

	return func(s llb.State) llb.State {
		return s.File(
			llb.Mkdir(dir, 0o755, llb.WithParents(true)).
				Mkfile(f.location, 0o644, f.inject(ts.t, ts.attr)),
		)
	}
}

func (ts *TestState) customScript(s script) llb.StateOption {
	dir := customScriptDir
	absPath := filepath.Join(dir, s.basename)

	return func(worker llb.State) llb.State {
		return worker.File(
			llb.Mkdir(dir, 0o755, llb.WithParents(true)).
				Mkfile(absPath, 0o755, s.inject(ts.t, ts.attr)),
		)
	}
}

// startSSHServer starts an sshd instance in a container hosting the git repo.
// It runs asynchonously and checks the connection after starting the server.
func (ts *TestState) startSSHServer(gitHost llb.State) chan error {
	t := ts.t

	// This script runs an ssh server. Rather than create a new user, we will
	// permit root login to simplify things. It is running in a container so
	// this should not be a security issue.
	serverScript := script{
		basename: "start_ssh_server.sh",
		template: `
            #!/usr/bin/env sh
            set -ex
            ssh-keygen -A
            exec /usr/sbin/sshd -o PermitRootLogin=yes -p {{ .Port }} -D
        `,
	}

	// This script attempts to connect to the ssh server. The `nc -z` flag
	// discconnects and exits with status 0 if a successful connection is made.
	// `nc -w5` gives up and exits with status 1 after a 5-second timeout.
	waitScript := script{
		basename: "wait_for_ssh.sh",
		template: `
            #!/usr/bin/env sh
            while ! nc -zw5 "{{ .Host }}" "{{ .SSHPort }}"; do
                sleep 0.1
            done
`,
	}

	gitHost = gitHost.
		With(ts.customScript(serverScript)).
		With(ts.customScript(waitScript))

	cont := ts.newContainer(gitHost)

	env := ts.getStateEnv(gitHost)
	errChan := ts.runContainer(cont, env, serverScript)

	t.Log("waiting for ssh server to come online")

	timeout := waitOnlineTimeout
	ts.runWaitScript(cont, env, waitScript, timeout)

	t.Logf("ssh server is online")

	return errChan
}

type bufCloser struct {
	*bytes.Buffer
}

func (b *bufCloser) Close() error {
	return nil
}

func (ts *TestState) startContainer(cont gwclient.Container, env []string, s script) gwclient.ContainerProcess {
	var (
		t   = ts.t
		ctx = ts.ctx
	)
	stdout := bufCloser{bytes.NewBuffer(nil)}
	stderr := bufCloser{bytes.NewBuffer(nil)}

	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Env:    env,
		Stdout: &stdout,
		Stderr: &stderr,
		Args:   []string{s.absPath()},
	})
	if err != nil {
		t.Fatalf("could not start server: %s\nstdout:\n%s\n===\nstderr:\n%s\n", err, stdout.String(), stderr.String())
	}

	return cp
}

func (ts *TestState) withTimeout(timeout time.Duration) (*TestState, func()) {
	if ts == nil {
		return ts, func() {}
	}

	ts2 := *ts

	var cancel func()
	ts2.ctx, cancel = context.WithTimeout(ts2.ctx, timeout)

	return &ts2, cancel
}

func (ts *TestState) runWaitScript(cont gwclient.Container, env []string, s script, timeout time.Duration) {
	ts2, cancel := ts.withTimeout(timeout)
	defer cancel()

	untilConnected := ts2.startContainer(cont, env, s)

	if err := untilConnected.Wait(); err != nil {
		if goerrors.Is(err, context.DeadlineExceeded) {
			ts2.t.Fatalf("Could not start server, timed out: %s", err)
		}

		ts2.t.Fatalf("could not check progress of server, container command failed: %s", err)
	}
}

var (
	errContainerNoStart = goerrors.New("could not start server container")
	errContainerFailed  = goerrors.New("container process failed")
)

// runContainer runs a container in the background and sends errors to the returned channel
func (ts *TestState) runContainer(cont gwclient.Container, env []string, s script) chan error {
	ec := make(chan error)

	var (
		ctx = ts.ctx
	)

	stdout := bufCloser{bytes.NewBuffer(nil)}
	stderr := bufCloser{bytes.NewBuffer(nil)}

	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Args:   []string{s.absPath()},
		Env:    env,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		ec <- goerrors.Join(errContainerNoStart, err)
	}

	// Log but do not fail, since you cannot fail from within a goroutine
	go func() {
		if err := cp.Wait(); err != nil {
			ec <- goerrors.Join(errContainerFailed, err)
		}
	}()

	return ec
}

func (ts *TestState) getStateEnv(st llb.State) []string {
	env, err := st.Env(ts.ctx)
	if err != nil {
		ts.t.Logf("unable to copy env: %s", err)
	}

	return env.ToArray()
}

func authorizedKey(pubkey ssh.PublicKey, username string) llb.StateOption {
	dir := filepath.Join("home", username)
	if username == usernameRoot {
		dir = "/root"
	}
	dir = filepath.Join(dir, ".ssh")

	const basename = "authorized_keys"
	absPath := filepath.Join(dir, basename)

	pubkeyData := ssh.MarshalAuthorizedKey(pubkey)

	return func(s llb.State) llb.State {
		return s.File(
			llb.Mkdir(dir, 0o700, llb.WithParents(true)).
				Mkfile(absPath, 0o600, pubkeyData),
		)
	}
}

func hostedRepo(repo llb.State, mountpoint string) llb.StateOption {
	return func(worker llb.State) llb.State {
		return worker.File(
			llb.Mkdir(mountpoint, 0o755, llb.WithParents(true)).
				Copy(repo, "/", mountpoint),
		)
	}
}

func (ts *TestState) mountScript(s script) dalec.RunOptFunc {
	scriptDir := customScriptDir
	st := llb.Scratch().With(ts.customScript(s))

	return func(ei *llb.ExecInfo) {
		llb.AddMount(scriptDir, st).SetRunOption(ei)
	}
}

// `runScript` is a replacement for `llb.State.Run(...)`. It mounts the
// specified script in the custom script directory, then generates the llb to
// run the script on `worker`.
func (ts *TestState) runScriptOn(worker llb.State, s script, runopts ...llb.RunOption) llb.ExecState {
	o := []llb.RunOption{
		llb.Args([]string{s.absPath()}),
		ts.mountScript(s),
	}

	o = append(o, runopts...)
	return worker.Run(o...)
}

// initializedGitRepo returns a stateOption that uses `worker` to create an
// initialized git repository from the base state.
func (ts *TestState) initializedGitRepo(worker llb.State) llb.StateOption {
	attr := ts.attr

	repoScript := script{
		basename: "git_init.sh",
		template: `
            #!/usr/bin/env sh

            set -ex
            export GIT_CONFIG_NOGLOBAL=true
            git init
            git config user.name foo
            git config user.email foo@bar.com

            git add -A
            git commit -m commit --no-gpg-sign
            git tag {{ .Tag }}
`,
	}

	return func(repo llb.State) llb.State {
		worker = worker.Dir(attr.PrivateRepoPath)

		return ts.runScriptOn(worker, repoScript).
			AddMount(attr.repoAbsDir(), llb.Scratch())
	}
}

func (ts *TestState) startSSHAgent(privkey crypto.PrivateKey) chan error {
	ec := make(chan error)
	ts.t.Cleanup(func() {
		close(ec)
	})

	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{
		PrivateKey: privkey,
	})

	listener, err := net.Listen("unix", ts.attr.AgentSock)
	if err != nil {
		ts.t.Fatalf("can't listen on unix socket: %s", err)
	}

	go func() {
		c, err := listener.Accept()
		if err != nil {
			ec <- fmt.Errorf("listener.Accept: %w", err)
		}

		if err := agent.ServeAgent(kr, c); err != nil {
			ec <- fmt.Errorf("cannot serve agent: %w", err)
		}
	}()

	return ec
}

// func testGomodGitAuthGeneric(t *testing.T, ctx context.Context, buildEnv *testenv.BuildxEnv, auth dalec.GomodGitAuth) {
// 	t.Parallel()
// 	ctx = startTestSpan(ctx, t)
// 	tag := identity.NewID()

// 	dependingGomodFileContents := generateGoDotModFileContents(t, dependingModfileTemplate, tag)
// 	port := getAvailablePort(t)
// 	hostPort := fmt.Sprintf("%s:%s", gomodGitHost, port)

// 	// spec :=
// }

// func gomodGitAuthTest(t *testing.T, parentCtx context.Context, buildEnv *testenv.BuildxEnv, spec *dalec.Spec) {
// 	ctx := startTestSpan(parentCtx, t)
// 	tag := identity.NewID()

// }

func generateKeyPair(t *testing.T) (ssh.PublicKey, crypto.PrivateKey) {
	u, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ssh keypair: %s", err)
	}

	pubkey, err := ssh.NewPublicKey(u)
	if err != nil {
		t.Fatalf("could not parse ssh public key: %s", err)
	}

	return pubkey, privkey
}

func getDirName(ctx context.Context, t *testing.T, res *gwclient.Result, base, dirPattern string) string {
	ref, err := res.SingleRef()
	if err != nil {
		t.Fatal(err)
	}

	stats, err := ref.ReadDir(ctx, gwclient.ReadDirRequest{
		Path:           base,
		IncludePattern: dirPattern,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(stats) == 0 {
		t.Fatalf("private go module directory not found")
	}

	t.Logf("HERE: %v", stats)

	return stats[0].Path
}

func worker(c gwclient.Client) llb.State {
	worker := llb.Image("alpine:latest", llb.Platform(ocispecs.Platform{Architecture: runtime.GOARCH, OS: "linux"}), llb.WithMetaResolver(c)).
		Run(llb.Shlex("apk add --no-cache go git ca-certificates patch openssh netcat-openbsd")).Root()
	return worker
}

func (ts *TestState) updateGitconfig() llb.StateOption {
	s := script{
		basename: "update_gitconfig.sh",
		template: `
            git config --global "url.http://{{ .Host }}:{{ .HTTPPort }}.insteadOf" "https://{{ .Host }}"
            git config --global credential."http://{{ .Host }}:{{ .HTTPPort }}.helper" "/usr/local/bin/frontend credential-helper --kind=token"
        `,
	}

	return func(st llb.State) llb.State {
		return ts.runScriptOn(st, s).Root()
	}
}

func (ts *TestState) stateToRef(st llb.State) gwclient.Reference {
	t := ts.t

	def, err := st.Marshal(ts.ctx)
	if err != nil {
		t.Fatalf("could not marshal git repo llb: %s", err)
	}

	res, err := ts.client.Solve(ts.ctx, gwclient.SolveRequest{Definition: def.ToPB()})
	if err != nil {
		t.Fatalf("could not solve git repo llb %s", err)
	}

	ref, err := res.SingleRef()
	if err != nil {
		t.Fatalf("could not convert result to single ref %s", err)
	}
	return ref
}

func findRandomAvailablePort(t *testing.T) string {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func(t *testing.T) {
		_ = l.Close() // if we got the port, ignore failure to close
	}(t)

	tcpa, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("extpeccted return value of l.Addr() to be a (*net.TCPAddr)")
	}

	p := tcpa.Port
	return strconv.Itoa(p)
}

func withExtraHost(host string, ipv4 string) func(cfg *newSolveRequestConfig) {
	return func(cfg *newSolveRequestConfig) {
		const addHostsKey = "add-hosts"
		r := cfg.req

		if r.FrontendOpt == nil {
			r.FrontendOpt = make(map[string]string)
		}

		var prefix string
		if existing, ok := r.FrontendOpt[addHostsKey]; ok {
			prefix = existing + ","
		}

		r.FrontendOpt[addHostsKey] = fmt.Sprintf("%s%s=%s", prefix, host, ipv4)
	}
}
