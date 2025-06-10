package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
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

func TestGomodGitAuth2(t *testing.T) {
	// 0. Test boilerplate
	t.Parallel()
	ctx := startTestSpan(baseCtx, t)
	netHostBuildxEnv := testenv.NewWithNetHostBuildxInstance(ctx, t)
	tmpDir := t.TempDir()

	// 1. Determine basic information, like the host and port for the http and
	// ssh services; also determine the socket file location for the ssh agent
	netHostBuildxEnv.RunTest(ctx, t, func(ctx context.Context, client gwclient.Client) {
		attr := GitServicesAttributes{
			ServerRoot:      "/srv/git",
			PublicRepoPath:  "username/public",
			PrivateRepoPath: "username/private",
			Host:            "host.docker.internal",
			Addr:            "127.0.0.1",

			// these are two distinct ports
			HTTPPort:  findRandomAvailablePort(t),
			SSHPort:   findRandomAvailablePort(t),
			AgentSock: filepath.Join(tmpDir, "ssh.agent.sock"),
		}

		testState := TestState{
			t:      t,
			ctx:    ctx,
			client: client,
		}

		// 1.5 Generate the go mod files
		dependingModFile := file{
			location: attr.inGitRepo("go.mod"),
			template: `
module {{ .Host }}/{{ .PublicRepoPath }}

go {{ .GoVersion }}

require {{ .Host }}/{{ .PrivateRepoPath }}.git {{ .Tag }}
`,
		}

		const privateModfileTemplate = `
module {{ .Host }}/user/private.git

go {{ .GoVersion }}
`

		worker := worker(client)
		initializedGitRepo := func() llb.StateOption {
			return testState.initializedGitRepo(t, &attr, worker)
		}

		// 2. Set up the git repository
		// 2a. Create the files
		repo := llb.Scratch().
			With(testState.customFile(dependingModFile)).
			With(testState.customFile(file{
				location: attr.inGitRepo("foo"),
				template: "bar\n",
			}))

		// 3c. Create the hosting container by loading the git repo into it
		gitHost := worker.With(hostedRepo(repo, attr.repoAbsDir()))

		// gitHost := repo.With()

		// 3. Set up SSH auth framework and run SSH git server
		// 3a. Generate the keypair
		pubkey, privkey := generateKeyPair(t)
		// 3b. Load the private key into the SSH agent, and start the server
		//     listening on the socket file
		go startSSHAgent(t, ctx, privkey, attr.AgentSock)

		// 3d. Load the authorized public key into the container
		const githostUsername = "root"
		sshGitHost := gitHost.With(authorizedKey(ctx, pubkey, githostUsername))

		// 3e. Start the SSH server
		startSSHServer(testState, sshGitHost)
		// 3f. Wait for it to come online
		//
		// 4. Set up Git HTTP server and run it
		// 4a. Start the git HTTP server
		// 4b. Wait for it to come online

		// 6. Generate the HTTP spec, and run the test with the secrets provided
		//
		// 7. Generate the SSH spec, and run the test with the auth socket provided
	})
}

func newContainerWithRoot(t *testing.T, ctx context.Context, client gwclient.Client, st llb.State, attr *GitServicesAttributes) gwclient.Container {
	ref := stateToRef(ctx, t, client, st)

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts: []gwclient.Mount{
			{
				Dest: "/",
				Ref:  ref,
			},
		},
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

	return func(st llb.State) llb.State {
		return st.File(
			llb.Mkdir(dir, 0o755, llb.WithParents(true)).
				Mkfile(absPath, 0o755, s.inject(ts.t, ts.attr)),
		)
	}
}

// startSSHServer starts an sshd instance in a container hosting the git repo.
// It runs asynchonously and checks the connection after starting the server.
func startSSHServer(ts TestState, gitHost llb.State, attr *GitServicesAttributes) {
	t := ts.t
	ctx := ts.ctx
	client := ts.client

	const (
		serverScriptName = "start_ssh_server.sh"
		waitScriptName   = "wait.sh"
	)
	serverScript := script{
		basename: "start_ssh_server.sh",
		template: `
            #!/usr/bin/env sh
            set -ex
            ssh-keygen -A
            exec /usr/sbin/sshd -o PermitRootLogin=yes -p {{ .Port }} -D
        `,
	}

	// serverScript := injectTemplate(t, scriptTemplate, attr)

	// This script attempts to connect to the ssh server. The `nc -z` flag
	// discconnects and exits with status 0 if a successful connection is made.
	// `nc -w5` gives up and exits with status 1 after a 5-second timeout.
	waitScript := script{
		basename: "wait_for_ssh.sh",
		template: `
            #!/usr/bin/env sh
            while ! nc -zw5 "$ADDR" "$SSH_PORT"; do
                sleep 0.1
            done
`,
	}

	scriptDir := llb.Scratch().
		With(ts.customScript(serverScript)).
		With(ts.customScript())

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts: []gwclient.Mount{
			{
				Dest: "/",
				Ref:  stateToRef(ts, gitHost),
			},
			//TODO double check that this works. I'm assuming it will with an overlay mount
			{
				Dest: customScriptDir,
				Ref:  stateToRef(ts, scriptDir),
			},
		},
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

	env := getEnv(ts, gitHost, "HOST="+attr.Host, "SSH_PORT="+attr.SSHPort)
	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Args:   []string{scriptAbsPath},
		Env:    env,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatalf("could not start ssh server container: %s", err)
	}

	go func() {
		if err := cp.Wait(); err != nil {
			t.Logf("error running ssh sever container: %s", err)
		}
	}()

	t.Log("waiting for ssh server to come online")
	ctxT, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	untilConnected, err := cont.Start(ctxT, gwclient.StartRequest{
		Env: env,
		Args: []string{
			"sh", "-c", waitScript,
		},
	})
	if err != nil {
		t.Fatalf("could not check progress of git server: %s", err)
	}

	if err := untilConnected.Wait(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Could not start git server: %s", err)
		}

		t.Fatalf("could not check progress of git server: %s", err)
	}

	t.Logf("ssh server is online")

}

func getEnv(ts TestState, st llb.State, extra ...string) []string {
	env, err := st.Env(ts.ctx)
	if err != nil {
		ts.t.Logf("unable to copy env: %s", err)
	}

	return append(env.ToArray(), extra...)
}

func authorizedKey(ctx context.Context, pubkey ssh.PublicKey, username string) llb.StateOption {
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

type gomodGitAuthTestConfig struct {
	attr GitServicesAttributes

	rrunSSHAgent  func(t *testing.T, ctx context.Context, sockfile string)
	rrunSSHServer func(t *testing.T)
	rrunGitServer func(t *testing.T)

	dependingGoDotMod []byte
	dependentGoDotMod []byte

	pubkey  ssh.PublicKey
	privkey crypto.PrivateKey

	worker llb.State
}

func NewGomodGitAuthTestConfig(opts ...func(*gomodGitAuthTestConfig)) gomodGitAuthTestConfig {
	var cfg gomodGitAuthTestConfig

	for _, f := range opts {
		f(&cfg)
	}

	return cfg
}

func WithServerRoot(s string) func(*gomodGitAuthTestConfig) {
	return func(cfg *gomodGitAuthTestConfig) {
		cfg.serverRoot = s
	}
}

func WithRepoDir(s string) func(*gomodGitAuthTestConfig) {
	return func(cfg *gomodGitAuthTestConfig) {
		cfg.repoDir = s
	}
}

func WithHost(s string) func(*gomodGitAuthTestConfig) {
	return func(cfg *gomodGitAuthTestConfig) {
		cfg.host = s
	}
}

func WithPort(s string) func(*gomodGitAuthTestConfig) {
	return func(cfg *gomodGitAuthTestConfig) {
		cfg.port = s
	}
}

func injectTemplate(t *testing.T, tp string, attr *GitServicesAttributes) []byte {
	tmpl, err := template.New("depending go mod").Parse(tp)
	if err != nil {
		t.Fatalf("could not parse go mod template: %s", err)
	}

	type injector struct {
		GitServicesAttributes
		GoVersion string
	}

	if attr == nil {
		t.Fatalf("attributes struct was nil: %#v", attr)
	}

	var gomodContents bytes.Buffer
	tmpl.Execute(&gomodContents, injector{
		GitServicesAttributes: *attr,
		GoVersion:             goVersion,
	})

	return gomodContents.Bytes()
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

func startSSHAgent(t *testing.T, ctx context.Context, privkey crypto.PrivateKey, sockAddr string) {
	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{
		PrivateKey: privkey,
	})

	listener, err := net.Listen("unix", sockAddr)
	if err != nil {
		t.Fatalf("can't listen on unix socket: %s", err)
	}

	c, err := listener.Accept()
	if err != nil {
		t.Fatalf("listener.Accept: %s", err)
	}

	if err := agent.ServeAgent(kr, c); err != nil {
		t.Fatalf("cannot serve agent: %s", err)
	}
}

func TestGomodGitAuth(t *testing.T) {
	t.Parallel()
	ctx := startTestSpan(baseCtx, t)
	netHostBuildxEnv := testenv.NewWithNetHostBuildxInstance(ctx, t)
	httpPort := findRandomAvailablePort(t)
	sshPort := findRandomAvailablePort(t)

	cfg := gomodGitAuthTestConfig{
		serverRoot: "/git_server",
		repoDir:    "/user/private",
		host:       "host.docker.internal",
		addr:       "127.0.0.1",
		sourceName: "gitauth",
	}

	spec := cfg.generateSpec()

	t.Run("HTTPS", func(t *testing.T) {
		netHostBuildxEnv.RunTest(ctx, t, func(ctx context.Context, client gwclient.Client) {
			cfg := cfg
			cfg.tag = identity.NewID()
			cfg.port = httpPort
			cfg.worker = cfg.initGomodWorker(client)
			cfg.dependingGoDotMod = cfg.injectTemplate(t, dependingModfileTemplate)
			cfg.dependentGoDotMod = cfg.injectTemplate(t, dependentModfileTemplate)

			cfg.runGitServer(t, ctx, client)
		}, testenv.WithSecrets(testenv.KeyVal{
			K: "super-secret",
			V: "value",
		}), testenv.WithHostNetworking)
		testGomodGitAuthHTTPS(t, ctx, netHostBuildxEnv)
	})

	t.Run("SSH", func(t *testing.T) {
		netHostBuildxEnv.RunTest(ctx, t, func(ctx context.Context, client gwclient.Client) {
			cfg := cfg
			cfg.tag = identity.NewID()
			cfg.port = sshPort
			cfg.sshGitUser = "root"
			cfg.sshID = "dalecssh"
			cfg.worker = cfg.initGomodWorker(client)
		}, testenv.WithSecrets(testenv.KeyVal{
			K: "super-secret",
			V: "value",
		}), testenv.WithHostNetworking)
		testGomodGitAuthSSH(t, ctx, netHostBuildxEnv)
	})

}

func (cfg *gomodGitAuthTestConfig) repoMountpoint() string {
	return fmt.Sprintf("%s%s", cfg.serverRoot, cfg.repoDir)
}

func (cfg *gomodGitAuthTestConfig) runSSHAgent(t *testing.T, ctx context.Context, client gwclient.Client) {
	if cfg.sshID == "" {
		return
	}
}

func (cfg *gomodGitAuthTestConfig) runSSHServer(t *testing.T, ctx context.Context, client gwclient.Client) {
	if cfg.sshID == "" {
		return
	}
}

func (cfg *gomodGitAuthTestConfig) runGitServer(t *testing.T, ctx context.Context, client gwclient.Client) {
	repo := cfg.createDependentModule()
	script := string(cfg.injectTemplate(t, initGitRepoScriptTemplate))

	cfg.worker = cfg.worker.Dir(cfg.repoMountpoint()).Run(
		llb.AddMount(cfg.repoMountpoint(), repo),
		dalec.ShArgs(script),
	).Root()

	dc, err := dockerui.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	gitServerProgramPtr, err := dc.MainContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	gitServerProgramSt := *gitServerProgramPtr
	gitServerBinSt := worker.Run(
		dalec.ShArgs("cd /tmp/dalec/internal/dalec && go build -o /tmp/out/host ./test/cmd/git_repo"),
		llb.AddMount("/tmp/dalec/internal/dalec", gitServerProgramSt),
	).AddMount("/tmp/out", llb.Scratch())

	workerRef := stateToRef(ctx, t, client, worker)
	gitServerProgramRef := stateToRef(ctx, t, client, gitServerBinSt)

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts: []gwclient.Mount{
			{
				Dest:     "/",
				Ref:      workerRef,
				Readonly: true,
			},
			{
				Dest:     "/git_repo",
				Ref:      gitServerProgramRef,
				Readonly: true,
			},
		},
		NetMode: pb.NetMode_HOST,
		ExtraHosts: []*pb.HostIP{
			{
				Host: gomodGitHost,
				IP:   localhostAddr,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := worker.Env(ctx)
	if err != nil {
		t.Logf("unable to copy env: %s", err)
	}

	envArr := env.ToArray()
	envArr = append(envArr, "HOST="+gomodGitHost, "ADDR="+localhostAddr, "PORT="+port)

	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Args:      []string{"/git_repo/host", serverRoot, localhostAddr, port},
		Env:       envArr,
		SecretEnv: []*pb.SecretEnv{},
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := cp.Wait(); err != nil {
			t.Logf("unexpected server error: %s", err)
		}
	}()

	t.Log("waiting for git server to come online")
	ctxT, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	// netcat's -z will return 0 if a connection can be made, 1 if not
	// -w5 means timeout after 5 seconds
	untilConnected, err := cont.Start(ctxT, gwclient.StartRequest{
		Env: envArr,
		Args: []string{
			"sh", "-c", `
while ! nc -zw5 "$ADDR" "$PORT"; do
	sleep 0.1
done
			`,
		},
	})
	if err != nil {
		t.Fatalf("could not check progress of git server: %s", err)
	}

	if err := untilConnected.Wait(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Could not start git server: %s", err)
		}

		t.Fatalf("could not check progress of git server: %s", err)
	}

	t.Logf("git server is online")

	return nil
}

func (cfg *gomodGitAuthTestConfig) hostPort() string {
	return fmt.Sprintf("%s:%s", cfg.host, cfg.port)
}

func (cfg *gomodGitAuthTestConfig) generateSpec() *dalec.Spec {
	auth := map[string]dalec.GomodGitAuth{
		cfg.hostPort(): {
			Token: "super-secret",
		},
	}

	if cfg.sshID != "" {
		a := auth[cfg.hostPort()]
		a.Token = ""
		a.SSH = &dalec.GomodGitAuthSSH{
			ID:       cfg.sshID,
			Username: cfg.sshGitUser,
		}
		auth[cfg.hostPort()] = a
	}

	return &dalec.Spec{
		Name: "gomod-git-auth",
		Sources: map[string]dalec.Source{
			cfg.sourceName: {
				Inline: &dalec.SourceInline{
					Dir: &dalec.SourceInlineDir{
						Files: map[string]*dalec.SourceInlineFile{
							"go.mod": {
								Contents: string(cfg.dependingGoDotMod),
							},
						},
					},
				},
				Generate: []*dalec.SourceGenerator{
					{
						Gomod: &dalec.GeneratorGomod{
							Auth: auth,
						},
					},
				},
			},
		},
	}
}

func (cfg *gomodGitAuthTestConfig) createDependentModule() llb.State {
	return llb.Scratch().
		File(
			llb.Mkdir(cfg.repoDir, 0o755, llb.WithParents(true))).
		Dir(repoDir).
		File(
			llb.Mkfile("hello", 0o644, []byte("hello\n")).
				Mkfile("go.mod", 0o644, cfg.dependentGoDotMod),
		)
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

func (cfg *gomodGitAuthTestConfig) injectTemplate(t *testing.T, tmplstr string) []byte {
	tmpl, err := template.New("depending go mod").Parse(dependingModfileTemplate)
	if err != nil {
		t.Fatalf("could not parse go mod template: %s", err)
	}

	var gomodContents bytes.Buffer
	tmpl.Execute(&gomodContents, struct{ Host, Tag string }{
		Host: cfg.host,
		Tag:  cfg.tag,
	})

	return gomodContents.Bytes()
}

// func gomodGitAuthTest(t *testing.T, parentCtx context.Context, buildEnv *testenv.BuildxEnv, spec *dalec.Spec) {
// 	ctx := startTestSpan(parentCtx, t)
// 	tag := identity.NewID()

// }

func testGomodGitAuthHTTPS(t *testing.T, parentCtx context.Context, buildEnv *testenv.BuildxEnv) {
	t.Parallel()
	ctx := startTestSpan(parentCtx, t)
	tag := identity.NewID()

	buildEnv.RunTest(ctx, t, func(ctx context.Context, c gwclient.Client) {
		tmpl, err := template.New("depending go mod").Parse(dependingModfileTemplate)
		if err != nil {
			t.Fatalf("could not parse go mod template: %s", err)
		}

		var gomodContents bytes.Buffer
		tmpl.Execute(&gomodContents, struct {
			Host    string
			Version string
		}{
			Host:    gomodGitHost,
			Version: tag,
		})

		port := findRandomAvailablePort(t)

		spec := &dalec.Spec{
			Name: "gomod-git-auth",
			Sources: map[string]dalec.Source{
				sourceName: {
					Inline: &dalec.SourceInline{
						Dir: &dalec.SourceInlineDir{
							Files: map[string]*dalec.SourceInlineFile{
								"go.mod": {
									Contents: gomodContents.String(),
								},
							},
						},
					},
					Generate: []*dalec.SourceGenerator{
						{
							Gomod: &dalec.GeneratorGomod{
								Auth: map[string]dalec.GomodGitAuth{
									fmt.Sprintf("%s:%s", gomodGitHost, port): {
										Token: "super-secret",
									},
								},
							},
						},
					},
				},
			},
		}

		gomodContents.Reset()
		// Private git repo
		modFileTmpl, err := template.New("dependent go mod template").Parse(dependentModfileTemplate)
		if err != nil {
			t.Fatalf("could not parse go mod template: %s", err)
		}
		modFileTmpl.Execute(&gomodContents, struct{ Host string }{Host: gomodGitHost})
		worker := initGomodWorker(c, gomodGitHost, port, nil)
		repo := newFunction(repoDir, gomodContents, worker, tag)

		if err := runGitServer(ctx, t, c, repo, port, tag); err != nil {
			t.Fatal(err)
		}

		sr := newSolveRequest(
			withBuildTarget("debug/gomods"),
			withSpec(ctx, t, spec),
			withExtraHost(gomodGitHost, localhostAddr),
			withBuildContext(ctx, t, "gomod-worker", initGomodWorker(c, gomodGitHost, port, nil)),
		)

		const outDirBase = gomodGitHost + "/user"
		res := solveT(ctx, t, c, sr)
		modDir := getDirName(ctx, t, res, outDirBase, "private.git@*")

		filename := filepath.Join(outDirBase, modDir, "hello")
		checkFile(ctx, t, filename, res, []byte("hello\n"))
	}, testenv.WithSecrets(testenv.KeyVal{
		K: "super-secret",
		V: "value",
	}), testenv.WithHostNetworking)
}

func newFunction(repoDir string, gomodContents bytes.Buffer, worker, repoContents llb.State, tag string) llb.State {
	repo := llb.Scratch().
		File(
			llb.Mkdir(repoDir, 0o755, llb.WithParents(true))).
		Dir(repoDir).
		File(
			llb.Mkfile("hello", 0o644, []byte("hello\n")).
				Mkfile("go.mod", 0o644, gomodContents.Bytes()),
		)

	worker = worker.File(llb.Copy(repo, "/", serverRoot))
	return worker.Dir(repoMountpoint).Run(
		llb.AddMount(serverRoot, repo),
		dalec.ShArgsf(`
set -ex
export GIT_CONFIG_NOGLOBAL=true
git init
git config user.name foo
git config user.email foo@bar.com

git add -A
git commit -m commit --no-gpg-sign
git tag %s
`,
			tag)).
		AddMount(repoMountpoint, llb.Scratch())
}

func testGomodGitAuthSSH(t *testing.T, parentCtx context.Context, buildxEnv *testenv.BuildxEnv) {
	const gituser = "root"
	const sshID = "dalecssh"

	t.Parallel()

	ctx := startTestSpan(parentCtx, t)
	sourceName := "gitauth"

	tag := identity.NewID()
	sockfile := "/tmp/dalec.test.socket." + tag
	pubkeyBytes, privkeyBytes := runSSHAgent(ctx, t, sockfile)

	buildxEnv.RunTest(ctx, t, func(ctx context.Context, c gwclient.Client) {
		t.Cleanup(func() {
			_ = os.RemoveAll(sockfile)
		})
		const gomodFmt = `module %[1]s/user/public

go 1.23.5

require %[1]s/user/private.git %[2]s
`

		gomodContents := fmt.Sprintf(gomodFmt, gomodGitHost, tag)
		port := findRandomAvailablePort(t)

		spec := &dalec.Spec{
			Name: "gomod-git-auth",
			Sources: map[string]dalec.Source{
				sourceName: {
					Inline: &dalec.SourceInline{
						Dir: &dalec.SourceInlineDir{
							Files: map[string]*dalec.SourceInlineFile{
								"go.mod": {
									Contents: gomodContents,
								},
							},
						},
					},
					Generate: []*dalec.SourceGenerator{
						{
							Gomod: &dalec.GeneratorGomod{
								Auth: map[string]dalec.GomodGitAuth{
									fmt.Sprintf("%s:%s", gomodGitHost, port): {
										SSH: &dalec.GomodGitAuthSSH{
											ID:       sshID,
											Username: gituser,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		// Private git repo
		modFile := fmt.Sprintf("module %s/user/private.git\n"+
			"\n"+
			"\n"+
			"go 1.23.5\n", gomodGitHost)

		repo := llb.Scratch().
			File(
				llb.Mkdir(repoDir, 0o755, llb.WithParents(true))).
			Dir(repoDir).
			File(
				llb.Mkfile("hello", 0o644, []byte("hello\n")).
					Mkfile("go.mod", 0o644, []byte(modFile)),
			)

		runSSHServer(ctx, t, c, repo, port, tag, pubkeyBytes)

		sr := newSolveRequest(
			withBuildTarget("debug/gomods"),
			withSpec(ctx, t, spec),
			withExtraHost(gomodGitHost, localhostAddr),
			withBuildContext(ctx, t, "gomod-worker", initGomodWorker(c, gomodGitHost, port, privkeyBytes)),
		)

		const outDirBase = gomodGitHost + "/user"
		res := solveT(ctx, t, c, sr)
		modDir := getDirName(ctx, t, res, outDirBase, "private.git@*")

		filename := filepath.Join(outDirBase, modDir, "hello")
		checkFile(ctx, t, filename, res, []byte("hello\n"))
	}, testenv.WithHostNetworking, testenv.WithSSHSocket(sshID, sockfile))
}

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

// Returns pubkey already marshaled for use in ssh server
func runSSHAgent(ctx context.Context, t *testing.T, sockfile string) ([]byte, []byte) {
	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ssh keypair: %s", err)
	}

	k, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		t.Fatalf("could not parse ssh public key: %s", err)
	}
	pubkeyBytes := ssh.MarshalAuthorizedKey(k)

	var b bytes.Buffer
	blk, err := ssh.MarshalPrivateKey(privkey, "")
	if err != nil {
		t.Fatalf("could not parse ssh public key: %s", err)
	}
	if err := pem.Encode(&b, blk); err != nil {
		t.Fatalf("could not encode ssh private key to pem: %s", err)
	}

	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{
		PrivateKey: &privkey,
	})

	listener, err := net.Listen("unix", sockfile)
	if err != nil {
		t.Fatalf("can't listen on unix socket: %s", err)
	}

	go func() {
		c, err := listener.Accept()
		if err != nil {
			t.Fatalf("listener.Accept: %s", err)
		}

		if err := agent.ServeAgent(kr, c); err != nil {
			t.Fatalf("cannot serve agent: %s", err)
		}
	}()

	return pubkeyBytes, b.Bytes()
}

func runSSHServer(ctx context.Context, t *testing.T, client gwclient.Client, repo llb.State, port, tag string, pubkey []byte) {
	worker := initGomodWorker(client, gomodGitHost, port, nil)
	worker = worker.File(llb.Copy(repo, "/", serverRoot))
	gitDir := worker.Dir(repoMountpoint).Run(dalec.ShArgsf(`set -ex
export GIT_CONFIG_NOGLOBAL=true
git init
git config user.name foo
git config user.email foo@bar.com

git add -A
git commit -m commit --no-gpg-sign
git tag %s
    `, tag)).AddMount(repoMountpoint+"/.git", llb.Scratch())

	bareGitRepo := worker.Dir(serverRoot).Run(dalec.ShArgs(`
git init --bare
    `)).AddMount(serverRoot, gitDir)

	worker = worker.File(
		llb.Mkdir("/root/.ssh", 0o600, llb.WithParents(true)).
			Mkfile("/root/.ssh/authorized_keys", 0o600, pubkey),
	)

	workerRef := stateToRef(ctx, t, client, worker)
	bareGitRepoRef := stateToRef(ctx, t, client, bareGitRepo)

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts: []gwclient.Mount{
			{
				Dest: "/",
				Ref:  workerRef,
			},
			{
				Dest: "/user/private",
				Ref:  bareGitRepoRef,
			},
		},
		NetMode: pb.NetMode_HOST,
		ExtraHosts: []*pb.HostIP{
			{
				Host: gomodGitHost,
				IP:   localhostAddr,
			},
		},
		Constraints: &pb.WorkerConstraints{
			Filter: []string{},
		},
	})
	if err != nil {
		t.Fatalf("could not create ssh server container: %s", err)
	}

	env, err := worker.Env(ctx)
	if err != nil {
		t.Logf("unable to copy env: %s", err)
	}

	envArr := env.ToArray()

	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Args:   []string{"sh", "-c", `ssh-keygen -A && /usr/sbin/sshd -o PermitRootLogin=yes -p ` + port + " -D"},
		Env:    envArr,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatalf("could not start ssh server container: %s", err)
	}

	go func() {
		if err := cp.Wait(); err != nil {
			t.Logf("error running ssh sever container: %s", err)
		}
	}()

	t.Log("waiting for ssh server to come online")
	ctxT, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	envArr = append(envArr, "HOST="+gomodGitHost, "ADDR="+localhostAddr, "PORT="+port)

	untilConnected, err := cont.Start(ctxT, gwclient.StartRequest{
		Env: envArr,
		Args: []string{
			"sh", "-c", `
while ! nc -zw5 "$ADDR" "$PORT"; do
	sleep 0.1
done
			`,
		},
	})
	if err != nil {
		t.Fatalf("could not check progress of git server: %s", err)
	}

	if err := untilConnected.Wait(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Could not start git server: %s", err)
		}

		t.Fatalf("could not check progress of git server: %s", err)
	}

	t.Logf("ssh server is online")
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

func (cfg *gomodGitAuthTestConfig) initGomodWorker(c gwclient.Client) llb.State {
	worker := llb.Image("alpine:latest", llb.Platform(ocispecs.Platform{Architecture: runtime.GOARCH, OS: "linux"}), llb.WithMetaResolver(c)).
		Run(llb.Shlex("apk add --no-cache go git ca-certificates patch openssh netcat-openbsd")).Root()

	run := func(cmd string) {
		// tell git to use the port along with the host
		worker = worker.Run(
			dalec.ShArgs(cmd),
			llb.AddEnv("HOST", cfg.host),
			llb.AddEnv("PORT", cfg.port),
		).Root()
	}

	run(`sh -c 'git config --global "url.http://${HOST}:${PORT}.insteadOf" "https://${HOST}"'`)
	run(`sh -c 'git config --global credential."http://${HOST}:${PORT}.helper" "/usr/local/bin/frontend credential-helper --kind=token"'`)

	return worker
}

func runGitServer(ctx context.Context, t *testing.T, client gwclient.Client, repo llb.State, port, tag string) error {

	worker := initGomodWorker(client, gomodGitHost, port, nil)
	worker = worker.File(llb.Copy(repo, "/", serverRoot))
	worker = worker.Dir(repoMountpoint).Run(dalec.ShArgsf(`
set -ex
export GIT_CONFIG_NOGLOBAL=true
git init
git config user.name foo
git config user.email foo@bar.com

git add -A
git commit -m commit --no-gpg-sign
git tag %s
    `, tag)).Root()

	dc, err := dockerui.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	gitServerProgramPtr, err := dc.MainContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	gitServerProgramSt := *gitServerProgramPtr
	gitServerBinSt := worker.Run(
		dalec.ShArgs("cd /tmp/dalec/internal/dalec && go build -o /tmp/out/host ./test/cmd/git_repo"),
		llb.AddMount("/tmp/dalec/internal/dalec", gitServerProgramSt),
	).AddMount("/tmp/out", llb.Scratch())

	workerRef := stateToRef(ctx, t, client, worker)
	gitServerProgramRef := stateToRef(ctx, t, client, gitServerBinSt)

	cont, err := client.NewContainer(ctx, gwclient.NewContainerRequest{
		Mounts: []gwclient.Mount{
			{
				Dest:     "/",
				Ref:      workerRef,
				Readonly: true,
			},
			{
				Dest:     "/git_repo",
				Ref:      gitServerProgramRef,
				Readonly: true,
			},
		},
		NetMode: pb.NetMode_HOST,
		ExtraHosts: []*pb.HostIP{
			{
				Host: gomodGitHost,
				IP:   localhostAddr,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := worker.Env(ctx)
	if err != nil {
		t.Logf("unable to copy env: %s", err)
	}

	envArr := env.ToArray()
	envArr = append(envArr, "HOST="+gomodGitHost, "ADDR="+localhostAddr, "PORT="+port)

	cp, err := cont.Start(ctx, gwclient.StartRequest{
		Args:      []string{"/git_repo/host", serverRoot, localhostAddr, port},
		Env:       envArr,
		SecretEnv: []*pb.SecretEnv{},
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := cp.Wait(); err != nil {
			t.Logf("unexpected server error: %s", err)
		}
	}()

	t.Log("waiting for git server to come online")
	ctxT, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	// netcat's -z will return 0 if a connection can be made, 1 if not
	// -w5 means timeout after 5 seconds
	untilConnected, err := cont.Start(ctxT, gwclient.StartRequest{
		Env: envArr,
		Args: []string{
			"sh", "-c", `
while ! nc -zw5 "$ADDR" "$PORT"; do
	sleep 0.1
done
			`,
		},
	})
	if err != nil {
		t.Fatalf("could not check progress of git server: %s", err)
	}

	if err := untilConnected.Wait(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Could not start git server: %s", err)
		}

		t.Fatalf("could not check progress of git server: %s", err)
	}

	t.Logf("git server is online")

	return nil
}

func stateToRef(ts TestState, st llb.State) gwclient.Reference {
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
