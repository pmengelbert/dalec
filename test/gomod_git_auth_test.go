package test

import (
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
	serverRoot     = "/git_server"
	repoDir        = "/user/private"
	repoMountpoint = serverRoot + repoDir

	gomodGitHost  = "host.docker.internal"
	localhostAddr = "127.0.0.1"

	sourceName = "gitauth"
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

	// _tag is a private field and should not be accessed directly
	_tag string
}

func (a *GitServicesAttributes) tag() string {
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

func TestGomodGitAuth2(t *testing.T) {
	// 1. Determine basic information, like the host and port for the http and
	// ssh services; also determine the socket file location for the ssh agent

	attr := GitServicesAttributes{
		ServerRoot:      "/srv/git",
		PublicRepoPath:  "username/public",
		PrivateRepoPath: "username/private",
		Host:            "host.docker.internal",
		Addr:            "127.0.0.1",

		// these are two distinct ports
		HTTPPort: findRandomAvailablePort(t),
		SSHPort:  findRandomAvailablePort(t),
	}

	// 1.5 Generate the go mod files
	const dependingModfileTemplate = `
module {{ .Host }}/{{ .PublicRepoPath }}

go {{ .GoVersion }}

require {{ .Host }}/{{ .PrivateRepoPath }}.git {{ .Tag }}
`

	const dependentModfileTemplate = `
module {{ .Host }}/user/private.git

go {{ .GoVersion }}
`

	injectTemplate := func() []byte {
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

	// 2. Set up the git repository
	// 2a. Create the files
	repo := llb.Scratch().File(
		llb.Mkdir(a.privateRepoPath, 0o644, llb.WithParents(true)).
			Mkfile(a.inGitRepo("go.mod")),
	)

	// 2b. Initialize the git repo

	// 3. Set up SSH auth framework and run SSH git server
	// 3a. Generate the keypair
	// 3b. Load the private key into the SSH agent, and start the server
	//     listening on the socket file
	// 3c. Create the hosting container, and load the authorized public key into it
	// 3d. Start the SSH server
	// 3e. Wait for it to come online
	//
	// 4. Set up Git HTTP server and run it
	// 4a. Start the git HTTP server
	// 4b. Wait for it to come online

	// 5. Bootstrap the worker (requires client)
	//
	// 6. Generate the HTTP spec, and run the test with the secrets provided
	//
	// 7. Generate the SSH spec, and run the test with the auth socket provided
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

const initGitRepoScriptTemplate = `
set -ex
export GIT_CONFIG_NOGLOBAL=true
git init
git config user.name foo
git config user.email foo@bar.com

git add -A
git commit -m commit --no-gpg-sign
git tag {{ .Tag }}
`

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

func stateToRef(ctx context.Context, t *testing.T, client gwclient.Client, st llb.State) gwclient.Reference {
	def, err := st.Marshal(ctx)
	if err != nil {
		t.Fatalf("could not marshal git repo llb: %s", err)
	}

	res, err := client.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB()})
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
