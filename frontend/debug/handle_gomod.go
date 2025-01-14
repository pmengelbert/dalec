package debug

import (
	"context"
	"fmt"

	"github.com/Azure/dalec"
	"github.com/Azure/dalec/frontend"
	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const keyGomodWorker = "context:gomod-worker"

// Gomods outputs all the gomodule dependencies for the spec
func Gomods(ctx context.Context, client gwclient.Client) (*client.Result, error) {
	return frontend.BuildWithPlatform(ctx, client, func(ctx context.Context, client gwclient.Client, platform *ocispecs.Platform, spec *dalec.Spec, targetKey string) (gwclient.Reference, *dalec.DockerImageSpec, error) {
		sOpt, err := frontend.SourceOptFromClient(ctx, client)
		if err != nil {
			return nil, nil, err
		}

		inputs, err := client.Inputs(ctx)
		if err != nil {
			return nil, nil, err
		}

		p := platform
		if p == nil {
			pp := platforms.DefaultSpec()
			p = &pp
		}

		// Allow the client to override the worker image
		// This is useful for keeping pre-built worker image, especially for CI.
		worker, ok := inputs[keyGomodWorker]
		if !ok {
			worker = llb.Image("alpine:latest", llb.WithMetaResolver(client), llb.Platform(*p)).
				Run(llb.Shlex("apk add --no-cache go git ca-certificates patch")).Root()
		}

		st, err := spec.GomodDeps(sOpt, worker, llb.Platform(*p))
		if err != nil {
			return nil, nil, err
		}

		def, err := st.Marshal(ctx)
		if err != nil {
			return nil, nil, err
		}

		res, err := client.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, nil, err
		}

		platformStr := platforms.FormatAll(*p)
		ref, found := res.FindRef(platformStr)
		if !found {
			return nil, nil, fmt.Errorf("no ref found for platform: %s", platformStr)
		}

		return ref, &dalec.DockerImageSpec{
			Image: ocispecs.Image{
				Platform: *platform,
			},
		}, nil
	})
}
