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

// Sources is a handler that outputs all the sources.
func Sources(ctx context.Context, client gwclient.Client) (*client.Result, error) {
	return frontend.BuildWithPlatform(ctx, client, func(ctx context.Context, client gwclient.Client, platform *ocispecs.Platform, spec *dalec.Spec, targetKey string) (gwclient.Reference, *dalec.DockerImageSpec, error) {
		if platform == nil {
			p := platforms.DefaultSpec()
			platform = &p
		}
		*platform = platforms.Normalize(*platform)

		sOpt, err := frontend.SourceOptFromClient2(ctx, client, platform)
		if err != nil {
			return nil, nil, err
		}

		opts := []llb.ConstraintsOpt{
			llb.Platform(*platform),
		}

		sources, err := dalec.Sources(spec, sOpt, opts...)
		if err != nil {
			return nil, nil, err
		}

		for k, v := range sources {
			st := llb.Scratch().File(llb.Copy(v, "/", k), opts...)
			sources[k] = st
		}

		def, err := dalec.MergeAtPath(llb.Scratch(), dalec.SortedMapValues(sources), "/").Marshal(ctx)
		if err != nil {
			return nil, nil, err
		}

		res, err := client.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, nil, err
		}

		platformStr := platforms.Format(*platform)
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
