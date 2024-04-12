package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/moby/buildkit/util/bklog"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"
)

func main() {
	bklog.L.Logger.SetOutput(os.Stderr)
	grpclog.SetLoggerV2(grpclog.NewLoggerV2WithVerbosity(bklog.L.WriterLevel(logrus.InfoLevel), bklog.L.WriterLevel(logrus.WarnLevel), bklog.L.WriterLevel(logrus.ErrorLevel), 1))

	ctx := appcontext.Context()

	if err := grpcclient.RunFromEnvironment(ctx, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		bopts := c.BuildOpts().Opts
		_ = bopts
		inputs, err := c.Inputs(ctx)
		if err != nil {
			return nil, err
		}

		artifacts, ok := inputs["initialstate"]
		if !ok {
			return nil, fmt.Errorf("no artifact state provided to signer")
		}

		base, ok := inputs["context"]
		if !ok {
			return nil, fmt.Errorf("no base signing image provided")
		}

		base = base.File(llb.Mkfile("/script.sh", 0o700, []byte(`
			set -exu
			KEYVAULT_NAME="temp-azcu-signing-kv"
			az login --use-device-code
			export AZURE_CLIENT_SECRET=$(az keyvault secret show --name esrp-token --vault-name $KEYVAULT_NAME --query value -o tsv)
			export AZURE_CLIENT_ID=$(az keyvault secret show --name esrp-sp-id --vault-name $KEYVAULT_NAME --query value -o tsv)
			export ESRP_KEYCODE=$(az keyvault secret show --name esrp-keycode-test --vault-name $KEYVAULT_NAME --query value -o tsv)
			export AZURE_TENANT_ID=$(az keyvault secret show --name esrp-sp-tenant --vault-name $KEYVAULT_NAME --query value -o tsv)
			az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" --allow-no-subscriptions
			az xsign sign-file --file-name /artifacts/RPMS/x86_64/* --config-file /config.json`)))
		base = base.File(llb.Mkfile("/config.json", 0o600, []byte(`
{
  "clientId": "12f74099-0b7a-4e7b-8b7f-c1e0747fadc8",
  "gatewayApi": "https://api.esrp.microsoft.com",
  "requestSigningCert": {
    "subject": "esrp-prss",
    "vaultName": "upstreamci-ado"
  },
  "driEmail": [
    "pengelbert@microsoft.com"
  ],
  "signingOperations": [
    {
      "keyCode": "CP-450778-Pgp",
      "operationSetCode": "LinuxSign",
      "parameters": [],
      "toolName": "sign",
      "toolVersion": 1
    }
  ],
  "hashType": "sha256"
}
`)))

		output := base.Run(llb.Args([]string{"/script.sh"})).AddMount("/artifacts", artifacts)

		def, err := output.Marshal(ctx)
		if err != nil {
			return nil, err
		}

		return c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
		})
	}); err != nil {
		bklog.L.WithError(err).Fatal("error running frontend")
		os.Exit(137)
	}
}
