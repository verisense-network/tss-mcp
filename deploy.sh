gcloud builds submit --config gc.yaml .
gcloud run services update tss-mcp --image=us-central1-docker.pkg.dev/beta-testnet-20250403/mcp/tss-mcp:latest --region=us-central1 \
  --vpc-connector=vm-connector \
  --vpc-egress=private-ranges-only