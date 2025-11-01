Node CLI Docker + GitLab CI

- Image path: `registry.gitlab.com/<group>/<project>/node-cli`
- Built automatically by GitLab CI on every push.

Local build

- Build: `docker build -f docker/node-cli.Dockerfile -t node-cli:local .`
- Run: `docker run --rm -it -p 6000:6000 -p 7000:7000 -v lofs_data:/data node-cli:local`

Runtime notes

- The app reads/writes data in the working directory (`/data` in the image):
  - `blockchain.json`, `peers.json`, `mempool.json`
- Mount a volume to persist: `-v lofs_data:/data`
- Network ports:
  - `6000/tcp` P2P
  - `7000/tcp` HTTP explorer
- Env vars (optional):
  - `BIND_ADDR` (default `0.0.0.0`)
  - `EXPLORER_BIND_ADDR` (default `0.0.0.0`)

GitLab CI/CD

- Pipeline file: `.gitlab-ci.yml`
- Requirements:
  - GitLab Container Registry enabled for the project.
  - Runner supports Docker-in-Docker (`docker:dind`).
- Tags pushed:
  - Always: `:SHA` (e.g., `:a1b2c3d4`)
  - Default branch: `:latest`
  - Git tags: `:<tag>` (e.g., `:v1.0.0`)

Example pull/run on nodes

- `docker pull registry.gitlab.com/<group>/<project>/node-cli:latest`
- `docker run -d --name lofs-node -p 6000:6000 -p 7000:7000 -v lofs_data:/data registry.gitlab.com/<group>/<project>/node-cli:latest`

