# Argo CD threat model — github.com/cx-benchmark/argo-cd

Read at commit b7bc418289a96130340ea79964c4491b416c14f2 (`VERSION` 3.7.0), reviewed whole. Paths are relative to the repository root. "Out of view" = not opened; "not verified" = opened but could not confirm.

## system

**Purpose.** Argo CD is a declarative GitOps continuous-delivery tool for Kubernetes (`README.md`). It clones Git repositories and pulls Helm/OCI artifacts, renders Kubernetes manifests with built-in tools or plugins, and applies them to target clusters using credentials it stores. The default cluster install gives the application controller a ClusterRole with `*` on all resources and non-resource URLs (`manifests/cluster-rbac/application-controller/argocd-application-controller-clusterrole.yaml`) and the API server a ClusterRole with get/patch/delete on all resources, `pods/log` get, and create on `batch/jobs` and Argo `workflows` (`manifests/cluster-rbac/server/argocd-server-clusterrole.yaml`). The applicationset-controller ClusterRole can get/list/watch Secrets and ConfigMaps in every namespace (`manifests/cluster-rbac/applicationset-controller/`).

**Components.** One Go binary dispatches on its name (`cmd/main.go` `selectCommand`); the image symlinks each name to `/usr/local/bin/argocd` (`Dockerfile`).
- **argocd-server** (`cmd/argocd-server`, `server/`): gRPC services and a grpc-gateway REST API on one port via cmux, grpc-web, web UI, SSO login/callback, Dex reverse proxy, `/api/webhook`, `/api/badge`, `/terminal` (pod exec over websocket), proxy extensions, CLI download (`server/server.go` `newGRPCServer`, `newHTTPServer`). Holds a Role that can create/update/delete Secrets and ConfigMaps in its namespace (`manifests/base/server/argocd-server-role.yaml`).
- **argocd-repo-server** (`reposerver/`): gRPC service that clones repos and runs `helm`, `kustomize`, go-jsonnet and config-management plugins (CMP) to produce manifests (`reposerver/repository/repository.go`). No Kubernetes token is mounted (`automountServiceAccountToken: false` in `manifests/base/repo-server/argocd-repo-server-deployment.yaml`).
- **argocd-cmp-server** (`cmpserver/`): sidecar run in plugin images; listens on a unix socket in a volume shared with repo-server (`cmpserver/server.go`) and runs the plugin's `init`/`generate` commands (`cmpserver/plugin/plugin.go` `runCommand`).
- **argocd-application-controller** (`controller/`, library `gitops-engine/`): reconciles Applications, syncs to clusters, runs Lua health checks and actions (`util/lua`).
- **argocd-applicationset-controller** (`applicationset/`): generators (list, cluster, git, SCM provider, pull request, plugin, cluster-decision, OCI, matrix/merge) and templating that create Applications; webhook listener on `:7000`.
- **argocd-commit-server** (`commitserver/`): writes hydrated manifests to Git with write credentials. Shipped only in the `*-with-hydrator` manifests (absent from `manifests/install.yaml`).
- **argocd-notifications** (`notification_controller/`, `cmd/argocd-notification`): feeds Applications and AppProjects to the external notifications-engine library (out of view), which renders and sends notifications; with `--self-service-notification-enabled` (default false) config is also read from the app's namespace (`notification_controller/controller/controller.go`).
- **argocd-dex** (`cmd/argocd-dex`, `util/dex`): runs the upstream Dex image `ghcr.io/dexidp/dex` with generated config (`manifests/base/dex/argocd-dex-server-deployment.yaml`).
- **Redis** (upstream `redis:8.10.3-alpine`, `manifests/base/redis/`): cache for manifests, app state, OIDC token cache, login-failure counts, revoked token IDs.
- **CLI** `argocd` (`cmd/argocd`), helpers `argocd-git-ask-pass` (`util/askpass`) and `argocd-k8s-auth`.
- **UI** (`ui/`, React 19 + TypeScript) built in the Dockerfile and embedded into the server (`ui/embed.go`).

**Principals it trusts.**
- Whoever can write the Argo CD namespace's ConfigMaps/Secrets/AppProjects (`argocd-cm`, `argocd-rbac-cm`, `argocd-secret`, cluster and repository Secrets): this is the configuration source (`util/settings/settings.go`, `util/db`) and is admin-equivalent.
- Argo CD admins: local `admin`, enabled by default with a random 16-character initial password written to Secret `argocd-initial-admin-secret` (`util/settings/settings.go` `InitializeSettings`; `util/settings/accounts.go` `parseAdminAccount`), and `role:admin` (`assets/builtin-policy.csv`).
- The configured OIDC provider or Dex for user identity and groups.
- Admin-installed code and templates: CMP sidecar images, proxy-extension backends, UI extension JavaScript, Lua resource customizations, deep-link and hydrator README templates in `argocd-cm`.
- Kubernetes API servers of managed clusters.

**Build, ship, deploy.**
- Go module `github.com/argoproj/argo-cd/v3` (`go.mod`); nested module `gitops-engine/` is linked through a `replace` and tagged `gitops-engine/<tag>` at release (`.github/workflows/release.yaml` "Tag gitops-engine submodule").
- `make argocd-all` builds `./cmd` with `CGO_ENABLED=0` by default on Linux, static ldflags, and `GODEBUG=tarinsecurepath=0,zipinsecurepath=0` (`Makefile`).
- Image (`Dockerfile`): digest-pinned Ubuntu base; non-root uid 999; adds git, git-lfs (system-wide `git lfs install --system`), helm and kustomize (`hack/install.sh`, checksums in `hack/installers/checksums`), gpg, tini, openssh-client; copies `hack/gpg-wrapper.sh` and `hack/git-verify-wrapper.sh` into `/usr/local/bin`.
- Release on `v*` tags (`.github/workflows/release.yaml`): multi-arch image via `image-reuse.yaml`, SLSA provenance (`slsa-github-generator` v2.1.0), CLI binaries for linux/darwin/windows (`.goreleaser.yaml`), SBOM. The goreleaser release header says images are cosign-signed. Master pushes publish images and deploy to a staging repo (`image.yaml` `build-and-publish`, `Deploy`; PR builds use `build-only` with `push: false`).
- Deployment: kustomize-built manifests (`manifests/install.yaml`, `namespace-install.yaml`, `core-install.yaml`, `ha/`, `*-with-hydrator`); the release notes tell users to `kubectl apply` `manifests/install.yaml`. Shipped pods set runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities, seccomp RuntimeDefault (server and repo-server deployments), and NetworkPolicies per component (A6).

## adversaries

Ordered from least to most access. The 109 RPCs declared in `server/*/*.proto` are summarized per service, not listed one by one (registered in `server/server.go` `newGRPCServer` and `newHTTPServer` `mustRegisterGWHandler`); the 18 repo-server RPCs (`reposerver/repository/repository.proto`) are summarized under A6.

### A1 — Unauthenticated network client of argocd-server

Reaches port 8080 (Service `argocd-server` ports 80/443 → 8080; NetworkPolicy `argocd-server-network-policy` allows all ingress). gRPC, grpc-web and HTTP share the port (`server/server.go` `Run`, cmux). TLS is on unless `--insecure`/`server.insecure`; a self-signed certificate is generated when none is configured (`InitializeSettings`). Plain-HTTP requests are 307-redirected to HTTPS when TLS is on (`newRedirectServer`).

Application-wide default: every gRPC call passes `grpc_auth` interceptors calling `ArgoCDServer.Authenticate` (`server/server.go` `newGRPCServer`), which rejects calls without valid claims unless `users.anonymous.enabled` is `"true"` (default off, `util/settings/settings.go`) or `--disable-auth`. REST under `/api/` is relayed by grpc-gateway to the same gRPC server over localhost, and grpc-web (`content-type: application/grpc-web+proto`) is routed by `handlerSwitcher` to `grpcweb.WrapServer(grpcS)`, so both get the same interceptors. Opt-outs (`AuthFuncOverride`):
- `grpc.health.v1.Health` — anonymous (`healthServer.AuthFuncOverride`).
- `SessionService` (`Create` = login, `GetUserInfo`, `Delete`) — anonymous; claims are populated if present (`server/session/session.go`).
- `VersionService.Version` — anonymous; returns only the version string when not logged in (`server/version/version.go`).
- `SettingsService.Get` — anonymous (`server/settings/settings.go`: override nulls the auth error only for `/cluster.SettingsService/Get`); returns URL, OIDC issuer/client IDs/scopes/device and token URLs, Dex connector names/types/IDs, help URLs, UI and feature flags, installation ID; banner, controller namespace, resource overrides and password pattern only when logged in. `GetPlugins` keeps the auth error.
- gRPC reflection is registered (`reflection.Register`) with no override, so `Authenticate` applies.

HTTP routes outside the gateway (`server/server.go` `newHTTPServer` unless noted):

| Route | Access | Handler / check |
|---|---|---|
| `/api/badge` | anonymous | `server/badge/badge.go` `ServeHTTP`; data only if `statusbadge.enabled` = `"true"` (default off); validates name/namespace (`argo.IsValidAppName`, `IsValidNamespaceName`, `security.IsNamespaceEnabled`); returns app or per-project aggregate health/sync and optionally revision; sets `Access-Control-Allow-Origin: *`. Dispatched by `handlerSwitcher` before the mux. |
| `/auth/logout` | anonymous | `server/logout/logout.go`; reads `argocd.token` cookie, revokes it if it verifies, clears cookies, redirects to the OIDC `logoutURL` with the token substituted (`constructLogoutURL`) or to the Argo CD URL. |
| `/auth/login`, `/auth/callback` | anonymous | `util/oidc/oidc.go` `HandleLogin`/`HandleCallback`; registered only when SSO is configured (`registerDexHandlers`). `return_url` must match `url`/`additionalUrls` scheme+host and path prefix (`isValidRedirectURL`); state nonce kept in AES-GCM-encrypted `argocd.oauthstate` cookie (`generateAppState`/`verifyAppState`); optional PKCE; implicit-flow page rendered with `html/template`; with `ARGOCD_SSO_DEBUG=1` the callback renders the ID and refresh token (`renderToken`). |
| `/api/dex/*` | anonymous | `util/dex/dex.go` `NewDexHTTPReverseProxy` to the Dex HTTP port; only when SSO is configured. |
| `/api/webhook` | anonymous; per-provider secret | `util/webhook` `HandleRequest`: body capped by `http.MaxBytesReader` at `webhook.maxPayloadSizeMB` (default 50 MB, `defaultMaxWebhookPayloadSize`); first matching parser (`NewParsers`: Azure DevOps basic auth, Gogs, GitHub, GitLab, Bitbucket UUID, Bitbucket Server, Harbor, GHCR, Docker Hub) verifies with secrets from `argocd-secret`. Shipped `argocd-secret` has no webhook keys (`manifests/base/config/argocd-secret.yaml`). Docker Hub parser refuses all requests when its secret is empty (`dockerhub.go` `CanHandle`); GHCR logs that events "will not be validated" when its secret is empty (`ghcr.go` `NewGHCRParser`); the go-playground parsers' behaviour with an empty secret is out of view (library not vendored); Harbor not verified. Effect: queues app refreshes/hydrations for apps whose sources match the payload repo and changed files, and may move cached manifests from the payload's `before` SHA key to its `after` SHA key (`webhook.go` `HandleEvent`, `storePreviouslyCachedManifests`). Bitbucket API calls with stored repo credentials only when the Bitbucket UUID/secret is set (`affectedRevisionInfo`). |
| `/swagger-ui`, `/swagger.json` | anonymous | `util/swagger/swagger.go`; static spec `assets/swagger.json`; disabled by `server.disable.swagger.ui` (default enabled). |
| `/healthz` | anonymous | `util/healthz`; `?full=true` lists clusters (`healthCheck`). |
| `/download/argocd-linux`, `/download/argocd-linux-<arch>` | anonymous | `registerDownloadHandlers` serves the `argocd` binary found on PATH. |
| `/extensions.js` | anonymous | `serveExtensions` concatenates non-symlink files matching `^extension(.*)\.js$` under `/tmp/extensions/`. |
| `/` (static UI) | anonymous | `newStaticAssetsHandler`: embedded `ui/dist/app` composed with optional `--staticassets` dir (default `/shared/app`, opened with `os.OpenRoot`); sets `X-Frame-Options` (default `sameorigin`) and CSP (default `frame-ancestors 'self';`). |
| `/terminal` | cookie session | see A2. |
| `/extensions/*` | cookie session | see A2; only with `--enable-proxy-extension` (default false). |
| metrics `:8083` `/metrics`, `/debug/pprof/*` | anonymous | `server/metrics/metrics.go`; pprof answers only if `/home/argocd/params/profiler.enabled` is `"true"` (`util/profile`; `server.profile.enabled`). Bound in `Listen()` with `ListenHost` (default `0.0.0.0`). |

Login brute force is bounded by `VerifyUsernamePassword` (`util/session/sessionmanager.go`): usernames ≤32 bytes, per-user failure count (default 5 in 300 s, env `ARGOCD_SESSION_FAILURE_*`) stored via Redis-backed user-state storage, random 500–1000 ms delay, a dummy hash on unknown users, striped per-user locks; plus at most 50 concurrent logins per server divided by `ARGOCD_API_SERVER_REPLICAS` (`server/server.go` `maxConcurrentLoginRequestsCount`, `server/session/ratelimiter.go`).

With `users.anonymous.enabled` the subject is the empty claims value and RBAC uses `policy.default` (`util/rbac/rbac.go` `enforce`). With `--disable-auth`, `Authenticate` returns immediately and the enforcer is disabled (`enf.EnableEnforce(!opts.DisableAuth)`), so every route above is fully privileged.

### A2 — Authenticated user with limited RBAC, or another tenant (project)

**Authentication.** Token taken from gRPC metadata `token`, then `Authorization: Bearer`, then the `argocd.token` cookie (relayed by the gateway as `grpcgateway-cookie`) (`server/server.go` `getToken`). `SessionManager.VerifyToken` (`util/session/sessionmanager.go`) dispatches on the unverified `iss`: `argocd` → `Parse` (HMAC only, key `server.secretkey`; project-role subjects `proj:<p>:<role>` must match a token entry in the AppProject role by `iat`/`jti`; local accounts must be enabled, have the capability encoded in `sub` (`login`/`apiKey`), carry a `jti` not revoked in Redis, API keys must be listed on the account, and `iat` must be after the last password change); any other issuer → OIDC `Provider.Verify` (`util/oidc/provider.go`: requires `aud` ∈ `OAuth2AllowedAudiences` when present; tokens without `aud` pass only if `skipAudienceCheckWhenTokenHasNoAudience`), then revocation check by `jti`/`uti`/at_hash. Groups may be filled from UserInfo (`SetGroupsClaimFromEndpoint`). Login tokens with <5 min left are re-issued.

**Authorization.** Casbin model `assets/model.conf` (glob-or-regex matching, explicit deny wins), built-in roles `role:readonly`/`role:admin` (`assets/builtin-policy.csv`), user policy from `argocd-rbac-cm` (shipped empty, so no `policy.default`: `manifests/base/config/argocd-rbac-cm.yaml`), and per-project role policies injected at enforcement (`server/rbacpolicy/rbacpolicy.go` `EnforceClaims`; project tokens only get their project's policies, `enforceProjectToken`). Group claims are read from the configured scopes (default `groups`, `rbac.DefaultScopes`).

Per-method checks (pattern seen across `server/application`, `server/applicationset`, `server/repository`, `server/project`, `server/cluster`, `server/account`): each RPC calls `s.enf.EnforceErr` or a helper. For Applications, `getAppEnforceRBAC` (`server/application/application.go`) checks the requested and the actual `<project>/<ns>/<name>` (`security.RBACName`), denies namespaces outside `--application-namespaces` (`isNamespaceEnabled`) and fetches the AppProject; `Create`/`Update` call `validateAndNormalizeApp` → `argo.ValidatePermissions` (source repo, destination, cluster permitted by project). Exceptions seen:
- `NotificationService` `ListTriggers`/`ListServices`/`ListTemplates`: no RBAC, any authenticated caller (`server/notification/notification.go`).
- `AccountService`: a local (`iss=argocd`) account always passes `ensureHasAccountPermission` for itself (get, create/delete own API keys); `UpdatePassword` skips RBAC for one's own local account; `CanI` only evaluates (`server/account/account.go`).
- `ProjectService.GetGlobalProjects` relies on `Get`'s check.

What A2 can reach (with the matching RBAC):
- Application data: manifests (`GetManifests`; `GetManifestsWithFiles` streams caller-supplied local files to the repo-server for rendering and needs only `applications, get`), live resources (`GetResource`, `PatchResource`, `DeleteResource`, `RunResourceActionV2` with Lua actions), resource tree/events, `PodLogs` (`logs, get`), `ServerSideDiff`, `ListLinks`/`ListResourceLinks`. Secret data is masked by `diff.HideSecretData` (`gitops-engine/pkg/diff`) in `GetManifests`, `GetManifestsWithFiles`, `GetResource`/`replaceSecretValues`, `PatchResource` responses, `ListResourceLinks`, `ServerSideDiff`, and in controller-computed managed resources (`controller/appcontroller.go`).
- Deep links: admin templates from `argocd-cm` evaluated with `expr` conditions and `text/template` over the app, resource, cluster and project (`server/deeplinks/deeplinks.go` `EvaluateDeepLinksResponse`); the rendered URL's scheme is not checked there (UI handling not verified); the `managed-by-url` annotation is checked with `settings.ValidateExternalURL`.
- Sync: `applications, sync`; syncing with local manifests or overriding revision/source needs `applications, override` (`Sync`, `resolveSourceRevisions`). An operation set at create time is dropped (`Create`).
- App spec fields reach the repo-server: Helm values/parameters, remote values-file URLs (schemes from `helm.valuesFileSchemes`, default `https`,`http` — `GetHelmSettings`), Kustomize options, Jsonnet TLAs/ext vars as code (`makeJsonnetVM`), plugin env/parameters, multi-source `$ref` values, repo URLs (Git, Helm, OCI) the project permits.
- ApplicationSets via API: `Create`/`Generate` need `applicationsets, create` in the target project (`checkCreatePermissions`); server-side generation uses `tokenRefStrictMode=true` (`server/applicationset/applicationset.go` `generateApplicationSetApps`).
- Repositories/credentials: create/update with `repositories`/`write-repositories` RBAC on `<project>/<url>`; `ValidateAccess` makes the repo-server contact a caller-supplied URL with caller-supplied credentials (`server/repository/repository.go`).
- Clusters (`clusters` RBAC; cluster config may carry `execProviderConfig` commands, `docs/operator-manual/declarative-setup.md`), project roles and JWTs (`projects, update`), account API keys (`accounts, update`; `CreateToken` with `expiresIn` 0 issues a token without `exp`, `SessionManager.Create`).
- `/terminal`: `session.WithAuthMiddleware` (cookie `argocd.token` only) → `WithFeatureFlagMiddleware` (`exec.enabled`, default off) → `applications, get` and `exec, create` on the app, app project must match, pod must be in the app's resource tree, shell from `exec.shells` (default bash, sh, powershell, cmd) (`server/application/terminal.go`). The websocket upgrader's `CheckOrigin` returns true (`server/application/websocket.go`).
- `/extensions/<name>/*`: `AuthMiddlewareFunc` (cookie) → `Manager.authorize`: `applications, get` on headers `Argocd-Application-Name`/`Argocd-Project-Name`, `extensions, invoke`, project match and destination permitted; proxy strips `Authorization` and `Cookie` and sets `Argocd-Username`/`User-Id`/`User-Groups` only when non-empty (`server/extension/extension.go` `NewProxy`, `prepareRequest`).
- CSRF-related: non-GET `/api/` requests must have a content type in `--api-content-types` (default `application/json`; empty disables, logged as a high-severity warning) (`enforceContentTypes`); cookies are `SameSite=lax; httpOnly` and `Secure` unless `--insecure` (`util/http/http.go` `SetTokenCookie`). The content-type check covers `/api/` only, not grpc-web, `/terminal`, `/extensions` or `/auth/*`.

### A3 — Author of source content (push to a permitted Git repo, Helm chart or OCI artifact publisher, owner of a Kustomize remote base or Helm dependency)

Content is processed by repo-server `GenerateManifest` → `runRepoOperation`/`runManifestGen` (`reposerver/repository/repository.go`):
- Out-of-bounds symlink scan of the git checkout (skipping `.git`), extracted Helm chart and OCI artifact unless `reposerver.allow.oob.symlinks` (default false) (`checkOutOfBoundsSymlinks` → `util/app/path` `CheckOutOfBoundsSymlinks`); streamed local files checked the same way (`GenerateManifestWithFiles`).
- Value files and Jsonnet libs resolved inside the repo root after symlink resolution, URL schemes allow-listed (`util/io/path/resolved.go` `ResolveValueFilePathOrUrl`, `ResolveFileOrDirectoryPath`).
- Jsonnet imports confined to the repo root and regular files, checked before reading (`confinedImporter`).
- Kustomize runs with a `git` wrapper inserting `--end-of-options` for remote-base fetches (`util/kustomize/gitwrapper.go`, GHSA-9v9p-x54c-58gc) and a `helm` wrapper pinning `HELM_DATA_HOME`/`HELM_PLUGINS` for `--enable-helm` (`util/kustomize/helmwrapper.go`, GHSA-fw5c-w8rc-j7fx). Kustomize's own load restrictions are not overridden in code read (not verified). Remote bases and Helm dependencies make the repo-server fetch further URLs named by the content.
- Archives are extracted through `os.Root` with symlink-ancestor checks and a size cap (`util/io/files/tar.go` `untar`); defaults: directory manifests 10M combined, streamed tar 100M / extracted 1G, Helm and OCI extracted 1G, OCI layer media types allow-listed (`cmd/argocd-repo-server/commands/argocd_repo_server.go`).
- CMP: repo tarball streamed to the sidecar (`util/cmp`), app path kept inside the work dir (`generateManifestGeneric`), file modes reset unless `preserveFileMode`; plugin commands receive app env and `PARAM_*` values (`cmpserver/plugin/plugin.go`).
- Git over SSH uses `StrictHostKeyChecking=yes` with the known-hosts file unless the repository is marked insecure (`util/git/creds.go`); credentials are handed to git through the askpass unix socket by nonce (`util/askpass/server.go`). Checkouts live under randomized paths in `/tmp/_argocd-repo` (`repository.NewService`, `NewRandomizedTempPaths`).
- Rendered manifests are applied by the controller only if each object's group/kind and namespace pass the AppProject (`controller/sync.go` `validateSyncPermissions`); manifests that create `Application` objects in the control-plane namespace may name any project (docs, out-of-scope). Lua health scripts run against these objects (A7).
- With the hydrator, rendered output is written by the commit-server into a checkout opened with `os.OpenRoot` (`commitserver/commit/commit.go`, `hydratorhelper.go` `WriteForPaths`); dry and hydrate-to sources must be permitted by the project (`controller/hydrator/hydrator.go` `validateApplications`).

### A4 — SCM metadata and webhook senders feeding ApplicationSets

- Generator parameters (branch names, PR titles/labels/SHAs, file contents from git file generators, cluster labels, plugin responses) are substituted into Application templates with `text/template` + sprig (`env`, `expandenv`, `getHostByName` removed) or `fasttemplate` (`applicationset/utils/utils.go`). A templated `project` field lets generator data choose the project (`docs/operator-manual/applicationset/Security.md`).
- SCM/PR generators read tokens from Secrets named in `tokenRef` in the ApplicationSet's namespace; the controller requires the SCM-creds label only with `--token-ref-strict-mode` (default false) (`cmd/argocd-applicationset-controller/commands/applicationset_controller.go`; `applicationset/generators/pull_request.go` → `utils.GetSecretRef`). Custom SCM API URLs are unrestricted unless `--allowed-scm-providers` is set (default empty = all); SCM/PR generators can be turned off with `--enable-scm-providers=false` (default true).
- Webhook `:7000/api/webhook` on the applicationset-controller: anonymous, same parsers and secrets as argocd-server (`applicationset/webhook/webhook.go` `NewWebhookHandler`); effect: refresh matching ApplicationSets. NetworkPolicy allows 7000 and 8080 from all namespaces.

### A5 — Kubernetes user who can create Application/ApplicationSet objects directly

- In namespaces listed in `application.namespaces` (apps-in-any-namespace), Argo CD API RBAC is bypassed; the controller processes an app only if its AppProject's `sourceNamespaces` allow its namespace (`controller/appcontroller.go` `IsAppNamespacePermitted`), and sync still enforces project restrictions.
- Applications in the control-plane namespace may use any project (`docs/operator-manual/app-any-namespace.md`).
- `argocd ... --core` runs an in-process server enforcing only Kubernetes RBAC (`docs/operator-manual/user-management/index.md`).

### A6 — Pod on the cluster network reaching internal services

| Service | Auth | Network (shipped NetworkPolicy) |
|---|---|---|
| repo-server gRPC `:8081` (`RepoServerService`, version, health, reflection) | none in interceptors (`reposerver/server.go`); TLS with self-signed cert if none mounted; client certs required only when `client-ca.crt` exists at `--client-ca-path` (from optional Secret `argocd-repo-server-mtls`) | from server, controller, notifications, applicationset pods |
| repo-server metrics `:8084` (+pprof gate) | none | all namespaces |
| commit-server gRPC `:8086` (`CommitHydratedManifests`) | none, plaintext (`commitserver/server.go`) | from controller only |
| commit-server metrics `:8087` | none | all namespaces |
| Redis `:6379` | `requirepass` from Secret `argocd-redis` (created by `argocd admin redis-initial-password` init container); plaintext | from server, repo-server, controller |
| Dex `:5556`/`:5557`; metrics `:5558` | Dex's own (out of view) | 5556/5557 from server; 5558 all namespaces |
| controller metrics `:8082` (+pprof gate) | none | all namespaces |
| notifications metrics `0.0.0.0:9001` (`http.DefaultServeMux`) | none | all namespaces |
| CMP and askpass unix sockets | filesystem only | pod-local |

Repo-server RPCs: `GenerateManifest`, `GenerateManifestWithFiles`, `TestRepository`, `ResolveRevision`, `ListRefs`, `ListOCITags`, `ListApps`, `ListPlugins`, `GetAppDetails`, `GetRevisionMetadata`, `GetOCIMetadata`, `GetRevisionChartDetails`, `GetHelmCharts`, `GetGitFiles`, `GetGitDirectories`, `GetOciFiles`, `GetOciDirectories`, `UpdateRevisionForPaths`. Requests carry the repository and Helm/OCI credentials the caller chose (`server/application/application.go` `queryRepoServer` filters them by project with `argo.GetPermittedRepos`/`GetPermittedReposCredentials`); the repo-server does not re-check projects. Clients connecting to repo-server skip certificate verification unless strict TLS or a CA is configured (`reposerver/apiclient/clientset.go`). Whoever can write Redis can alter cached manifests and app state read by server and controller (`util/cache/redis.go`, JSON + gzip).

### A7 — Workloads and users of managed clusters

Live objects flow back into Argo CD: resource tree, events, pod logs, Lua health checks and actions run on live objects (`util/lua/lua.go`: package, base, table and a safe `os` library; full libraries only when a resource override sets `useOpenLibs`; 1 s timeout), status shown in the UI. Resource tracking defaults to annotation (`GetTrackingMethod`). Sync uses the controller's cluster credentials unless `application.sync.impersonation.enabled` (default false) maps destinations to service accounts (`controller/sync.go`).

### A8 — Admin-installed extension code and identity providers

CMP sidecars, proxy-extension backends, UI `extension*.js` and Lua customizations run with the trust the docs assign them (out-of-scope). The OIDC provider and Dex connectors decide identity and groups; a token from another audience is accepted only if that audience is in `allowedAudiences` (`util/oidc/provider.go`).

### A9 — Against the CLI

The CLI stores tokens in its config file with mode 0600 (`util/config/reader.go` `MarshalLocalYAMLFile`), runs the SSO callback on `localhost` with a state nonce and PKCE (`cmd/argocd/commands/login.go`), uses a grpc-web proxy on a unix socket (`pkg/apiclient/grpcproxy.go`), and executes `argocd-<name>` plugins found on PATH (`cmd/argocd/commands/plugin.go`).

### A10 — Contributors from forks

`auto-assign-pr-author.yaml` and `cherry-pick.yml` run on `pull_request_target`; their comments say they never check out or run PR code (not verified beyond the comments). Registry credentials are passed only on push/tag events (`image.yaml` `build-and-publish` condition `github.event_name == 'push'`; `release.yaml` on tags).

## assets

1. **Ability to deploy to and read from target clusters**: controller and server service accounts (ClusterRoles above), cluster Secrets in the Argo CD namespace (`util/db`). Boundary: AppProject destinations, resource allow/deny lists and source repos — API (`argo.ValidatePermissions`), controller (`controller/state.go`, `controller/appcontroller.go` `IsLiveResourcePermitted`) and sync (`validateSyncPermissions`). The default project allows every repo, destination and cluster-scoped kind (`server/server.go` `initializeDefaultProject`).
2. **Repository, Helm, OCI, SCM and write credentials, GitHub App keys**: Secrets read by `util/db`; sent per request to repo-server/commit-server; exposed to CMP plugins only with `provideGitCreds`.
3. **`argocd-secret`**: `server.secretkey` signs all Argo-issued JWTs (HS256, `SessionManager.signClaims`) and, via scrypt with salt = SHA-256 of the key (`util/crypto/crypto.go` `KeyFromPassphrase`), keys the AES-GCM encryption of the OAuth state cookie and the OIDC token cache (`util/oidc/oidc.go`); also admin bcrypt hash, API key IDs, webhook secrets, server TLS key, SSO client secrets.
4. **Sessions and tokens**: `argocd.token` cookie, API keys, project-role JWTs (identified by `iat`/`jti` in the AppProject), revocation list in Redis (`util/session/state.go`).
5. **Integrity of RBAC and project policy**: `argocd-rbac-cm`, AppProjects, application namespaces. argocd-server can write Secrets/ConfigMaps/AppProjects in its namespace (`argocd-server-role.yaml`), so its compromise is admin.
6. **Redis contents**: rendered manifests in plaintext (per `docs/operator-manual/secret-management.md`), app state, encrypted OIDC tokens, login-failure counts.
7. **Hydrated branches and signed commits** (`commitserver`, `util/gpgsign`).
8. **Availability**: repo-server CPU/memory (size limits above; `--parallelismlimit` 0 = unlimited), controller, webhook queues (parallelism 50, refresh workers 20, `cmd/argocd-server/commands/argocd_server.go`); gRPC messages up to 200 MB on the API server and 100 MB on repo/commit servers (`MaxGRPCMessageSize` in `pkg/apiclient`, `reposerver/apiclient`, `commitserver/apiclient`).
9. **Shipped artifacts**: images, CLI binaries, manifests, SBOM and provenance from `.github/workflows/release.yaml`.

Trust boundaries:
- Browser/CLI ↔ argocd-server: TLS, `Authenticate`, per-RPC RBAC, cookie flags and content-type check (A1, A2).
- argocd-server ↔ Dex: reverse proxy; TLS to Dex unless `--dex-server-plaintext`; strict verification only with `--dex-server-strict-tls`.
- Server/controller/appset/notifications ↔ repo-server: TLS without client authentication by default (A6).
- repo-server ↔ CMP sidecar: unix socket in a shared emptyDir; tarball with `--plugin-tar-exclude` globs.
- controller ↔ commit-server: plaintext gRPC limited by NetworkPolicy.
- Components ↔ Redis: password, plaintext, NetworkPolicy.
- Argo CD ↔ managed clusters: REST configs built from cluster Secrets; optional impersonation.
- Tenant ↔ tenant: AppProject + RBAC + allowed application namespaces; one repo-server and one Redis serve all tenants.

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


- `SECURITY.md`: asks reporters not to file scanner output and to validate LLM findings before reporting; low/medium issues are published immediately and fixed in the open; supports the last 3 minor versions; dependency bumps only within a patch series unless exploitable in Argo CD.
- `docs/operator-manual/security.md`:
  - Unauthorized write access to a trusted Git repo means attackers "would be able to affect the Kubernetes resources which are deployed".
  - Malicious Helm charts or kustomizations may "read files out-of-tree", including "adjacent git repos, as well as files on the repo-server itself"; whether that matters depends on the repos' sensitivity, and plugins holding secrets require trusted repo contents.
  - The repository allow-list "only restricts the initial repository"; Kustomize remote bases and Helm dependencies can pull other repos.
  - Redis traffic is plain by default. `/swagger-ui` is "unauthenticated by design".
  - Webhook payloads are untrusted and only trigger a refresh.
  - Directory apps can exhaust repo-server memory unless `reposerver.max.combined.directory.manifests.size` is set; users who can create Applications can raise total memory use.
  - The API server "can enforce" TLS 1.2 with `--tlsminversion`; the doc says all inter-component traffic uses TLS.
- `docs/operator-manual/applicationset/Security.md`: only admins may create/update/delete ApplicationSets; a git generator can read Secrets in the Argo CD namespace and send them to arbitrary URLs; with a templated `project` field, admins must control every generator source of truth.
- `docs/operator-manual/applicationset/Appset-Any-Namespace.md`: the SCM URL allow-list applies only to providers with a custom `api`; enabling `tokenRef` restrictions is "highly recommended".
- `docs/operator-manual/app-any-namespace.md`: never put user-controlled namespaces or the `argocd` namespace in a privileged project's `sourceNamespaces`; apps in the control-plane namespace may use any project.
- `docs/operator-manual/declarative-setup.md`: a project that can deploy into the Argo CD namespace grants admin access; push access to its source repos must be limited to admins.
- `docs/operator-manual/web_based_terminal.md`: exec is disabled by default; with `exec/create` a user effectively gets the privileges of the pod's service account.
- `docs/operator-manual/config-management-plugins.md`: plugins are trusted; admins must install them only from trusted sources and plugins must escape user input; `preserveFileMode` and `provideGitCreds` carry warnings.
- `docs/operator-manual/rbac.md`: all authenticated users get at least the default policy, which a deny rule cannot block; with anonymous access use a `role:unauthenticated` default; globs do not treat `/` as a separator; SSO groups named like local users inherit their roles.
- `docs/operator-manual/user-management/index.md`: group changes apply only at re-authentication; `allowedAudiences` must be unique to the instance; `--core` bypasses Argo CD authentication and RBAC; Dex token-exchange subjects must be exact; non-expiring tokens are discouraged.
- `docs/operator-manual/app-sync-using-impersonation.md`: without impersonation, syncs run with control-plane privileges and AppProjects are "not secure enough" against a compromised Argo CD.
- `docs/operator-manual/secret-management.md`: Argo CD stores generated manifests in plaintext in Redis; injecting secrets into manifests is discouraged.
- `docs/operator-manual/high_availability.md`: profiling is disabled by default; enabling it is the operator's choice.
- `docs/operator-manual/ingress.md`: running `argocd-server --insecure` behind a TLS-terminating gateway is acceptable "if your security requirements allow it".
- `docs/developer-guide/extensions/proxy-extensions.md`: proxy extensions are Beta.
- Left to deployers by code defaults: configure webhook secrets in `argocd-secret`; provide repo-server/Dex CAs and the `argocd-repo-server-mtls` client CA for verified internal TLS; set `--token-ref-strict-mode` and `--allowed-scm-providers`; restrict the `default` project. NetworkPolicies are shipped; whether the cluster enforces them is outside the repository.
- `AGENTS.md`/`CLAUDE.md` hold contribution rules for AI agents and say nothing about scope.

## production

- `applicationset/` — production (applicationset-controller; also linked into argocd-server for the ApplicationSet API). `applicationset/examples/` — examples.
- `assets/` — production, embedded via `assets/embed.go` (built-in RBAC policy, Casbin model, swagger.json, badge SVG).
- `cmd/` — production entry points of the single `argocd` binary.
- `cmpserver/` — production (sidecar server copied into plugin containers by the repo-server init container).
- `commitserver/` — production in the `*-with-hydrator` manifests only.
- `common/` — production constants and defaults.
- `controller/` — production (application controller).
- `docs/` — documentation (`mkdocs.yml`, `.readthedocs.yaml`).
- `examples/` — examples (dashboards, sample plugins, RBAC samples); not shipped.
- `gitops-engine/` — production library (`gitops-engine/pkg`, linked via `replace` and tagged at release). `gitops-engine/agent/` — separate sample agent with its own image target in `gitops-engine/Makefile`; not built by `release.yaml`.
- `hack/` — tooling, except `hack/install.sh`, `hack/tool-versions.sh` and `hack/installers/` (run in the image build) and `hack/gpg-wrapper.sh`, `hack/git-verify-wrapper.sh` (shipped in the image).
- `manifests/` — production (published install manifests and CRDs). `manifests/dev-tilt/` — dev tooling.
- `notification_controller/` — production.
- `notifications_catalog/` — published catalog of notification templates/triggers (`install.yaml`); not part of `manifests/base`.
- `overrides/` — docs theme.
- `pkg/` — production (CRD types, generated clients, `pkg/apiclient` used by CLI and published as Go packages).
- `renovate-presets/` — tooling (Renovate config).
- `reposerver/` — production.
- `resource_customizations/` — production Lua health checks/actions embedded via `resource_customizations/embed.go` (`go:embed all:*`); the `*_test.go` and testdata files in it are tests.
- `server/` — production (API server).
- `test/` — e2e tests and fixtures (`test/container`, `test/remote` images are test-only).
- `tools/` — tooling (`cmd-docs` generator).
- `ui/` — production (built by the Dockerfile, embedded via `ui/embed.go`).
- `util/` — production libraries.
- `.github/` — CI/CD; `release.yaml` and `image.yaml` hold publishing credentials.
- Root files: `Dockerfile`, `.goreleaser.yaml`, `Makefile` — release build; `Dockerfile.dev`, `Dockerfile.tilt`, `Dockerfile.ui.tilt`, `Tiltfile`, `Procfile` — local development.

## facts

**Security policy**: `SECURITY.md` (v1.7, 2026-10-22; reports via GitHub draft advisories), `SECURITY_CONTACTS`, `SECURITY-INSIGHTS.yml` (links Argo threat-model PDFs in another repository, out of view).

**Template engines and escaping**
- `html/template` (contextual auto-escaping): `util/oidc/oidc.go` implicit-flow page, `util/oidc/templates.go` SSO debug token page.
- `text/template` (no escaping) + sprig with `env`/`expandenv`/`getHostByName` removed: `applicationset/utils/utils.go`, `server/deeplinks/deeplinks.go`, `commitserver/commit/hydratorhelper.go` (README from `GetHydratorReadmeMessageTemplate`); also `util/hydrator/template.go`. `fasttemplate` for non-Go-template ApplicationSets.
- Notification templates: notifications-engine (out of view).
- UI: React; no `dangerouslySetInnerHTML`, `innerHTML`, `eval(` or `new Function` in `ui/src`; logs rendered with `ansi-to-react`.

**Serialization**
- gRPC protobuf (gogo) for all services; REST JSON through grpc-gateway with `grpc_util.JSONMarshaler` (`server/server.go`).
- YAML via `sigs.k8s.io/yaml` (JSON-compatible) for manifests and settings; `gopkg.in/yaml` imported in `server/server.go`, `server/extension/extension.go`, `util/helm/client.go`, `commitserver/commit/hydratorhelper.go`.
- Redis values: JSON, gzip by default (`util/cache/redis.go`; `REDIS_COMPRESSION` default `gzip` in `util/cache/cache.go`). In-process cache uses `encoding/gob` (`util/cache/inmemory.go`).
- Archives: tar/tgz via `util/io/files/tar.go` (`os.Root`, `LimitReader`); Helm charts (`util/helm`), OCI layers (`util/oci`), CMP and manifest streams (`util/cmp`, `util/manifeststream`).
- Jsonnet via go-jsonnet with `confinedImporter`; Lua via gopher-lua (`util/lua`); `expr` for deep-link conditions; JWT via golang-jwt v5 and coreos/go-oidc.

**Authentication and sessions**
- Local accounts: `admin` plus `accounts.<name>` in `argocd-cm` with capabilities `login`/`apiKey` (`util/settings/accounts.go`); bcrypt at ≥ default cost (`util/password/password.go`).
- Argo-issued JWTs: HS256 with `server.secretkey` (generated when missing, `InitializeSettings`); login sessions last `users.session.duration`, default 24 h (`util/settings/settings.go`).
- SSO: OIDC directly or via Dex; groups from token or UserInfo; refresh tokens cached encrypted in Redis (`util/oidc/oidc.go`).
- Cookies: `argocd.token` (chunked, `SameSite=lax`, `httpOnly`, `Secure` unless `--insecure`), `argocd.oauthstate` (HttpOnly, SameSite=Lax, Secure if the configured URL is https).
- Anonymous mode `users.anonymous.enabled`; `--disable-auth` turns off authentication and RBAC.

**Default configuration values that change exposure**
- argocd-server flags (`cmd/argocd-server/commands/argocd_server.go`): `--insecure` false; `--disable-auth` false; `--api-content-types` `application/json`; `--enable-gzip` true; `--x-frame-options` `sameorigin`; `--content-security-policy` `frame-ancestors 'self';`; swagger enabled; proxy extensions off; listen `0.0.0.0:8080`, metrics `0.0.0.0:8083`; repo/Dex clients non-strict TLS; `--hydrator-enabled` false; `--sync-with-replace-allowed` true; appset SCM providers enabled, allow-list empty; source-IP logging off.
- `argocd-cm` keys (`util/settings/settings.go`): `exec.enabled` false; `exec.shells` bash,sh,powershell,cmd; `statusbadge.enabled` false; `users.anonymous.enabled` false; `admin.enabled` true; tracking method annotation; `application.sync.impersonation.enabled` false; `helm.valuesFileSchemes` https,http; `webhook.maxPayloadSizeMB` 50.
- Shipped `argocd-rbac-cm`, `argocd-cmd-params-cm` and `argocd-secret` carry no data; the `default` AppProject is permissive (`initializeDefaultProject`).
- repo-server (`argocd_repo_server.go`): TLS on; mTLS only if the client CA file exists; `--allow-oob-symlinks` false; `--include-hidden-directories` false; size limits as in A3; `--parallelismlimit` 0 (unlimited). Git submodules: `common/common.go` comment says enabled by default (not verified).
- applicationset-controller: `--token-ref-strict-mode` false; `--webhook-addr` `:7000`; `--metrics-addr` `:8080`; `--probe-addr` `:8081`; leader election off; `--policy` empty (sync).
- notifications: self-service notifications off; metrics on `0.0.0.0:9001`.
- pprof handlers on server, repo-server, controller and applicationset metrics muxes answer only when the profiler flag file reads `"true"` (`util/profile/profile.go`).
- Redis: password required, no persistence (`--save ""`, `--appendonly no`).

**Build and hardening**: `CGO_ENABLED=0`, static linking, `GODEBUG=tarinsecurepath=0,zipinsecurepath=0` (`Makefile`); non-root image with tini; restrictive pod securityContexts in `manifests/base`; workflows pin actions by SHA, use step-security harden-runner in audit mode, CodeQL (`codeql.yml`), zizmor (`zizmor.yaml`), Scorecard, Snyk (`update-snyk.yaml`); golangci-lint (`.golangci.yaml`); SLSA provenance for image, CLI and SBOM.

**Where routes, schemas and permissions are defined**
- HTTP mux: `server/server.go` (`newHTTPServer`, `registerDexHandlers`, `registerExtensions`, `registerDownloadHandlers`, `withRootPath`); appset webhook in `cmd/argocd-applicationset-controller/commands/applicationset_controller.go` `startWebhookServer`.
- gRPC services and REST mappings: `server/*/*.proto` (google.api.http), generated `pkg/apiclient/*/*.pb.gw.go`; OpenAPI `assets/swagger.json`. Internal: `reposerver/repository/repository.proto`, `commitserver/commit/commit.proto`, `cmpserver/plugin/plugin.proto`, `util/askpass/askpass.proto`.
- CRD schemas: `pkg/apis/application/v1alpha1`, `manifests/crds`.
- Permissions: `assets/builtin-policy.csv`, `assets/model.conf`, `util/rbac/rbac.go` (resources/actions, `policy.default`, `policy.matchMode`), `server/rbacpolicy/rbacpolicy.go`; AppProject checks in `pkg/apis/application/v1alpha1` (`IsSourcePermitted`, `IsDestinationPermitted`, `IsGroupKindNamePermitted`, `IsAppNamespacePermitted`).
- Settings keys: `util/settings/settings.go`; component env wiring from `argocd-cmd-params-cm` in `manifests/base/*/*-deployment.yaml`.

**Languages** (tracked lines, `git ls-files`): Go ≈88% of code (≈543k lines: ≈192k hand-written non-test, ≈204k tests, ≈142k generated `*.pb*.go`); TypeScript/TSX ≈7% (`ui/`); Lua ≈2% (`resource_customizations/`); SCSS ≈1%; JavaScript and shell <1% each. About 377k lines of YAML (manifests, CRDs, testdata) are not counted as code.


<!-- written at these commits:
b7bc418289a96130340ea79964c4491b416c14f2 https://github.com/cx-benchmark/argo-cd
-->
