# Lab 7 — Container and Kubernetes Hardening

I scanned Juice Shop and an intentionally unsafe Dockerfile, then ran the
same image in a local Kubernetes cluster with restricted Pod Security,
network isolation, and a read-only root filesystem. The final manifests are
in [labs/lab7/k8s](../labs/lab7/k8s/); raw scanner output and runtime evidence
remain local in the ignored `labs/lab7/results/` directory.

## Environment and reproducibility

| Item | Version or reference |
|---|---|
| Scan date | 23 September 2026 |
| Application | `bkimminich/juice-shop:v20.0.0`, Linux/amd64 |
| Pinned image | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Trivy | 0.74.0 on Windows; Linux container used to cross-check Kubernetes misconfigurations |
| Trivy container | `aquasec/trivy:0.74.0`, digest `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| Vulnerability DB | Schema 2, updated `2026-09-23T07:12:28.724391795Z` |
| k3d / kubectl | 5.9.0 / 1.34.1 |
| Kubernetes | `rancher/k3s:v1.33.0-k3s1` |

The image digest and configured user came from `docker inspect`, not from
assumptions about the tag. I used a separate k3d kubeconfig and a loopback-only
API endpoint:

```powershell
k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1 `
  --api-port 127.0.0.1:6550 `
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
$env:KUBECONFIG = (k3d kubeconfig write lab7)
```

## Task 1

### Image vulnerabilities and available fixes

```powershell
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL `
  --format json --output labs/lab7/results/trivy-image.json
```

The scan completed successfully in 10.08 seconds. These counts come from
the JSON's `Vulnerabilities` arrays and represent vulnerability/package
matches, not unique advisory IDs; secret findings are excluded.

| Severity | Matches | With a listed fix | Without a listed fix |
|---|---:|---:|---:|
| Critical | 10 | 8 | 2 |
| High | 64 | 63 | 1 |
| **Total** | **74** | **71** | **3** |

Other severities were filtered out, so this is not an all-severity total.
For fix availability I required a nonempty `FixedVersion`; the assignment's
`FixedVersion != null` filter returns the same 71 rows in this report.

The earlier Grype SBOM scan of this same digest is available for comparison:

| Comparable severity | Grype, 20 September | Trivy, 23 September |
|---|---:|---:|
| Critical | 14 | 10 |
| High | 85 | 64 |
| **High + Critical** | **99** | **74** |

Grype's original all-severity total was 183, which should not be compared
directly with a High/Critical-only scan. The 99-versus-74 difference can
reflect inventory and matching coverage, severity sources, advisory aliases,
and the three-day difference between database snapshots; it does not mean
that the unchanged image became safer.

### First ten fixable findings

These are the first ten rows after sorting fixable matches by Critical then
High, retaining Trivy's existing order within each severity:

| Severity | Advisory | Package | Installed | Listed fix |
|---|---|---|---|---|
| Critical | CVE-2023-46233 | crypto-js | 3.3.0 | 4.2.0 |
| Critical | CVE-2026-71851 | crypto-js | 3.3.0 | 4.0.0 |
| Critical | CVE-2015-9235 | jsonwebtoken | 0.1.0 | 4.2.2 |
| Critical | CVE-2015-9235 | jsonwebtoken | 0.4.0 | 4.2.2 |
| Critical | CVE-2019-10744 | lodash | 2.4.2 | 4.17.12 |
| Critical | CVE-2026-59873 | tar | 4.4.19 | 7.5.19 |
| Critical | CVE-2026-59873 | tar | 6.2.1 | 7.5.19 |
| Critical | CVE-2026-59873 | tar | 7.5.15 | 7.5.19 |
| High | CVE-2026-14456 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| High | CVE-2026-45447 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

The fix version is specific to that advisory, not a recommendation to stop
at the oldest listed release. For example, `crypto-js` must satisfy both
listed thresholds, and all affected copies of `tar` need attention.

### Dockerfile findings

I placed the exact demonstration in `labs/lab7/results/df-demo/Dockerfile`
and scanned the directory without filtering out Medium or Low findings:

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

```powershell
trivy config labs/lab7/results/df-demo --format json `
  --output labs/lab7/results/trivy-dockerfile.json
```

| Check | Severity | Finding and practical impact |
|---|---|---|
| `DS-0001` | Medium | The mutable `latest` base tag makes rebuild contents unpredictable; an unwanted or compromised upstream change could enter a later build. Pin and review the base image digest. |
| `DS-0002` | High | The final user is root, so code execution in the application gains root privileges inside the container and a wider ability to modify files. It does not automatically grant host root. |
| `DS-0004` | Medium | Port 22 advertises an SSH access surface that would need separate authentication and patching if an SSH service were installed and exposed. `EXPOSE` alone neither starts SSH nor publishes a host port. |
| `DS-0026` | Low | Missing health checks can leave a failed or attacker-disrupted process without a container health signal, delaying automated detection or recovery. This is an operational weakness, not an exploit by itself. |

There were four failures: one High, two Medium, and one Low. This scan did
not flag the remote `ADD` instruction, so I have not invented an additional
`DS-*` finding for it; the downloaded artifact would still need integrity
verification in a real build.

### Handling findings without a fix

The three matches without a listed fix affect `decompress@4.2.1`
(`CVE-2026-53486`, Critical), `marsdb@0.6.11` (`GHSA-5mrr-rgp6-x4gr`,
Critical), and `lodash.set@4.3.2` (`CVE-2020-8203`, High).

I would first check whether each vulnerable behavior is reachable in our
application, then remove or replace the dependency, disable that feature,
or restrict the inputs that reach it. While a replacement is prepared,
least privilege, network isolation, read-only filesystems, and monitoring
can limit impact, but they do not remove the vulnerable code. Each accepted
exception should have an owner, a justification, an expiry date, and a
scheduled rescan. I would tell a manager that zero findings is not a reliable
release criterion: the useful evidence is which risks remain reachable,
what controls reduce them, and when remediation will be reviewed.

## Task 2

### Restricted workload

The [namespace](../labs/lab7/k8s/namespace.yaml) sets all three admission modes
to `restricted` and pins their policy version to `v1.33`:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

The pod-level security context in the
[Deployment](../labs/lab7/k8s/deployment.yaml) is:

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
```

Both the application and the initContainer use this container-level context:

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

The dedicated [ServiceAccount](../labs/lab7/k8s/serviceaccount.yaml) and pod
both set `automountServiceAccountToken: false`. The application requests
100m CPU and 256 MiB memory, with limits of one CPU and 512 MiB; the initContainer
requests 100m/128 MiB and is limited to 500m/256 MiB. Both images are pinned
to the same digest, and storage requests, limits, and a bounded `emptyDir`
make the temporary writable space explicit.

I applied the namespace first; applying the ServiceAccount before the
Deployment also avoids a transient missing-ServiceAccount event:

```powershell
kubectl apply -f labs/lab7/k8s/namespace.yaml
kubectl apply -f labs/lab7/k8s/serviceaccount.yaml
kubectl apply -f labs/lab7/k8s/
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=180s
kubectl -n juice-shop get pod -l app=juice-shop -o yaml
```

The saved pod evidence shows:

```text
NAME                          READY   STATUS    RESTARTS
juice-shop-5785cd548d-lb784     1/1     Running   0
```

I checked the actual runtime UID using the Node executable available in
this shell-less image:

```powershell
kubectl -n juice-shop exec deployment/juice-shop -c juice-shop -- `
  /nodejs/bin/node -e 'console.log(process.getuid())'
# 65532
```

That matches `docker inspect --format '{{.Config.User}}'
bkimminich/juice-shop:v20.0.0`, which returned `65532`. Additional runtime
checks confirmed GID 65532 and no mounted ServiceAccount token.

### Network isolation

The [NetworkPolicy](../labs/lab7/k8s/networkpolicy.yaml) selects `app=juice-shop`
and isolates both ingress and egress. It permits TCP 3000 only from pods in
the same namespace with `access=juice-shop-client`; outbound traffic is
limited to TCP/UDP 53 on CoreDNS pods in `kube-system`, using both namespace
and pod selectors. Temporary probe pods demonstrated the behavior:

| Probe | Observed result |
|---|---|
| Same-namespace client with the allowed label | HTTP 200 |
| Same-namespace client without the allowed label | Connection refused |
| App resolving `kubernetes.default.svc.cluster.local` | DNS returned `10.43.0.1` |
| App connecting to the plain Juice Shop pod on TCP 3000 | Connection refused |
| Health check inside that destination pod | HTTP 200 |

The blocked destination was healthy, so the negative result was not caused
by a stopped server. The local k3s policy implementation rejected the
connection rather than silently timing it out. Port-forward access travels
through the Kubernetes API/kubelet path and is not proof of NetworkPolicy
enforcement; the pod-to-pod probes provide that evidence.

### Scanner comparison

I created the comparison workload with the assignment's commands:

```powershell
kubectl create namespace juice-plain
kubectl -n juice-plain create deployment juice --image=bkimminich/juice-shop:v20.0.0
kubectl -n juice-plain rollout status deployment/juice --timeout=180s
```

The initial Windows Kubernetes scan omitted configuration results even
though a scan of the exported Deployment found three High failures. In
Trivy 0.74.0's [temporary-file generator](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/k8s/scanner/io.go),
Windows sanitization replaces the `*` placeholder before creating the file,
so the random suffix is appended after `.yaml`; an explicit file pattern
restored detection. A Linux scan independently returned the same three
failures, so the comparison below uses the corrected Windows invocation:

```powershell
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL `
  --report summary --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$'

trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL `
  --report summary --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$'

trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL `
  --disable-node-collector --skip-db-update --skip-check-update `
  --file-patterns 'kubernetes:.*\.yaml[0-9]+$' `
  --format json --output labs/lab7/results/trivy-k8s.json
```

These commands use the dedicated `$env:KUBECONFIG` above. I disabled the
node collector because this comparison concerns application workloads,
not host configuration, and froze the DB/check bundle across both scans.
The file-pattern workaround is for this Windows version; it is unnecessary
on Linux. Completed summary and JSON scans exited 0.

The actual **raw summary rows** for the final manifests were:

| Workload | Critical vulnerabilities | High vulnerabilities | Critical misconfigurations | High misconfigurations | High secrets |
|---|---:|---:|---:|---:|---:|
| `juice-plain / Deployment/juice` | 10 | 64 | 0 | 3 | 2 |
| `juice-shop / Deployment/juice-shop` | 20 | 128 | 0 | 0 | 4 |

The final Deployment includes the bonus initContainer, which uses the same
image as the application. Trivy reports that image twice, doubling its raw
vulnerability and secret counts; I have retained those totals rather than
presenting them as 74 in the original summary.

For the assignment's image comparison, counting each identical image's
package/advisory matches once gives:

| Same image, counted once | Plain | Hardened |
|---|---:|---:|
| Critical vulnerabilities | 10 | 10 |
| High vulnerabilities | 64 | 64 |
| **High + Critical** | **74** | **74** |
| High/Critical workload misconfigurations | 3 | 0 |

The plain Deployment fails `KSV-0014` once for its writable root filesystem
and `KSV-0118` twice for missing explicit security contexts. The hardened
manifest removes all three findings, while the image's 74 High/Critical
matches remain unchanged because no package was rebuilt or upgraded.
The image already defaults to UID 65532 in both namespaces, so the default
security-context warnings should not be misread as proof that the plain
pod actually ran as root.

### An enforced control and an extra control

I submitted a server-side dry-run Pod with the correct non-root UID,
seccomp profile, and dropped capabilities but with
`allowPrivilegeEscalation: true`. Admission rejected it with:

```text
violates PodSecurity "restricted:v1.33": allowPrivilegeEscalation != false
(container "juice-shop" must set securityContext.allowPrivilegeEscalation=false)
```

The final manifest sets that field to false. I also added
`readOnlyRootFilesystem: true`, which the
[restricted standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
does not require; making the application work with it is the bonus below.

## Bonus

### Discovering the writable paths

`docker run --rm --read-only bkimminich/juice-shop:v20.0.0` exited 1 with
`SQLITE_CANTOPEN: unable to open database file`. I then started a normal
disposable container and used `docker diff lab7-writepaths`; the relevant
changes included:

```text
A /juice-shop/data/juiceshop.sqlite
A /juice-shop/logs/access.log.2026-09-23
A /juice-shop/logs/audit.json
A /juice-shop/ftp/legal.md
C /juice-shop/.well-known/csaf/provider-metadata.json
C /juice-shop/frontend/dist/frontend/index.html
C /juice-shop/frontend/dist/frontend/assets/private/threejs-demo.html
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/i18n/en.json
A /juice-shop/i18n/ru_RU.json
```

The full diff contains more generated locale files. I grouped these observed
writes into six application directories rather than guessing a database-only
mount.

### Final volume layout

One disk-backed `emptyDir`, `writable-paths`, is limited to 512 MiB. Its
subdirectories are mounted separately, leaving the rest of the image
read-only:

| Mount path | Subpath | Why it is writable |
|---|---|---|
| `/juice-shop/data` | `data` | SQLite database and runtime data; packaged seed files must remain visible. |
| `/juice-shop/logs` | `logs` | Access logs and audit output. |
| `/juice-shop/ftp` | `ftp` | Generated legal document alongside files already shipped in the image. |
| `/juice-shop/.well-known` | `wellknown` | Updated CSAF provider metadata. |
| `/juice-shop/frontend/dist/frontend` | `frontend` | Startup changes to the page and generated/copied assets. |
| `/juice-shop/i18n` | `i18n` | Runtime locale generation. |
| `/tmp` | `tmp` | Bounded scratch space; added defensively, not observed in the startup diff. |

The initContainer uses the same pinned image and its Node `fs.cpSync` to
seed all six application directories into the empty volume. It runs as
65532 with the same restrictions, and `fsGroup: 65532` makes the volume
writable without a root initContainer or a shell. The app then mounts the
seeded subpaths over the original locations. Server code under
`/juice-shop/build` and `node_modules` stays read-only; the frontend assets
are writable within their dedicated mount because startup modifies them.

An empty mount over `/juice-shop/data` is insufficient. I verified this with
a separate read-only Docker run and a writable, empty tmpfs at that path:
startup could not open `/juice-shop/data/static/securityQuestions.yml` and
exited with `TypeError: questions.map is not a function`. Seeding the
directory preserves that file, and the final pod confirmed it exists.
The other seeded directories likewise retain their packaged contents.

These volumes are ephemeral: replacing the pod loses its database and
generated files. That is appropriate for this disposable lab, but durable
application state would require a separate persistence design.

### Runtime proof

The saved pod spec has `readOnlyRootFilesystem: true` on both containers,
and the application is Ready with zero restarts. A Node-based runtime check
returned:

```json
{
  "uid": 65532,
  "gid": 65532,
  "rootWrite": "EROFS",
  "tokenMounted": false,
  "seedFile": true
}
```

`rootWrite` is the result of attempting to create
`/juice-shop/readonly-proof`; `seedFile` checks
`/juice-shop/data/static/securityQuestions.yml`. Finally:

```powershell
kubectl -n juice-shop port-forward deployment/juice-shop 3008:3000 --address 127.0.0.1
# In another terminal:
(Invoke-WebRequest http://127.0.0.1:3008/ -UseBasicParsing).StatusCode
# 200
```

The response contained the Juice Shop page. The Kubernetes JSON report is
retained locally as `labs/lab7/results/trivy-k8s.json` for later import.
After saving the evidence, I deleted the `lab7` cluster and the disposable
Docker container used to inspect writes.
