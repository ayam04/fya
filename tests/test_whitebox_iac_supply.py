from __future__ import annotations

import os

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def _write(root, relpath, content):
    path = os.path.join(str(root), *relpath.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def _scan(tmp_path, check):
    result = run_scan(
        detect_target(str(tmp_path)), profile=Profile.PASSIVE, detect_external=False
    )
    assert not result.errors, result.errors
    return [f for f in result.findings if f.check == check]


# ---------------------------------------------------------------------------
# whitebox.dockerfile_hardening
# ---------------------------------------------------------------------------

_BAD_DOCKERFILE = """\
# build the app
FROM node:latest

ARG BUILD_ID=1
ENV DB_PASSWORD=hunter2abcd

ADD http://cdn.acme-vendor.net/tool.tar.gz /opt/tool.tar.gz

RUN curl -sSL https://get.acme-vendor.net/install.sh | sh && \\
    chmod 777 /opt/tool

CMD ["node", "server.js"]
"""

_GOOD_DOCKERFILE = """\
FROM node:20-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

RUN useradd --create-home --shell /bin/bash appuser
COPY --chown=appuser:appuser . /srv/app
RUN chmod 0750 /srv/app

USER appuser
CMD ["node", "server.js"]
"""


def test_dockerfile_hardening_fires(tmp_path):
    _write(tmp_path, "Dockerfile", _BAD_DOCKERFILE)
    findings = _scan(tmp_path, "whitebox.dockerfile_hardening")
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected dockerfile findings"
    assert "runs as root" in titles
    assert "not pinned" in titles
    assert "remote url" in titles
    assert "credential baked" in titles
    assert "unverified code" in titles
    assert all(f.location.startswith("Dockerfile:") for f in findings)


def test_dockerfile_hardening_silent_on_hardened_image(tmp_path):
    _write(tmp_path, "Dockerfile", _GOOD_DOCKERFILE)
    assert not _scan(tmp_path, "whitebox.dockerfile_hardening")


def test_dockerfile_secret_file_pointer_is_not_a_baked_credential(tmp_path):
    content = (
        "FROM gcr.io/distroless/static-debian12:nonroot\n"
        "ENV JWT_SECRET_FILE=/run/secrets/jwt\n"
        "USER 10001\n"
    )
    _write(tmp_path, "Dockerfile", content)
    findings = _scan(tmp_path, "whitebox.dockerfile_hardening")
    assert not [f for f in findings if "credential baked" in f.title.lower()]


def test_dockerfile_hardening_ignores_builder_stage_root(tmp_path):
    content = (
        "FROM golang:1.22 AS builder\n"
        "USER root\n"
        "RUN go build -o /out/app ./cmd/app\n"
        "\n"
        "FROM gcr.io/distroless/static-debian12:nonroot\n"
        "COPY --from=builder /out/app /app\n"
        "ENTRYPOINT [\"/app\"]\n"
    )
    _write(tmp_path, "Dockerfile", content)
    findings = _scan(tmp_path, "whitebox.dockerfile_hardening")
    assert not [f for f in findings if "runs as root" in f.title.lower()]


# ---------------------------------------------------------------------------
# whitebox.k8s_workload_security
# ---------------------------------------------------------------------------

_BAD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: agent
          image: busybox
          securityContext:
            privileged: true
            capabilities:
              add:
                - SYS_ADMIN
          volumeMounts:
            - name: sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
"""

_BAD_CLUSTERROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: everything
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""

_GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: web
          image: ghcr.io/acme/web@sha256:1111111111111111111111111111111111111111111111111111111111111111
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""


def test_k8s_workload_security_fires(tmp_path):
    _write(tmp_path, "deploy/agent.yaml", _BAD_DEPLOYMENT)
    findings = _scan(tmp_path, "whitebox.k8s_workload_security")
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected kubernetes findings"
    assert "privileged container" in titles
    assert "host namespace" in titles or "hostpath" in titles


def test_k8s_wildcard_rbac_fires(tmp_path):
    _write(tmp_path, "rbac/clusterrole.yaml", _BAD_CLUSTERROLE)
    findings = _scan(tmp_path, "whitebox.k8s_workload_security")
    assert any("wildcard rbac" in f.title.lower() for f in findings)


def test_k8s_workload_security_silent_on_hardened_manifest(tmp_path):
    _write(tmp_path, "deploy/web.yaml", _GOOD_DEPLOYMENT)
    assert not _scan(tmp_path, "whitebox.k8s_workload_security")


def test_k8s_ignores_non_kubernetes_yaml(tmp_path):
    # A CI config that happens to contain 'kind:' style keys but is not a K8s manifest.
    _write(
        tmp_path,
        "config/app.yaml",
        "kind: application\nserver:\n  privileged: true\n  hostNetwork: true\n",
    )
    assert not _scan(tmp_path, "whitebox.k8s_workload_security")


# ---------------------------------------------------------------------------
# whitebox.terraform_exposure
# ---------------------------------------------------------------------------

_BAD_TF = """\
# database tier
resource "aws_security_group" "db" {
  name = "db"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  publicly_accessible = true
  storage_encrypted   = false
}
"""

_BAD_TF_IAM = """\
resource "aws_iam_policy" "admin" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
"""

_GOOD_TF = """\
resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


def test_terraform_exposure_fires(tmp_path):
    _write(tmp_path, "infra/main.tf", _BAD_TF)
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected terraform findings"
    assert "sensitive ports" in titles
    assert "publicly readable" in titles or "publicly accessible" in titles


def test_terraform_iam_wildcard_fires(tmp_path):
    _write(tmp_path, "infra/iam.tf", _BAD_TF_IAM)
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    assert any("'*' on '*'" in f.title for f in findings)


def test_terraform_tfvars_credential_fires(tmp_path):
    _write(tmp_path, "infra/prod.tfvars", 'region = "eu-west-1"\ndb_password = "Kq93ZmnRb1"\n')
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    assert any("hardcoded credential" in f.title.lower() for f in findings)


def test_terraform_exposure_silent_on_safe_stack(tmp_path):
    _write(tmp_path, "infra/main.tf", _GOOD_TF)
    assert not _scan(tmp_path, "whitebox.terraform_exposure")


def test_terraform_egress_only_security_group_is_not_ingress(tmp_path):
    # The near-universal allow-all egress block, with ingress supplied by other resources.
    content = (
        'resource "aws_security_group" "web" {\n'
        '  name = "web"\n'
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    _write(tmp_path, "infra/sg.tf", content)
    assert not _scan(tmp_path, "whitebox.terraform_exposure")


def test_terraform_standalone_ingress_rule_fires(tmp_path):
    content = (
        'resource "aws_security_group_rule" "ssh" {\n'
        '  type              = "ingress"\n'
        "  from_port         = 22\n"
        "  to_port           = 22\n"
        '  protocol          = "tcp"\n'
        '  cidr_blocks       = ["0.0.0.0/0"]\n'
        "  security_group_id = aws_security_group.web.id\n"
        "}\n"
    )
    _write(tmp_path, "infra/rule.tf", content)
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    assert any("sensitive ports" in f.title.lower() for f in findings)


def test_terraform_dynamic_ingress_block_fires(tmp_path):
    content = (
        'resource "aws_security_group" "db" {\n'
        '  name = "db"\n'
        '  dynamic "ingress" {\n'
        "    for_each = var.rules\n"
        "    content {\n"
        "      from_port   = 3306\n"
        "      to_port     = 3306\n"
        '      protocol    = "tcp"\n'
        '      cidr_blocks = ["0.0.0.0/0"]\n'
        "    }\n"
        "  }\n"
        "  egress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    _write(tmp_path, "infra/dyn.tf", content)
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    assert any("sensitive ports" in f.title.lower() for f in findings)


_CONDITIONED_KMS_POLICY = """\
resource "aws_kms_key" "main" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {"StringEquals": {"kms:CallerAccount": "111122223333"}}
    }
  ]
}
POLICY
}
"""

_PUBLIC_BUCKET_POLICY = """\
resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::assets/*"
    }
  ]
}
POLICY
}
"""


def test_terraform_condition_scoped_key_policy_is_not_public(tmp_path):
    _write(tmp_path, "infra/kms.tf", _CONDITIONED_KMS_POLICY)
    assert not _scan(tmp_path, "whitebox.terraform_exposure")


def test_terraform_public_bucket_policy_still_fires(tmp_path):
    _write(tmp_path, "infra/s3.tf", _PUBLIC_BUCKET_POLICY)
    findings = _scan(tmp_path, "whitebox.terraform_exposure")
    assert any("publicly readable" in f.title.lower() for f in findings)


def test_terraform_secret_pointer_variable_is_not_a_credential(tmp_path):
    content = 'variable "db_password_secret_name" {\n  default = "prod/app/db"\n}\n'
    _write(tmp_path, "infra/vars.tf", content)
    assert not _scan(tmp_path, "whitebox.terraform_exposure")


def test_terraform_comments_are_not_matched(tmp_path):
    content = (
        'resource "aws_db_instance" "main" {\n'
        "  # publicly_accessible = true\n"
        "  storage_encrypted = true\n"
        "}\n"
    )
    _write(tmp_path, "infra/db.tf", content)
    assert not _scan(tmp_path, "whitebox.terraform_exposure")


# ---------------------------------------------------------------------------
# whitebox.compose_hardening
# ---------------------------------------------------------------------------

_BAD_COMPOSE = """\
version: "3.9"
services:
  admin:
    image: docker:24
    privileged: true
    pid: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: mysql:8
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: r00tpw0rd99
"""

_GOOD_COMPOSE = """\
version: "3.9"
services:
  web:
    image: ghcr.io/acme/web:1.4.2
    user: "10001:10001"
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      APP_SECRET: ${APP_SECRET}
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
"""


def test_compose_hardening_fires(tmp_path):
    _write(tmp_path, "docker-compose.yml", _BAD_COMPOSE)
    findings = _scan(tmp_path, "whitebox.compose_hardening")
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected compose findings"
    assert "docker socket" in titles
    assert "privileged" in titles or "host pid" in titles


def test_compose_exposed_datastore_fires(tmp_path):
    content = (
        "services:\n"
        "  cache:\n"
        "    image: redis:7\n"
        "    ports:\n"
        '      - "6379:6379"\n'
    )
    _write(tmp_path, "docker-compose.yml", content)
    findings = _scan(tmp_path, "whitebox.compose_hardening")
    assert any("datastore port" in f.title.lower() for f in findings)


def test_compose_hardening_silent_on_safe_stack(tmp_path):
    _write(tmp_path, "docker-compose.yml", _GOOD_COMPOSE)
    assert not _scan(tmp_path, "whitebox.compose_hardening")


def test_compose_docker_secrets_pointer_is_not_a_hardcoded_credential(tmp_path):
    # The pattern the official postgres/mysql images document.
    content = (
        "services:\n"
        "  db:\n"
        "    image: postgres:16\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n"
        "    secrets:\n"
        "      - db_password\n"
        "secrets:\n"
        "  db_password:\n"
        "    file: ./db_password.txt\n"
    )
    _write(tmp_path, "docker-compose.yml", content)
    assert not _scan(tmp_path, "whitebox.compose_hardening")


def test_compose_check_ignores_kubernetes_yaml(tmp_path):
    content = (
        "apiVersion: v1\n"
        "kind: Pod\n"
        "services:\n"
        "  web:\n"
        "    privileged: true\n"
    )
    _write(tmp_path, "compose.yaml", content)
    assert not _scan(tmp_path, "whitebox.compose_hardening")


# ---------------------------------------------------------------------------
# whitebox.actions_supply_chain
# ---------------------------------------------------------------------------

_BAD_WORKFLOW = """\
name: ci
on: pull_request
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - uses: evilcorp/setup-toolchain@main
      - run: curl -sSL https://get.acme-vendor.net/install.sh | sh
"""

_GOOD_WORKFLOW = """\
name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@0d4c9c5ea7693da7b068278f7b52bda2a190a446
      - run: npm ci && npm test
"""

# GitLab exports CI_COMMIT_* as ordinary environment variables and writes the script
# verbatim, so only a construct that re-evaluates the value is injectable.
_BAD_GITLAB = """\
build:
  script:
    - eval "deploy --tag $CI_COMMIT_REF_NAME"
    - make build
"""

_SAFE_GITLAB = """\
build:
  script:
    - docker build -t registry.example.com/app:$CI_COMMIT_REF_NAME .
    - echo "Building $CI_COMMIT_MESSAGE"
"""


def test_actions_supply_chain_fires(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", _BAD_WORKFLOW)
    findings = _scan(tmp_path, "whitebox.actions_supply_chain")
    titles = " | ".join(f.title.lower() for f in findings)
    assert findings, "expected workflow findings"
    assert "not pinned" in titles
    assert "write-all" in titles
    assert "unsecure workflow commands" in titles
    assert "self-hosted" in titles


def test_actions_gitlab_injection_fires(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", _BAD_GITLAB)
    findings = _scan(tmp_path, "whitebox.actions_supply_chain")
    assert any("re-evaluates attacker-controlled input" in f.title.lower() for f in findings)


def test_actions_gitlab_injection_fires_on_command_substitution(tmp_path):
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        'build:\n  script:\n    - export SLUG=$(echo $CI_COMMIT_MESSAGE | tr " " "-")\n',
    )
    findings = _scan(tmp_path, "whitebox.actions_supply_chain")
    assert any("re-evaluates attacker-controlled input" in f.title.lower() for f in findings)


def test_actions_gitlab_plain_ci_variable_expansion_is_not_injection(tmp_path):
    # `$CI_COMMIT_REF_NAME` in a script line is a shell parameter expansion, not a template
    # substitution: a crafted branch name cannot become a command.
    _write(tmp_path, ".gitlab-ci.yml", _SAFE_GITLAB)
    assert not _scan(tmp_path, "whitebox.actions_supply_chain")


def test_actions_supply_chain_silent_on_pinned_workflow(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", _GOOD_WORKFLOW)
    assert not _scan(tmp_path, "whitebox.actions_supply_chain")


def test_actions_self_hosted_needs_a_real_pull_request_trigger(tmp_path):
    # `on: push`; `pull_request` only appears inside a context expression.
    content = (
        "name: p\n"
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: self-hosted\n"
        "    steps:\n"
        "      - run: echo ${{ github.event.pull_request.number }}\n"
    )
    _write(tmp_path, ".github/workflows/push.yml", content)
    assert not _scan(tmp_path, "whitebox.actions_supply_chain")


def test_actions_self_hosted_fires_on_nested_pull_request_trigger(tmp_path):
    content = (
        "name: pr\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: [main]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: self-hosted\n"
        "    steps:\n"
        "      - run: make test\n"
    )
    _write(tmp_path, ".github/workflows/pr.yml", content)
    findings = _scan(tmp_path, "whitebox.actions_supply_chain")
    assert any("self-hosted" in f.title.lower() for f in findings)


def test_actions_secret_echo_fires_when_it_reaches_the_log(tmp_path):
    content = (
        "name: e\n"
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ secrets.API_TOKEN }}"\n'
    )
    _write(tmp_path, ".github/workflows/echo.yml", content)
    findings = _scan(tmp_path, "whitebox.actions_supply_chain")
    assert any("prints a secret" in f.title.lower() for f in findings)


def test_actions_secret_piped_to_stdin_is_not_a_log_leak(tmp_path):
    # The documented docker/gh login idiom keeps the credential out of the log.
    content = (
        "name: release\n"
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ secrets.DOCKER_PASSWORD }}" | docker login -u u --password-stdin\n'
        '      - run: echo "::add-mask::${{ secrets.API_TOKEN }}"\n'
    )
    _write(tmp_path, ".github/workflows/release.yml", content)
    assert not _scan(tmp_path, "whitebox.actions_supply_chain")


# ---------------------------------------------------------------------------
# whitebox.insecure_package_source
# ---------------------------------------------------------------------------


def test_insecure_package_source_fires_on_plaintext_registry(tmp_path):
    _write(tmp_path, ".npmrc", "registry=http://npm.acme-vendor.net/\n")
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("plaintext http" in f.title.lower() for f in findings)


def test_insecure_package_source_fires_on_disabled_verification(tmp_path):
    _write(tmp_path, "pip.conf", "[global]\nindex-url = https://pypi.org/simple\ntrusted-host = pypi.org\n")
    _write(tmp_path, ".npmrc", "strict-ssl=false\n")
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("verification disabled" in f.title.lower() for f in findings)


def test_insecure_package_source_fires_on_git_dependency(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "dependencies": {"widget": "git://github.com/acme/widget"}}',
    )
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("unauthenticated protocol" in f.title.lower() for f in findings)


def test_insecure_package_source_fires_on_install_hook(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "scripts": {"postinstall": "curl -sSL https://acme-vendor.net/s.sh | sh"}}',
    )
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("install-time script" in f.title.lower() for f in findings)


def test_insecure_package_source_silent_on_https(tmp_path):
    _write(tmp_path, ".npmrc", "registry=https://registry.npmjs.org/\n")
    _write(tmp_path, "pip.conf", "[global]\nindex-url = https://pypi.org/simple\n")
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "dependencies": {"left-pad": "^1.3.0"}, "scripts": {"build": "tsc"}}',
    )
    assert not _scan(tmp_path, "whitebox.insecure_package_source")


def test_insecure_package_source_allows_private_mirror(tmp_path):
    _write(tmp_path, ".npmrc", "registry=http://10.0.4.12:4873/\n")
    _write(tmp_path, "pip.conf", "[global]\nindex-url = http://pypi.internal/simple\n")
    assert not _scan(tmp_path, "whitebox.insecure_package_source")


_STOCK_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 \
http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>net.acme</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <url>http://acme.example/app</url>
</project>
"""

_HTTP_REPO_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <repositories>
    <repository>
      <id>acme</id>
      <url>http://repo.acme-vendor.net/maven2</url>
    </repository>
  </repositories>
</project>
"""


def test_insecure_package_source_ignores_xml_namespace_uris(tmp_path):
    _write(tmp_path, "pom.xml", _STOCK_POM)
    assert not _scan(tmp_path, "whitebox.insecure_package_source")


def test_insecure_package_source_fires_on_plaintext_maven_repository(tmp_path):
    _write(tmp_path, "pom.xml", _HTTP_REPO_POM)
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("plaintext http" in f.title.lower() for f in findings)


def test_insecure_package_source_ignores_project_metadata_urls(tmp_path):
    _write(tmp_path, "setup.cfg", "[metadata]\nname = app\nurl = http://github.com/acme/app\n")
    _write(
        tmp_path,
        "package.json",
        '{"name": "app", "homepage": "http://acme.example",'
        ' "repository": {"type": "git", "url": "http://github.com/acme/app.git"}}',
    )
    assert not _scan(tmp_path, "whitebox.insecure_package_source")


def test_insecure_package_source_fires_on_plaintext_poetry_source(tmp_path):
    content = (
        '[tool.poetry]\nname = "app"\nhomepage = "http://acme.example"\n\n'
        '[[tool.poetry.source]]\nname = "acme"\nurl = "http://pypi.acme-vendor.net/simple"\n'
    )
    _write(tmp_path, "pyproject.toml", content)
    findings = _scan(tmp_path, "whitebox.insecure_package_source")
    assert any("plaintext http" in f.title.lower() for f in findings)


def test_insecure_package_source_ignores_distro_apt_sources(tmp_path):
    content = (
        "FROM debian:12-slim@sha256:2222222222222222222222222222222222222222222222222222222222222222\n"
        'RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list \\\n'
        "    && apt-get update\n"
        "USER 10001\n"
    )
    _write(tmp_path, "Dockerfile", content)
    assert not _scan(tmp_path, "whitebox.insecure_package_source")
