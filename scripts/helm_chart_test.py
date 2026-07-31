#!/usr/bin/env python3
"""Chart tests for ``helm/rastreo``: render with ``helm template``, assert on the output.

Run from the repo root::

    python3 scripts/helm_chart_test.py

Stdlib-only — the assertions read the rendered text rather than parsing it with a
YAML library, so the harness needs nothing but ``helm`` on ``PATH``. Rendered
manifests are the chart's contract, so asserting on them directly is also what a
reader of a failure message wants to see.

The suite covers the two ways a secret reaches a server-side sink config
(``${VAR}`` from the container environment, ``!file`` from a mounted Secret),
every values combination the chart refuses to render, and two golden renders
that pin the output for values that predate those knobs.

``--chart`` points the suite at a copy of the chart, which is how a change is
checked for being load-bearing: revert one guard in the copy and the tests that
name it go red.

``--update-goldens`` rewrites the files under ``scripts/testdata/helm/``. The
golden output carries a ``{{VERSION}}`` placeholder wherever the chart version
appears, so a release bump does not redden the suite.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART = REPO_ROOT / "helm" / "rastreo"
GOLDEN_DIR = REPO_ROOT / "scripts" / "testdata" / "helm"
RELEASE = "rastreo"
NAMESPACE = "rastreo"
VERSION_TOKEN = "{{VERSION}}"
CHECKSUM_RE = re.compile(r"^(\s*checksum/sink-config:\s*)[0-9a-f]{64}$", re.MULTILINE)
HELM_TIMEOUT_S = 120.0

# Overridden by --chart so a mutated copy can be rendered instead.
chart_under_test = CHART


AUTH_VALUES = """\
auth:
  existingSecret: rastreo-api-token
"""

SINK_CONFIG_VALUES = (
    AUTH_VALUES
    + """\
sink:
  config:
    type: kafka
    brokers: ["kafka.observability.svc:9092"]
    topic: rastreo.discovery.records.v1
    sasl:
      mechanism: scram_sha_512
      username: rastreo
      password: "${KAFKA_PASSWORD}"
"""
)

ENV_SECRET_VALUES = (
    SINK_CONFIG_VALUES
    + """\
extraEnv:
  - name: KAFKA_PASSWORD
    valueFrom:
      secretKeyRef:
        name: rastreo-kafka
        key: password
extraEnvFrom:
  - secretRef:
      name: rastreo-kafka-extra
"""
)

FILE_SECRET_DOCUMENT = """\
type: kafka
brokers: ["kafka.observability.svc:9092"]
topic: rastreo.discovery.records.v1
sasl:
  mechanism: scram_sha_512
  username: rastreo
  password: !file /run/secrets/kafka/password
"""

FILE_SECRET_VALUES = (
    AUTH_VALUES
    + """\
sink:
  configYaml: |
"""
    + "".join(f"    {line}\n" for line in FILE_SECRET_DOCUMENT.splitlines())
    + """\
extraVolumes:
  - name: kafka-credentials
    secret:
      secretName: rastreo-kafka
extraVolumeMounts:
  - name: kafka-credentials
    mountPath: /run/secrets/kafka
    readOnly: true
"""
)

GOLDENS = {
    "default.yaml": AUTH_VALUES,
    "sink-config.yaml": SINK_CONFIG_VALUES,
}


def extra_list_keys() -> list:
    """Every top-level ``extra*`` key in values.yaml.

    Read out of the chart rather than listed here so a list added later is
    covered by the contract tests below without anyone remembering to add it.
    """
    text = (chart_under_test / "values.yaml").read_text(encoding="utf-8")
    return re.findall(r"^(extra[A-Za-z]+):", text, re.MULTILINE)


def mounted(path: str, *, volume: str = "mine", mount: str = "mine") -> str:
    """Values defining one extra volume and mounting it at ``path``."""
    return (
        AUTH_VALUES
        + f"extraVolumes:\n  - name: {volume}\n    emptyDir: {{}}\n"
        + f"extraVolumeMounts:\n  - name: {mount}\n    mountPath: {path!r}\n"
    )


# --- Rendering ---------------------------------------------------------------


def helm_template(values: str, *, show_only: str = "") -> subprocess.CompletedProcess:
    argv = [
        "helm",
        "template",
        RELEASE,
        str(chart_under_test),
        "--namespace",
        NAMESPACE,
    ]
    if show_only:
        argv += ["--show-only", show_only]
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write(values)
        values_path = handle.name
    try:
        return subprocess.run(
            argv + ["--values", values_path],
            capture_output=True,
            text=True,
            timeout=HELM_TIMEOUT_S,
        )
    finally:
        Path(values_path).unlink(missing_ok=True)


def render(values: str, *, show_only: str = "") -> str:
    """The rendered manifests, or an assertion failure carrying helm's stderr."""
    result = helm_template(values, show_only=show_only)
    if result.returncode != 0:
        raise AssertionError(
            f"helm template exited {result.returncode} on values that should "
            f"render:\n{values}\n--- stderr ---\n{result.stderr}"
        )
    return result.stdout


def render_error(values: str) -> str:
    """Helm's stderr, or an assertion failure when the values rendered anyway."""
    result = helm_template(values)
    if result.returncode == 0:
        raise AssertionError(
            f"helm template rendered values the chart should refuse:\n{values}\n"
            f"--- stdout ---\n{result.stdout}"
        )
    return result.stderr


def helm_version() -> str:
    result = subprocess.run(
        ["helm", "version", "--short"],
        capture_output=True,
        text=True,
        timeout=HELM_TIMEOUT_S,
    )
    return result.stdout.strip() or "unknown"


def chart_versions() -> list:
    text = (chart_under_test / "Chart.yaml").read_text(encoding="utf-8")
    found = re.findall(r"^(?:version|appVersion):\s*(\S+)\s*$", text, re.MULTILINE)
    if not found:
        raise AssertionError(f"no version in {chart_under_test}/Chart.yaml")
    return found


def normalized(text: str) -> str:
    """The render with every chart-version occurrence replaced by a placeholder.

    Chart version and appVersion collapse into one token on purpose: they move
    together on a release bump, and a golden that told them apart would go red
    on the bump commit for a change nobody made.

    The sink-config checksum is a digest of a ConfigMap that carries the chart
    version in its labels, so it moves on that same bump and no version
    substitution can reach inside it. It collapses to the same token; that the
    annotation tracks the sink config is pinned by the tests that edit one.
    """
    for version in chart_versions():
        text = text.replace(version, VERSION_TOKEN)
    return CHECKSUM_RE.sub(rf"\g<1>{VERSION_TOKEN}", text)


# --- Reading the rendered output ---------------------------------------------


def document(rendered: str, template: str) -> str:
    """The one manifest rendered from ``templates/<template>``."""
    marker = f"# Source: rastreo/templates/{template}"
    chunks = [chunk for chunk in rendered.split("\n---\n") if marker in chunk]
    if len(chunks) != 1:
        raise AssertionError(
            f"expected exactly one {template} manifest, found {len(chunks)}"
        )
    return chunks[0]


def block(text: str, key: str) -> list:
    """Dedented lines of the indented block under the first ``key:`` line."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != key:
            continue
        indent = len(line) - len(line.lstrip())
        body = []
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                body.append("")
                continue
            if len(candidate) - len(candidate.lstrip()) <= indent:
                break
            body.append(candidate)
        pad = min(len(item) - len(item.lstrip()) for item in body if item.strip())
        return [item[pad:] if item.strip() else "" for item in body]
    raise AssertionError(f"no {key!r} block in:\n{text}")


def list_items(lines: Sequence[str]) -> list:
    """A dedented YAML list block split into one line-list per entry."""
    items: list = []
    for line in lines:
        if line.startswith("- "):
            items.append([line[2:]])
        elif items and line.startswith("  "):
            items[-1].append(line[2:])
        elif line.strip():
            raise AssertionError(f"line {line!r} is not part of a list entry")
    return items


def container(deployment: str) -> str:
    """The one container's spec, lifted out of the pod spec.

    The pod and the container both carry a ``securityContext:``, so a lookup for
    the container's has to start below ``containers:``.
    """
    return "\n".join(list_items(block(deployment, "containers:"))[0])


def env_entry(deployment: str, name: str) -> list:
    """The rendered EnvVar entry for ``name``."""
    for item in list_items(block(deployment, "env:")):
        if f"name: {name}" in item:
            return item
    raise AssertionError(f"no {name} entry in the container env")


def env_names(deployment: str) -> list:
    return [
        line.split("name: ", 1)[1]
        for item in list_items(block(deployment, "env:"))
        for line in item
        if line.startswith("name: ")
    ]


def sink_yaml(rendered: str) -> str:
    """The sink config document the ConfigMap carries."""
    configmap = document(rendered, "configmap-sink.yaml")
    return "\n".join(block(configmap, "sink.yaml: |")).rstrip("\n") + "\n"


# --- Tests -------------------------------------------------------------------


class _GoldenRenderTests(unittest.TestCase):
    def _assert_golden(self, name: str, values: str) -> None:
        golden = GOLDEN_DIR / name
        self.assertTrue(
            golden.exists(),
            f"{golden} is missing; regenerate with --update-goldens",
        )
        self.assertEqual(
            golden.read_text(encoding="utf-8"),
            normalized(render(values)),
            f"the render changed for values that predate this chart's extra* and "
            f"sink.configYaml knobs (helm {helm_version()}). Regenerate with "
            f"--update-goldens only after confirming the change is intended.",
        )

    def test_default_values_render_byte_identically(self) -> None:
        self._assert_golden("default.yaml", AUTH_VALUES)

    def test_sink_config_values_render_byte_identically(self) -> None:
        self._assert_golden("sink-config.yaml", SINK_CONFIG_VALUES)


class _EnvironmentSecretTests(unittest.TestCase):
    """`${VAR}` in the sink config, resolved from a Secret through extraEnv."""

    def test_extra_env_reaches_the_container_from_a_secret(self) -> None:
        deployment = document(render(ENV_SECRET_VALUES), "deployment.yaml")
        self.assertEqual(
            env_entry(deployment, "KAFKA_PASSWORD"),
            [
                "name: KAFKA_PASSWORD",
                "valueFrom:",
                "  secretKeyRef:",
                "    key: password",
                "    name: rastreo-kafka",
            ],
        )

    def test_the_reference_reaches_the_configmap_and_the_secret_does_not(self) -> None:
        rendered = render(ENV_SECRET_VALUES)
        self.assertIn("password: ${KAFKA_PASSWORD}", sink_yaml(rendered))
        self.assertNotIn("rastreo-kafka\n", sink_yaml(rendered))

    def test_extra_env_from_reaches_the_container(self) -> None:
        deployment = document(render(ENV_SECRET_VALUES), "deployment.yaml")
        self.assertEqual(
            block(deployment, "envFrom:"),
            ["- secretRef:", "    name: rastreo-kafka-extra"],
        )

    def test_the_chart_env_survives_alongside_extra_env(self) -> None:
        deployment = document(render(ENV_SECRET_VALUES), "deployment.yaml")
        names = env_names(deployment)
        self.assertIn("RASTREO_SINK_CONFIG_PATH", names)
        self.assertIn("RASTREO_API_TOKEN", names)
        self.assertEqual(len(names), len(set(names)))


class _FileSecretTests(unittest.TestCase):
    """`!file` in the sink config, reading a Secret mounted through extraVolumes."""

    def test_config_yaml_reaches_the_configmap_verbatim(self) -> None:
        self.assertEqual(sink_yaml(render(FILE_SECRET_VALUES)), FILE_SECRET_DOCUMENT)

    def test_helm_strips_a_file_tag_out_of_structured_sink_config(self) -> None:
        """No sound detector exists for this; `sink.configYaml` is the escape.

        Helm's parser drops the `!file` tag before any template runs, so the value
        already reads as a plain string by the time a guard could look at it.
        """
        values = (
            AUTH_VALUES
            + "sink:\n  config:\n    type: file\n"
            + "    path: !file /run/secrets/kafka/password\n"
        )
        self.assertIn("path: /run/secrets/kafka/password", sink_yaml(render(values)))

    def test_the_secret_volume_and_its_mount_render(self) -> None:
        deployment = document(render(FILE_SECRET_VALUES), "deployment.yaml")
        self.assertIn(
            ["name: kafka-credentials", "secret:", "  secretName: rastreo-kafka"],
            list_items(block(deployment, "volumes:")),
        )
        self.assertIn(
            [
                "mountPath: /run/secrets/kafka",
                "name: kafka-credentials",
                "readOnly: true",
            ],
            list_items(block(deployment, "volumeMounts:")),
        )

    def test_config_yaml_wires_up_the_sink_config_path_and_mount(self) -> None:
        deployment = document(render(FILE_SECRET_VALUES), "deployment.yaml")
        self.assertEqual(
            env_entry(deployment, "RASTREO_SINK_CONFIG_PATH"),
            ["name: RASTREO_SINK_CONFIG_PATH", "value: /etc/rastreo/sink/sink.yaml"],
        )
        self.assertIn("RASTREO_SINK_PROBE_INTERVAL_SECS", env_names(deployment))
        self.assertIn(
            ["name: sink-config", "configMap:", "  name: rastreo-sink"],
            list_items(block(deployment, "volumes:")),
        )
        self.assertIn("checksum/sink-config:", deployment)

    def test_editing_config_yaml_rolls_the_pods(self) -> None:
        def checksum(values: str) -> str:
            deployment = document(render(values), "deployment.yaml")
            return block(deployment, "annotations:")[0]

        edited = FILE_SECRET_VALUES.replace(
            "/run/secrets/kafka/password", "/run/secrets/kafka/other-password"
        )
        self.assertNotEqual(checksum(FILE_SECRET_VALUES), checksum(edited))

    def test_a_mount_does_not_relax_the_hardened_security_context(self) -> None:
        hardened = block(
            container(document(render(AUTH_VALUES), "deployment.yaml")),
            "securityContext:",
        )
        self.assertIn("readOnlyRootFilesystem: true", hardened)
        self.assertIn("  - ALL", hardened)
        self.assertEqual(
            hardened,
            block(
                container(document(render(FILE_SECRET_VALUES), "deployment.yaml")),
                "securityContext:",
            ),
        )


class _CollisionTests(unittest.TestCase):
    def test_both_sink_config_keys_fail_naming_both(self) -> None:
        stderr = render_error(
            AUTH_VALUES + "sink:\n  config:\n    type: stdout\n  configYaml: |\n"
            "    type: stdout\n"
        )
        self.assertIn("sink.config", stderr)
        self.assertIn("sink.configYaml", stderr)

    def test_extra_env_may_not_shadow_a_chart_variable(self) -> None:
        for name in (
            "RASTREO_API_TOKEN",
            "RASTREO_SINK_CONFIG_PATH",
            "RASTREO_MAX_BODY_BYTES",
        ):
            with self.subTest(name=name):
                values = (
                    SINK_CONFIG_VALUES
                    + f"extraEnv:\n  - name: {name}\n    value: mine\n"
                )
                self.assertIn(name, render_error(values))

    def test_extra_env_may_not_name_a_variable_twice(self) -> None:
        values = (
            AUTH_VALUES + "extraEnv:\n"
            "  - name: KAFKA_PASSWORD\n    value: one\n"
            "  - name: KAFKA_PASSWORD\n    value: two\n"
        )
        self.assertIn("KAFKA_PASSWORD", render_error(values))

    def test_extra_volumes_may_not_take_the_sink_config_name(self) -> None:
        values = (
            AUTH_VALUES + "extraVolumes:\n  - name: sink-config\n    emptyDir: {}\n"
        )
        self.assertIn("sink-config", render_error(values))

    def test_a_mount_must_name_a_volume_the_pod_defines(self) -> None:
        values = mounted("/run/secrets/kafka", volume="mine", mount="mien")
        stderr = render_error(values)
        self.assertIn("mien", stderr)
        self.assertIn("mine", stderr)

    def test_a_mount_may_not_overlap_the_sink_config_mount(self) -> None:
        for path in (
            "/etc/rastreo/sink",
            "/etc/rastreo/sink/sink.yaml",
            "/etc/rastreo",
            "/etc/rastreo/sink/",
            "/etc/rastreo/./sink",
            "//etc/rastreo/sink",
            "/etc/rastreo/sink/../sink",
            "/",
        ):
            with self.subTest(path=path):
                self.assertIn("/etc/rastreo/sink", render_error(mounted(path)))

    def test_a_mount_beside_the_sink_config_mount_renders(self) -> None:
        for path in ("/etc/rastreo/sinkfoo", "/run/secrets/kafka"):
            with self.subTest(path=path):
                deployment = document(render(mounted(path)), "deployment.yaml")
                self.assertIn(
                    [f"mountPath: {path}", "name: mine"],
                    list_items(block(deployment, "volumeMounts:")),
                )


class _ExtraListContractTests(unittest.TestCase):
    """The structural contract each extra* list is held to before it is spliced in.

    Every case here renders a Go template error naming nothing the user wrote if
    the guard that catches it is removed.
    """

    def test_every_extra_list_refuses_a_scalar_in_place_of_the_list(self) -> None:
        keys = extra_list_keys()
        self.assertTrue(keys, "no extra* key found in values.yaml")
        for key in keys:
            with self.subTest(key=key):
                stderr = render_error(AUTH_VALUES + f"{key}: just-a-string\n")
                self.assertIn(f"{key} is not a list", stderr)

    def test_every_extra_list_refuses_an_entry_that_is_not_a_mapping(self) -> None:
        keys = extra_list_keys()
        self.assertTrue(keys, "no extra* key found in values.yaml")
        for key in keys:
            with self.subTest(key=key):
                stderr = render_error(AUTH_VALUES + f"{key}:\n  - just-a-string\n")
                self.assertIn(f"{key}[0] is not a mapping", stderr)

    def test_an_entry_needs_the_fields_kubernetes_requires(self) -> None:
        for key, entry, missing in (
            ("extraEnv", "  - value: orphan\n", "name"),
            ("extraVolumes", "  - emptyDir: {}\n", "name"),
            ("extraVolumeMounts", "  - mountPath: /run/secrets/kafka\n", "name"),
            ("extraVolumeMounts", "  - name: mine\n", "mountPath"),
        ):
            with self.subTest(key=key, missing=missing):
                stderr = render_error(AUTH_VALUES + f"{key}:\n{entry}")
                self.assertIn(f"{key}[0] has no {missing}", stderr)

    def test_a_required_field_must_be_text(self) -> None:
        for key, entry, field in (
            ("extraEnv", "  - name: 8080\n", "name"),
            ("extraVolumes", "  - name: 8080\n", "name"),
            ("extraVolumeMounts", "  - name: mine\n    mountPath: 8080\n", "mountPath"),
        ):
            with self.subTest(key=key, field=field):
                stderr = render_error(AUTH_VALUES + f"{key}:\n{entry}")
                self.assertIn(f"{key}[0] does not give {field} text", stderr)


class _SinkConfigShapeTests(unittest.TestCase):
    def test_sink_must_be_a_mapping(self) -> None:
        stderr = render_error(AUTH_VALUES + "sink: none\n")
        self.assertIn("sink is not a mapping", stderr)

    def test_sink_config_must_be_a_mapping(self) -> None:
        values = AUTH_VALUES + "sink:\n  config: type=stdout\n"
        self.assertIn("sink.config is not a mapping", render_error(values))

    def test_sink_config_yaml_must_be_text(self) -> None:
        values = AUTH_VALUES + "sink:\n  configYaml:\n    type: stdout\n"
        self.assertIn("sink.configYaml is not text", render_error(values))


class _ReadingHelperTests(unittest.TestCase):
    def test_block_stops_at_the_first_line_back_at_its_own_indent(self) -> None:
        text = "spec:\n  env:\n    - name: A\n      value: b\n  ports:\n    - 8080\n"
        self.assertEqual(block(text, "env:"), ["- name: A", "  value: b"])

    def test_list_items_group_continuation_lines(self) -> None:
        self.assertEqual(
            list_items(["- name: A", "  value: b", "- name: C"]),
            [["name: A", "value: b"], ["name: C"]],
        )


# --- Entry point -------------------------------------------------------------


def update_goldens() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for name, values in GOLDENS.items():
        (GOLDEN_DIR / name).write_text(normalized(render(values)), encoding="utf-8")
        print(f"wrote {GOLDEN_DIR / name}", file=sys.stderr)
    return 0


def run_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for obj in vars(sys.modules[__name__]).values():
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            suite.addTests(loader.loadTestsFromTestCase(obj))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--chart",
        default=str(CHART),
        help="Chart directory to render. Point this at a copy to check that a "
        "guard is load-bearing.",
    )
    parser.add_argument(
        "--update-goldens",
        action="store_true",
        help="Rewrite the golden renders from the chart under test, then exit.",
    )
    args = parser.parse_args(list(argv))

    if shutil.which("helm") is None:
        print(
            "helm is not on PATH: install Helm 3 to run the chart tests",
            file=sys.stderr,
        )
        return 1

    global chart_under_test
    chart_under_test = Path(args.chart).resolve()
    if not (chart_under_test / "Chart.yaml").exists():
        print(f"{chart_under_test} is not a chart directory", file=sys.stderr)
        return 1

    return update_goldens() if args.update_goldens else run_tests()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
