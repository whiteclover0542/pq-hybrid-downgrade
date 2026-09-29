"""v1.7: browser ClientHello survey and audit visibility in verbose outputs.

Part 1 (browser survey): headless Chrome for Testing and Firefox (tools/v17_setup.sh) load a page from the
v1.6 survey server (OpenSSL 3.5.6, default groups); the pcap records their supported_groups and key_share.
Part 2 (trace): the v1.2 CVE conditions (3.5.5 S1/S3, 3.5.6 S3) rerun with `s_client -trace` instead of -msg.
Part 3 (tshark -V): offline pass over preserved pcaps; does one verbose output show the advertised groups
and the negotiated group together, and does it carry any TLS warning?
No manipulation in any part. The OpenSSL 3.6 causal-isolation runs use faultinject.v12 (see analyze --v17).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

from faultinject.audit import WARNING_RE
from faultinject.harness import ScenarioSpec, parse_group, run_scenario
from faultinject.record import RunRecord
from faultinject.v12 import (
    PHASE2_ROOT, _port_free, evaluate_v12, native_environment, provenance_for, sha256_file, v12_paths, v12_spec,
)
from faultinject.v15 import PORT
from faultinject.v16 import SURVEY_SERVER, _clean_env, evaluate_v16, render_v16

V17 = f"{PHASE2_ROOT}/v17"
URL = f"https://127.0.0.1:{PORT}/"
CHROME = f"{V17}/chrome-headless-shell-linux64/chrome-headless-shell"
FIREFOX = f"{V17}/firefox/firefox"
# `timeout` bounds each browser run below the harness's 30 s client limit; index 2 is the browser binary
BROWSERS = {
    "chrome": ["timeout", "20", CHROME, "--no-sandbox", "--ignore-certificate-errors", "--dump-dom", URL],
    "firefox": ["timeout", "25", FIREFOX, "--headless", "--no-remote", "--profile", f"{V17}/ffprofile",
                "--screenshot", f"{V17}/firefox.png", URL],
}
TRACE_CONDITIONS = (("3.5.5", "S1"), ("3.5.5", "S3"), ("3.5.6", "S3"))

_SUPPORTED_RE = re.compile(r"Supported Group: (\S+) \(0x[0-9a-f]{4}\)")
_KEY_SHARE_RE = re.compile(r"Key Share Entry: Group: ([^,]+),")
_EXPERT_RE = re.compile(r"\[Expert Info \((Warning|Error)/([^)]*)\): ([^\]]*)\]")


def v17_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "docs/research/baselines/raw/v1.7"


def browser_spec(browser: str, repetition: int, out_dir: Path) -> ScenarioSpec:
    return ScenarioSpec(
        impl="openssl", fault_type="client-default", repetition=repetition, condition=browser,
        server_cmd=SURVEY_SERVER, client_cmd=BROWSERS[browser], listen_port=PORT, env=_clean_env(),
        out_dir=out_dir, capture_traffic=True, server_env=native_environment("3.5.6"), capture_seconds=30,
    )


def trace_spec(version: str, setting: str, repetition: int, out_dir: Path, paths: dict) -> ScenarioSpec:
    spec = v12_spec(version, setting, repetition, out_dir, paths)
    return replace(spec, fault_type="server-setting-trace",
                   client_cmd=[arg if arg != "-msg" else "-trace" for arg in spec.client_cmd])


_TRACE_GROUP_RE = re.compile(r"^\s+(.+?) \((\d+)\)\s*$", re.M)


def _trace_groups(section: str) -> list[str]:
    """Group names listed under the first supported_groups extension of a -trace section."""
    if "extension_type=supported_groups" not in section:
        return []
    block = section.split("extension_type=supported_groups", 1)[1].split("\n", 1)[-1]
    block = re.split(r"\n\s*(?:extension_type=|\S+ TLS Record)", block, maxsplit=1)[0]
    return [name for name, _ in _TRACE_GROUP_RE.findall(block)]


def trace_audit(text: str) -> dict:
    """Does one `s_client -trace` log name both the advertised groups and the negotiated group?"""
    client_part = text.partition("ServerHello, Length=")[0]  # the first ServerHello may be an HRR
    server_part = text.partition("EncryptedExtensions, Length=")[2]
    advertised = _trace_groups(client_part)
    negotiated = parse_group("openssl", text)
    warning = WARNING_RE.search(text)
    return {
        "advertised_groups": advertised,
        # TLS 1.3 servers list their own groups in EncryptedExtensions; -trace decodes them
        "server_groups": _trace_groups(server_part),
        "negotiated_group": negotiated,
        "single_output": bool(advertised and negotiated),
        "explicit_warning": bool(warning),
        "warning_text": warning.group(0) if warning else None,
    }


def verbose_audit(text: str) -> dict:
    """Same question for `tshark -V`: ClientHello supported groups and the final ServerHello key share."""
    frames = text.split("Handshake Type: ")
    client = next((f for f in frames if f.startswith("Client Hello")), "")
    servers = [f for f in frames if f.startswith("Server Hello")]
    shares = [_KEY_SHARE_RE.findall(f) for f in servers]
    experts = [m.groups() for m in _EXPERT_RE.finditer(text)]
    tls_experts = [e for e in experts if e[1] != "Sequence"]
    return {
        "advertised_groups": _SUPPORTED_RE.findall(client),
        "negotiated_group": shares[-1][-1] if shares and shares[-1] else None,
        "single_output": bool(_SUPPORTED_RE.search(client) and shares and shares[-1]),
        "explicit_warning": bool(WARNING_RE.search(text)) or bool(tls_experts),
        "warning_text": [": ".join(e) for e in tls_experts] or None,
    }


def tshark_verbose(pcap: Path, runner=subprocess.run) -> str | None:
    result = runner(["tshark", "-r", str(pcap), "-V"], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def run_browsers(repetitions: int, out_dir: Path, scenario_runner=run_scenario) -> list[RunRecord]:
    records = []
    for rep in range(1, repetitions + 1):
        for browser in BROWSERS:
            spec = browser_spec(browser, rep, out_dir)
            record = evaluate_v16(scenario_runner(spec), out_dir, spec)
            record.provenance.update(browser=True, binary_sha256=sha256_file(Path(BROWSERS[browser][2])))
            record.to_json_path(out_dir)
            records.append(record)
    return records


def run_trace(repetitions: int, out_dir: Path, scenario_runner=run_scenario) -> list[RunRecord]:
    versions = tuple(dict.fromkeys(v for v, _ in TRACE_CONDITIONS))
    paths = v12_paths(versions)
    hashes = {key: sha256_file(Path(value)) for key, value in paths.items() if key != "cert"}
    hashes.update({f"server_lib_{v}": sha256_file(Path(paths[f"server_bin_{v}"]).parents[1] / "lib64/libssl.so.3")
                   for v in versions})
    records = []
    for rep in range(1, repetitions + 1):
        for version, setting in TRACE_CONDITIONS:
            spec = trace_spec(version, setting, rep, out_dir, paths)
            record = evaluate_v12(scenario_runner(spec), out_dir, provenance_for(spec, paths, hashes))
            log = out_dir / record.artifacts["client_log"]
            record = replace(record, audit={**record.audit, "trace": trace_audit(log.read_text(errors="replace"))})
            record.to_json_path(out_dir)
            records.append(record)
    return records


def verbose_pass(run_dirs: list[Path], out_path: Path, runner=subprocess.run) -> list[dict]:
    rows = []
    for run_dir in run_dirs:
        for json_path in sorted(Path(run_dir).glob("*.json")):
            record = RunRecord.from_json(json_path)
            pcap = Path(run_dir) / record.artifacts.get("pcap", "")
            text = tshark_verbose(pcap, runner) if pcap.is_file() else None
            rows.append({"run_dir": Path(run_dir).name, "run_id": record.run_id,
                         "final_group_recorded": record.metrics.final_negotiated_group,
                         **(verbose_audit(text) if text is not None else {"error": "no pcap or tshark failed"})})
    out_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return rows


def render_v17(run_dir: Path, verbose_json: Path | None = None) -> str:
    lines = ["## browser survey", render_v16(run_dir).split("\n\n")[0], "", "## s_client -trace",
             "| condition | n | final group | HRR (PCAP) | advertised groups in log | server groups in log | single output | warning |",
             "|---|---:|---|---:|---|---|---:|---:|"]
    trace: dict = {}
    for path in sorted(Path(run_dir).glob("*.json")):
        record = RunRecord.from_json(path)
        if record.fault_type != "server-setting-trace":
            continue
        # recompute from the preserved log: the JSON audit.trace of HRR runs predates the EncryptedExtensions fix
        t = trace_audit((Path(run_dir) / record.artifacts["client_log"]).read_text(encoding="utf-8", errors="replace"))
        c = trace.setdefault(record.condition, {"n": 0, "final": set(), "hrr": 0, "adv": set(), "srv": set(), "single": 0, "warn": 0})
        c["n"] += 1
        c["final"].add(str(record.metrics.final_negotiated_group))
        c["hrr"] += int(record.metrics.hrr_pcap_present is True)
        c["adv"].add(",".join(t["advertised_groups"]))
        c["srv"].add(",".join(t["server_groups"]))
        c["single"] += int(t["single_output"])
        c["warn"] += int(t["explicit_warning"])
    lines += [f"| {k} | {v['n']} | {'/'.join(sorted(v['final']))} | {v['hrr']} | {' / '.join(sorted(v['adv']))} | {' / '.join(sorted(v['srv']))} | "
              f"{v['single']} | {v['warn']} |" for k, v in sorted(trace.items())]
    if verbose_json and Path(verbose_json).is_file():
        rows = json.loads(Path(verbose_json).read_text(encoding="utf-8"))
        lines += ["", "## tshark -V (preserved pcaps)",
                  "| run dir | pcaps | advertised visible | negotiated visible | single output | negotiated = recorded | TLS warning |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        by_dir: dict = {}
        for row in rows:
            c = by_dir.setdefault(row["run_dir"], [0, 0, 0, 0, 0, 0])
            c[0] += 1
            c[1] += int(bool(row.get("advertised_groups")))
            c[2] += int(bool(row.get("negotiated_group")))
            c[3] += int(bool(row.get("single_output")))
            c[4] += int(_same_group(row.get("negotiated_group"), row.get("final_group_recorded")))
            c[5] += int(bool(row.get("explicit_warning")))
        lines += [f"| {d} | {' | '.join(map(str, c))} |" for d, c in sorted(by_dir.items())]
    return "\n".join(lines)


def _same_group(tshark_name: str | None, recorded: str | None) -> bool:
    return bool(tshark_name and recorded and tshark_name.lower() == recorded.lower())


def preflight_v17() -> tuple[bool, str]:
    for binary in (CHROME, FIREFOX):
        if not Path(binary).exists():
            return False, f"missing: {binary} (run tools/v17_setup.sh)"
    if not _port_free(PORT):
        return False, f"port {PORT} in use"
    return True, "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="v1.7 browser survey and verbose audit visibility")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repeat", type=int, metavar="N", help="run the browser survey and -trace reruns")
    mode.add_argument("--verbose-pass", nargs="+", type=Path, metavar="RUN_DIR", help="tshark -V over run dirs")
    mode.add_argument("--report", type=Path, metavar="DIR")
    parser.add_argument("--output-dir", type=Path, metavar="PATH")
    parser.add_argument("--verbose-json", type=Path, metavar="PATH")
    arguments = parser.parse_args(argv)
    out_dir = Path(arguments.output_dir or v17_output_dir())
    if arguments.report:
        print(render_v17(arguments.report, arguments.verbose_json))
        return 0
    if arguments.verbose_pass:
        rows = verbose_pass(arguments.verbose_pass, arguments.verbose_json or out_dir / "tshark-verbose-audit.json")
        print(f"{len(rows)} pcaps audited")
        return 0
    ok, reason = preflight_v17()
    if not ok:
        print(f"preflight failed: {reason}")
        return 1
    if out_dir.exists() and any(out_dir.glob("*.json")):
        raise RuntimeError(f"{out_dir} is not empty; choose a fresh --output-dir")
    for record in [*run_browsers(arguments.repeat, out_dir), *run_trace(arguments.repeat, out_dir)]:
        print(f"{record.run_id}: groups={record.provenance.get('client_hello_groups')} "
              f"shares={record.provenance.get('client_hello_key_shares')} hrr={record.metrics.hrr_pcap_present} "
              f"final={record.metrics.final_negotiated_group}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
