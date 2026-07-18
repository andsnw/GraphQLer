"""Measure vulnerability-detector precision and recall against labeled runs."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Finding:
    detector: str
    node: str
    level: str


def _level_satisfies(actual: str, expected: str) -> bool:
    return expected == "potential" or actual == "confirmed"


def load_findings(stats_path: Path) -> list[Finding]:
    """Load flagged findings from a GraphQLer ``stats.json`` report."""
    report = json.loads(stats_path.read_text())
    findings: list[Finding] = []
    for detector, nodes in report.get("vulnerabilities", {}).items():
        for node, result in nodes.items():
            if result.get("is_vulnerable"):
                findings.append(Finding(detector, node, "confirmed"))
            elif result.get("potentially_vulnerable"):
                findings.append(Finding(detector, node, "potential"))
    return findings


def _matches(expected: Finding, actual: Finding) -> bool:
    return (
        expected.detector == actual.detector
        and (expected.node == "*" or expected.node == actual.node)
        and _level_satisfies(actual.level, expected.level)
    )


def evaluate_findings(expected: list[Finding], actual: list[Finding]) -> dict[str, Any]:
    """Match expected and actual findings, returning aggregate and per-detector metrics."""
    unmatched_actual = set(range(len(actual)))
    matched_pairs: list[tuple[Finding, Finding]] = []
    false_negatives: list[Finding] = []

    for expected_finding in expected:
        match_index = next(
            (index for index in sorted(unmatched_actual) if _matches(expected_finding, actual[index])),
            None,
        )
        if match_index is None:
            false_negatives.append(expected_finding)
            continue
        unmatched_actual.remove(match_index)
        matched_pairs.append((expected_finding, actual[match_index]))

    false_positives = [actual[index] for index in sorted(unmatched_actual)]
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for expected_finding, _ in matched_pairs:
        counts[expected_finding.detector]["tp"] += 1
    for finding in false_positives:
        counts[finding.detector]["fp"] += 1
    for finding in false_negatives:
        counts[finding.detector]["fn"] += 1

    def metrics(values: dict[str, int]) -> dict[str, float | int]:
        tp, fp, fn = values["tp"], values["fp"], values["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {**values, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}

    totals = {
        "tp": len(matched_pairs),
        "fp": len(false_positives),
        "fn": len(false_negatives),
    }
    return {
        "metrics": metrics(totals),
        "per_detector": {name: metrics(values) for name, values in sorted(counts.items())},
        "false_positives": [asdict(finding) for finding in false_positives],
        "false_negatives": [asdict(finding) for finding in false_negatives],
    }


def evaluate_corpus(corpus_path: Path, results_root: Path) -> dict[str, Any]:
    """Evaluate every labeled target in a detector corpus."""
    corpus = yaml.safe_load(corpus_path.read_text())
    if corpus.get("version") != 1:
        raise ValueError(f"Unsupported detector corpus version: {corpus.get('version')}")

    combined_expected: list[Finding] = []
    combined_actual: list[Finding] = []
    targets: dict[str, Any] = {}
    for target_name, target in corpus.get("targets", {}).items():
        stats_path = results_root / target["results"] / "stats.json"
        if not stats_path.exists():
            raise FileNotFoundError(f"Missing detector results for {target_name}: {stats_path}")
        expected = [Finding(**finding) for finding in target.get("findings", [])]
        actual = load_findings(stats_path)
        targets[target_name] = evaluate_findings(expected, actual)
        combined_expected.extend(expected)
        combined_actual.extend(actual)

    return {
        "corpus": str(corpus_path),
        "results_root": str(results_root),
        "aggregate": evaluate_findings(combined_expected, combined_actual),
        "targets": targets,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).parent / "ground_truth" / "detectors.yml",
    )
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = evaluate_corpus(args.corpus, args.results_root)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
