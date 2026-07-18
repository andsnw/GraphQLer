import json

import yaml

from benchmark.benchmark_detector_accuracy import Finding, evaluate_corpus, evaluate_findings


def test_evaluate_findings_counts_true_false_positive_and_negative():
    expected = [
        Finding("SQL", "search", "confirmed"),
        Finding("SSRF", "*", "potential"),
        Finding("IDOR", "getUser", "confirmed"),
    ]
    actual = [
        Finding("SQL", "search", "confirmed"),
        Finding("SSRF", "fetchUrl", "confirmed"),
        Finding("XSS", "createPost", "potential"),
    ]

    report = evaluate_findings(expected, actual)

    assert report["metrics"] == {
        "tp": 2,
        "fp": 1,
        "fn": 1,
        "precision": 0.6667,
        "recall": 0.6667,
        "f1": 0.6667,
    }
    assert report["per_detector"]["SQL"]["tp"] == 1
    assert report["per_detector"]["XSS"]["fp"] == 1
    assert report["per_detector"]["IDOR"]["fn"] == 1


def test_confirmed_ground_truth_rejects_potential_finding():
    report = evaluate_findings(
        [Finding("SQL", "search", "confirmed")],
        [Finding("SQL", "search", "potential")],
    )

    assert report["metrics"]["tp"] == 0
    assert report["metrics"]["fp"] == 1
    assert report["metrics"]["fn"] == 1


def test_evaluate_corpus_loads_stats_reports(tmp_path):
    corpus = {
        "version": 1,
        "targets": {
            "example": {
                "results": "example-output",
                "findings": [{"detector": "SQL", "node": "search", "level": "confirmed"}],
            }
        },
    }
    corpus_path = tmp_path / "corpus.yml"
    corpus_path.write_text(yaml.safe_dump(corpus))
    output = tmp_path / "example-output"
    output.mkdir()
    (output / "stats.json").write_text(
        json.dumps(
            {
                "vulnerabilities": {
                    "SQL": {
                        "search": {
                            "is_vulnerable": True,
                            "potentially_vulnerable": True,
                        }
                    }
                }
            }
        )
    )

    report = evaluate_corpus(corpus_path, tmp_path)

    assert report["aggregate"]["metrics"]["f1"] == 1.0
    assert report["targets"]["example"]["metrics"]["tp"] == 1
