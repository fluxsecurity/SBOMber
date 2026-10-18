#!/usr/bin/env python3
"""Compare author-labelled Component 2 fixtures with usage-graph.json.

This is a per-fixture evaluator, not a reachability evaluation.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity_import(item, observed=False):
    if observed:
        loc = item['location']
        return (loc['file'], loc['line'], item['importedSpecifier'],
                item.get('importedSymbol', ''), item.get('localAlias', ''),
                item['importKind'], item.get('purl', ''))
    return (item['file'], item['line'], item['specifier'],
            item.get('imported', ''), item.get('local', ''), item['kind'], item.get('purl', ''))


def expected_binding(call, imports):
    selectors = (('importFile', 'file'), ('importLine', 'line'),
                 ('importSpecifier', 'specifier'), ('importLocal', 'local'),
                 ('imported', 'imported'), ('importKind', 'kind'))
    candidates = [item for item in imports if all(
        item.get(field) == call[selector]
        for selector, field in selectors if selector in call
    )]
    if len(candidates) != 1:
        raise ValueError(
            f"call at {call.get('file')}:{call.get('line')} requires an "
            f"unambiguous import binding; found {len(candidates)}"
        )
    return identity_import(candidates[0])


def identity_call(binding, call):
    return (*binding, call['file'], call['line'], call.get('symbol', ''))


def count_diff(counter):
    return [{'identity': list(key), 'count': value}
            for key, value in sorted(counter.items())]


def score(expected, actual):
    both = expected & actual
    false_pos, false_neg = actual - expected, expected - actual
    tp, fp, fn = (sum(items.values()) for items in
                  (both, false_pos, false_neg))
    return {
        'tp': tp, 'fp': fp, 'fn': fn,
        'precision': round(tp / (tp + fp), 4) if tp + fp else None,
        'recall': round(tp / (tp + fn), 4) if tp + fn else None,
        'extra': count_diff(false_pos), 'missing': count_diff(false_neg),
    }


def evaluate(labels, graph):
    if graph.get('analysis', {}).get('status') != 'complete':
        raise ValueError('evaluation requires a complete analysis')
    expected = labels['expected']
    imports = expected['thirdPartyImports']
    exp_imports = Counter((identity_import(x), x.get('resolution', 'resolved'))
                          for x in imports)
    exp_calls = Counter()
    exp_unknown = Counter()
    excluded = Counter()
    for name, dest in (('thirdPartyCalls', exp_calls),
                       ('unresolvedCalls', exp_unknown),
                       ('excludedCalls', excluded)):
        for item in expected.get(name, []):
            dest[identity_call(expected_binding(item, imports), item)] += 1
    if exp_calls & excluded or exp_unknown & excluded:
        raise ValueError('a call cannot be both expected and excluded')

    got_imports = Counter()
    got_calls = Counter()
    got_unknown = Counter()
    got_all = Counter()
    for observation in graph.get('observations', []):
        binding = identity_import(observation, observed=True)
        import_state = observation['resolution']
        got_imports[(binding, import_state)] += 1
        for call in observation.get('callSites', []):
            key = (*binding, call['file'], call['line'],
                   call.get('calledSymbol', ''))
            got_all[key] += 1
            if import_state == 'resolved' and call['resolution'] == 'resolved':
                got_calls[key] += 1
            else:
                got_unknown[key] += 1
    return {
        'importEvaluation': score(exp_imports, got_imports),
        'callEvaluation': score(exp_calls, got_calls),
        'unresolvedCallEvaluation': score(exp_unknown, got_unknown),
        'excludedCallViolations': count_diff(got_all & excluded),
        'observedImportOutcomes': dict(sorted(Counter(
            state for _, state in got_imports.elements()).items())),
    }


def aggregate(results):
    """Micro-average counts; empty predicted/expected denominators stay undefined."""
    totals = {key: sum(item[key] for item in results) for key in ('tp', 'fp', 'fn')}
    tp, fp, fn = (totals[key] for key in ('tp', 'fp', 'fn'))
    return {**totals, 'predicted': tp + fp, 'expected': tp + fn,
            'precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'recall': round(tp / (tp + fn), 4) if tp + fn else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--labels', required=True, type=Path)
    parser.add_argument('--graph', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    labels = json.loads(args.labels.read_text())
    graph = json.loads(args.graph.read_text())
    try:
        outcome = evaluate(labels, graph)
    except (ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    report = {
        'fixture': labels['fixture'],
        'construct': labels['construct'],
        'labelMethod': labels['labelMethod'],
        'analyserCommit': args.commit,
        'schemaVersion': graph['schemaVersion'],
        'analyser': graph.get('analyser'),
        'labelSha256': sha256(args.labels),
        'graphSha256': sha256(args.graph),
        **outcome,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print('Fixture:', report['fixture'], '| Construct:', report['construct'])
    for label in ('importEvaluation', 'callEvaluation',
                  'unresolvedCallEvaluation'):
        item = report[label]
        print(f"{label}: TP={item['tp']} FP={item['fp']} FN={item['fn']} "
              f"precision={item['precision']} recall={item['recall']}")
    print('Excluded call violations:', sum(
        item['count'] for item in report['excludedCallViolations']))
    print('Saved:', args.out)


if __name__ == '__main__':
    main()
