# === Pareto & Concentration Add-on ============================================
from typing import List, Dict, Tuple
import math
import csv
from collections import Counter, defaultdict

def _get_score(v: Dict) -> float:
    """Best-effort score getter across possible field names."""
    for k in ("rpi_score", "rpi", "RPI", "score", "final_score"):
        if k in v and v[k] is not None:
            try:
                return float(v[k])
            except Exception:
                pass
    # If metrics were nested:
    m = v.get("rpi_metrics") or v.get("metrics") or {}
    for k in ("rpi_score", "rpi", "score"):
        if isinstance(m, dict) and k in m:
            try:
                return float(m[k])
            except Exception:
                pass
    return 0.0

def _safe_key(v: Dict, keys: List[str], default="(n/a)"):
    """Try multiple key names; return first found non-empty."""
    for k in keys:
        val = v.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if val not in (None, "", []):
            return val
    return default

def top_p_share(prioritized: List[Dict], p: float = 0.20) -> float:
    """Return cumulative RPI share captured by the top p fraction (sorted desc)."""
    scores = [max(_get_score(v), 0.0) for v in prioritized]
    scores.sort(reverse=True)
    if not scores or sum(scores) == 0:
        return 0.0
    n_top = max(1, int(math.ceil(len(scores) * p)))
    return sum(scores[:n_top]) / sum(scores)

def rsi_at_share(prioritized: List[Dict], target_share: float = 0.80) -> Tuple[int, float, float]:
    """Smallest k s.t. cumulative share >= target_share. Returns (k, share, k/N)."""
    scores = [max(_get_score(v), 0.0) for v in prioritized]
    scores.sort(reverse=True)
    total = sum(scores)
    if not scores or total == 0:
        return 0, 0.0, 0.0
    cum = 0.0
    for i, s in enumerate(scores, 1):
        cum += s
        if cum / total >= target_share:
            return i, cum / total, i / len(scores)
    return len(scores), 1.0, 1.0

def gini(prioritized: List[Dict]) -> float:
    """Gini coefficient of the RPI distribution."""
    x = [max(_get_score(v), 0.0) for v in prioritized]
    n = len(x)
    if n == 0:
        return 0.0
    x = sorted(x)
    s = sum(x)
    if s == 0:
        return 0.0
    # Gini via Lorenz area
    cum = 0.0
    lorenz_area = 0.0
    for i, xi in enumerate(x, 1):
        cum += xi
        lorenz_area += cum / s
    lorenz_area /= n
    # Perfect equality area = 0.5
    return 1 - 2 * (0.5 - (lorenz_area - 0.5))

def coverage_points(prioritized: List[Dict], thresholds=(0.50, 0.75, 0.80, 0.90, 0.95)) -> List[Tuple[float, int, float]]:
    """For each threshold, return (threshold, k, k/N)."""
    out = []
    for t in thresholds:
        k, _, frac = rsi_at_share(prioritized, t)
        out.append((t, k, frac))
    return out

def decile_table(prioritized: List[Dict], deciles: int = 10) -> List[Tuple[int, float]]:
    """Return [(decile_index, share)] with equal-population bins along the ranked list."""
    scores = [max(_get_score(v), 0.0) for v in prioritized]
    scores.sort(reverse=True)
    total = sum(scores) or 1.0
    n = len(scores)
    out = []
    for d in range(deciles):
        start = int(round(d * n / deciles))
        end = int(round((d + 1) * n / deciles))
        out.append((d + 1, sum(scores[start:end]) / total))
    return out

def aggregate_contributors(prioritized: List[Dict], field_candidates: List[List[str]], top_k=10):
    """
    Aggregate RPI by the first available key from each candidate list.
    Example field_candidates:
      [
        ["asset_name","asset","host","servername"],
        ["team","owner_team","tribe"],
        ["component_name","package","library","product"],
        ["environment","env"],
      ]
    """
    results = {}
    for keys in field_candidates:
        acc = Counter()
        for v in prioritized:
            key = _safe_key(v, keys)
            acc[key] += max(_get_score(v), 0.0)
        total = sum(acc.values()) or 1.0
        items = [(k, s, s/total) for k, s in acc.most_common(top_k)]
        results[tuple(keys)] = items
    return results

def print_concentration_report(prioritized: List[Dict]):
    n = len(prioritized)
    k80, share80, frac80 = rsi_at_share(prioritized, 0.80)
    s20 = top_p_share(prioritized, 0.20)
    g = gini(prioritized)
    gap_pp = max(0.0, frac80 - 0.20) * 100

    print("\n══════════════════════════════════════════════════════════════════════")
    print("📈  Pareto & Concentration Report")
    print("══════════════════════════════════════════════════════════════════════")
    print(f"• N vulnerabilities: {n}")
    print(f"• Top-20% capture (share@20%): {s20*100:5.1f}%  ← quão '80/20' você já é")
    print(f"• RSI@80: {frac80*100:5.1f}%  (k={k80} itens cobrem 80% do RPI total)")
    print(f"• Concentration Gap vs 80/20: +{gap_pp:0.1f} p.p.")
    print(f"• Gini(RPI): {g:0.3f}  (mais alto = mais concentrado)")
    print("• Coverage points (mínimo k e % backlog para atingir alvo):")
    for t, k, frac in coverage_points(prioritized):
        print(f"    - {int(t*100):>2}%  → k={k:<6} ({frac*100:4.1f}% do backlog)")
    print("• Decile distribution (share por faixas de 10% do rank):")
    for d, sh in decile_table(prioritized):
        print(f"    - D{d}: {sh*100:5.1f}%")

    print("\n• Top risk contributors (para direcionar squads):")
    fields = [
        ["asset_name","asset","host","servername"],
        ["team","owner_team","tribe"],
        ["component_name","package","library","product"],
        ["environment","env"],
    ]
    agg = aggregate_contributors(prioritized, fields, top_k=8)
    for keys, items in agg.items():
        label = " / ".join(keys)
        print(f"   - Por {label}:")
        for name, s, sh in items:
            print(f"       · {str(name)[:40]:<40}  RPI={s:10.2f}  ({sh*100:5.1f}%)")
    print("══════════════════════════════════════════════════════════════════════\n")

# Chame assim, após obter `prioritized`:
# print_concentration_report(prioritized)
