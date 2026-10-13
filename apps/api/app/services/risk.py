from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

Priority = Literal["act_now", "prioritize", "plan", "monitor"]

# Version 1.0 is deliberately stable and transparent: 55% technical impact, 25%
# exploitation probability, 10% known exploit availability and 10% Tenable VPR.
NEO_SCORE_SQL = """
least(
    100,
    greatest(
        0,
        round(
            (
                coalesce(
                    cvss4,
                    cvss3,
                    cvss2,
                    CASE severidade
                        WHEN 4 THEN 9.0
                        WHEN 3 THEN 7.0
                        WHEN 2 THEN 5.0
                        WHEN 1 THEN 2.5
                        ELSE 0.0
                    END
                ) / 10.0 * 55
            )
            + (coalesce(epss, 0) * 25)
            + (CASE WHEN exploravel THEN 10 ELSE 0 END)
            + (coalesce(vpr, 0) / 10.0 * 10)
        )
    )
)::integer
"""


@dataclass(frozen=True, slots=True)
class NeoScore:
    total: int
    priority: Priority
    cvss_component: float
    epss_component: float
    exploit_component: float
    vpr_component: float
    factors: tuple[str, ...]


def calculate_neo_score(
    *,
    severity: int,
    cvss2: float | None,
    cvss3: float | None,
    cvss4: float | None,
    epss: float | None,
    exploitable: bool,
    vpr: float | None,
) -> NeoScore:
    cvss = _first_score(cvss4, cvss3, cvss2) or _severity_fallback(severity)
    bounded_epss = min(max(epss or 0.0, 0.0), 1.0)
    bounded_vpr = min(max(vpr or 0.0, 0.0), 10.0)

    cvss_component = cvss / 10 * 55
    epss_component = bounded_epss * 25
    exploit_component = 10.0 if exploitable else 0.0
    vpr_component = bounded_vpr
    total = _round_score(cvss_component + epss_component + exploit_component + vpr_component)

    factors = [f"Impacto técnico CVSS {cvss:.1f}"]
    if epss is not None:
        factors.append(f"Probabilidade EPSS de {bounded_epss * 100:.1f}%")
    if exploitable:
        factors.append("Exploit disponível reportado pelo scanner")
    if vpr is not None:
        factors.append(f"VPR {bounded_vpr:.1f} informado pelo Tenable")
    if epss is None and not exploitable and vpr is None:
        factors.append("Sem sinais adicionais de exploração no arquivo importado")

    return NeoScore(
        total=total,
        priority=priority_for_score(total),
        cvss_component=round(cvss_component, 1),
        epss_component=round(epss_component, 1),
        exploit_component=exploit_component,
        vpr_component=round(vpr_component, 1),
        factors=tuple(factors),
    )


def priority_for_score(score: int) -> Priority:
    if score >= 80:
        return "act_now"
    if score >= 60:
        return "prioritize"
    if score >= 35:
        return "plan"
    return "monitor"


def _severity_fallback(severity: int) -> float:
    return {4: 9.0, 3: 7.0, 2: 5.0, 1: 2.5}.get(severity, 0.0)


def _first_score(*scores: float | None) -> float | None:
    return next((score for score in scores if score is not None), None)


def _round_score(value: float) -> int:
    bounded = min(max(value, 0.0), 100.0)
    return int(Decimal(str(bounded)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
