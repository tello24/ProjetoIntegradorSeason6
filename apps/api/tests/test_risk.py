from app.services.risk import calculate_neo_score, priority_for_score


def test_neo_score_combines_technical_and_exploitation_signals() -> None:
    score = calculate_neo_score(
        severity=4,
        cvss2=None,
        cvss3=9.8,
        cvss4=None,
        epss=0.4,
        exploitable=True,
        vpr=8.1,
    )

    assert score.total == 82
    assert score.priority == "act_now"
    assert score.cvss_component == 53.9
    assert score.epss_component == 10.0
    assert score.exploit_component == 10.0
    assert score.vpr_component == 8.1


def test_neo_score_uses_severity_when_cvss_is_missing() -> None:
    score = calculate_neo_score(
        severity=2,
        cvss2=None,
        cvss3=None,
        cvss4=None,
        epss=None,
        exploitable=False,
        vpr=None,
    )

    assert score.total == 28
    assert score.priority == "monitor"
    assert "Sem sinais adicionais" in score.factors[-1]


def test_priority_bands_are_stable() -> None:
    assert priority_for_score(80) == "act_now"
    assert priority_for_score(79) == "prioritize"
    assert priority_for_score(60) == "prioritize"
    assert priority_for_score(35) == "plan"
    assert priority_for_score(34) == "monitor"
