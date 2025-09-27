from aegisflow_backend.services.ranking import leverage_score


def test_leverage_score_bounds():
    assert leverage_score(10, 10, 10) <= 10
    assert leverage_score(-5, -5, -5) >= 0


def test_leverage_score_weighting():
    value = leverage_score(5, 5, 5)
    assert value == 5.0
