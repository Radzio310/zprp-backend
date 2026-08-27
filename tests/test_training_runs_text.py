from app.training_text import actor_text


def test_training_actor_text_repairs_windows_1252_mojibake():
    assert actor_text("WITKOWICZ RadosÅ‚aw") == "WITKOWICZ Radosław"


def test_training_actor_text_keeps_correct_polish_and_ascii():
    assert actor_text("ŻÓŁĆ Anna") == "ŻÓŁĆ Anna"
    assert actor_text("NOWAK Jan") == "NOWAK Jan"
