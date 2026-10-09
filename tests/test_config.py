import pytest

from twa.config import Config, load_config, save_config


def test_config_defaults_and_roundtrip(tmp_path):
    initial = load_config(tmp_path)
    assert initial.agent["max_steps"] == 10
    saved = save_config(initial, tmp_path)
    assert saved.exists()
    assert load_config(tmp_path).ai["model"] is None


def test_config_rejects_unknown_or_out_of_range_options():
    with pytest.raises(ValueError, match="Unknown configuration key"):
        Config(agent={"unexpected": True})
    with pytest.raises(ValueError, match="between 1 and 50"):
        Config(agent={"max_steps": 500})
