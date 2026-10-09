from typer.testing import CliRunner

from twa.cli import app
from twa.core import Session, save_session
from twa.providers import FailureKind, ProviderFailure


def test_help_and_version():
    runner = CliRunner()
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert "TWA" in runner.invoke(app, ["version"]).output


def test_mutually_exclusive_inputs():
    result = CliRunner().invoke(app, ["-f", ".", "-u", "https://example.test", "--s"])
    assert result.exit_code == 2
    assert "exactly one" in result.output


def test_solve_text_json_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "clue file.txt"
    source.write_text("proof: flag{saved}", encoding="utf-8")
    result = CliRunner().invoke(app, ["-f", str(source), "--s", "--offline", "--json"])
    assert result.exit_code == 0, result.output
    assert '"value": "flag{saved}"' in result.output
    assert (tmp_path / ".twa" / "sessions").exists()
    assert (tmp_path / ".twa" / "reports").exists()


def test_local_findings_survive_model_refusal(tmp_path, monkeypatch):
    import twa.cli as cli

    monkeypatch.chdir(tmp_path)
    source = tmp_path / "challenge.txt"
    source.write_text("flag{found_before_filter}", encoding="utf-8")
    monkeypatch.setattr(cli, "discover_models", lambda: [{"id": "test/opus", "name": "Opus"}])

    def refusal(*args, **kwargs):
        raise ProviderFailure(FailureKind.MODEL_REFUSAL, "model declined")

    monkeypatch.setattr(cli.OmniRouteClient, "chat", refusal)
    result = CliRunner().invoke(app, ["-f", str(source), "--s", "--model", "test/opus", "--json"])
    assert result.exit_code == 0, result.output
    assert "flag{found_before_filter}" in result.output
    assert '"status": "candidate"' in result.output
    assert "MODEL_REFUSAL" in result.output


def test_resume_saved_local_session_without_new_input(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "saved clue.txt"
    source.write_text("flag{resume_me}", encoding="utf-8")
    session = Session(target=str(source))
    save_session(session)
    result = CliRunner().invoke(app, ["--resume", session.session_id, "--offline", "--json"])
    assert result.exit_code == 0, result.output
    assert '"status": "candidate"' in result.output
    assert "flag{resume_me}" in result.output


def test_remote_scope_mismatch_fails_before_request():
    result = CliRunner().invoke(
        app, ["-u", "https://challenge.example", "--scope", "other.example", "--s"]
    )
    assert result.exit_code == 2
    assert "exactly match" in result.output


def test_silent_filter_failure_is_reported_as_critical(tmp_path, monkeypatch):
    import twa.cli as cli

    monkeypatch.chdir(tmp_path)
    source = tmp_path / "clue.txt"
    source.write_text("no flag in this evidence", encoding="utf-8")
    monkeypatch.setattr(cli, "discover_models", lambda: [{"id": "model/test", "name": "Test"}])

    def filtered(*args, **kwargs):
        raise ProviderFailure(FailureKind.PROVIDER_CONTENT_FILTER, "blocked by content_filter")

    monkeypatch.setattr(cli.OmniRouteClient, "chat", filtered)
    result = CliRunner().invoke(
        app, ["-f", str(source), "--s", "--model", "model/test", "--silent"]
    )
    assert result.exit_code == 1
    assert "PROVIDER_CONTENT_FILTER" in result.output


def test_login_uses_omniroute_and_remembers_available_opus(tmp_path, monkeypatch):
    import twa.cli as cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "omniroute_version", lambda: "3.8.49")
    monkeypatch.setattr(
        cli,
        "discover_models",
        lambda timeout=25: [{"id": "antigravity/claude-opus", "name": "Claude Opus"}],
    )
    monkeypatch.setattr(cli, "start_antigravity_login", lambda no_browser: (True, ""))
    monkeypatch.setattr(cli, "antigravity_status", lambda: "AUTHENTICATED")
    result = CliRunner().invoke(app, ["login", "--no-browser"])
    assert result.exit_code == 0, result.output
    assert "Antigravity: AUTHENTICATED" in result.output
    assert "Selected available Opus model" in result.output
    assert "opus" in (tmp_path / ".twa" / "config.yaml").read_text(encoding="utf-8")


def test_login_fails_fast_if_omniroute_server_is_unavailable(monkeypatch):
    import twa.cli as cli

    started = False

    def unavailable(timeout=25):
        raise RuntimeError("Server not running")

    def should_not_start(no_browser=False):
        nonlocal started
        started = True
        return True, ""

    monkeypatch.setattr(cli, "omniroute_version", lambda: "3.8.49")
    monkeypatch.setattr(cli, "discover_models", unavailable)
    monkeypatch.setattr(cli, "start_antigravity_login", should_not_start)
    result = CliRunner().invoke(app, ["login"])
    assert result.exit_code == 3
    assert "omniroute serve" in result.output
    assert not started
