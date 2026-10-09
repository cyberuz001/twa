from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import config_path, load_config, save_config
from .core import (
    FLAG_DEFAULT,
    Session,
    analyze_path,
    analyze_remote,
    list_sessions,
    load_session,
    report_path,
    save_session,
    validate_remote_target,
)
from .providers import (
    ModelResponseRecoveryEngine,
    OmniRouteClient,
    ProviderFailure,
    antigravity_status,
    discover_models,
    omniroute_version,
    preferred_model,
    revoke_antigravity,
    should_skip_browser,
    start_antigravity_login,
)

app = typer.Typer(
    help="Local-first, scope-aware CTF investigation CLI",
    no_args_is_help=True,
    invoke_without_command=True,
)
console = Console()


def _fail(message: str, code: int = 2) -> None:
    Console(stderr=True).print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code)


@app.callback()
def main(
    ctx: typer.Context,
    url: Annotated[str | None, typer.Option("-u", "--url", help="Remote target URL")] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "-f", "--file", help="Local evidence file or directory", exists=True, readable=True
        ),
    ] = None,
    solve: Annotated[
        bool, typer.Option("--s", "--solve", help="Run bounded autonomous analysis")
    ] = False,
    model: Annotated[
        str | None, typer.Option("--model", help="Configured OmniRoute model ID")
    ] = None,
    silent: Annotated[
        bool | None,
        typer.Option("--silent/--no-silent", help="Suppress progress and noncritical detail"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Show detailed evidence diagnostics")
    ] = False,
    offline: Annotated[bool, typer.Option("--offline", help="Disable all network access")] = False,
    scope: Annotated[
        str | None, typer.Option("--scope", help="Exact authorized remote hostname")
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout", min=1, max=3600, help="Per-request AI/network timeout in seconds"
        ),
    ] = 90,
    max_steps: Annotated[
        int, typer.Option("--max-steps", min=1, max=50, help="Maximum bounded analysis actions")
    ] = 10,
    flag_format: Annotated[
        str,
        typer.Option("--flag-format", help="Expected flag regex", show_default=False),
    ] = FLAG_DEFAULT,
    output: Annotated[
        Path | None, typer.Option("--output", help="Directory for session and JSON report")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print final session as JSON")
    ] = False,
    resume_id: Annotated[
        str | None, typer.Option("--resume", help="Resume a saved session ID")
    ] = None,
) -> None:
    if ctx.invoked_subcommand:
        return
    if not resume_id and bool(url) == bool(file):
        _fail("Provide exactly one of -u/--url or -f/--file")
    if not solve and not resume_id:
        _fail("Use --s/--solve to run analysis")
    if resume_id and (url or file):
        _fail("Use --resume by itself; saved input is restored from its session")
    if resume_id:
        try:
            session = load_session(resume_id)
        except (ValueError, OSError) as exc:
            _fail(f"Could not load saved session: {exc}")
        session.status = "running"
        session.recovery_actions.append("Session resumed; previous evidence preserved.")
    else:
        target = str(file.resolve()) if file else (url or "")
        if url and offline:
            _fail("Remote targets are unavailable with --offline")
        if url:
            try:
                validate_remote_target(url, scope)
            except ValueError as exc:
                _fail(str(exc))
        session = Session(target=target, scope=scope, model_id=model)

    cfg = load_config()
    silent = cfg.application.get("default_silent", True) if silent is None else silent
    session.model_id = model or session.model_id or cfg.ai.get("model")
    try:
        if file:
            analyze_path(session, file, flag_format, max_files=max_steps)
        elif url and not offline:
            analyze_remote(session, url, scope or "", timeout=min(timeout, 20), pattern=flag_format)
        elif resume_id:
            if session.target.startswith(("http://", "https://")):
                if offline:
                    session.recovery_actions.append(
                        "Offline resume kept saved remote evidence without network access."
                    )
                elif session.scope:
                    analyze_remote(
                        session,
                        session.target,
                        session.scope,
                        timeout=min(timeout, 20),
                        pattern=flag_format,
                    )
                else:
                    session.recovery_actions.append(
                        "Remote session has no saved scope; retained prior evidence "
                        "without network access."
                    )
            else:
                analyze_path(session, Path(session.target), flag_format, max_files=max_steps)
    except (ValueError, OSError) as exc:
        session.errors.append({"source": session.target, "message": str(exc)[:500]})

    if len(session.evidence) > max_steps * 50:
        session.evidence = session.evidence[: max_steps * 50]

    if not offline and session.model_id:
        try:
            models = discover_models()
            model_ids = {item["id"] for item in models}
            if session.model_id not in model_ids:
                raise ValueError(
                    f"Selected model '{session.model_id}' is not exposed by OmniRoute; "
                    "use `twa models` to refresh"
                )
            summary = "\n".join(
                f"- {item.kind}: {item.source}: {item.summary}"
                for item in session.evidence[:max_steps]
            )[:12000]
            prompt = (
                "Analyze this authorized CTF challenge evidence. Suggest only safe local "
                "analytical next steps. Do not invent findings. Return a concise factual summary.\n"
                f"Category: {session.category}\nEvidence:\n"
                f"{summary or '(No local evidence collected)'}"
            )
            engine = ModelResponseRecoveryEngine(int(cfg.agent.get("max_retries", 2)))

            def on_recovery(failure, attempt):
                session.recovery_actions.append(
                    f"Provider attempt {attempt + 1}: {failure.kind.value}; "
                    "local evidence retained."
                )

            compact_evidence = "\n".join(
                f"{item.kind} {Path(item.source).name}: {item.summary[:120]}"
                for item in session.evidence[:max_steps]
            )[:3500]
            compact_prompt = (
                "Analyze this compact but evidence-backed CTF summary. Suggest safe local steps. "
                "Do not invent findings.\n"
                f"Category: {session.category}\n{compact_evidence}"
            )

            session.ai_summary = engine.run(
                lambda: OmniRouteClient(timeout=min(timeout, 120)).chat(
                    session.model_id or "", prompt
                ),
                on_recovery,
                compact_operation=lambda: OmniRouteClient(timeout=min(timeout, 120)).chat(
                    session.model_id or "", compact_prompt
                ),
            )
        except ProviderFailure as exc:
            session.errors.append({"source": "OmniRoute", "message": str(exc)[:500]})
        except (RuntimeError, ValueError, OSError) as exc:
            session.errors.append({"source": "OmniRoute", "message": str(exc)[:500]})
    elif not offline and not session.model_id:
        session.recovery_actions.append(
            "No AI model selected; completed local analysis without fabricating a model result."
        )

    session.status = "candidate" if session.flags else "unsolved"
    root = output.resolve() if output else None
    save_session(session)
    result_path = report_path(session, root)
    save_session(session)
    if json_output:
        console.print_json(json.dumps(session.model_dump(mode="json"), ensure_ascii=False))
    elif not silent:
        console.print("TWA — TERMINAL WEB AGENT")
        console.print(f"STATUS: {session.status.upper()}")
        console.print(f"CATEGORY: {session.category.upper()}")
        console.print(f"FLAG: {session.flags[0].value if session.flags else 'NOT FOUND'}")
        evidence_status = (
            "CANDIDATE ONLY; NOT INDEPENDENTLY VERIFIED" if session.flags else "ANALYSIS RECORDED"
        )
        console.print(f"EVIDENCE: {evidence_status}")
        console.print(f"REPORT: {result_path}")
        if session.ai_summary:
            console.print(f"AI SUMMARY: {session.ai_summary[:1000]}")
        if session.errors:
            for error in session.errors:
                console.print(f"[yellow]{error['source']}: {error['message']}[/yellow]")
    elif not json_output:
        console.print(f"TWA: {session.status.upper()} | {session.category} | report: {result_path}")
        for error in session.errors:
            console.print(f"[yellow]{error['source']}: {error['message']}[/yellow]")
    raise typer.Exit(0 if session.flags else 1)


@app.command("login")
def login(
    browser: Annotated[
        bool | None,
        typer.Option("--browser/--no-browser", help="Open OAuth in a local browser"),
    ] = None,
) -> None:
    if not omniroute_version():
        _fail("Install OmniRoute CLI first: https://github.com/Henrikmatos/omniroute", 3)
    try:
        discover_models(timeout=8)
    except (RuntimeError, OSError, TimeoutError) as exc:
        _fail(
            "OmniRoute model service is not reachable yet. Start and configure it with "
            f"`omniroute setup` and `omniroute serve`, then retry `twa login`. ({exc})",
            3,
        )
    no_browser = not browser if browser is not None else should_skip_browser()
    console.print("Starting OmniRoute's official Antigravity OAuth flow.")
    if no_browser:
        console.print(
            "Browser auto-open is disabled. OmniRoute will print the authorization URL "
            "below; for a remote Linux host, keep the SSH port forward open during sign-in."
        )
    else:
        console.print("Complete sign-in in the browser opened by OmniRoute.")
    try:
        success, output_text = start_antigravity_login(no_browser=no_browser)
    except (RuntimeError, OSError, TimeoutError) as exc:
        _fail(str(exc), 3)
    status = antigravity_status()
    console.print(f"Antigravity: {status}")
    if not success or status != "AUTHENTICATED":
        raise typer.Exit(3)
    try:
        models = discover_models()
        choice = preferred_model(models)
        if choice:
            cfg = load_config()
            cfg.ai["model"] = choice
            save_config(cfg)
            console.print(f"Selected available Opus model: {choice}")
    except (RuntimeError, ValueError):
        console.print(
            "OAuth completed; model listing unavailable until the OmniRoute server is ready."
        )


@app.command("logout")
def logout() -> None:
    if antigravity_status() == "NOT_CONNECTED":
        console.print("Antigravity is not connected.")
        return
    try:
        success, message = revoke_antigravity()
    except (RuntimeError, OSError, TimeoutError) as exc:
        _fail(str(exc), 3)
    console.print(
        "Antigravity connection revoked." if success else "OmniRoute could not revoke Antigravity."
    )
    if not success and message:
        console.print(message)
        raise typer.Exit(3)


@app.command("models")
def models_command() -> None:
    try:
        models = discover_models()
    except (RuntimeError, OSError, TimeoutError) as exc:
        _fail(str(exc), 3)
    cfg = load_config()
    selected = cfg.ai.get("model")
    table = Table(title="AVAILABLE MODELS")
    table.add_column("Model ID")
    table.add_column("Display name")
    for item in models:
        table.add_row(item["id"], item["name"])
    console.print(table)
    console.print(f"Selected: {selected or preferred_model(models) or 'None configured'}")


@app.command("config")
def config_command(
    setting: str | None = typer.Argument(
        default=None, help="Use 'model' to select an available model"
    ),
) -> None:
    cfg = load_config()
    if setting == "model":
        try:
            available = discover_models()
        except (RuntimeError, OSError, TimeoutError) as exc:
            _fail(str(exc), 3)
        if not available:
            _fail("OmniRoute returned no available models", 3)
        table = Table(title="AVAILABLE MODELS")
        table.add_column("#")
        table.add_column("Model ID")
        for index, item in enumerate(available, 1):
            table.add_row(str(index), item["id"])
        console.print(table)
        choice = typer.prompt("Enter model ID or number")
        ids = {item["id"] for item in available}
        selected = (
            available[int(choice) - 1]["id"]
            if choice.isdigit() and 1 <= int(choice) <= len(available)
            else choice
        )
        if selected not in ids:
            _fail("Model ID is not in the live OmniRoute model list")
        cfg.ai["model"] = selected
        save_config(cfg)
        console.print(f"Selected model: {selected}")
        return
    if setting:
        _fail("Supported form: `twa config model`")
    console.print(f"Configuration: {config_path()}")
    console.print_json(cfg.model_dump_json(indent=2))


@app.command("doctor")
def doctor() -> None:
    version = omniroute_version()
    status = antigravity_status() if version else "OmniRoute CLI not installed"
    try:
        available = discover_models() if version else []
        models_status = str(len(available))
    except (RuntimeError, OSError, TimeoutError):
        models_status = "unavailable (is OmniRoute server running?)"
    cfg = load_config()
    configured = cfg.ai.get("model")
    console.print("TWA SYSTEM DIAGNOSTICS")
    console.print("CLI                OK")
    console.print(f"Python             {sys.version.split()[0]}")
    console.print(f"OmniRoute          {version or 'NOT INSTALLED'}")
    console.print(f"Antigravity        {status}")
    console.print(f"Available Models   {models_status}")
    console.print(f"Preferred Model    {configured or 'not configured'}")
    console.print("Local Tools        READY")
    console.print("Sandbox            DISABLED (no untrusted code execution is provided)")


@app.command("version")
def version_command() -> None:
    console.print(f"TWA {__version__}")


@app.command("sessions")
def sessions_command() -> None:
    table = Table(title="SAVED SESSIONS")
    for title in ("Session", "Status", "Category", "Target", "Created"):
        table.add_column(title)
    for item in list_sessions():
        table.add_row(
            item.session_id, item.status, item.category, item.target[:70], item.created_at[:19]
        )
    console.print(table)


@app.command("resume")
def resume_command(session_id: str) -> None:
    try:
        session = load_session(session_id)
    except (OSError, ValueError) as exc:
        _fail(f"Could not load session: {exc}")
    if session.target.startswith(("http://", "https://")):
        _fail(
            "Remote session resume requires starting a new scoped run: twa -u URL --scope HOST --s"
        )
    try:
        analyze_path(session, Path(session.target))
    except (OSError, ValueError) as exc:
        session.errors.append({"source": session.target, "message": str(exc)[:500]})
    session.status = "candidate" if session.flags else "unsolved"
    save_session(session)
    path = report_path(session)
    save_session(session)
    console.print(f"Session {session.session_id}: {session.status}; report: {path}")


@app.command("report")
def report_command(session_id: str) -> None:
    try:
        session = load_session(session_id)
    except (OSError, ValueError) as exc:
        _fail(f"Could not load session: {exc}")
    console.print_json(session.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
