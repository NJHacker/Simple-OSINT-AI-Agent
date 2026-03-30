from __future__ import annotations

import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.pretty import pprint

from src.agent.loop import generate_report, run_collection_phase, run_initial_phase
from src.agent.reporter import render_markdown_report
from src.agent.schemas import SubjectsEnvelope
from src.llm.claude_client import ClaudeClient
from src.utils.config import load_settings
from src.utils.io import create_timestamped_run_dir, read_json, write_json, write_text
from src.utils.logging import setup_logging

console = Console()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple AI Agent Demo")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON input file. Example: demo_subjects/multi_subject_input.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and input only, without calling Claude.",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    settings = load_settings()
    run_output_dir = create_timestamped_run_dir(settings.output_dir)

    setup_logging(run_output_dir / "agent_debug.log")
    logger = logging.getLogger("simple_ai_agent.main")
    logger.info("Run started | input=%s | model=%s", args.input, settings.anthropic_model)

    input_payload = read_json(args.input)
    subjects_envelope = SubjectsEnvelope.model_validate(input_payload)

    console.print("[bold green]Simple_AI_Agent_Demo[/bold green]")
    console.print(f"Loaded input file: [cyan]{Path(args.input).resolve()}[/cyan]")
    console.print(f"Run output dir: [cyan]{run_output_dir}[/cyan]")
    console.print(f"Configured model: [cyan]{settings.anthropic_model}[/cyan]")
    console.print(f"Search backend: [cyan]{settings.search_backend}[/cyan]")
    console.print()

    console.print("[bold]Subjects provided:[/bold]")
    pprint(subjects_envelope.model_dump())

    if args.dry_run:
        console.print("\n[yellow]Dry run complete. No Claude calls were made.[/yellow]")
        return

    llm_client = ClaudeClient(settings)

    state, plan = run_initial_phase(llm_client, subjects_envelope)
    state = run_collection_phase(llm_client, settings, state, plan)
    report = generate_report(llm_client, settings, state)
    markdown_report = render_markdown_report(report)

    write_json(run_output_dir / "initial_state.json", state.model_dump(mode="json"))
    write_json(run_output_dir / "initial_plan.json", plan.model_dump(mode="json"))
    write_json(run_output_dir / "evidence_collection_state.json", state.model_dump(mode="json"))
    write_json(run_output_dir / "investigation_report.json", report.model_dump(mode="json"))
    write_text(run_output_dir / "investigation_report.md", markdown_report)

    console.print("\n[bold]Final report JSON:[/bold]")
    pprint(report.model_dump(mode="json"))

    console.print(f"\n[green]Saved outputs under:[/green] {run_output_dir}")


if __name__ == "__main__":
    main()