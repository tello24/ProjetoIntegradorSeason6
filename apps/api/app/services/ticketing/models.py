from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TicketDraft:
    summary: str
    description_lines: tuple[str, ...]
    stable_label: str


@dataclass(frozen=True, slots=True)
class CreatedTicket:
    external_key: str
    external_url: str
