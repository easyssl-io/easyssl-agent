# EasySSL Client - Agent Guide

Simple, procedural, explicit code is preferred over clever, abstract, or
implicit code. Prefer straightforward control flow, clear names, minimal magic.

Constraints that shape this codebase:

- Single Go binary, kept as light as possible (Constitution Principle II).
  Capabilities ship as on-demand plugins, not baked into the base binary
  (Principle I, Plugin-First Extensibility).
- The Client only ever initiates connections to the Server, never the reverse.
- The Client exposes a CLI alongside its TUI; CLI output supports both
  human-readable and JSON formats, and errors are written to stderr.
- The shared Client-to-Server contract lives in the `easyssl-contract` module;
  do not duplicate wire types here.
- Every change that alters runtime behavior lands with the tests that would
  catch its regression (Principle III).

Status: scaffolding.
