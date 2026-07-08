# Long reasoning dataset

This directory contains multi-step reverse engineering task examples. These are
not single action-to-command rows: each item teaches a workflow, the commands
that gather evidence, and the reasoning expected from a model.

The verifier executes `setup` and `starter_commands` and checks that the output
contains the facts used by the answer. The full reasoning can still require
human review when a task depends on subjective vulnerability judgment,
decompiler quality, or ambiguous firmware architecture heuristics.
