"""Allow ``python -m trueai``.

The console script is the normal entry point, but a module entry point is what
people reach for when the script is not on PATH — in a CI step, a container, or a
virtual environment that was not activated. Both routes run the same CLI.
"""

from trueai.cli.app import main

main()
