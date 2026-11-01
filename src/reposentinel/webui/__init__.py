"""Optional local web interface: a thin adapter over the scan and comparison engine.

Nothing in this package decides what a finding, a status or an exit code is:
it calls ``engine.run_scan``, ``report_loader`` and ``compare.compare_reports``
and returns their results through the existing JSON and HTML renderers. See
``server.py`` for the local-only security model.
"""
