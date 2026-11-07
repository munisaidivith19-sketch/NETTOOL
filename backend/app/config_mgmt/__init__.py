"""Configuration management shared with the agent (masking, denylist, job signing) plus the
Jinja2 change templates. masking.py, denylist.py and jobsign.py are byte-for-byte copies of
the agent's files; tests/test_config_shared.py fails if they drift apart."""
