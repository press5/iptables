"""
Shared fixtures for iptables role template tests.

Renders Jinja2 templates directly (no Ansible required) using the same
trim_blocks/lstrip_blocks settings Ansible uses, so output is faithful to
what the role produces on a real host.
"""
import os
import yaml
import pytest
from jinja2 import Environment, FileSystemLoader

ROLE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(ROLE_ROOT, "templates")
DEFAULTS_FILE = os.path.join(ROLE_ROOT, "defaults", "main.yml")


@pytest.fixture(scope="session")
def jinja_env():
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


@pytest.fixture(scope="session")
def defaults():
    with open(DEFAULTS_FILE) as f:
        return yaml.safe_load(f)


@pytest.fixture
def render_v4(jinja_env, defaults):
    """Render rules.v4.j2 with defaults merged with any keyword overrides."""
    tmpl = jinja_env.get_template("rules.v4.j2")

    def _render(**overrides):
        ctx = dict(defaults)
        ctx.update(overrides)
        return tmpl.render(**ctx)

    return _render


@pytest.fixture
def render_v6(jinja_env, defaults):
    """Render rules.v6.j2 with defaults merged with any keyword overrides."""
    tmpl = jinja_env.get_template("rules.v6.j2")

    def _render(**overrides):
        ctx = dict(defaults)
        ctx.update(overrides)
        return tmpl.render(**ctx)

    return _render


@pytest.fixture
def render_ipset(jinja_env, defaults):
    """Render ipset.conf.j2 with defaults merged with any keyword overrides."""
    tmpl = jinja_env.get_template("ipset.conf.j2")

    def _render(**overrides):
        ctx = dict(defaults)
        ctx.update(overrides)
        return tmpl.render(**ctx)

    return _render
