"""Single source of truth for the tool's version string.

pyproject.toml reads this attribute at build time
([tool.setuptools.dynamic]), so there is nothing else to keep in sync.
"""
__version__ = "0.2.0"
