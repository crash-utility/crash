# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options.  For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

# -- Project information -----------------------------------------------------

project = 'crash'
copyright = '2002-2025, Red Hat, Inc. and contributors'
author = 'The crash utility developers'

# The short X.Y version.
version = ''
# The full version, including alpha/beta/rc tags.
release = ''

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings.
extensions = []

# The suffix(es) of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['output', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# The whitepaper contains shell transcripts, crash command output and C code
# in untyped literal blocks.  Do not guess a language for them.
highlight_language = 'none'

# Keep the original straight quotes/apostrophes of the source document instead
# of converting them to typographic quotes.
smartquotes = False

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory.  They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
html_title = 'crash utility documentation'

html_last_updated_fmt = '%b %d, %Y'

# -- Options for LaTeX/PDF output --------------------------------------------

latex_engine = 'pdflatex'

latex_documents = [
    (master_doc, 'crash.tex', 'crash utility documentation',
     author, 'manual'),
]
