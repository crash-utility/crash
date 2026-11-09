# SPDX-License-Identifier: GPL-2.0
# Makefile for the crash documentation.
#
# The reStructuredText sources in this directory are the source of truth for
# the crash documentation.

SPHINXBUILD   ?= sphinx-build
SPHINXOPTS    ?=
SOURCEDIR      = .
BUILDDIR       = output
PAPER          ?= a4
WEBSITE_DIR   ?= $(abspath ../_site)

.PHONY: help html htmldocs website pdf latexpdf clean cleandocs

help:
	@echo "Please use 'make <target>' where <target> is one of:"
	@echo "  html / htmldocs    to make standalone HTML files"
	@echo "  website            to build the HTML documentation to a directory"
	@echo "  pdf / latexpdf     to make a PDF file (requires a LaTeX toolchain)"
	@echo "  clean / cleandocs  to remove the build directory"

html htmldocs:
	$(SPHINXBUILD) -b html $(SPHINXOPTS) $(SOURCEDIR) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

website:
	$(SPHINXBUILD) -b html -d $(BUILDDIR)/doctrees $(SPHINXOPTS) $(SOURCEDIR) $(WEBSITE_DIR)
	@echo
	@echo "Build finished. The HTML pages are in $(WEBSITE_DIR)."

latex:
	$(SPHINXBUILD) -b latex $(SPHINXOPTS) $(SOURCEDIR) $(BUILDDIR)/latex

pdf latexpdf: latex
	$(MAKE) -C $(BUILDDIR)/latex all-pdf
	@echo "Build finished. The PDF is in $(BUILDDIR)/latex."

clean cleandocs:
	rm -rf $(BUILDDIR)
