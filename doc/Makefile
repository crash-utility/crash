# SPDX-License-Identifier: GPL-2.0
# Makefile for the crash documentation.
#
# The reStructuredText sources in this directory are the source of truth for
# the crash documentation; the HTML output generated here is what is published
# on the crash-utility web site.

SPHINXBUILD   ?= sphinx-build
SPHINXOPTS    ?=
SOURCEDIR      = .
BUILDDIR       = output
PAPER          ?= a4

.PHONY: help html htmldocs pdf latexpdf clean cleandocs

help:
	@echo "Please use 'make <target>' where <target> is one of:"
	@echo "  html / htmldocs    to make standalone HTML files"
	@echo "  pdf / latexpdf     to make a PDF file (requires a LaTeX toolchain)"
	@echo "  clean / cleandocs  to remove the build directory"

html htmldocs:
	$(SPHINXBUILD) -b html $(SPHINXOPTS) $(SOURCEDIR) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

latex:
	$(SPHINXBUILD) -b latex $(SPHINXOPTS) $(SOURCEDIR) $(BUILDDIR)/latex

pdf latexpdf: latex
	$(MAKE) -C $(BUILDDIR)/latex all-pdf
	@echo "Build finished. The PDF is in $(BUILDDIR)/latex."

clean cleandocs:
	rm -rf $(BUILDDIR)
