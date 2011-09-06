SUBDIRS = agentx

EXTRA_DIST = .tarball-version
.tarball-version:
	echo "$(VERSION)" > $@

distclean-local:
	rm -f .tarball-version

dist_check_SCRIPTS = check.scm
TESTS = $(dist_check_SCRIPTS)
