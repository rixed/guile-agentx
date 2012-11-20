SUBDIRS = agentx

EXTRA_DIST = .tarball-version
.tarball-version:
	echo "$(VERSION)" > $@

distclean-local:
	rm -f .tarball-version

dist_check_SCRIPTS = check.scm
TESTS = $(dist_check_SCRIPTS)
TESTS_ENVIRONMENT = \
	GUILE_LOAD_PATH=$(top_srcdir) \
	GUILE_AUTO_COMPILE=0 \
	GUILE_WARN_DEPRECATED=no
