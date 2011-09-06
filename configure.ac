#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)

AC_INIT([guile-agentx],
        m4_esyscmd([build-aux/git-version-gen .tarball-version | tr -d '\n']),
        [devs@securactive.net])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(agentx/tools.scm)

AM_INIT_AUTOMAKE([-Wall foreign])

# Additional parameters
DEFAULT_GUILELIBDIR="$(guile-config info sitedir)"
AC_ARG_VAR([GUILELIBDIR], [Where to install guile modules [wherever guile-config says]])
AS_IF([test "x$GUILELIBDIR" = x], [if test -n "$DEFAULT_GUILELIBDIR"; then GUILELIBDIR="$DEFAULT_GUILELIBDIR"; else exit 1; fi])

AC_CONFIG_FILES([
	Makefile
	agentx/Makefile
])

AC_OUTPUT
