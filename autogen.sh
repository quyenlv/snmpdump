#!/bin/sh
#
# Run this to generate all the initial makefiles.
#
# $Id$

DIE=true
PROJECT="snmpdump"


VER=`bison --version | sed 's/^[a-zA-Z ]*//'`
case "$VER" in
0* | 1\.[0-9] | 1\.1[0-9] | 1\.2[0-4] )
  cat >&2 <<_EOF_

	You must have bison 1.25 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/bison/
_EOF_
  DIE="exit 1"
  ;;
esac


VER=`flex --version | sed 's/^[a-zA-Z ]*//'`
case "$VER" in
[0-1]* | 2\.[0-4]\.* | 2\.5\.[0-3] )
  cat >&2 <<_EOF_

	You must have flex 2.5.4 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/flex/
_EOF_
  DIE="exit 1"
  ;;
esac


VER=`autoconf --version | grep '^autoconf' | sed 's/.*)//'`
case "$VER" in
0* | 1\.* | 2\.[0-9] | 2\.[0-9][a-z]* | \
2\.1[0-2] | 2\.1[0-2][a-z]* )
  cat >&2 <<_EOF_

	You must have autoconf 2.13 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/autoconf/
_EOF_
  DIE="exit 1"
  ;;
esac


VER=`automake --version | grep '^automake' | sed 's/.*)//'`
case "$VER" in
0* | 1\.[0-3] | 1\.[0-3][a-z]* )

  cat >&2 <<_EOF_

	You must have automake 1.4 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/automake/
_EOF_
  DIE="exit 1"
  ;;
esac


$DIE

if test -z "$*"; then
	echo "Running ./configure with no arguments. If you wish to pass any,"
	echo "please specify them on the $0 command line."
fi

#aclocal_flags="`./aclocal-flags`"
aclocal_flags=""
aclocalinclude="$ACLOCAL_FLAGS $aclocal_flags"; \
echo aclocal $aclocalinclude
aclocal $aclocalinclude || exit 1
echo autoheader
autoheader || exit 1
echo automake --add-missing --gnu $am_opt
automake --add-missing --gnu $am_opt || exit 1
echo autoconf
autoconf || exit 1

./configure "$@" || exit 1

echo
echo "Now type 'make' to compile $PROJECT."
