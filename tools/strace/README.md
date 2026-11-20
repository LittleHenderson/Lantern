# strace's fix of 2026-11-10, as its makers wrote it

`3a4f0c7.patch` is commit `3a4f0c7c3969ec6e25e729ed6b36a0391764a375` of strace ("strace: handle ESRCH from
PTRACE_GETSIGINFO during termination", strace's issue 433), byte for byte as `git format-patch -1 --stdout
3a4f0c7c3969ec6e25e729ed6b36a0391764a375` (git 2.43.0) writes it from a clone of https://github.com/strace/strace.
Nothing in it was changed. It is strace's code under strace's licences (LGPL-2.1-or-later for `src/strace.c`,
GPL-2.0-or-later for the helper and the test it adds, as their own licence lines say), it is not part of Lantern's
package, and only CI uses it.

CI's Linux test jobs apply it (`.github/workflows/ci.yml`, the step that builds strace): `tools/netless.py --watch` has
strace write down every address a program of the tests tries, and every released strace (7.3 and older) can stop at
random when a program it follows ends right after a signal, which cut the record of the tests off three times between
2026-11-14 and 2026-11-18. The fix came after strace's newest release, so CI builds the 7.3 release with it, shows
strace's own test of the fault failing on the release and passing with the fix, and installs that one.
`tests/test_ci_recorder.py` keeps the file and the step as they are. When a strace release that holds the fix comes
out, CI can take that release instead and this folder can go.
