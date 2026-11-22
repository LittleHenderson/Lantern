# Lantern's test machine: one machine is made from this image for one check of the website and removed after it
# (a firm pass or fail, stage 3). Build from the REPOSITORY ROOT:
#   docker build -f cloud/runner/Dockerfile -t lantern-runner .
# It holds Lantern's own code and the programs a project's tests run with, each fixed to the version it was checked
# with (the same images the test sandbox names in lantern/sandbox.py `IMAGES`); nothing of anyone's project, no key
# and no secret. The website hands in the project and the libraries it fetched for it before the machine was made,
# as one archive; the machine fetches nothing (docs/deploy.md, "The test machine").
FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS node

FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
# Node and npm for JavaScript tests, copied from the node image of the same Debian release: npm runs a project's
# own `test` script with the libraries the website fetched, and is never asked to fetch any here.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node --version && npm --version
# Lantern's own code, nothing else of Python's: the program inside needs Python's own library only, and pip goes,
# so nothing on the machine can fetch a library.
COPY lantern /usr/local/lib/python3.12/site-packages/lantern
# The commit being built, so a check's result can name the exact Lantern that ran it. Only a full 40-character
# commit is written; anything else leaves it empty.
ARG LANTERN_COMMIT=""
RUN case "$LANTERN_COMMIT" in \
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) \
        [ ${#LANTERN_COMMIT} -eq 40 ] \
          && printf 'COMMIT = "%s"\n' "$LANTERN_COMMIT" >> /usr/local/lib/python3.12/site-packages/lantern/_build.py ;; \
    esac; true
RUN python -m pip uninstall --yes --no-input pip setuptools wheel \
 && python -I -c "import lantern.runner"
# The image starts as root for the runner alone: it opens the one door the website talks to, and it runs the
# project's tests with Lantern's own sandbox as an ordinary user (uid 65534), in a network of their own that holds
# only the machine's own address, so the tests can neither reach the door nor read what the runner holds. The
# door answers only to the key made for this one check, of which the machine is given the fingerprint alone
# (LANTERN_RUNNER_KEY_SHA256, when the machine is made). A wall the design counts on that does not stand on the
# machine means no test runs there (lantern/runner.py `walls`).
EXPOSE 8080
CMD ["python", "-I", "-m", "lantern.runner", "serve", "--host", "0.0.0.0", "--port", "8080"]
