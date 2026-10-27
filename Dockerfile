# SPDX-License-Identifier: Apache-2.0
# Builds qorescan from source and runs it as an unprivileged user.
#
#   docker build -t qorescan .
#   docker run --rm -v "$PWD/home:/scan/home:ro" qorescan scan --node-home /scan/home

FROM golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/qorescan ./cmd/qorescan

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/qorescan /usr/local/bin/qorescan
COPY LICENSE NOTICE /usr/share/doc/qorescan/
USER 65532:65532
WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/qorescan"]
CMD ["--help"]
