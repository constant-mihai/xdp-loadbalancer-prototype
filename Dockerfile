# Deps
FROM debian:bookworm AS deps

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
	curl \
        iproute2 \
        tcpdump

# Build
FROM public.ecr.aws/docker/library/golang:1.23.3-bookworm AS build

RUN echo "StrictHostKeyChecking no" > /etc/ssh_config

WORKDIR /build

COPY . .

# TODO: should go generate be called here?
# If yes, there are some deps that need to be installed in the build layer.
RUN --mount=type=ssh \
            go build -ldflags \
            "-X main.GitCommit=$(git rev-parse --short HEAD) \
            -X main.GitBranch=$(git rev-parse --abbrev-ref HEAD) \
            -X main.ApplicationVersion=$(git describe --always)" \
            ./cmd/xlbp

# Release
FROM deps AS release

COPY --from=build /build/xlbp .
COPY --from=build /build/xlbp.yaml /etc/xlbp/

ENTRYPOINT [ "./xlbp" ]
