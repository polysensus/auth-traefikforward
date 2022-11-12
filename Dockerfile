# Go binaries are standalone, so use a multi-stage build to produce smaller images.

# Use base golang image from Docker Hub
FROM golang:1.18 as build

# For debuging via delve source mappings are determined by the build path, so
# we make this the same as the run path to avoid many many wasted hours
WORKDIR /service

# Install dependencies in go.mod and go.sum
COPY go/go.mod ./
RUN go mod download && go mod tidy

# Copy rest of the application source code
COPY go/ ./

RUN find .

# Skaffold passes in debug-oriented compiler flags
ARG SKAFFOLD_GO_GCFLAGS
RUN echo "Go gcflags: ${SKAFFOLD_GO_GCFLAGS}"
RUN go build -gcflags="${SKAFFOLD_GO_GCFLAGS}" -mod=readonly -v -o /authex

RUN find . && ls -la /authex
# Now create separate deployment image
FROM gcr.io/distroless/base

# Definition of this variable is used by 'skaffold debug' to identify a golang binary.
# Default behavior - a failure prints a stack trace for the current goroutine.
# See https://golang.org/pkg/runtime/
ENV GOTRACEBACK=single

WORKDIR /service
COPY --from=build /authex .
ENTRYPOINT ["/service/authex"]
