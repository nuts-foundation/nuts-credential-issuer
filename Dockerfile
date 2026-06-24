FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/nuts-credential-issuer .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nuts-credential-issuer /usr/local/bin/nuts-credential-issuer
EXPOSE 8080
# The distroless image has no shell/curl, so the binary checks its own /health.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
  CMD ["/usr/local/bin/nuts-credential-issuer", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/nuts-credential-issuer"]
