FROM alpine:3.19 AS builder
WORKDIR /src
RUN apk add --no-cache bash curl git ca-certificates
ENV PATH="/root/.local/bin:${PATH}"
COPY mise.toml ./
ENV MISE_TRUSTED_CONFIG_PATHS=/src/mise.toml
RUN curl -fsSL https://mise.jdx.dev/install.sh | sh
RUN mise install
COPY go.mod go.sum ./
RUN mise exec go -- go mod download
COPY . .
RUN CGO_ENABLED=0 mise exec go -- go build -o /out/idplease .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/idplease /usr/local/bin/idplease
VOLUME /data
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["idplease"]
CMD ["server"]
