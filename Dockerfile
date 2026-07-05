# Image du serveur de coordination OmniUp VPN (HTTP + STUN + relais).
# L'agent omnid ne se conteneurise pas tel quel (TUN + réseau hôte) :
# installez-le directement sur les machines.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/omni-server ./cmd/omni-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/omni-server /omni-server
VOLUME /var/lib/omniup
EXPOSE 8080/tcp 3478/udp 3479/udp
ENTRYPOINT ["/omni-server"]
CMD ["serve", "--addr", ":8080", "--state", "/var/lib/omniup/server.json"]
