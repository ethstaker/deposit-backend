FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build make

FROM debian:bookworm-slim
RUN apt update && apt install -y ca-certificates
COPY --from=build /src/deposit-backend /deposit-backend
ENTRYPOINT ["/deposit-backend"]
