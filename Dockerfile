# PLANTED: outdated base with known CVEs, runs as root
FROM golang:1.20-bullseye AS build
WORKDIR /src
COPY . .
RUN go build -o /mediport .

FROM debian:bullseye
COPY --from=build /mediport /mediport
EXPOSE 8080
ENTRYPOINT ["/mediport"]
