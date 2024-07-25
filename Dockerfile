FROM golang:1.22 AS builder
ENV CGO_ENABLED 0
ARG VERSION
WORKDIR /go/src/app
ADD . .
RUN go build -o /quickauth

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /quickauth /quickauth
ENTRYPOINT ["/quickauth"]
