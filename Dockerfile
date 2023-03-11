FROM golang:1.20 as build
WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/katsnet

FROM gcr.io/distroless/static-debian11
COPY --from=build /go/bin/katsnet /
CMD ["/katsnet"]
