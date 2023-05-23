FROM golang:1.17-alpine3.13 AS fabconnect-builder
RUN apk add make git
WORKDIR /fabconnect

RUN git clone https://github.com/hnamzian/fabric-sdk-go
WORKDIR /fabconnect/fabric-sdk-go
RUN git checkout fabconnect-int
WORKDIR /fabconnect

ADD go.mod go.sum ./

RUN go mod download -x
ADD . .
RUN make build

FROM alpine:latest
WORKDIR /fabconnect
COPY --from=fabconnect-builder /fabconnect/fabconnect ./
ADD ./openapi ./openapi/
RUN ln -s /fabconnect/fabconnect /usr/bin/fabconnect
ENTRYPOINT [ "fabconnect" ]
