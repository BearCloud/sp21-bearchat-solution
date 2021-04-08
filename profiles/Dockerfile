FROM golang:latest

ADD . /go/src/github.com/BearCloud/fa20-project-dev/profiles

WORKDIR /go/src/github.com/BearCloud/fa20-project-dev/profiles

RUN go mod download

RUN go build -o main .

EXPOSE 82

ENTRYPOINT [ "./main" ]
