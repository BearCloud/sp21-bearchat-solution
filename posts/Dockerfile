FROM golang:latest

ADD . /go/src/github.com/BearCloud/fa20-project-dev/posts-service

WORKDIR /go/src/github.com/BearCloud/fa20-project-dev/posts-service

RUN go mod download

RUN go build -o main .

EXPOSE 80

ENTRYPOINT [ "./main" ]
