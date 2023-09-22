FROM alpine:3.18

LABEL maintainer="YoMin Su<b10823027@yuntech.edu.tw>"

WORKDIR /data/netflow

RUN apk update
RUN apk add nfdump=1.7.2-r0

EXPOSE 9995

CMD [ "nfcapd", "-t", "60", "-w", "/data/netflow" ]