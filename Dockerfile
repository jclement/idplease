FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY idplease /usr/local/bin/idplease
EXPOSE 8080
ENTRYPOINT ["idplease"]
CMD ["server"]
