#Build Stage
FROM rust:1.72-alpine3.18 AS chef

WORKDIR /app
RUN apk add musl-dev --no-cache
RUN cargo install cargo-chef

FROM chef AS planner

COPY . .
RUN cargo chef prepare

FROM chef AS builder

COPY --from=planner /app/recipe.json /app/recipe.json
RUN cargo chef cook --release

COPY . .
RUN cargo build --release

#Production Stage
FROM alpine:3.18 AS runner

LABEL maintainer="YoMin Su<b10823027@yuntech.edu.tw>"

RUN apk update
RUN apk add nfdump=1.7.2-r0

WORKDIR /app
COPY --from=builder /app/target/release/netflow-post-processor /app/

CMD [ "/app/netflow-post-processor" ]
