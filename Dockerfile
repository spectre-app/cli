FROM alpine
WORKDIR /spectre/cli
ADD . /spectre

RUN apk update && apk add cmake make gcc musl-dev ncurses-dev libsodium-dev json-c-dev libxml2-dev
RUN cmake -DBUILD_SPECTRE_TESTS=ON . && make install
RUN spectre-tests

CMD spectre
