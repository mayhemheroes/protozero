FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_compare.cpp -fsanitize=fuzzer,address -I /repo/include/protozero/ -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/build/tools/pbf-decoder /
COPY --from=builder /fuzz /fuzz_compare
