FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 python3 tcpdump tshark iptables && rm -rf /var/lib/apt/lists/*
