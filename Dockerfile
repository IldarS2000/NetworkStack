FROM ubuntu:22.04
RUN apt update
RUN apt install -y dpdk=21.11.6-0ubuntu0.22.04.2
RUN apt install -y dpdk-dev=21.11.6-0ubuntu0.22.04.2
RUN apt install -y iputils-ping net-tools
RUN echo 'export PS1="nstk> "' >> /root/.bashrc
COPY build/output/bin/fwdd /usr/bin
COPY build/output/bin/fwdd_start.sh /usr/bin
COPY build/output/bin/fwdctl /usr/bin
CMD ["/usr/bin/fwdd_start.sh"]
