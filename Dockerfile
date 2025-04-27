FROM ubuntu
COPY build/output/conf/fwdd.service /etc/systemd/system/
COPY build/output/bin/fwdd /usr/bin
COPY build/output/bin/fwdctl /usr/bin
RUN apt-get update && apt-get install -y systemd
RUN systemctl enable fwdd.service
ENTRYPOINT ["/lib/systemd/systemd"]
