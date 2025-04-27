FROM ubuntu
COPY fwdd.service /etc/systemd/system/
COPY temp/fwdd /usr/bin
COPY temp/fwdctl /usr/bin
RUN apt-get update && apt-get install -y systemd
RUN systemctl enable fwdd.service
ENTRYPOINT ["/sbin/init"]