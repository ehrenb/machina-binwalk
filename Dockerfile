FROM behren/machina-base-ubuntu:latest

COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
RUN rm /tmp/requirements.txt

ENV DEBIAN_FRONTEND noninteractive

# install Binwalk

# dep.sh requires 'python' to exist, not just 'python3'
RUN ln -s $(which python3) /usr/bin/python

# a patched version of binwalk's deps.sh
# that applies this fix: https://github.com/devttys0/sasquatch/issues/48#issuecomment-1267506233
COPY deps.sh /tmp/
RUN chmod +x /tmp/deps.sh
RUN wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.zip -P /machina &&\
    cd /machina && unzip v2.3.4.zip

# execute patched deps.sh
RUN cd /tmp && apt update && ./deps.sh --yes

# install binwalk python api
RUN cd /machina/binwalk-2.3.4 &&\
    python3 setup.py install

COPY BinwalkAnalysis.json /schemas/

COPY src /machina/src

