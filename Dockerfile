FROM behren/machina-base-ubuntu:latest

COPY requirements.txt /tmp/
RUN pip3 install --trusted-host pypi.org \
                --trusted-host pypi.python.org \
                --trusted-host files.pythonhosted.org \
                -r /tmp/requirements.txt
RUN rm /tmp/requirements.txt


# install Binwalk

RUN wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.3.zip -P /machina &&\
    cd /machina && unzip v2.3.3.zip

# dep.sh requires 'python' to exist, not just 'python3'
RUN ln -s $(which python3) /usr/bin/python
RUN cd /machina/binwalk-2.3.3 &&\
    ./deps.sh --yes &&\
    python3 setup.py install

COPY Binwalk.json /schemas/

COPY src /machina/src

