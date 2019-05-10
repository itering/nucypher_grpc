FROM python:3.6.7-stretch

RUN mkdir app

COPY requirements.txt app/requirements.txt

RUN pip3 install -r app/requirements.txt

ADD . app

WORKDIR app

CMD ["python","rpc_server.py"]
