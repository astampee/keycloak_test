FROM python:3
COPY ./Flask /usr/src/app
WORKDIR /usr/src/app
RUN pip install flask
RUN pip install python-keycloak 
CMD ["python", "api.py"]