FROM python:3
COPY ./Flask /usr/src/app
WORKDIR /usr/src/app
RUN pip install flask
RUN pip install PyJWT
RUN pip install flask-login
RUN pip install flask-oidc
CMD ["python", "login_test.py"]