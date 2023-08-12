FROM python:3.9

ENV PYTHONBUFFERED=1

WORKDIR /LMS

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY .. .

EXPOSE 8000

CMD ["py", "manage.py", "runserver"]