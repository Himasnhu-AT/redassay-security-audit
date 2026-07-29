FROM python:3.11
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
ADD https://example.invalid/bootstrap.sh /tmp/bootstrap.sh
ENV DATABASE_PASSWORD=pr0d_p4ssw0rd_do_not_ship
COPY . .
CMD ["python", "app/views.py"]
