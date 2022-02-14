
FROM python:latest

WORKDIR /home/csd

ADD requirements.txt .
ADD service_priority.csv .
ADD service_priority-02.csv .
ADD kpi-restconf-03.py .
#Here we added the python file that we want to run in docker and define its location.

RUN pip install -r requirements.txt
#Here we installed the dependencies, we are using the pygame library in our main.py file so we have to use the pip command for installing the library
CMD [ "python", "kpi-restconf-03.py" ]
#lastly we specified the entry command this line is simply running python ./main.py in our container terminal