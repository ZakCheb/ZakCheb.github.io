FROM ubuntu:18.04
RUN apt-get -y update && apt-get install -y jekyll 
RUN apt-get install -y curl net-tools
WORKDIR /opt
COPY . /opt/
CMD ["jekyll","serve","--host","0.0.0.0"]
