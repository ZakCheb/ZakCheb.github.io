systemctl start docker
docker build .  --tag blog
docker run   -v $(pwd):/opt -p 800:4000 blog
